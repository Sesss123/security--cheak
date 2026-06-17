use reqwest::Client;
use crate::models::vulnerability::{Vulnerability, VulnCategory, OwaspCategory, Evidence, EvidenceType};
use crate::models::scan::Severity;
use crate::modules::crawler::CrawlResult;
use tracing::{info, warn};

/// [FIX #24] SSRF detection now tests:
///   1. GET form parameters (original behaviour)
///   2. POST form body as JSON {"<param>": "<payload>"} — catches APIs that accept JSON
///   3. Common SSRF-injectable HTTP headers (X-Forwarded-For, X-Real-IP, etc.)
///
/// [FIX #36] Removed the local `encode_url` function that re-implemented
/// percent-encoding. Now uses `url::form_urlencoded` (already a dependency).
pub struct SsrfDetector {
    client: Client,
    #[allow(dead_code)]
    base_url: String,
}

impl SsrfDetector {
    pub fn new(base_url: String) -> Self {
        let client = crate::utils::http::get_global_client();
        Self { client, base_url }
    }

    pub async fn detect(&self, crawl_result: &CrawlResult) -> Vec<Vulnerability> {
        info!("Testing for Server-Side Request Forgery (SSRF)...");
        let mut vulns = vec![];

        let ssrf_params = [
            "url", "dest", "redirect", "uri", "path", "continue",
            "window", "next", "data", "reference", "site", "html",
        ];

        // Payloads that attempt to access internal resources
        let ssrf_payloads = [
            "http://127.0.0.1:80",
            "http://127.0.0.1:22",
            "http://localhost:6379", // Redis
            "http://169.254.169.254/latest/meta-data/", // AWS Metadata
            "file:///etc/passwd",
        ];

        // ── 1. GET form parameters (original) ─────────────────────────────
        let mut get_test_urls = vec![];
        for form in &crawl_result.forms {
            if form.method == "GET" {
                for param in &form.inputs {
                    let p_lower = param.to_lowercase();
                    if ssrf_params.iter().any(|&s| p_lower.contains(s)) {
                        for payload in &ssrf_payloads {
                            get_test_urls.push((
                                format!("{}?{}={}", form.action, param, percent_encode(payload)),
                                payload.to_string(),
                            ));
                        }
                    }
                }
            }
        }

        for (url, payload) in &get_test_urls {
            if let Some(vuln) = self.test_ssrf_url(url, &format!("GET {}", url), &payload).await {
                vulns.push(vuln);
            }
        }

        // ── 2. [FIX #24] POST body as JSON ────────────────────────────────
        // Many modern APIs accept JSON bodies. SSRF via POST is commonly missed.
        for form in &crawl_result.forms {
            if form.method == "POST" {
                for param in &form.inputs {
                    let p_lower = param.to_lowercase();
                    if ssrf_params.iter().any(|&s| p_lower.contains(s)) {
                        for payload in &ssrf_payloads {
                            let json_body = serde_json::json!({ param: payload });
                            let request_desc = format!("POST {} body: {}", form.action, json_body);

                            match self.client
                                .post(&form.action)
                                .json(&json_body)
                                .send()
                                .await
                            {
                                Ok(resp) => {
                                    let body = resp.text().await.unwrap_or_default();
                                    if self.is_ssrf_response(&body) {
                                        warn!("SSRF via POST JSON body at {}", form.action);
                                        vulns.push(self.make_ssrf_vuln(&form.action, &request_desc, &body));
                                    }
                                }
                                Err(e) => warn!("POST SSRF test failed for {}: {}", form.action, e),
                            }
                        }
                    }
                }
            }
        }

        // ── 3. [FIX #24] SSRF-injectable HTTP headers ─────────────────────
        // Some backends use headers like X-Forwarded-For to make backend requests.
        let ssrf_headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Forwarded-Host",
            "X-Original-URL",
            "X-Rewrite-URL",
        ];

        for payload in &ssrf_payloads {
            for header in &ssrf_headers {
                let test_url = format!("{}/", self.base_url.trim_end_matches('/'));
                let request_desc = format!("GET {} ({}: {})", test_url, header, payload);

                match self.client
                    .get(&test_url)
                    .header(*header, *payload)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let body = resp.text().await.unwrap_or_default();
                        if self.is_ssrf_response(&body) {
                            warn!("SSRF via header {} at {}", header, test_url);
                            vulns.push(self.make_ssrf_vuln(&test_url, &request_desc, &body));
                        }
                    }
                    Err(e) => warn!("Header SSRF test failed: {}", e),
                }
            }
        }

        vulns
    }

    /// Send a GET request and check for SSRF indicators in the response body.
    async fn test_ssrf_url(&self, url: &str, request_desc: &str, _payload: &str) -> Option<Vulnerability> {
        match self.client.get(url).send().await {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                if self.is_ssrf_response(&body) {
                    warn!("SSRF Vulnerability found at {}", url);
                    Some(self.make_ssrf_vuln(url, request_desc, &body))
                } else {
                    None
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                // Blind SSRF heuristic: connection refused on an internal port we injected
                if err_str.contains("tcp connect error") || err_str.contains("Connection refused") {
                    warn!("Possible blind SSRF at {} (connection refused — internal port may have been reached)", url);
                }
                None
            }
        }
    }

    /// Returns true if the response body contains SSRF indicator strings.
    fn is_ssrf_response(&self, body: &str) -> bool {
        body.contains("root:x:0:0:")   // /etc/passwd
            || body.contains("ami-id")         // AWS metadata
            || body.contains("instance-id")    // AWS metadata
            || body.contains("redis_version")  // Redis info
    }

    /// Builds a standard SSRF vulnerability report.
    fn make_ssrf_vuln(&self, url: &str, request_desc: &str, body: &str) -> Vulnerability {
        Vulnerability::new(
            "Server-Side Request Forgery (SSRF)",
            "The application fetches internal or external resources based on user input \
            without proper validation. An attacker can access internal network services, \
            cloud metadata, or local files.",
            Severity::Critical,
            VulnCategory::Ssrf,
            url.to_string(),
        )
        .with_remediation(
            "Implement strict allow-lists for URLs. Do not allow users to specify arbitrary \
            domains or IPs. Block requests to internal IPs (127.0.0.1, 169.254.169.254, \
            10.0.0.0/8, etc.). Validate all URL/header inputs on the server side."
        )
        .with_owasp(OwaspCategory::A10ServerSideRequestForgery)
        .with_cwe(918)
        .with_evidence(Evidence {
            evidence_type: EvidenceType::HttpResponse,
            request: Some(request_desc.to_string()),
            response: Some(body.chars().take(300).collect()),
            payload: None,
            screenshot_path: None,
            description: "Sensitive internal data returned via SSRF".to_string(),
        })
    }
}

// [FIX #36] Shared percent-encoding helper — replaces the inline `encode_url` function
// that re-implemented URL encoding from scratch. Now uses the `url` crate's
// `form_urlencoded` which is already a project dependency.
fn percent_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
