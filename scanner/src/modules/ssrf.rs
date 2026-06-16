use reqwest::Client;
use crate::models::vulnerability::{Vulnerability, VulnCategory, OwaspCategory, Evidence, EvidenceType};
use crate::models::scan::Severity;
use crate::modules::crawler::CrawlResult;
use tracing::{info, warn};

pub struct SsrfDetector {
    client: Client,
    #[allow(dead_code)]
    base_url: String,
}

impl SsrfDetector {
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        Self { client, base_url }
    }

    pub async fn detect(&self, crawl_result: &CrawlResult) -> Vec<Vulnerability> {
        info!("Testing for Server-Side Request Forgery (SSRF)...");
        let mut vulns = vec![];

        let ssrf_params = ["url", "dest", "redirect", "uri", "path", "continue", "window", "next", "data", "reference", "site", "html"];
        // Payloads that attempt to access internal resources
        let ssrf_payloads = [
            "http://127.0.0.1:80",
            "http://127.0.0.1:22",
            "http://localhost:6379", // Redis
            "http://169.254.169.254/latest/meta-data/", // AWS Metadata
            "file:///etc/passwd",
        ];

        let mut test_urls = vec![];

        for form in &crawl_result.forms {
            if form.method == "GET" {
                for param in &form.inputs {
                    let p_lower = param.to_lowercase();
                    if ssrf_params.iter().any(|&s| p_lower.contains(s)) {
                        for payload in &ssrf_payloads {
                            test_urls.push(format!("{}?{}={}", form.action, param, encode_url(payload)));
                        }
                    }
                }
            }
        }

        for url in test_urls {
            match self.client.get(&url).send().await {
                Ok(resp) => {
                    let body = resp.text().await.unwrap_or_default();
                    
                    // Basic heuristic: Did we get root contents or AWS metadata?
                    if body.contains("root:x:0:0:") || body.contains("ami-id") || body.contains("instance-id") || body.contains("redis_version") {
                        warn!("SSRF Vulnerability found at {}", url);
                        
                        vulns.push(Vulnerability::new(
                            "Server-Side Request Forgery (SSRF)",
                            "The application fetches internal or external resources based on user input without proper validation. An attacker can access internal network services, cloud metadata, or local files.",
                            Severity::Critical,
                            VulnCategory::Ssrf,
                            url.clone(),
                        )
                        .with_remediation("Implement strict allow-lists for URLs. Do not allow users to specify arbitrary domains or IPs. Block requests to internal IPs (127.0.0.1, 169.254.169.254, 10.0.0.0/8, etc.).")
                        .with_owasp(OwaspCategory::A10ServerSideRequestForgery)
                        .with_cwe(918)
                        .with_evidence(Evidence {
                            evidence_type: EvidenceType::HttpResponse,
                            request: Some(format!("GET {}", url)),
                            response: Some(body.chars().take(300).collect()),
                            payload: None,
                            screenshot_path: None,
                            description: "Sensitive internal data returned via SSRF".to_string(),
                        }));
                    }
                }
                Err(e) => {
                    // Timeouts or connection refused might indicate we hit a closed internal port.
                    // To avoid false positives, we log but don't strictly alert unless it's a known internal port like 22 or 6379 giving a specific error.
                    let err_str = e.to_string();
                    if err_str.contains("tcp connect error") || err_str.contains("Connection refused") {
                        // Potential blind SSRF, but we'll skip alerting to avoid spam for now.
                    }
                }
            }
        }

        vulns
    }
}

fn encode_url(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            ' ' => "+".to_string(),
            c => format!("%{:02X}", c as u32),
        })
        .collect()
}
