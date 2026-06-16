use reqwest::{Client, StatusCode};
use tracing::{info, warn};
use std::time::Duration;

use crate::models::vulnerability::{Vulnerability, VulnCategory, Evidence, EvidenceType};
use crate::models::scan::Severity;

pub struct WafDetector {
    client: Client,
    base_url: String,
}

impl WafDetector {
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        Self { client, base_url: base_url.trim_end_matches('/').to_string() }
    }

    pub async fn detect(&self) -> Vec<Vulnerability> {
        info!("Testing for Web Application Firewall (WAF)...");
        let mut vulns = vec![];

        let mut waf_name = String::new();
        let mut evidence_str = String::new();

        // 1. Send normal request to check headers
        if let Ok(resp) = self.client.get(&self.base_url).send().await {
            let headers = resp.headers();
            if let Some(server) = headers.get("server") {
                let server_str = server.to_str().unwrap_or("").to_lowercase();
                if server_str.contains("cloudflare") {
                    waf_name = "Cloudflare".to_string();
                } else if server_str.contains("akamai") {
                    waf_name = "Akamai".to_string();
                } else if server_str.contains("awselb") || server_str.contains("aws") {
                    waf_name = "AWS WAF / ALB".to_string();
                } else if server_str.contains("imperva") || server_str.contains("incapsula") {
                    waf_name = "Imperva / Incapsula".to_string();
                } else if server_str.contains("sucuri") {
                    waf_name = "Sucuri".to_string();
                }
            }

            // Other header checks
            if headers.contains_key("cf-ray") {
                waf_name = "Cloudflare".to_string();
            } else if headers.contains_key("x-amz-cf-id") {
                waf_name = "AWS CloudFront WAF".to_string();
            } else if headers.contains_key("x-sucuri-id") {
                waf_name = "Sucuri".to_string();
            }
        }

        // 2. Send malicious payload to trigger block page
        let test_payloads = [
            format!("{}/?q=<script>alert(1)</script>", self.base_url),
            format!("{}/?file=../../../../etc/passwd", self.base_url),
            format!("{}/?id=1%20UNION%20SELECT%20NULL--", self.base_url),
        ];

        let mut blocked = false;

        for url in &test_payloads {
            if let Ok(resp) = self.client.get(url).send().await {
                let status = resp.status();
                if status == StatusCode::FORBIDDEN || status == StatusCode::NOT_ACCEPTABLE || status.as_u16() == 429 {
                    blocked = true;
                    if let Ok(body) = resp.text().await {
                        let body_lower = body.to_lowercase();
                        if waf_name.is_empty() {
                            if body_lower.contains("cloudflare") {
                                waf_name = "Cloudflare".to_string();
                            } else if body_lower.contains("amazon") || body_lower.contains("aws") {
                                waf_name = "AWS WAF".to_string();
                            } else if body_lower.contains("imperva") || body_lower.contains("incapsula") {
                                waf_name = "Imperva".to_string();
                            } else if body_lower.contains("security rules") || body_lower.contains("blocked") {
                                waf_name = "Generic WAF".to_string();
                            }
                        }
                        evidence_str = format!("Status: {}\nBlock Page Extract: {}", status, &body[..body.len().min(200)]);
                    }
                    break;
                }
            }
        }

        if !waf_name.is_empty() {
            warn!("WAF Detected: {}", waf_name);
            vulns.push(Vulnerability::new(
                format!("Web Application Firewall (WAF) Detected: {}", waf_name),
                format!(
                    "The target application is protected by '{}'. This will block standard security testing payloads. \
                    The scanner automatically attempted basic evasion, but advanced manual testing may be required.",
                    waf_name
                ),
                Severity::Info,
                VulnCategory::InformationDisclosure,
                self.base_url.clone()
            )
            .with_remediation(
                "WAFs are a good defense-in-depth measure. Ensure the WAF rules are actively maintained and updated."
            )
            .with_evidence(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                request: None,
                response: Some(evidence_str),
                payload: None,
                screenshot_path: None,
                description: format!("Identified {} blocking suspicious requests", waf_name),
            }));
        } else if blocked {
            vulns.push(Vulnerability::new(
                "Security Filter / WAF Detected",
                "The server blocked suspicious requests with a 403 Forbidden or 406 Not Acceptable status, indicating a WAF or IPS is in place, but the exact vendor could not be identified.",
                Severity::Info,
                VulnCategory::InformationDisclosure,
                self.base_url.clone()
            ));
        }

        vulns
    }
}
