use reqwest::Client;
use tracing::{info, warn};
use std::time::Duration;
use crate::models::vulnerability::{Vulnerability, VulnCategory, Evidence, EvidenceType, OwaspCategory};
use crate::models::scan::Severity;

pub struct ApiFuzzer {
    client: Client,
    base_url: String,
}

impl ApiFuzzer {
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        Self { client, base_url: base_url.trim_end_matches('/').to_string() }
    }

    pub async fn detect(&self) -> Vec<Vulnerability> {
        info!("Scanning for OpenAPI/Swagger documentation...");
        let mut vulns = vec![];

        let common_paths = [
            "/swagger.json",
            "/api/swagger.json",
            "/openapi.json",
            "/api/v1/swagger.json",
            "/v1/swagger.json",
            "/api-docs",
            "/v2/api-docs",
            "/v3/api-docs",
        ];

        let mut doc_url = String::new();
        let mut api_json: serde_json::Value = serde_json::Value::Null;

        for path in &common_paths {
            let test_url = format!("{}{}", self.base_url, path);
            if let Ok(resp) = self.client.get(&test_url).send().await {
                if resp.status().is_success() {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        if body.get("swagger").is_some() || body.get("openapi").is_some() {
                            doc_url = test_url;
                            api_json = body;
                            break;
                        }
                    }
                }
            }
        }

        if !doc_url.is_empty() {
            warn!("OpenAPI documentation found at: {}", doc_url);
            
            vulns.push(Vulnerability::new(
                "OpenAPI/Swagger Documentation Exposed",
                "API documentation is publicly accessible. This maps out the entire API attack surface, making it extremely easy for attackers to find and exploit undocumented endpoints.",
                Severity::Medium,
                VulnCategory::InformationDisclosure,
                doc_url.clone()
            )
            .with_owasp(OwaspCategory::A05SecurityMisconfiguration));

            // Fuzz the documented endpoints
            let fuzzed_vulns = self.fuzz_endpoints(&api_json).await;
            vulns.extend(fuzzed_vulns);
        }

        vulns
    }

    async fn fuzz_endpoints(&self, spec: &serde_json::Value) -> Vec<Vulnerability> {
        info!("Fuzzing documented OpenAPI endpoints...");
        let mut vulns = vec![];

        if let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) {
            // Limit fuzzing to first 5 paths to avoid huge scan times
            for (path, methods) in paths.iter().take(5) {
                if let Some(methods_obj) = methods.as_object() {
                    if methods_obj.contains_key("get") {
                        let fuzzed_url = format!("{}{}", self.base_url, path.replace("{id}", "1'%20OR%20'1'='1"));
                        
                        if let Ok(resp) = self.client.get(&fuzzed_url).send().await {
                            if resp.status().is_server_error() {
                                vulns.push(Vulnerability::new(
                                    "API Endpoint Vulnerable to Fuzzing (500 Error)",
                                    format!("The endpoint '{}' returned a 500 Internal Server Error when injected with an SQLi/Fuzz payload. This indicates missing input validation and potential SQL Injection or application crash.", path),
                                    Severity::High,
                                    VulnCategory::SqlInjection,
                                    fuzzed_url.clone()
                                )
                                .with_owasp(OwaspCategory::A03Injection)
                                .with_evidence(Evidence {
                                    evidence_type: EvidenceType::HttpResponse,
                                    request: None,
                                    response: Some("HTTP 500 Internal Server Error".to_string()),
                                    payload: Some("1' OR '1'='1".to_string()),
                                    screenshot_path: None,
                                    description: "Server crashed on unexpected input".to_string(),
                                }));
                            }
                        }
                    }
                }
            }
        }
        vulns
    }
}
