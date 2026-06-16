use anyhow::Result;
use reqwest::Client;
use serde_json::json;
use tracing::info;
use url::Url;

use crate::models::vulnerability::{Vulnerability, VulnCategory, OwaspCategory};
use crate::models::scan::Severity;

pub struct GraphqlScanner {
    base_url: String,
    client: Client,
}

impl GraphqlScanner {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    pub async fn scan(&self, targets: &[String]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let mut endpoints_to_test = Vec::new();
        
        // Discover typical GraphQL endpoints
        let common_paths = ["/graphql", "/api/graphql", "/v1/graphql"];
        for path in &common_paths {
            if let Ok(base) = Url::parse(&self.base_url) {
                if let Ok(full_url) = base.join(path) {
                    endpoints_to_test.push(full_url.to_string());
                }
            }
        }
        
        // Also check if any discovered target looks like GraphQL
        for target in targets {
            if target.contains("graphql") && !endpoints_to_test.contains(target) {
                endpoints_to_test.push(target.clone());
            }
        }

        // Add base url just in case it's a direct endpoint
        if !endpoints_to_test.contains(&self.base_url) {
            endpoints_to_test.push(self.base_url.clone());
        }

        for endpoint in endpoints_to_test {
            if let Ok(true) = self.check_is_graphql(&endpoint).await {
                info!("Valid GraphQL endpoint discovered: {}", endpoint);
                
                // 1. Introspection Check
                if let Ok(Some(vuln)) = self.check_introspection(&endpoint).await {
                    vulnerabilities.push(vuln);
                }

                // 2. Batch Query (DoS) Check
                if let Ok(Some(vuln)) = self.check_batch_query(&endpoint).await {
                    vulnerabilities.push(vuln);
                }
            }
        }

        vulnerabilities
    }

    async fn check_is_graphql(&self, endpoint: &str) -> Result<bool> {
        // Send a malformed query to see if the server responds with standard GraphQL errors
        let payload = json!({
            "query": "query { __invalid_field }"
        });

        let res = self.client.post(endpoint).json(&payload).send().await?;
        let text = res.text().await?;
        
        Ok(text.contains("errors") && text.contains("Cannot query field"))
    }

    async fn check_introspection(&self, endpoint: &str) -> Result<Option<Vulnerability>> {
        let payload = json!({
            "query": "query { __schema { types { name } } }"
        });

        let res = self.client.post(endpoint).json(&payload).send().await?;
        let text = res.text().await?;

        if text.contains("__schema") && text.contains("types") && text.contains("name") {
            return Ok(Some(
                Vulnerability::new(
                    "GraphQL Introspection Enabled",
                    "The GraphQL endpoint has introspection enabled, allowing attackers to query the entire API schema, including hidden queries, mutations, and types.",
                    Severity::Medium,
                    VulnCategory::InformationDisclosure,
                    endpoint.to_string(),
                )
                .with_owasp(OwaspCategory::A01BrokenAccessControl)
                .with_remediation("Disable GraphQL introspection in production environments. If using Apollo Server, set introspection: false.")
                .with_evidence(
                    crate::models::vulnerability::Evidence {
                        evidence_type: crate::models::vulnerability::EvidenceType::HttpResponse,
                        request: None,
                        response: Some(text.chars().take(200).collect::<String>()),
                        payload: Some(payload.to_string()),
                        screenshot_path: None,
                        description: "GraphQL Introspection Query".to_string(),
                    }
                )
            ));
        }

        Ok(None)
    }

    async fn check_batch_query(&self, endpoint: &str) -> Result<Option<Vulnerability>> {
        // Send an array of queries
        let queries = vec![json!({"query": "query { __typename }"}); 50];

        let res = self.client.post(endpoint).json(&queries).send().await?;
        
        if res.status().is_success() {
            let text = res.text().await?;
            if text.starts_with('[') && text.contains("__typename") {
                return Ok(Some(
                    Vulnerability::new(
                        "GraphQL Batch Query Enabled (Potential DoS/Brute Force)",
                        "The GraphQL endpoint accepts batched queries in an array. This can be abused for Denial of Service (DoS) or to bypass rate limits by sending thousands of operations in a single HTTP request.",
                        Severity::High,
                        VulnCategory::SecurityMisconfiguration,
                        endpoint.to_string(),
                    )
                    .with_owasp(OwaspCategory::A04InsecureDesign)
                    .with_remediation("Disable batching if not required, or strictly limit the maximum number of batched operations allowed per request.")
                    .with_evidence(
                        crate::models::vulnerability::Evidence {
                            evidence_type: crate::models::vulnerability::EvidenceType::HttpResponse,
                            request: None,
                            response: None,
                            payload: Some("[{\"query\": \"query { __typename }\"}, ... 50 times]".to_string()),
                            screenshot_path: None,
                            description: "Server processed all queries in one request.".to_string(),
                        }
                    )
                ));
            }
        }

        Ok(None)
    }
}
