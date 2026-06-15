use tracing::info;
use crate::models::vulnerability::{Vulnerability, VulnCategory};

pub struct ThreatIntel {
    // Client can be kept for future direct queries if needed, or removed
}

impl ThreatIntel {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn enrich_vulnerabilities(&self, vulns: &mut Vec<Vulnerability>) {
        info!("Threat Intel enrichment has been offloaded to the NestJS API backend.");
        // The Rust scanner now primarily focuses on detection.
        // Full Threat Correlation, CISA KEV checks, and Exploit-DB lookups 
        // are performed dynamically by the API's ThreatCorrelationEngine.
        
        for vuln in vulns.iter_mut() {
            // We can still do very basic tagging if required before sending to the backend
            if vuln.category == VulnCategory::HardcodedSecret {
                 vuln.description.push_str("\n\n[LOCAL TAG] Secret detected. Awaiting backend Threat Intel correlation.");
            }
        }
    }
}
