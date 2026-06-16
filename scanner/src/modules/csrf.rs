use crate::models::vulnerability::{Vulnerability, VulnCategory, OwaspCategory};
use crate::models::scan::Severity;
use crate::modules::crawler::CrawlResult;
use tracing::{info, warn};

pub struct CsrfDetector {
    #[allow(dead_code)]
    base_url: String,
}

impl CsrfDetector {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }

    pub fn detect(&self, crawl_result: &CrawlResult) -> Vec<Vulnerability> {
        info!("Testing for Cross-Site Request Forgery (CSRF)...");
        let mut vulns = vec![];

        let csrf_token_names = ["csrf", "_csrf", "authenticity_token", "csrf_token", "xsrf"];

        for form in &crawl_result.forms {
            if form.method == "POST" {
                let mut has_token = false;
                
                for input in &form.inputs {
                    let i_lower = input.to_lowercase();
                    if csrf_token_names.iter().any(|&s| i_lower.contains(s)) {
                        has_token = true;
                        break;
                    }
                }

                if !has_token {
                    // Filter out search forms and logins which sometimes intentionally omit CSRF (though login CSRF is a thing)
                    // We'll alert on endpoints that look state-changing
                    let action_lower = form.action.to_lowercase();
                    if action_lower.contains("update") || action_lower.contains("delete") || action_lower.contains("change") || action_lower.contains("setting") {
                        warn!("Missing CSRF Token in form at {}", form.action);
                        
                        vulns.push(Vulnerability::new(
                            "Cross-Site Request Forgery (CSRF) - Missing Token",
                            "A state-changing POST form was found without an anti-CSRF token. An attacker could trick an authenticated user into submitting this form unintentionally via a malicious site.",
                            Severity::Medium,
                            VulnCategory::SecurityMisconfiguration,
                            form.action.clone(),
                        )
                        .with_remediation("Implement synchronized token pattern (anti-CSRF tokens) for all state-changing operations. Also configure cookies with SameSite=Lax or SameSite=Strict.")
                        .with_owasp(OwaspCategory::A01BrokenAccessControl)
                        .with_cwe(352));
                    }
                }
            }
        }

        vulns
    }
}
