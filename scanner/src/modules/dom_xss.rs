use std::sync::Arc;
use headless_chrome::{Browser, LaunchOptions};
use anyhow::Result;
use tracing::{info, warn, error};
use url::Url;

use crate::models::vulnerability::{Vulnerability, VulnCategory, OwaspCategory};
use crate::models::scan::Severity;

pub struct DomXssScanner {
    base_url: String,
}

impl DomXssScanner {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }

    pub async fn scan(&self, targets: &[String]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let mut all_targets = vec![self.base_url.clone()];
        all_targets.extend_from_slice(targets);
        all_targets.truncate(10); // Limit to 10 for performance

        // Typical DOM XSS payloads leveraging location.hash
        let payloads = [
            "#javascript:alert(document.domain)",
            "#<script>alert(1)</script>",
            "#\"><img src=x onerror=alert(1)>",
        ];

        // Launch headless browser
        let launch_options = LaunchOptions {
            headless: true,
            sandbox: false,
            enable_logging: false,
            ..Default::default()
        };

        let browser = match Browser::new(launch_options) {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to launch headless browser for DOM XSS: {}", e);
                return vulnerabilities;
            }
        };

        for target in all_targets {
            for payload in &payloads {
                let test_url = format!("{}{}", target, payload);
                info!("Testing DOM XSS on: {}", test_url);

                match self.test_payload_with_browser(&browser, &test_url) {
                    Ok(true) => {
                        vulnerabilities.push(
                            Vulnerability::new(
                                "DOM-Based XSS (Headless Browser)",
                                format!("JavaScript execution detected via DOM manipulation using payload: {}", payload),
                                Severity::High,
                                VulnCategory::Xss,
                                test_url.clone(),
                            )
                            .with_owasp(OwaspCategory::A03Injection)
                            .with_remediation(
                                "Avoid using sink functions like innerHTML, document.write, or eval with untrusted data (like location.hash). Use safe alternatives like textContent or DOMPurify."
                            )
                            .with_evidence(
                                crate::models::vulnerability::Evidence {
                                    evidence_type: crate::models::vulnerability::EvidenceType::HttpResponse,
                                    request: None,
                                    response: Some(format!("Navigated to {}", test_url)),
                                    payload: None,
                                    screenshot_path: None,
                                    description: "A JavaScript alert/prompt/confirm dialog was triggered upon rendering the page.".to_string(),
                                }
                            )
                        );
                        // Stop testing payloads for this URL if one works
                        break;
                    }
                    Ok(false) => {
                        // No alert triggered
                    }
                    Err(e) => {
                        warn!("Error testing DOM XSS on {}: {}", test_url, e);
                    }
                }
            }
        }

        vulnerabilities
    }

    fn test_payload_with_browser(&self, browser: &Browser, url: &str) -> Result<bool> {
        let tab = browser.new_tab()?;
        
        // We use a shared boolean to track if an alert was fired
        let alert_triggered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let alert_triggered_clone = Arc::clone(&alert_triggered);

        // Register event listener for JavaScript dialogs (alerts)
        tab.add_event_listener(Arc::new(move |event: &headless_chrome::protocol::cdp::types::Event| {
            // Ignored TargetCrashed check to fix compile error
            // For headless_chrome 1.0.8, we check if the event involves a JavascriptDialogOpening
            // Since the event enum might be complex, we just try to parse the JSON string or use the debug format
            let ev_str = format!("{:?}", event);
            if ev_str.contains("JavascriptDialogOpening") {
                alert_triggered_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }))?;

        // Navigate and wait a moment for scripts to execute
        let _ = tab.navigate_to(url)?;
        std::thread::sleep(std::time::Duration::from_secs(2));

        let triggered = alert_triggered.load(std::sync::atomic::Ordering::SeqCst);
        
        let _ = tab.close(true);

        Ok(triggered)
    }
}
