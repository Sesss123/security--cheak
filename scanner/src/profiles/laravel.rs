use crate::models::vulnerability::{Vulnerability, VulnCategory, OwaspCategory};
use crate::models::scan::Severity;
use tracing::info;

pub async fn scan(target_url: &str) -> Vec<Vulnerability> {
    info!("Starting Laravel specific scan on {}", target_url);
    let mut vulns = vec![];
    let base_url = target_url.trim_end_matches('/');

    let client = crate::utils::http::get_global_client();

    // Check 1: Exposed Laravel .env configuration files
    let env_url = format!("{}/.env", base_url);
    if let Ok(resp) = client.get(&env_url).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                // If it exposes key database configurations
                if body.contains("APP_KEY=") || body.contains("DB_PASSWORD=") {
                    vulns.push(
                        Vulnerability::new(
                            "Exposed Laravel Environment Configuration",
                            "The Laravel .env configuration file is publicly accessible, disclosing application secrets, API tokens, and database passwords.",
                            Severity::Critical,
                            VulnCategory::InformationDisclosure,
                            env_url.clone(),
                        )
                        .with_remediation("Configure the web server rules to deny access to all hidden dotfiles (.env, .git, etc.) and restrict root web access strictly to Laravel's /public folder.")
                        .with_owasp(OwaspCategory::A05SecurityMisconfiguration)
                    );
                }
            }
        }
    }

    // Check 2: Laravel Debug Page exposure (sending invalid payload to trigger error stack trace)
    let debug_url = format!("{}/_ignition/health-check", base_url); // ignition endpoint
    if let Ok(resp) = client.get(&debug_url).send().await {
        let status = resp.status();
        if status.is_success() {
            vulns.push(
                Vulnerability::new(
                    "Laravel Debugger API Exposed",
                    "The application exposes Laravel Ignition debugger helper endpoints, allowing potential configuration leakages or remote execution vulnerabilities.",
                    Severity::High,
                    VulnCategory::SecurityMisconfiguration,
                    debug_url.clone(),
                )
                .with_remediation("Turn APP_DEBUG=false in the environment config and verify ignition developer tools dependencies are disabled in production.")
                .with_owasp(OwaspCategory::A05SecurityMisconfiguration)
            );
        }
    }

    vulns
}
