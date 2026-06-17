use crate::models::vulnerability::{Vulnerability, VulnCategory, OwaspCategory};
use crate::models::scan::Severity;
use tracing::info;

pub async fn scan(target_url: &str) -> Vec<Vulnerability> {
    info!("Starting WordPress specific scan on {}", target_url);
    let mut vulns = vec![];
    let base_url = target_url.trim_end_matches('/');

    let client = crate::utils::http::get_global_client();

    // Check 1: xmlrpc.php exposure
    let xmlrpc_url = format!("{}/xmlrpc.php", base_url);
    if let Ok(resp) = client.get(&xmlrpc_url).send().await {
        let status = resp.status();
        // XML-RPC can return 200 OK (with XML payload), or 405 Method Not Allowed
        if status.is_success() || status == reqwest::StatusCode::METHOD_NOT_ALLOWED {
            if let Ok(body) = resp.text().await {
                if body.contains("XML-RPC") || body.contains("xmlrpc") {
                    vulns.push(
                        Vulnerability::new(
                            "WordPress XML-RPC API Enabled",
                            "The xmlrpc.php file is exposed, which can be used for brute-force attacks and DDoS amplification.",
                            Severity::Medium,
                            VulnCategory::SecurityMisconfiguration,
                            xmlrpc_url.clone(),
                        )
                        .with_remediation("Disable XML-RPC by installing a plugin, or block access to xmlrpc.php via .htaccess or Nginx configuration.")
                        .with_owasp(OwaspCategory::A05SecurityMisconfiguration)
                    );
                }
            }
        }
    }

    // Check 2: wp-json user enumeration
    let users_url = format!("{}/wp-json/wp/v2/users", base_url);
    if let Ok(resp) = client.get(&users_url).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                if body.contains("\"slug\"") || body.contains("\"name\"") {
                    vulns.push(
                        Vulnerability::new(
                            "WordPress User Enumeration",
                            "The wp-json REST API exposes the database of registered WordPress users, which allows brute-force reconnaissance.",
                            Severity::Medium,
                            VulnCategory::InformationDisclosure,
                            users_url.clone(),
                        )
                        .with_remediation("Restrict public access to the /wp-json/wp/v2/users endpoint through security plugins or server access controls.")
                        .with_owasp(OwaspCategory::A01BrokenAccessControl)
                    );
                }
            }
        }
    }

    vulns
}
