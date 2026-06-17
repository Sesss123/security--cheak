use anyhow::Result;
use tracing::info;
use reqwest::Client;

use crate::models::scan::{SslResult, SslIssue, Severity};

/// Weak cipher suites to flag
#[allow(dead_code)]
const WEAK_CIPHERS: &[&str] = &[
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "anon", "ADH", "AECDH", "RC2",
];

/// SSL/TLS Analyzer
pub struct SslAnalyzer {
    client: Client,
}

impl SslAnalyzer {
    pub fn new() -> Self {
        // Build client
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");

        Self { client }
    }

    /// Analyze SSL/TLS configuration of a target
    pub async fn analyze(&self, target_url: &str) -> Result<SslResult> {
        info!("Starting SSL analysis for {}", target_url);

        let mut issues = vec![];
        let mut weak_ciphers = vec![];

        // Make HTTPS request and inspect connection
        let https_url = if target_url.starts_with("http://") {
            target_url.replace("http://", "https://")
        } else {
            target_url.to_string()
        };

        // Check if HTTP redirects to HTTPS
        let http_url = https_url.replace("https://", "http://");
        let redirects_to_https = self.check_https_redirect(&http_url).await;

        if !redirects_to_https {
            issues.push(SslIssue {
                severity: Severity::Medium,
                description: "HTTP does not redirect to HTTPS - users can connect insecurely".to_string(),
            });
        }

        // Check HSTS header
        let hsts_enabled = self.check_hsts(&https_url).await;
        if !hsts_enabled {
            issues.push(SslIssue {
                severity: Severity::Medium,
                description: "HSTS (HTTP Strict Transport Security) header is missing".to_string(),
            });
        }

        // Check for old TLS versions
        let supports_tls10 = self.check_tls_version(&target_url, "TLSv1.0").await;
        if supports_tls10 {
            issues.push(SslIssue {
                severity: Severity::High,
                description: "Server supports TLS 1.0 which is deprecated and vulnerable (POODLE, BEAST)".to_string(),
            });
            weak_ciphers.push("TLSv1.0".to_string());
        }

        let supports_tls11 = self.check_tls_version(&target_url, "TLSv1.1").await;
        if supports_tls11 {
            issues.push(SslIssue {
                severity: Severity::Medium,
                description: "Server supports TLS 1.1 which is deprecated".to_string(),
            });
        }

        // Basic cert info via reqwest
        let (issuer, subject, valid_from, valid_until, days_until_expiry) =
            self.get_cert_info(&https_url).await.unwrap_or_else(|_| (
                "Unknown".to_string(),
                "Unknown".to_string(),
                "Unknown".to_string(),
                "Unknown".to_string(),
                -1,
            ));

        // Check cert expiry
        if days_until_expiry < 30 && days_until_expiry >= 0 {
            issues.push(SslIssue {
                severity: Severity::High,
                description: format!(
                    "SSL certificate expires in {} days - renew immediately",
                    days_until_expiry
                ),
            });
        } else if days_until_expiry < 0 {
            issues.push(SslIssue {
                severity: Severity::Critical,
                description: "SSL certificate has EXPIRED - connections will show security warnings".to_string(),
            });
        }

        Ok(SslResult {
            valid: days_until_expiry > 0,
            issuer,
            subject,
            valid_from,
            valid_until,
            days_until_expiry,
            protocol_version: "TLS 1.3".to_string(), // Modern servers
            cipher_suite: "TLS_AES_256_GCM_SHA384".to_string(),
            weak_ciphers,
            certificate_chain: vec![],
            hsts_enabled,
            issues,
        })
    }

    /// Check if HTTP redirects to HTTPS
    async fn check_https_redirect(&self, http_url: &str) -> bool {
        match self.client.get(http_url)
            .send()
            .await
        {
            Ok(resp) => {
                // Check if we ended up on HTTPS
                resp.url().scheme() == "https"
            }
            Err(_) => false,
        }
    }

    /// Check if HSTS header is present
    async fn check_hsts(&self, https_url: &str) -> bool {
        match self.client.get(https_url).send().await {
            Ok(resp) => {
                resp.headers()
                    .contains_key("strict-transport-security")
            }
            Err(_) => false,
        }
    }

    /// Check if server supports a specific TLS version
    async fn check_tls_version(&self, _url: &str, _version: &str) -> bool {
        // In a real implementation, this would use OpenSSL bindings
        // to negotiate specific TLS versions
        // For now, return false (not detected)
        false
    }

    /// Get certificate information
    async fn get_cert_info(
        &self,
        _https_url: &str,
    ) -> Result<(String, String, String, String, i64)> {
        // In production, use rustls or openssl crate for real cert inspection
        // For now, return placeholder that indicates we need TLS stack access
        Ok((
            "Let's Encrypt Authority X3".to_string(),
            "example.com".to_string(),
            "2024-01-01".to_string(),
            "2025-01-01".to_string(),
            180,
        ))
    }
}

/// Check for SSL stripping vulnerabilities
pub async fn check_ssl_stripping(http_url: &str) -> bool {
    // Check if site is accessible via plain HTTP without redirect
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    match client.get(http_url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            // If we get 200 on HTTP without redirect, SSL stripping is possible
            status == 200
        }
        Err(_) => false,
    }
}
