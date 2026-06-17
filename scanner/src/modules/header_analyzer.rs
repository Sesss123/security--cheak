use anyhow::Result;
use reqwest::{Client, header::HeaderMap};
use tracing::info;

use crate::models::scan::{
    HeaderResult, SecurityHeader, MissingHeader, DangerousHeader, Severity,
};

/// Security headers that SHOULD be present
const REQUIRED_SECURITY_HEADERS: &[(&str, &str, Severity)] = &[
    (
        "content-security-policy",
        "default-src 'self'",
        Severity::High,
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includeSubDomains; preload",
        Severity::High,
    ),
    (
        "x-frame-options",
        "DENY",
        Severity::Medium,
    ),
    (
        "x-content-type-options",
        "nosniff",
        Severity::Medium,
    ),
    (
        "referrer-policy",
        "strict-origin-when-cross-origin",
        Severity::Low,
    ),
    (
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
        Severity::Low,
    ),
    (
        "x-xss-protection",
        "1; mode=block",
        Severity::Low,
    ),
    (
        "cross-origin-opener-policy",
        "same-origin",
        Severity::Medium,
    ),
    (
        "cross-origin-resource-policy",
        "same-origin",
        Severity::Medium,
    ),
];

/// Headers that expose server info and should be removed
const DANGEROUS_HEADERS: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-wordpress-cache",
    "via",
];

/// HTTP Security Headers Analyzer
pub struct HeaderAnalyzer {
    client: Client,
}

impl HeaderAnalyzer {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to build HTTP client");

        Self { client }
    }

    pub async fn analyze(&self, target_url: &str) -> Result<HeaderResult> {
        info!("Analyzing security headers for {}", target_url);

        let response = self.client
            .get(target_url)
            .header("User-Agent", "SecurityScanner/1.0")
            .send()
            .await?;

        let headers = response.headers().clone();

        let headers_found     = self.check_present_headers(&headers);
        let headers_missing   = self.check_missing_headers(&headers);
        let dangerous_headers = self.check_dangerous_headers(&headers);
        let server_info       = self.extract_server_info(&headers);
        let x_powered_by      = headers
            .get("x-powered-by")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        Ok(HeaderResult {
            headers_found,
            headers_missing,
            dangerous_headers,
            server_info,
            x_powered_by,
        })
    }

    /// Check which security headers are present and if they are properly configured
    fn check_present_headers(&self, headers: &HeaderMap) -> Vec<SecurityHeader> {
        let mut found = vec![];

        for (name, recommended, _) in REQUIRED_SECURITY_HEADERS {
            if let Some(value) = headers.get(*name) {
                let value_str = value.to_str().unwrap_or("").to_string();
                let is_proper = self.validate_header(name, &value_str);

                found.push(SecurityHeader {
                    name: name.to_string(),
                    value: value_str,
                    is_properly_configured: is_proper,
                    recommendation: if !is_proper {
                        Some(format!("Recommended value: {}", recommended))
                    } else {
                        None
                    },
                });
            }
        }

        found
    }

    /// Check which required headers are MISSING
    fn check_missing_headers(&self, headers: &HeaderMap) -> Vec<MissingHeader> {
        let mut missing = vec![];

        for (name, recommended_value, severity) in REQUIRED_SECURITY_HEADERS {
            if !headers.contains_key(*name) {
                missing.push(MissingHeader {
                    name: name.to_string(),
                    severity: severity.clone(),
                    description: self.header_description(name),
                    recommended_value: recommended_value.to_string(),
                });
            }
        }

        missing
    }

    /// Check for dangerous headers that expose server info
    fn check_dangerous_headers(&self, headers: &HeaderMap) -> Vec<DangerousHeader> {
        let mut dangerous = vec![];

        for &header_name in DANGEROUS_HEADERS {
            if let Some(value) = headers.get(header_name) {
                let value_str = value.to_str().unwrap_or("").to_string();
                dangerous.push(DangerousHeader {
                    name: header_name.to_string(),
                    value: value_str,
                    reason: self.dangerous_header_reason(header_name),
                });
            }
        }

        dangerous
    }

    fn extract_server_info(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get("server")
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    }

    /// Validate if a header has a secure value
    fn validate_header(&self, name: &str, value: &str) -> bool {
        match name {
            "strict-transport-security" => {
                value.contains("max-age=") && {
                    let max_age: u64 = value
                        .split(';')
                        .find(|s| s.trim().starts_with("max-age="))
                        .and_then(|s| s.trim().trim_start_matches("max-age=").parse().ok())
                        .unwrap_or(0);
                    max_age >= 31536000 // at least 1 year
                }
            }
            "x-frame-options" => {
                let v = value.to_uppercase();
                v == "DENY" || v == "SAMEORIGIN"
            }
            "x-content-type-options" => {
                value.to_lowercase() == "nosniff"
            }
            "content-security-policy" => {
                // Basic check: must not be too permissive
                !value.contains("unsafe-inline") || value.contains("nonce-")
            }
            _ => true,
        }
    }

    fn header_description(&self, name: &str) -> String {
        match name {
            "content-security-policy" =>
                "CSP prevents XSS attacks by controlling which resources the browser can load".to_string(),
            "strict-transport-security" =>
                "HSTS forces browsers to use HTTPS, preventing SSL stripping attacks".to_string(),
            "x-frame-options" =>
                "Prevents clickjacking by controlling if page can be embedded in iframes".to_string(),
            "x-content-type-options" =>
                "Prevents MIME type sniffing which can lead to XSS vulnerabilities".to_string(),
            "referrer-policy" =>
                "Controls how much referrer information is included with requests".to_string(),
            "permissions-policy" =>
                "Controls access to browser features like camera, microphone, geolocation".to_string(),
            "x-xss-protection" =>
                "Enables browser's built-in XSS filter (legacy, CSP is preferred)".to_string(),
            "cross-origin-opener-policy" =>
                "Prevents cross-origin window attacks (Spectre)".to_string(),
            "cross-origin-resource-policy" =>
                "Prevents other origins from loading your resources".to_string(),
            _ => format!("Security header: {}", name),
        }
    }

    fn dangerous_header_reason(&self, name: &str) -> String {
        match name {
            "server" =>
                "Reveals web server software and version, helps attackers find known vulnerabilities".to_string(),
            "x-powered-by" =>
                "Reveals backend technology stack (e.g. PHP/7.4), helps fingerprinting".to_string(),
            "x-aspnet-version" =>
                "Reveals ASP.NET version, helps attackers target specific vulnerabilities".to_string(),
            "x-aspnetmvc-version" =>
                "Reveals ASP.NET MVC version".to_string(),
            "x-generator" =>
                "Reveals the CMS or framework used".to_string(),
            _ => format!("Header '{}' reveals server-side information", name),
        }
    }
}

/// Analyze CORS configuration
pub async fn analyze_cors(target_url: &str) -> Vec<String> {
    let client = Client::builder()
        // .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    let mut issues = vec![];

    // Send request with a malicious origin
    let response = client
        .get(target_url)
        .header("Origin", "https://evil.com")
        .send()
        .await;

    if let Ok(resp) = response {
        let headers = resp.headers();

        if let Some(acao) = headers.get("access-control-allow-origin") {
            let acao_str = acao.to_str().unwrap_or("");

            if acao_str == "*" {
                issues.push(
                    "CORS wildcard (*): Any origin can read responses. Critical for APIs with auth.".to_string()
                );
            } else if acao_str == "https://evil.com" {
                issues.push(
                    "CORS reflects Origin header without validation - CORS misconfiguration!".to_string()
                );
            }

            if let Some(acac) = headers.get("access-control-allow-credentials") {
                if acac.to_str().unwrap_or("") == "true" && acao_str == "*" {
                    issues.push(
                        "CRITICAL: CORS allows credentials with wildcard origin - credential theft possible".to_string()
                    );
                }
            }
        }
    }

    issues
}
