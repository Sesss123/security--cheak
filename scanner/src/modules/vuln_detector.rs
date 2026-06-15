use reqwest::Client;
use tracing::{info, warn};

use crate::models::vulnerability::{
    Vulnerability, VulnCategory, OwaspCategory, Evidence, EvidenceType,
};
use crate::models::scan::Severity;

/// SQL Injection test payloads
const SQLI_PAYLOADS: &[&str] = &[
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1 UNION SELECT NULL--",
    "' AND 1=1--",
    "' AND 1=2--",
    "1; DROP TABLE users--",
];

/// SQL error patterns to detect
const SQL_ERROR_PATTERNS: &[&str] = &[
    "SQL syntax",
    "mysql_fetch",
    "ORA-",
    "PostgreSQL ERROR",
    "Warning: mysql",
    "Microsoft OLE DB Provider for SQL Server",
    "Unclosed quotation mark",
    "SQLSTATE",
    "sqlite3.OperationalError",
    "PG::SyntaxError",
    "syntax error at or near",
    "You have an error in your SQL syntax",
    "supplied argument is not a valid MySQL",
    "Division by zero in SQL",
];

/// XSS test payloads
const XSS_PAYLOADS: &[&str] = &[
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "\"><script>alert('XSS')</script>",
    "'><script>alert(1)</script>",
    "<svg onload=alert('XSS')>",
    "';alert('XSS')//",
    "<iframe src=javascript:alert('XSS')>",
];

/// Open redirect test payloads
const REDIRECT_PAYLOADS: &[&str] = &[
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "%2F%2Fevil.com",
];

/// Common redirect parameters to test
const REDIRECT_PARAMS: &[&str] = &[
    "redirect", "url", "next", "return", "goto",
    "destination", "continue", "redir", "redirect_url",
    "return_url", "redirect_uri", "callback",
];

/// Vulnerability Detector
pub struct VulnDetector {
    client: Client,
    base_url: String,
}

impl VulnDetector {
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("Failed to build HTTP client");

        Self { client, base_url }
    }

    /// Run all vulnerability detection modules
    pub async fn detect_all(&self) -> Vec<Vulnerability> {
        info!("Starting vulnerability detection for {}", self.base_url);
        let mut vulns = vec![];

        // Run all checks concurrently
        let (sqli_vulns, xss_vulns, redirect_vulns, info_vulns, jwt_vulns) = tokio::join!(
            self.check_sql_injection(),
            self.check_xss(),
            self.check_open_redirect(),
            self.check_information_disclosure(),
            self.check_jwt_weaknesses(),
        );

        vulns.extend(sqli_vulns);
        vulns.extend(xss_vulns);
        vulns.extend(redirect_vulns);
        vulns.extend(info_vulns);
        vulns.extend(jwt_vulns);

        info!("Found {} vulnerabilities", vulns.len());
        vulns
    }

    /// SQL Injection detection
    async fn check_sql_injection(&self) -> Vec<Vulnerability> {
        info!("Testing for SQL Injection...");
        let mut vulns = vec![];

        // Common injectable endpoints to test
        let test_urls = vec![
            format!("{}/search?q=", self.base_url),
            format!("{}/user?id=", self.base_url),
            format!("{}/product?id=", self.base_url),
            format!("{}/page?id=", self.base_url),
            format!("{}/article?id=", self.base_url),
        ];

        for base_test_url in &test_urls {
            for payload in SQLI_PAYLOADS {
                let test_url = format!("{}{}", base_test_url, urlencoding::encode(payload));

                match self.client.get(&test_url).send().await {
                    Ok(resp) => {
                        if let Ok(body) = resp.text().await {
                            for pattern in SQL_ERROR_PATTERNS {
                                if body.to_lowercase().contains(&pattern.to_lowercase()) {
                                    warn!("SQL Injection found at {} with payload: {}", test_url, payload);

                                    let vuln = Vulnerability::new(
                                        "SQL Injection Detected",
                                        format!(
                                            "SQL error message exposed when injecting payload '{}'. \
                                            The application returns database error messages which \
                                            indicates unsanitized input being passed to SQL queries.",
                                            payload
                                        ),
                                        Severity::Critical,
                                        VulnCategory::SqlInjection,
                                        test_url.clone(),
                                    )
                                    .with_remediation(
                                        "Use parameterized queries / prepared statements. \
                                        Never concatenate user input into SQL queries. \
                                        Implement input validation and error handling that \
                                        doesn't expose database errors to users."
                                    )
                                    .with_owasp(OwaspCategory::A03Injection)
                                    .with_cwe(89)
                                    .with_evidence(Evidence {
                                        evidence_type: EvidenceType::HttpResponse,
                                        request: Some(format!("GET {}", test_url)),
                                        response: Some(
                                            body.chars().take(500).collect()
                                        ),
                                        payload: Some(payload.to_string()),
                                        screenshot_path: None,
                                        description: format!(
                                            "SQL error pattern '{}' found in response",
                                            pattern
                                        ),
                                    });

                                    vulns.push(vuln);
                                    break; // One vuln per endpoint
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // Connection errors can also indicate injection (crash)
                        warn!("Request failed for {}: {}", test_url, e);
                    }
                }
            }
        }

        vulns
    }

    /// XSS Detection
    async fn check_xss(&self) -> Vec<Vulnerability> {
        info!("Testing for XSS...");
        let mut vulns = vec![];

        let test_params = vec!["q", "search", "query", "name", "input", "message", "comment"];
        let test_urls: Vec<String> = test_params
            .iter()
            .map(|p| format!("{}/?{}=", self.base_url, p))
            .collect();

        for base_url in &test_urls {
            for payload in XSS_PAYLOADS {
                let encoded = urlencoding::encode(payload);
                let test_url = format!("{}{}", base_url, encoded);

                if let Ok(resp) = self.client.get(&test_url).send().await {
                    if let Ok(body) = resp.text().await {
                        // Check if payload is reflected without encoding
                        if body.contains(payload) {
                            warn!("Reflected XSS found at {}", test_url);

                            let vuln = Vulnerability::new(
                                "Reflected Cross-Site Scripting (XSS)",
                                format!(
                                    "User input is reflected in the HTML response without proper \
                                    encoding. Payload '{}' was returned unescaped, allowing \
                                    attackers to inject malicious scripts.",
                                    &payload[..payload.len().min(50)]
                                ),
                                Severity::High,
                                VulnCategory::Xss,
                                test_url.clone(),
                            )
                            .with_remediation(
                                "1. Encode all user output using HTML entity encoding.\n\
                                2. Implement Content Security Policy (CSP) headers.\n\
                                3. Use modern frameworks that auto-escape output.\n\
                                4. Validate and sanitize all user input on server-side."
                            )
                            .with_owasp(OwaspCategory::A03Injection)
                            .with_cwe(79)
                            .with_evidence(Evidence {
                                evidence_type: EvidenceType::HttpResponse,
                                request: Some(format!("GET {}", test_url)),
                                response: Some(body.chars().take(300).collect()),
                                payload: Some(payload.to_string()),
                                screenshot_path: None,
                                description: "XSS payload reflected unencoded in response".to_string(),
                            });

                            vulns.push(vuln);
                            break;
                        }
                    }
                }
            }
        }

        vulns
    }

    /// Open Redirect Detection
    async fn check_open_redirect(&self) -> Vec<Vulnerability> {
        info!("Testing for Open Redirect...");
        let mut vulns = vec![];

        for param in REDIRECT_PARAMS {
            for payload in REDIRECT_PAYLOADS {
                let test_url = format!(
                    "{}/?{}={}",
                    self.base_url,
                    param,
                    urlencoding::encode(payload)
                );

                // Use no-follow client to detect redirects
                let no_follow_client = Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .danger_accept_invalid_certs(true)
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .unwrap();

                if let Ok(resp) = no_follow_client.get(&test_url).send().await {
                    let status = resp.status().as_u16();

                    // Check for redirect to evil.com
                    if (301..=302).contains(&status) {
                        if let Some(location) = resp.headers().get("location") {
                            let location_str = location.to_str().unwrap_or("");
                            if location_str.contains("evil.com") || location_str.starts_with("//") {
                                warn!("Open redirect found: {} -> {}", test_url, location_str);

                                let vuln = Vulnerability::new(
                                    "Open Redirect Vulnerability",
                                    format!(
                                        "The parameter '{}' allows redirecting users to arbitrary \
                                        external URLs. Attacker can redirect to '{}' for phishing.",
                                        param, payload
                                    ),
                                    Severity::Medium,
                                    VulnCategory::OpenRedirect,
                                    test_url.clone(),
                                )
                                .with_remediation(
                                    "1. Validate redirect URLs against an allowlist of trusted domains.\n\
                                    2. Use relative URLs instead of absolute URLs for redirects.\n\
                                    3. Implement server-side validation before redirecting.\n\
                                    4. Show a warning page before redirecting to external URLs."
                                )
                                .with_owasp(OwaspCategory::A01BrokenAccessControl)
                                .with_cwe(601);

                                vulns.push(vuln);
                            }
                        }
                    }
                }
            }
        }

        vulns
    }

    /// Information Disclosure Detection
    async fn check_information_disclosure(&self) -> Vec<Vulnerability> {
        info!("Testing for Information Disclosure...");
        let mut vulns = vec![];

        // Sensitive files that should not be publicly accessible
        let sensitive_paths = vec![
            "/.env",
            "/.env.local",
            "/.env.production",
            "/config.php",
            "/wp-config.php",
            "/config.yml",
            "/config.yaml",
            "/.git/config",
            "/.git/HEAD",
            "/phpinfo.php",
            "/info.php",
            "/server-status",
            "/server-info",
            "/.DS_Store",
            "/backup.sql",
            "/dump.sql",
            "/database.sql",
            "/robots.txt",
            "/sitemap.xml",
            "/.htaccess",
            "/web.config",
            "/package.json",
            "/composer.json",
            "/Gemfile",
            "/requirements.txt",
            "/dockerfile",
            "/docker-compose.yml",
            "/api/v1/swagger.json",
            "/api/swagger.json",
            "/swagger.json",
            "/openapi.json",
            "/.well-known/security.txt",
        ];

        for path in &sensitive_paths {
            let test_url = format!("{}{}", self.base_url.trim_end_matches('/'), path);

            if let Ok(resp) = self.client.get(&test_url).send().await {
                let status = resp.status().as_u16();

                if status == 200 {
                    let content_length = resp.content_length().unwrap_or(0);

                    // Skip empty responses
                    if content_length == 0 {
                        continue;
                    }

                    let body_preview = resp.text().await.unwrap_or_default();
                    let body_short: String = body_preview.chars().take(200).collect();

                    let (severity, description) = self.classify_disclosure(path, &body_short);

                    warn!("Information disclosure at {}: {}", test_url, path);

                    let vuln = Vulnerability::new(
                        format!("Sensitive File Exposed: {}", path),
                        description,
                        severity,
                        VulnCategory::InformationDisclosure,
                        test_url.clone(),
                    )
                    .with_remediation(
                        "1. Remove or restrict access to sensitive files.\n\
                        2. Configure web server to block access to config files.\n\
                        3. Never deploy .env, .git, or config files to web root.\n\
                        4. Add these paths to .gitignore and web server deny rules."
                    )
                    .with_owasp(OwaspCategory::A05SecurityMisconfiguration)
                    .with_evidence(Evidence {
                        evidence_type: EvidenceType::HttpResponse,
                        request: Some(format!("GET {}", test_url)),
                        response: Some(body_short),
                        payload: None,
                        screenshot_path: None,
                        description: format!("Sensitive file accessible: {}", path),
                    });

                    vulns.push(vuln);
                }
            }
        }

        vulns
    }

    /// JWT Weakness Detection
    async fn check_jwt_weaknesses(&self) -> Vec<Vulnerability> {
        info!("Testing for JWT weaknesses...");
        let mut vulns = vec![];

        // Test with algorithm=none attack
        let none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.";

        let test_urls = vec![
            format!("{}/api/user", self.base_url),
            format!("{}/api/me", self.base_url),
            format!("{}/api/profile", self.base_url),
            format!("{}/api/admin", self.base_url),
        ];

        for test_url in &test_urls {
            if let Ok(resp) = self.client
                .get(test_url)
                .header("Authorization", format!("Bearer {}", none_token))
                .send()
                .await
            {
                let status = resp.status().as_u16();

                // If we get 200 with alg=none, major vulnerability!
                if status == 200 {
                    warn!("JWT alg=none vulnerability at {}", test_url);

                    let vuln = Vulnerability::new(
                        "JWT Algorithm Confusion (alg=none)",
                        "Server accepts JWT tokens with algorithm set to 'none', \
                        meaning no signature verification is performed. \
                        Attackers can forge any JWT token and bypass authentication.",
                        Severity::Critical,
                        VulnCategory::JwtWeakness,
                        test_url.clone(),
                    )
                    .with_remediation(
                        "1. Explicitly whitelist allowed JWT algorithms (RS256, ES256).\n\
                        2. Never accept 'none' as a valid algorithm.\n\
                        3. Use a well-maintained JWT library with secure defaults.\n\
                        4. Validate the algorithm header before processing tokens."
                    )
                    .with_owasp(OwaspCategory::A07AuthenticationFailures)
                    .with_cwe(347);

                    vulns.push(vuln);
                }
            }
        }

        vulns
    }

    /// Classify the severity and description of an information disclosure
    fn classify_disclosure(&self, path: &str, content: &str) -> (Severity, String) {
        if path.contains(".env") || content.contains("DB_PASSWORD") || content.contains("SECRET_KEY") {
            (
                Severity::Critical,
                "Environment file exposed containing credentials, API keys, and secrets. \
                Immediate action required.".to_string(),
            )
        } else if path.contains(".git") {
            (
                Severity::High,
                "Git repository files accessible. Source code and commit history may be downloadable.".to_string(),
            )
        } else if path.contains("config") && (content.contains("password") || content.contains("secret")) {
            (
                Severity::High,
                "Configuration file with sensitive data is publicly accessible.".to_string(),
            )
        } else if path.contains("phpinfo") || content.contains("PHP Version") {
            (
                Severity::Medium,
                "PHP info page exposed. Reveals PHP version, loaded modules, server paths.".to_string(),
            )
        } else if path.contains("swagger") || path.contains("openapi") {
            (
                Severity::Low,
                "API documentation is publicly accessible. Review if intentional.".to_string(),
            )
        } else {
            (
                Severity::Low,
                format!("Potentially sensitive file '{}' is publicly accessible.", path),
            )
        }
    }
}

// Add urlencoding as a helper (needed for encoding payloads)
mod urlencoding {
    pub fn encode(s: &str) -> String {
        s.chars()
            .map(|c| match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
                ' ' => "+".to_string(),
                c => format!("%{:02X}", c as u32),
            })
            .collect()
    }
}
