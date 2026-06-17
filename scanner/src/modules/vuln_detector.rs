use reqwest::Client;
use tracing::{info, warn};

use crate::models::vulnerability::{
    Vulnerability, VulnCategory, OwaspCategory, Evidence, EvidenceType,
};
use crate::models::scan::Severity;
use crate::modules::crawler::Crawler;
use crate::modules::subdomain_enum::SubdomainEnumerator;
use crate::modules::dir_bruteforce::DirBruteforcer;
use crate::modules::ssrf::SsrfDetector;
use crate::modules::xxe::XxeDetector;
use crate::modules::csrf::CsrfDetector;
use crate::modules::file_upload::FileUploadDetector;
use crate::modules::dom_xss::DomXssScanner;
use crate::modules::graphql::GraphqlScanner;
use crate::modules::waf_detector::WafDetector;
use crate::modules::cloud_scanner::CloudScanner;
use crate::modules::api_fuzzer::ApiFuzzer;

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
        let client = crate::utils::http::get_global_client();

        Self { client, base_url }
    }

    /// Run vulnerability detection modules based on requested scan types
    pub async fn detect_requested(&self, scan_types: &[crate::models::scan::ScanType]) -> Vec<Vulnerability> {
        info!("Starting vulnerability detection for {}", self.base_url);
        let mut vulns = vec![];
        
        use crate::models::scan::ScanType;

        let run_crawler = scan_types.contains(&ScanType::Crawler)
            || scan_types.contains(&ScanType::SqlInjection)
            || scan_types.contains(&ScanType::Xss)
            || scan_types.contains(&ScanType::OpenRedirect)
            || scan_types.contains(&ScanType::Ssrf)
            || scan_types.contains(&ScanType::Xxe)
            || scan_types.contains(&ScanType::Csrf)
            || scan_types.contains(&ScanType::Upload)
            || scan_types.contains(&ScanType::DomXss)
            || scan_types.contains(&ScanType::Graphql);

        let run_subdomains = scan_types.contains(&ScanType::Crawler) || scan_types.contains(&ScanType::InfoDisclosure);
        let run_dir_bf = scan_types.contains(&ScanType::DirBruteforce);

        // 1. Run Recon (Crawler, Subdomains, Dir Bruteforce) conditionally
        let crawler = Crawler::new(self.base_url.clone(), 2);
        let sub_enum = SubdomainEnumerator::new();
        let dir_bf = DirBruteforcer::new(self.base_url.clone());

        let crawl_future = async {
            if run_crawler { crawler.crawl_site().await } else { crate::modules::crawler::CrawlResult::default() }
        };
        let sub_future = async {
            if run_subdomains { sub_enum.enumerate(&self.base_url).await } else { vec![] }
        };
        let dir_future = async {
            if run_dir_bf { dir_bf.bruteforce().await } else { vec![] }
        };

        let (crawl_result, subdomains, hidden_dirs) = tokio::join!(crawl_future, sub_future, dir_future);

        // Add Recon findings as Informational "Vulnerabilities"
        for sub in subdomains {
            vulns.push(Vulnerability::new(
                "Subdomain Discovered",
                format!("Found subdomain: {}", sub),
                Severity::Low,
                VulnCategory::InformationDisclosure,
                format!("https://{}", sub),
            ));
        }

        for dir in hidden_dirs {
            vulns.push(Vulnerability::new(
                "Hidden Path Discovered",
                format!("Found accessible hidden path: {}", dir),
                Severity::Low,
                VulnCategory::InformationDisclosure,
                dir,
            ));
        }

        // 2. Run Vulnerability Checks using dynamic crawler data conditionally
        let sqli_future = async {
            if scan_types.contains(&ScanType::SqlInjection) { self.check_sql_injection(&crawl_result).await } else { vec![] }
        };
        let xss_future = async {
            if scan_types.contains(&ScanType::Xss) { self.check_xss(&crawl_result).await } else { vec![] }
        };
        let redirect_future = async {
            if scan_types.contains(&ScanType::OpenRedirect) { self.check_open_redirect(&crawl_result).await } else { vec![] }
        };
        let info_future = async {
            if scan_types.contains(&ScanType::InfoDisclosure) { self.check_information_disclosure().await } else { vec![] }
        };
        let jwt_future = async {
            if scan_types.contains(&ScanType::JwtAnalysis) { self.check_jwt_weaknesses().await } else { vec![] }
        };

        let (sqli_vulns, xss_vulns, redirect_vulns, info_vulns, jwt_vulns) = tokio::join!(
            sqli_future, xss_future, redirect_future, info_future, jwt_future
        );

        // 3. Run Advanced Attack Modules (Phase B) conditionally
        let ssrf = SsrfDetector::new(self.base_url.clone());
        let xxe = XxeDetector::new(self.base_url.clone());
        let csrf = CsrfDetector::new(self.base_url.clone());
        let upload = FileUploadDetector::new(self.base_url.clone());
        let dom_xss = DomXssScanner::new(self.base_url.clone());
        let graphql = GraphqlScanner::new(self.base_url.clone());
        let waf_det = WafDetector::new(self.base_url.clone());
        let cloud_scan = CloudScanner::new(self.base_url.clone());
        let api_fuzz = ApiFuzzer::new(self.base_url.clone());

        let target_urls: Vec<String> = crawl_result.urls.clone().into_iter().collect();

        let ssrf_future = async { if scan_types.contains(&ScanType::Ssrf) { ssrf.detect(&crawl_result).await } else { vec![] } };
        let xxe_future = async { if scan_types.contains(&ScanType::Xxe) { xxe.detect(&crawl_result).await } else { vec![] } };
        let csrf_future = async { if scan_types.contains(&ScanType::Csrf) { csrf.detect(&crawl_result) } else { vec![] } };
        let upload_future = async { if scan_types.contains(&ScanType::Upload) { upload.detect(&crawl_result).await } else { vec![] } };
        let dom_xss_future = async { if scan_types.contains(&ScanType::DomXss) { dom_xss.scan(&target_urls).await } else { vec![] } };
        let graphql_future = async { if scan_types.contains(&ScanType::Graphql) { graphql.scan(&target_urls).await } else { vec![] } };
        let waf_future = async { if scan_types.contains(&ScanType::WafDetector) { waf_det.detect().await } else { vec![] } };
        let cloud_future = async { if scan_types.contains(&ScanType::CloudScanner) { cloud_scan.detect().await } else { vec![] } };
        let api_future = async { if scan_types.contains(&ScanType::ApiFuzzer) || scan_types.contains(&ScanType::ApiSecurity) { api_fuzz.detect().await } else { vec![] } };

        let (
            ssrf_vulns, xxe_vulns, csrf_vulns, upload_vulns, 
            dom_xss_vulns, graphql_vulns, waf_vulns, cloud_vulns, api_vulns
        ) = tokio::join!(
            ssrf_future, xxe_future, csrf_future, upload_future,
            dom_xss_future, graphql_future, waf_future, cloud_future, api_future
        );

        vulns.extend(sqli_vulns);
        vulns.extend(xss_vulns);
        vulns.extend(redirect_vulns);
        vulns.extend(info_vulns);
        vulns.extend(jwt_vulns);
        vulns.extend(ssrf_vulns);
        vulns.extend(xxe_vulns);
        vulns.extend(csrf_vulns);
        vulns.extend(upload_vulns);
        vulns.extend(dom_xss_vulns);
        vulns.extend(graphql_vulns);
        vulns.extend(waf_vulns);
        vulns.extend(cloud_vulns);
        vulns.extend(api_vulns);

        info!("Found {} vulnerabilities", vulns.len());
        vulns
    }

    /// SQL Injection detection
    async fn check_sql_injection(&self, crawl_result: &crate::modules::crawler::CrawlResult) -> Vec<Vulnerability> {
        info!("Testing for SQL Injection on discovered endpoints...");
        let mut vulns = vec![];

        let mut test_urls = vec![
            format!("{}/search?q=", self.base_url),
            format!("{}/user?id=", self.base_url),
        ];

        // Add dynamic endpoints from crawler
        for form in &crawl_result.forms {
            if form.method == "GET" && !form.inputs.is_empty() {
                let param = &form.inputs[0];
                test_urls.push(format!("{}?{}=", form.action, param));
            }
        }
        
        for url in &crawl_result.urls {
            if url.contains("?") && url.contains("=") {
                let base = url.split("=").next().unwrap_or(url);
                test_urls.push(format!("{}=", base));
            }
        }

        for base_test_url in &test_urls {
            // [FALSE POSITIVE FIX] Check base request first for existing error strings
            let mut base_errors_present = std::collections::HashSet::new();
            if let Ok(resp) = self.client.get(base_test_url).send().await {
                if let Ok(body) = resp.text().await {
                    for pattern in SQL_ERROR_PATTERNS {
                        if body.to_lowercase().contains(&pattern.to_lowercase()) {
                            base_errors_present.insert(pattern);
                        }
                    }
                }
            }

            for payload in SQLI_PAYLOADS {
                let test_url = format!("{}{}", base_test_url, urlencoding::encode(payload));

                match self.client.get(&test_url).send().await {
                    Ok(resp) => {
                        if let Ok(body) = resp.text().await {
                            for pattern in SQL_ERROR_PATTERNS {
                                if !base_errors_present.contains(pattern) && body.to_lowercase().contains(&pattern.to_lowercase()) {
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
    async fn check_xss(&self, crawl_result: &crate::modules::crawler::CrawlResult) -> Vec<Vulnerability> {
        info!("Testing for XSS on discovered endpoints...");
        let mut vulns = vec![];

        let mut test_urls = vec![
            format!("{}/?q=", self.base_url),
        ];

        // Dynamic parameters
        for form in &crawl_result.forms {
            if form.method == "GET" && !form.inputs.is_empty() {
                let param = &form.inputs[0];
                test_urls.push(format!("{}?{}=", form.action, param));
            }
        }

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
    async fn check_open_redirect(&self, _crawl_result: &crate::modules::crawler::CrawlResult) -> Vec<Vulnerability> {
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
                    // .danger_accept_invalid_certs(true) // Removed per security review
                    .timeout(std::time::Duration::from_secs(10))
                    .connect_timeout(std::time::Duration::from_secs(5))
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
