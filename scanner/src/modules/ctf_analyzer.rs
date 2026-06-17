use anyhow::Result;
use reqwest::Client;
use tracing::info;
use serde::{Deserialize, Serialize};
use regex::Regex;
use std::collections::HashSet;

// ── Flag Patterns ─────────────────────────────────────────────
// Most common CTF flag formats
const FLAG_PATTERNS: &[(&str, &str)] = &[
    (r"flag\{[^}]+\}",           "Generic flag{}"),
    (r"CTF\{[^}]+\}",            "CTF{}"),
    (r"picoCTF\{[^}]+\}",        "picoCTF{}"),
    (r"HTB\{[^}]+\}",            "HackTheBox{}"),
    (r"THM\{[^}]+\}",            "TryHackMe{}"),
    (r"DUCTF\{[^}]+\}",          "DownUnderCTF{}"),
    (r"LACTF\{[^}]+\}",          "LACTF{}"),
    (r"dice\{[^}]+\}",           "DiceCTF{}"),
    (r"corctf\{[^}]+\}",         "corCTF{}"),
    (r"[A-Z0-9_]+\{[^}]{8,}\}",  "Unknown CTF format"),
    // Base64 encoded flags
    (r"[A-Za-z0-9+/]{20,}={0,2}", "Possible Base64"),
    // Hex encoded flags
    (r"(?:0x)?[0-9a-fA-F]{32,}",  "Possible Hex/Hash"),
];

// ── Hidden Paths for CTF ──────────────────────────────────────
const CTF_PATHS: &[&str] = &[
    // Common CTF hidden files
    "/flag", "/flag.txt", "/secret", "/secret.txt",
    "/key", "/key.txt", "/password", "/pass.txt",
    "/.flag", "/.secret", "/.hidden",
    "/flag.php", "/secret.php", "/admin/flag",

    // Git/Source exposure
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.hg/store",

    // Backup files
    "/backup", "/backup.zip", "/backup.tar.gz",
    "/www.zip", "/site.zip", "/source.zip",
    "/index.php.bak", "/index.bak", "/config.bak",

    // Config/env files
    "/.env", "/.env.local", "/.env.backup",
    "/config.php", "/configuration.php", "/settings.php",
    "/wp-config.php", "/wp-config.php.bak",

    // Admin panels
    "/admin", "/admin/", "/administrator",
    "/admin.php", "/admin/login", "/panel",
    "/dashboard", "/manage", "/manager",
    "/console", "/shell", "/cmd",

    // API endpoints
    "/api", "/api/v1", "/api/v2",
    "/api/flag", "/api/secret", "/api/admin",
    "/graphql", "/swagger", "/api-docs",

    // PHP/common vulns
    "/phpinfo.php", "/info.php", "/test.php",
    "/shell.php", "/cmd.php", "/upload.php",
    "/?debug=1", "/?test=1", "/?admin=1",

    // robots.txt hidden paths
    "/sitemap.xml",

    // Common CTF specific
    "/the-flag", "/get-flag", "/givemeflag",
    "/supersecret", "/top-secret", "/classified",
];

// ── Secret Patterns in Source Code ───────────────────────────
const SECRET_PATTERNS: &[(&str, &str)] = &[
    (r#"(?i)password\s*[=:]\s*['\"]([^'\"]{4,})['\"]"#,   "Password in source"),
    (r#"(?i)passwd\s*[=:]\s*['\"]([^'\"]{4,})['\"]"#,     "Password in source"),
    (r#"(?i)api[_-]?key\s*[=:]\s*['\"]([^'\"]{8,})['\"]"#,"API Key"),
    (r#"(?i)secret\s*[=:]\s*['\"]([^'\"]{4,})['\"]"#,     "Secret value"),
    (r#"(?i)token\s*[=:]\s*['\"]([^'\"]{8,})['\"]"#,      "Token"),
    (r#"(?i)auth\s*[=:]\s*['\"]([^'\"]{8,})['\"]"#,       "Auth credential"),
    (r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT Token"),
    (r"-----BEGIN [A-Z ]+KEY-----",                       "Private Key"),
    (r#"(?i)flag\s*[=:]\s*['\"]([^'\"]{4,})['\"]"#,       "Flag in source"),
];

// ── CTF Finding ───────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtfFinding {
    pub finding_type: CtfFindingType,
    pub title: String,
    pub description: String,
    pub url: String,
    pub evidence: String,
    pub hint: String,
    pub priority: u8, // 1-10
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CtfFindingType {
    FlagFound,        // 🚩 Actual flag!
    HiddenPath,       // Hidden file/endpoint found
    SecretInSource,   // Secret in HTML/JS source
    InterestingHeader,// Interesting HTTP header
    SubdomainFound,   // Subdomain discovered
    CookieSecret,     // Interesting cookie
    CommentInSource,  // HTML comment with hints
    RobotsDisallowed, // robots.txt disallowed paths
}

impl PartialEq for CtfFinding {
    fn eq(&self, other: &Self) -> bool {
        self.title == other.title && self.url == other.url && self.evidence == other.evidence
    }
}
impl Eq for CtfFinding {}

impl std::hash::Hash for CtfFinding {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.title.hash(state);
        self.url.hash(state);
        self.evidence.hash(state);
    }
}

// ── Main CTF Scanner ─────────────────────────────────────────
pub struct CtfScanner {
    client: Client,
    base_url: String,
}

impl CtfScanner {
    pub fn new(base_url: String) -> Self {
        let client = crate::utils::http::get_global_client();

        Self { client, base_url: base_url.trim_end_matches('/').to_string() }
    }

    /// Run all CTF checks
    pub async fn scan_all(&self) -> Vec<CtfFinding> {
        info!("🚩 Starting CTF scan for {}", self.base_url);
        let mut findings = vec![];

        // Run all checks concurrently
        let (flags, hidden, source_secrets, cookies, robots, subdomains) = tokio::join!(
            self.scan_for_flags_in_pages(),
            self.find_hidden_paths(),
            self.scan_source_secrets(),
            self.analyze_cookies(),
            self.check_robots_txt(),
            self.enumerate_subdomains(),
        );

        findings.extend(flags);
        findings.extend(hidden);
        findings.extend(source_secrets);
        findings.extend(cookies);
        findings.extend(robots);
        findings.extend(subdomains);

        // Deduplicate findings
        let unique_findings: HashSet<_> = findings.into_iter().collect();
        let mut findings: Vec<_> = unique_findings.into_iter().collect();

        // Sort by priority
        findings.sort_by(|a, b| b.priority.cmp(&a.priority));

        info!("🚩 CTF scan complete: {} findings", findings.len());
        findings
    }

    /// Scan page content for flag patterns
    async fn scan_for_flags_in_pages(&self) -> Vec<CtfFinding> {
        info!("Scanning for flags in page content...");
        let mut findings = vec![];

        let pages_to_check = vec![
            self.base_url.clone(),
            format!("{}/index.php", self.base_url),
            format!("{}/index.html", self.base_url),
        ];

        for url in &pages_to_check {
            if let Ok(resp) = self.client.get(url).send().await {
                if let Ok(body) = resp.text().await {
                    findings.extend(self.extract_flags(&body, url));
                    findings.extend(self.extract_html_comments(&body, url));
                }
            }
        }

        findings
    }

    /// Extract flags from text content
    fn extract_flags(&self, content: &str, url: &str) -> Vec<CtfFinding> {
        let mut findings = vec![];

        for (pattern, pattern_name) in FLAG_PATTERNS {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.find_iter(content) {
                    let matched = cap.as_str().to_string();

                    // Skip if too generic (base64/hex check)
                    if pattern_name.contains("Base64") || pattern_name.contains("Hex") {
                        // Only flag if near suspicious keywords
                        let context_start = cap.start().saturating_sub(50);
                        let context = &content[context_start..cap.end().min(content.len())];
                        let keywords = ["flag", "secret", "key", "password", "token", "ctf"];
                        if !keywords.iter().any(|k| context.to_lowercase().contains(k)) {
                            continue;
                        }
                    }

                    findings.push(CtfFinding {
                        finding_type: CtfFindingType::FlagFound,
                        title: format!("🚩 FLAG FOUND: {}", pattern_name),
                        description: format!(
                            "Flag pattern '{}' detected in page content!",
                            pattern_name
                        ),
                        url: url.to_string(),
                        evidence: matched.chars().take(200).collect(),
                        hint: "Submit this flag to the CTF platform!".to_string(),
                        priority: 10,
                    });
                }
            }
        }

        findings
    }

    /// Extract HTML comments (often contain hints in CTFs)
    fn extract_html_comments(&self, content: &str, url: &str) -> Vec<CtfFinding> {
        let mut findings = vec![];
        if let Ok(re) = Regex::new(r"<!--([\s\S]*?)-->") {
            for cap in re.captures_iter(content) {
                let comment = cap[1].trim().to_string();
                if comment.len() < 3 { continue; }

                // Skip empty or whitespace-only comments
                let interesting_keywords = [
                    "flag", "secret", "password", "hint", "todo", "fixme",
                    "admin", "key", "token", "debug", "test", "hack",
                ];

                let is_interesting = interesting_keywords
                    .iter()
                    .any(|k| comment.to_lowercase().contains(k));

                if is_interesting || comment.len() > 20 {
                    findings.push(CtfFinding {
                        finding_type: CtfFindingType::CommentInSource,
                        title: "💬 Interesting HTML Comment Found".to_string(),
                        description: "HTML comment may contain hints or sensitive info".to_string(),
                        url: url.to_string(),
                        evidence: comment.chars().take(300).collect(),
                        hint: "Check if this comment contains credentials or flag hints".to_string(),
                        priority: if is_interesting { 8 } else { 4 },
                    });
                }
            }
        }
        findings
    }

    /// Find hidden paths and files
    async fn find_hidden_paths(&self) -> Vec<CtfFinding> {
        info!("Brute-forcing hidden paths...");
        let mut findings = vec![];

        // Scan in batches of 20
        for chunk in CTF_PATHS.chunks(20) {
            let futures: Vec<_> = chunk.iter().map(|path| {
                let url = format!("{}{}", self.base_url, path);
                let client = self.client.clone();
                async move {
                    if let Ok(resp) = client.get(&url).send().await {
                        let status = resp.status().as_u16();
                        if status == 200 || status == 301 || status == 302 || status == 403 {
                            let body = resp.text().await.unwrap_or_default();
                            Some((url, status, body, *path))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            }).collect();

            let results = futures::future::join_all(futures).await;

            for result in results.into_iter().flatten() {
                let (url, status, body, path) = result;

                // Check for flags in the response
                let flag_findings = self.extract_flags(&body, &url);
                if !flag_findings.is_empty() {
                    findings.extend(flag_findings);
                    continue;
                }

                let (priority, hint) = match status {
                    200 => {
                        if path.contains("flag") || path.contains("secret") {
                            (9, "Check this file carefully for the flag!")
                        } else if path.contains(".git") {
                            (8, "Git repo exposed! Run: git-dumper <url> ./output")
                        } else if path.contains("backup") || path.ends_with(".zip") {
                            (7, "Backup file found! Download and extract it")
                        } else if path.contains("admin") {
                            (7, "Admin panel found! Try default credentials")
                        } else {
                            (5, "Accessible path found, investigate manually")
                        }
                    }
                    403 => (4, "Forbidden - authentication required or access denied"),
                    301 | 302 => (3, "Redirect found - follow it manually"),
                    _ => continue,
                };

                findings.push(CtfFinding {
                    finding_type: CtfFindingType::HiddenPath,
                    title: format!("📂 Hidden Path Found: {} ({})", path, status),
                    description: format!(
                        "Path '{}' returned HTTP {} - may contain sensitive data",
                        path, status
                    ),
                    url,
                    evidence: body.chars().take(300).collect(),
                    hint: hint.to_string(),
                    priority,
                });
            }
        }

        findings
    }

    /// Scan page source for secrets
    async fn scan_source_secrets(&self) -> Vec<CtfFinding> {
        info!("Scanning source code for secrets...");
        let mut findings = vec![];

        // Check main page + JS files
        let urls_to_check = vec![
            self.base_url.clone(),
            format!("{}/js/app.js", self.base_url),
            format!("{}/static/js/main.js", self.base_url),
            format!("{}/assets/js/app.js", self.base_url),
            format!("{}/app.js", self.base_url),
        ];

        for url in &urls_to_check {
            if let Ok(resp) = self.client.get(url).send().await {
                if resp.status().as_u16() == 200 {
                    if let Ok(body) = resp.text().await {
                        for (pattern, label) in SECRET_PATTERNS {
                            if let Ok(re) = Regex::new(pattern) {
                                for cap in re.find_iter(&body) {
                                    let matched = cap.as_str().to_string();

                                    // Get surrounding context
                                    let start = cap.start().saturating_sub(30);
                                    let end = (cap.end() + 30).min(body.len());
                                    let context = body[start..end].to_string();

                                    findings.push(CtfFinding {
                                        finding_type: CtfFindingType::SecretInSource,
                                        title: format!("🔑 Secret in Source: {}", label),
                                        description: format!(
                                            "{} found in page/script source code",
                                            label
                                        ),
                                        url: url.clone(),
                                        evidence: format!(
                                            "...{}...\nFull match: {}",
                                            context.chars().take(100).collect::<String>(),
                                            matched.chars().take(100).collect::<String>()
                                        ),
                                        hint: match *label {
                                            "JWT Token" => "Decode at jwt.io - check claims for flags".to_string(),
                                            "Private Key" => "Private key exposed! Check what it unlocks".to_string(),
                                            "Flag in source" => "This might be the flag!".to_string(),
                                            _ => format!("Use this {} to authenticate or find the flag", label),
                                        },
                                        priority: if label.contains("Flag") || label.contains("JWT") { 9 } else { 6 },
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    /// Analyze cookies for secrets
    async fn analyze_cookies(&self) -> Vec<CtfFinding> {
        info!("Analyzing cookies...");
        let mut findings = vec![];

        if let Ok(resp) = self.client.get(&self.base_url).send().await {
            let cookies: Vec<String> = resp.cookies()
                .map(|c| format!("{}={}", c.name(), c.value()))
                .collect();

            for cookie in &cookies {
                // Check for JWT in cookies
                if cookie.contains("eyJ") {
                    findings.push(CtfFinding {
                        finding_type: CtfFindingType::CookieSecret,
                        title: "🍪 JWT Token in Cookie".to_string(),
                        description: "JWT token found in cookie - may be vulnerable to algorithm confusion".to_string(),
                        url: self.base_url.clone(),
                        evidence: cookie.chars().take(200).collect(),
                        hint: "1. Decode at jwt.io\n2. Try alg=none attack\n3. Try HS256 with empty secret\n4. Check claims for flag hints".to_string(),
                        priority: 8,
                    });
                    continue;
                }

                // Check for base64 encoded values
                if let Some(value) = cookie.split('=').nth(1) {
                    if value.len() > 20 {
                        if let Ok(decoded) = base64_decode(value) {
                            let decoded_str = String::from_utf8_lossy(&decoded).to_string();
                            if decoded_str.contains("flag") || decoded_str.contains("admin") || decoded_str.contains("{") {
                                findings.push(CtfFinding {
                                    finding_type: CtfFindingType::CookieSecret,
                                    title: "🍪 Interesting Decoded Cookie Value".to_string(),
                                    description: "Cookie appears to be base64 encoded with interesting content".to_string(),
                                    url: self.base_url.clone(),
                                    evidence: format!("Raw: {}\nDecoded: {}", &cookie[..cookie.len().min(100)], &decoded_str[..decoded_str.len().min(200)]),
                                    hint: "Modify the decoded value (e.g. set admin=true) and re-encode".to_string(),
                                    priority: 7,
                                });
                                continue;
                            }
                        }
                    }
                }

                // Check for interesting cookie names
                let interesting_names = ["admin", "role", "user", "auth", "token", "session", "flag"];
                for name in interesting_names {
                    if cookie.to_lowercase().starts_with(name) {
                        findings.push(CtfFinding {
                            finding_type: CtfFindingType::CookieSecret,
                            title: format!("🍪 Interesting Cookie: {}", name),
                            description: format!("Cookie named '{}' found - try manipulating it", name),
                            url: self.base_url.clone(),
                            evidence: cookie.chars().take(200).collect(),
                            hint: format!("Try changing '{}' cookie value to 'admin', 'true', or '1'", name),
                            priority: 6,
                        });
                        break;
                    }
                }
            }
        }

        findings
    }

    /// Check robots.txt for hidden paths
    async fn check_robots_txt(&self) -> Vec<CtfFinding> {
        info!("Checking robots.txt...");
        let mut findings = vec![];

        let robots_url = format!("{}/robots.txt", self.base_url);

        if let Ok(resp) = self.client.get(&robots_url).send().await {
            if resp.status().as_u16() == 200 {
                if let Ok(body) = resp.text().await {
                    // Extract Disallow paths
                    let mut disallowed = vec![];
                    for line in body.lines() {
                        if line.to_lowercase().starts_with("disallow:") {
                            let path = line[9..].trim().to_string();
                            if !path.is_empty() && path != "/" {
                                disallowed.push(path);
                            }
                        }
                    }

                    if !disallowed.is_empty() {
                        findings.push(CtfFinding {
                            finding_type: CtfFindingType::RobotsDisallowed,
                            title: format!("🤖 robots.txt: {} Hidden Paths Found", disallowed.len()),
                            description: "robots.txt reveals hidden paths that are blocked from indexing".to_string(),
                            url: robots_url,
                            evidence: disallowed.join("\n"),
                            hint: format!(
                                "Check these paths:\n{}",
                                disallowed.iter()
                                    .map(|p| format!("{}{}", self.base_url, p))
                                    .collect::<Vec<_>>()
                                    .join("\n")
                            ),
                            priority: 7,
                        });
                    }

                    // Also check for flags in robots.txt itself
                    findings.extend(self.extract_flags(&body, &format!("{}/robots.txt", self.base_url)));
                }
            }
        }

        findings
    }

    /// Enumerate subdomains using crt.sh
    async fn enumerate_subdomains(&self) -> Vec<CtfFinding> {
        info!("Enumerating subdomains...");
        let mut findings = vec![];
        
        if let Ok(url) = url::Url::parse(&self.base_url) {
            if let Some(host) = url.host_str() {
                let root_domain = host.strip_prefix("www.").unwrap_or(host);
                
                // Skip if root_domain is an IP address
                if root_domain.parse::<std::net::IpAddr>().is_ok() {
                    return findings;
                }
                
                let crt_url = format!("https://crt.sh/?q=%.{}&output=json", root_domain);
                
                if let Ok(resp) = self.client.get(&crt_url).send().await {
                    if let Ok(body) = resp.text().await {
                        let mut subdomains = HashSet::new();
                        if let Ok(re) = Regex::new(r#""name_value":"([^"]+)""#) {
                            for cap in re.captures_iter(&body) {
                                let sub = cap[1].to_string();
                                let sub = sub.replace("*.", "");
                                if sub.ends_with(root_domain) && sub != root_domain {
                                    subdomains.insert(sub);
                                }
                            }
                        }

                        if !subdomains.is_empty() {
                            let subs_list: Vec<_> = subdomains.into_iter().collect();
                            findings.push(CtfFinding {
                                finding_type: CtfFindingType::SubdomainFound,
                                title: format!("🌐 Subdomains Discovered: {}", subs_list.len()),
                                description: "Found other subdomains that might host vulnerable services".to_string(),
                                url: self.base_url.clone(),
                                evidence: subs_list.join("\n"),
                                hint: "Check these subdomains for dev/staging environments or internal flags".to_string(),
                                priority: 8,
                            });
                        }
                    }
                }
            }
        }
        
        findings
    }
}

use base64::{Engine as _, engine::general_purpose};

// Simple base64 decode helper using base64 crate
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    // Basic base64 check to avoid unnecessary allocations
    let clean = input.trim_end_matches('=');
    if clean.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '-' || c == '_') {
        // Try decoding with standard alphabet and padding
        if let Ok(decoded) = general_purpose::STANDARD.decode(input) {
            return Ok(decoded);
        }
        // Try decoding with URL-safe alphabet
        if let Ok(decoded) = general_purpose::URL_SAFE.decode(input) {
            return Ok(decoded);
        }
        if let Ok(decoded) = general_purpose::URL_SAFE_NO_PAD.decode(input) {
            return Ok(decoded);
        }
    }
    
    Err(anyhow::anyhow!("Not base64"))
}
