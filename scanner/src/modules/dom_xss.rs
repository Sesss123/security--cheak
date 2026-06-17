// [FIXED] Bug #2: headless_chrome required a real Chromium binary that is not installed
// in the Docker runtime image. Any scan including dom-xss crashed the entire Rust process.
//
// New approach: HTTP-based heuristic scanner that:
//   1. Fetches the page HTML via reqwest (already a project dependency, zero new deps)
//   2. Searches for dangerous DOM sink patterns combined with taint sources (location, search params)
//   3. Reports findings as Medium severity with a note that manual confirmation is required.
//
// Trade-off: No JavaScript execution, so dynamically-injected sinks won't be detected.
// This is intentional — a stable, deployable scanner beats a crashing headless one.

use tracing::{info, warn};
use regex::Regex;

use crate::models::vulnerability::{Vulnerability, VulnCategory, OwaspCategory};
use crate::models::scan::Severity;

/// Heuristic patterns: (regex, human-readable description)
/// Each pattern matches a dangerous sink combined with a taint source commonly
/// found in DOM XSS vulnerabilities.
const SINK_PATTERNS: &[(&str, &str)] = &[
    // innerHTML + location sources
    (r"innerHTML\s*=\s*[^;]*location", "innerHTML sink reading from location (hash/search/href)"),
    (r"innerHTML\s*=\s*[^;]*decodeURI", "innerHTML sink with decoded URI value"),
    (r"\.innerHTML\s*\+=[^;]*\w",      "innerHTML concatenation — potential unsanitised append"),

    // document.write sources
    (r"document\.write\s*\([^)]*location",  "document.write() with location-derived value"),
    (r"document\.write\s*\([^)]*unescape",  "document.write() with unescape() — classic XSS pattern"),

    // eval / Function sinks
    (r"eval\s*\([^)]*location",    "eval() with location-derived value"),
    (r"eval\s*\([^)]*search",      "eval() with URLSearchParams / location.search"),
    (r"Function\s*\([^)]*location","new Function() constructor with location-derived value"),

    // jQuery legacy sinks
    (r#"\$\s*\([^)]*location\.hash"#, "jQuery selector with location.hash (DOM XSS via jQuery)"),
    (r#"\.html\s*\([^)]*location"#,   "jQuery .html() with location-derived value"),
];

pub struct DomXssScanner {
    base_url: String,
}

impl DomXssScanner {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }

    /// Scans up to 10 URLs for DOM XSS sink/source patterns via HTTP heuristics.
    pub async fn scan(&self, targets: &[String]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Build target list: base URL first, then additional crawled targets
        let mut all_targets = vec![self.base_url.clone()];
        all_targets.extend_from_slice(targets);
        all_targets.truncate(10); // Cap for performance

        // Pre-compile regex patterns once
        let compiled: Vec<(Regex, &str)> = SINK_PATTERNS
            .iter()
            .filter_map(|(pat, desc)| Regex::new(pat).ok().map(|re| (re, *desc)))
            .collect();

        // Use the shared HTTP client (includes SSRF protection + timeouts)
        let client = crate::utils::http::get_global_client();

        for target in &all_targets {
            info!("DOM XSS heuristic scan on: {}", target);

            match client.get(target).send().await {
                Ok(resp) => {
                    match resp.text().await {
                        Ok(body) => {
                            // Check each sink pattern — stop at first match per URL
                            for (re, description) in &compiled {
                                if re.is_match(&body) {
                                    warn!("Potential DOM XSS pattern detected on {}: {}", target, description);
                                    vulnerabilities.push(
                                        Vulnerability::new(
                                            "Potential DOM-Based XSS (Heuristic)",
                                            format!(
                                                "A dangerous DOM sink pattern was found in the page source of '{}'.\n\
                                                Pattern: {}\n\n\
                                                ⚠ This is a static heuristic — JavaScript was not executed. \
                                                Manual confirmation is required to determine if the sink is \
                                                reachable with attacker-controlled input.",
                                                target, description
                                            ),
                                            Severity::Medium,
                                            VulnCategory::Xss,
                                            target.clone(),
                                        )
                                        .with_owasp(OwaspCategory::A03Injection)
                                        .with_remediation(
                                            "Avoid passing untrusted data (e.g., location.hash, \
                                            URLSearchParams, document.referrer) to dangerous sinks such as \
                                            innerHTML, document.write, eval, or jQuery .html(). \
                                            Use textContent for plain text, or sanitise HTML with DOMPurify \
                                            before inserting into the DOM."
                                        )
                                    );
                                    // One finding per target — avoid flooding with duplicate patterns
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to read response body from {}: {}", target, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("HTTP request failed for DOM XSS scan on {}: {}", target, e);
                }
            }
        }

        vulnerabilities
    }
}
