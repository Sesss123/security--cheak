use anyhow::{Result, Context};
use tracing::info;
use url::Url;

use crate::models::scan::{ScanRequest, ScanResult, ScanStatus, ScanSummary, ScanType};
use crate::modules::{
    port_scanner::{PortScanner, flag_dangerous_ports},
    ssl_analyzer::SslAnalyzer,
    header_analyzer::{HeaderAnalyzer, analyze_cors},
    vuln_detector::VulnDetector,
    ctf_analyzer::CtfScanner,
    sast_analyzer::SastAnalyzer,
    threat_intel::ThreatIntel,
    asset_discovery::AssetDiscoveryEngine,
    recon_engine::ReconEngine,
    waf_detector::WafDetector,
    cloud_scanner::CloudScanner,
    api_fuzzer::ApiFuzzer,
    smart_scanner::SmartScanner,
};
use crate::models::vulnerability::{Vulnerability, VulnCategory, OwaspCategory};
use crate::models::scan::Severity;

/// Main orchestrator - coordinates all scanning modules
pub struct ScanOrchestrator;

impl ScanOrchestrator {
    pub fn new() -> Self {
        Self
    }

    /// Run a full security scan
    pub async fn run(&self, request: ScanRequest) -> Result<ScanResult> {
        info!("Starting scan for: {}", request.target_url);

        // Parse and validate the target URL
        let mut target_url = request.target_url.clone();
        if !target_url.starts_with("http://") && !target_url.starts_with("https://") {
            info!("No protocol provided. Defaulting to https://");
            target_url = format!("https://{}", target_url);
        }

        // URL parsing is always executed — target_url is guaranteed to have a scheme above
        // Parse URL; fall back to http:// if https:// scheme causes an error
        let url = match Url::parse(&target_url) {
            Ok(u) => u,
            Err(_) => {
                info!("HTTPS parsing failed. Falling back to http://");
                target_url = format!("http://{}", request.target_url);
                Url::parse(&target_url).context("Invalid target URL")?
            }
        };
        let mut target_ip = None;
        let url_scheme = url.scheme().to_string();
        let host = url.host_str()
            .context("Could not extract host from URL")?
            .to_string();

        // Resolve hostname to IP asynchronously to avoid thread blocking
        if let Ok(mut addrs) = tokio::net::lookup_host(format!("{}:80", host)).await {
            if let Some(addr) = addrs.next() {
                target_ip = Some(addr.ip());
            }
        }

        // ── Phase 1: Create Futures for Concurrent Execution ────────────────
        let port_fut = async {
            if request.scan_types.contains(&ScanType::PortScan) {
                if let Some(ip) = target_ip {
                    info!("Running port scan...");
                    let port_scanner = PortScanner::new(ip, request.options.timeout_secs * 1000);
                    return port_scanner.scan(&request.options.port_range).await.ok();
                }
            }
            None
        };

        let target_url_ref = &target_url;
        let is_https = url_scheme == "https";

        let ssl_fut = async {
            if request.scan_types.contains(&ScanType::SslAnalysis) && is_https {
                info!("Running SSL analysis...");
                let ssl_analyzer = SslAnalyzer::new();
                return ssl_analyzer.analyze(target_url_ref).await.ok();
            }
            None
        };

        let headers_fut = async {
            if request.scan_types.contains(&ScanType::SecurityHeaders)
                || request.scan_types.contains(&ScanType::HttpHeaders) {
                info!("Analyzing security headers...");
                let header_analyzer = HeaderAnalyzer::new();
                return header_analyzer.analyze(target_url_ref).await.ok();
            }
            None
        };

        let cors_fut = async {
            if request.scan_types.contains(&ScanType::CorsCheck) {
                info!("Checking CORS configuration...");
                return Some(analyze_cors(target_url_ref).await);
            }
            None
        };

        let vuln_fut = async {
            // Vulnerability detection always runs against the (validated) target URL
            info!("Running vulnerability detection...");
                let vuln_detector = VulnDetector::new(target_url_ref.clone());
            return Some(vuln_detector.detect_requested(&request.scan_types).await);
        };

        let ctf_fut = async {
            if request.scan_types.contains(&ScanType::CtfScan) {
                info!("Running CTF analysis...");
                let ctf_scanner = CtfScanner::new(target_url_ref.clone());
                return Some(ctf_scanner.scan_all().await);
            }
            None
        };

        let sast_fut = async {
            if request.scan_types.contains(&ScanType::Sast) {
                // [FIX #5] SastAnalyzer requires a local filesystem directory path.
                // Previously it received the HTTP URL (e.g., "https://example.com")
                // which caused an early return error "path does not exist or is not a directory".
                //
                // Detection: if the target starts with http:// or https://, it is a URL,
                // not a local path. SAST is only meaningful for local source trees.
                if target_url_ref.starts_with("http://") || target_url_ref.starts_with("https://") {
                    info!(
                        "SAST skipped: target '{}' is a URL, not a local file path. \
                        To run SAST, pass the path to your source directory (e.g., /path/to/src).",
                        target_url_ref
                    );
                    return None;
                }
                info!("Running SAST analysis on local path: {}", target_url_ref);
                let sast_analyzer = SastAnalyzer::new(target_url_ref.clone());
                return Some(sast_analyzer.analyze().await);
            }
            None
        };

        let asset_fut = async {
            if request.scan_types.contains(&ScanType::AssetDiscovery) {
                info!("Running Asset Discovery...");
                let engine = AssetDiscoveryEngine::new(target_url_ref.clone(), vec!["dns".into(), "ports".into(), "services".into()]);
                return Some(engine.run().await);
            }
            None
        };

        let recon_fut = async {
            if request.scan_types.contains(&ScanType::Recon) {
                info!("Running Recon Mode...");
                let engine = ReconEngine::new(target_url_ref.clone(), vec![
                    "technology_fingerprint".into(),
                    "header_analysis".into(),
                    "js_discovery".into(),
                    "endpoint_discovery".into(),
                ]);
                return Some(engine.run().await);
            }
            None
        };

        let waf_fut = async {
            if request.scan_types.contains(&ScanType::WafDetector) {
                info!("Running WAF Detection...");
                let waf = WafDetector::new(target_url_ref.clone());
                return Some(waf.detect().await);
            }
            None
        };

        let cloud_fut = async {
            if request.scan_types.contains(&ScanType::CloudScanner) {
                info!("Running Cloud Infrastructure Scanner...");
                let cloud = CloudScanner::new(target_url_ref.clone());
                return Some(cloud.detect().await);
            }
            None
        };

        let api_fuzzer_fut = async {
            if request.scan_types.contains(&ScanType::ApiFuzzer) {
                info!("Running OpenAPI Fuzzer...");
                let api_fuzzer = ApiFuzzer::new(target_url_ref.clone());
                return Some(api_fuzzer.detect().await);
            }
            None
        };

        let smart_fut = async {
            if request.scan_types.contains(&ScanType::SmartScan) {
                if let Some(framework) = &request.options.framework {
                    info!("Running Smart Web Scan for framework: {}", framework);
                    let scanner = SmartScanner::new(target_url_ref.clone(), framework.clone());
                    return Some(scanner.run().await);
                } else {
                    info!("Smart scan skipped: no framework specified");
                }
            }
            None
        };

        // ── Phase 2: Await All Futures Concurrently ───────────────────────
        let (
            port_res, ssl_res, headers_res, cors_res, vuln_res, ctf_res, sast_res,
            asset_res, recon_res, waf_res, cloud_res, api_fuzzer_res, smart_res
        ) = tokio::join!(
            port_fut, ssl_fut, headers_fut, cors_fut, vuln_fut, ctf_fut, sast_fut,
            asset_fut, recon_fut, waf_fut, cloud_fut, api_fuzzer_fut, smart_fut
        );

        // ── Phase 3: Process Results ──────────────────────────────────────
        let mut result = ScanResult::new(request.target_url.clone());

        if let Some(ports) = port_res {
            let dangerous = flag_dangerous_ports(&ports);
            for warning in dangerous {
                result.vulnerabilities.push(
                    Vulnerability::new(
                        "Dangerous Port Exposed",
                        warning.clone(),
                        Severity::High,
                        VulnCategory::SecurityMisconfiguration,
                        request.target_url.clone(),
                    )
                    .with_remediation(
                        "Restrict access to this port using a firewall. \
                        Only allow connections from trusted IP addresses. \
                        Consider disabling the service if not needed."
                    )
                    .with_owasp(OwaspCategory::A05SecurityMisconfiguration)
                );
            }
            result.port_results = ports;
        }

        if let Some(ssl_result) = ssl_res {
            for issue in &ssl_result.issues {
                result.vulnerabilities.push(
                    Vulnerability::new(
                        "SSL/TLS Issue",
                        issue.description.clone(),
                        issue.severity.clone(),
                        VulnCategory::SslTlsIssue,
                        request.target_url.clone(),
                    )
                    .with_owasp(OwaspCategory::A02CryptographicFailures)
                );
            }
            result.ssl_result = Some(ssl_result);
        }

        if let Some(header_result) = headers_res {
            for missing in &header_result.headers_missing {
                result.vulnerabilities.push(
                    Vulnerability::new(
                        format!("Missing Security Header: {}", missing.name),
                        missing.description.clone(),
                        missing.severity.clone(),
                        VulnCategory::MissingSecurityHeader,
                        request.target_url.clone(),
                    )
                    .with_remediation(
                        format!("Add header: {} = {}", missing.name, missing.recommended_value)
                    )
                    .with_owasp(OwaspCategory::A05SecurityMisconfiguration)
                );
            }
            result.header_result = Some(header_result);
        }

        if let Some(cors_issues) = cors_res {
            for issue in cors_issues {
                result.vulnerabilities.push(
                    Vulnerability::new(
                        "CORS Misconfiguration",
                        issue,
                        Severity::High,
                        VulnCategory::CorsMisconfiguration,
                        request.target_url.clone(),
                    )
                    .with_remediation(
                        "1. Never use wildcard (*) CORS with credentials.\n\
                        2. Validate Origin against an explicit allowlist.\n\
                        3. Avoid reflecting the Origin header directly.\n\
                        4. Use specific allowed origins in production."
                    )
                    .with_owasp(OwaspCategory::A05SecurityMisconfiguration)
                    .with_cwe(942)
                );
            }
        }

        if let Some(detected) = vuln_res {
            result.vulnerabilities.extend(detected);
        }

        if let Some(ctf_findings) = ctf_res {
            for finding in ctf_findings {
                result.vulnerabilities.push(
                    Vulnerability::new(
                        finding.title,
                        finding.description,
                        if finding.priority > 8 { Severity::High } else if finding.priority > 5 { Severity::Medium } else { Severity::Low },
                        VulnCategory::InformationDisclosure,
                        finding.url,
                    )
                    .with_remediation(finding.hint)
                );
            }
        }

        if let Some(sast_findings) = sast_res {
            result.vulnerabilities.extend(sast_findings);
        }

        result.discovered_assets = asset_res;
        result.recon_data = recon_res;

        if let Some(vulns) = waf_res { result.vulnerabilities.extend(vulns); }
        if let Some(vulns) = cloud_res { result.vulnerabilities.extend(vulns); }
        if let Some(vulns) = api_fuzzer_res { result.vulnerabilities.extend(vulns); }
        if let Some(vulns) = smart_res { result.vulnerabilities.extend(vulns); }

        // ── Phase 4: Threat Intel Enrichment ─────────────────────────────
        info!("Running Threat Intel Enrichment...");
        let threat_intel = ThreatIntel::new();
        threat_intel.enrich_vulnerabilities(&mut result.vulnerabilities).await;

        // ── Phase 5: Deduplication ───────────────────────────────────────
        self.deduplicate_vulnerabilities(&mut result.vulnerabilities);

        // ── Finalize ─────────────────────────────────────────────────────
        result.summary = ScanSummary::calculate_from_vulns(&result.vulnerabilities);
        result.status  = ScanStatus::Completed;
        result.completed_at = Some(chrono::Utc::now());

        info!(
            "Scan completed. Found {} vulnerabilities (risk score: {:.1})",
            result.summary.total_vulnerabilities,
            result.summary.risk_score,
        );

        Ok(result)
    }

    /// Removes duplicate vulnerabilities reported by multiple modules
    fn deduplicate_vulnerabilities(&self, vulns: &mut Vec<Vulnerability>) {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        vulns.retain(|vuln| {
            // Create a unique signature based on title and URL
            let sig = format!("{}|{}", vuln.title, vuln.affected_url);
            if seen.contains(&sig) {
                false
            } else {
                seen.insert(sig);
                true
            }
        });
    }
}
