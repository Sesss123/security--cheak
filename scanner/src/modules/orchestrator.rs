use std::net::ToSocketAddrs;
use anyhow::{Result, Context};
use tracing::{info, error};
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
        let is_url = request.target_url.starts_with("http://") || request.target_url.starts_with("https://");
        let mut target_ip = None;
        let mut url_scheme = String::new();

        if is_url {
            let url = Url::parse(&request.target_url)
                .context("Invalid target URL")?;

            url_scheme = url.scheme().to_string();
            let host = url.host_str()
                .context("Could not extract host from URL")?
                .to_string();

            // Resolve hostname to IP
            target_ip = format!("{}:80", host)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|addr| addr.ip());
        }

        let mut result = ScanResult::new(request.target_url.clone());

        // ── Phase 1: Port Scan ────────────────────────────────────────────
        if request.scan_types.contains(&ScanType::PortScan) {
            if let Some(ip) = target_ip {
                info!("Running port scan...");
                let port_scanner = PortScanner::new(ip, request.options.timeout_secs * 1000);

            match port_scanner.scan(&request.options.port_range).await {
                Ok(ports) => {
                    // Flag dangerous open ports as vulnerabilities
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
                Err(e) => error!("Port scan failed: {}", e),
            }
        }
        }

        // ── Phase 2: SSL/TLS Analysis ─────────────────────────────────────
        if request.scan_types.contains(&ScanType::SslAnalysis)
            && url_scheme == "https"
        {
            info!("Running SSL analysis...");
            let ssl_analyzer = SslAnalyzer::new();

            match ssl_analyzer.analyze(&request.target_url).await {
                Ok(ssl_result) => {
                    // Convert SSL issues to vulnerabilities
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
                Err(e) => error!("SSL analysis failed: {}", e),
            }
        }

        // ── Phase 3: HTTP Header Analysis ────────────────────────────────
        if (request.scan_types.contains(&ScanType::SecurityHeaders)
            || request.scan_types.contains(&ScanType::HttpHeaders)) && is_url
        {
            info!("Analyzing security headers...");
            let header_analyzer = HeaderAnalyzer::new();

            match header_analyzer.analyze(&request.target_url).await {
                Ok(header_result) => {
                    // Missing headers → vulnerabilities
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
                                format!(
                                    "Add header: {} = {}",
                                    missing.name, missing.recommended_value
                                )
                            )
                            .with_owasp(OwaspCategory::A05SecurityMisconfiguration)
                        );
                    }
                    result.header_result = Some(header_result);
                }
                Err(e) => error!("Header analysis failed: {}", e),
            }
        }

        // ── Phase 4: CORS Analysis ───────────────────────────────────────
        if request.scan_types.contains(&ScanType::CorsCheck) && is_url {
            info!("Checking CORS configuration...");
            let cors_issues = analyze_cors(&request.target_url).await;

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

        // ── Phase 5: Vulnerability Detection ────────────────────────────
        let vuln_checks: Vec<ScanType> = vec![
            ScanType::SqlInjection,
            ScanType::Xss,
            ScanType::ApiSecurity,
            ScanType::InfoDisclosure,
        ];

        let needs_vuln_scan = vuln_checks.iter()
            .any(|t| request.scan_types.contains(t));

        if needs_vuln_scan && is_url {
            info!("Running vulnerability detection...");
            let vuln_detector = VulnDetector::new(request.target_url.clone());
            let detected = vuln_detector.detect_all().await;
            result.vulnerabilities.extend(detected);
        }

        // ── Phase 6: CTF Analysis ────────────────────────────────────────
        if request.scan_types.contains(&ScanType::CtfScan) && is_url {
            info!("Running CTF analysis...");
            let ctf_scanner = CtfScanner::new(request.target_url.clone());
            let ctf_findings = ctf_scanner.scan_all().await;
            
            for finding in ctf_findings {
                result.vulnerabilities.push(
                    Vulnerability::new(
                        finding.title,
                        finding.description,
                        if finding.priority > 8 { Severity::High } else if finding.priority > 5 { Severity::Medium } else { Severity::Low },
                        VulnCategory::InformationDisclosure, // Or a custom CTF category if defined
                        finding.url,
                    )
                    .with_remediation(finding.hint)
                );
            }
        }

        // ── Phase 7: SAST Analysis ───────────────────────────────────────
        if request.scan_types.contains(&ScanType::Sast) {
            info!("Running SAST analysis...");
            let sast_analyzer = SastAnalyzer::new(request.target_url.clone());
            let sast_findings = sast_analyzer.analyze().await;
            result.vulnerabilities.extend(sast_findings);
        }

        // ── Phase 8: Threat Intel Enrichment ─────────────────────────────
        info!("Running Threat Intel Enrichment...");
        let threat_intel = ThreatIntel::new();
        threat_intel.enrich_vulnerabilities(&mut result.vulnerabilities).await;

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
}
