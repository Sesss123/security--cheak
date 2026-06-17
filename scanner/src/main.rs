use clap::{Parser, ValueEnum};
use anyhow::Result;
use tracing::info;

use scanner_lib::{
    models::scan::{ScanRequest, ScanType, ScanOptions, PortRange},
    modules::ScanOrchestrator,
    utils::init_logger,
};

#[derive(Parser, Debug)]
#[command(
    name = "security-scanner",
    about = "AI-Powered Web Application Security Scanner",
    version = "0.1.0",
    author  = "SecurityPlatform"
)]
struct Cli {
    /// Target URL to scan (e.g. https://example.com)
    #[arg(short, long)]
    target: String,

    /// Scan types to run
    #[arg(short, long, value_delimiter = ',', default_value = "all")]
    scans: Vec<ScanModule>,

    /// Requests per second limit
    #[arg(long, default_value = "10")]
    rate_limit: u32,

    /// Request timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Port scan range
    #[arg(long, default_value = "common")]
    ports: PortScanRange,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Allow invalid TLS certificates
    #[arg(long)]
    allow_invalid_certs: bool,
}

#[derive(Debug, Clone, ValueEnum, PartialEq)]
enum ScanModule {
    All,
    Ports,
    Ssl,
    Headers,
    Sqli,
    Xss,
    Cors,
    Info,
    Jwt,
    Redirect,
    Sast,
    Ssrf,
    Xxe,
    Csrf,
    Upload,
    Crawler,
    DirBruteforce,
    DomXss,
    Graphql,
    Waf,
    Cloud,
    ApiFuzzer,
    Ctf,
    Asset,
    Recon,
}

#[derive(Debug, Clone, ValueEnum)]
enum PortScanRange {
    Common,
    Extended,
    Full,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logger();

    let cli = Cli::parse();

    // Resolve scan types
    let scan_types: Vec<ScanType> = if cli.scans.contains(&ScanModule::All) {
        vec![
            ScanType::PortScan,
            ScanType::SslAnalysis,
            ScanType::HttpHeaders,
            ScanType::SecurityHeaders,
            ScanType::SqlInjection,
            ScanType::Xss,
            ScanType::CorsCheck,
            ScanType::InfoDisclosure,
            ScanType::JwtAnalysis,
            ScanType::OpenRedirect,
            ScanType::Sast,
            ScanType::Ssrf,
            ScanType::Xxe,
            ScanType::Csrf,
            ScanType::Upload,
            ScanType::Crawler,
            ScanType::DirBruteforce,
            ScanType::DomXss,
            ScanType::Graphql,
            ScanType::WafDetector,
            ScanType::CloudScanner,
            ScanType::ApiFuzzer,
            ScanType::CtfScan,
            ScanType::AssetDiscovery,
            ScanType::Recon,
        ]
    } else {
        cli.scans.iter().flat_map(|s| match s {
            ScanModule::All      => vec![],
            ScanModule::Ports    => vec![ScanType::PortScan],
            ScanModule::Ssl      => vec![ScanType::SslAnalysis],
            ScanModule::Headers  => vec![ScanType::HttpHeaders, ScanType::SecurityHeaders],
            ScanModule::Sqli     => vec![ScanType::SqlInjection],
            ScanModule::Xss      => vec![ScanType::Xss],
            ScanModule::Cors     => vec![ScanType::CorsCheck],
            ScanModule::Info     => vec![ScanType::InfoDisclosure],
            ScanModule::Jwt      => vec![ScanType::JwtAnalysis],
            ScanModule::Redirect => vec![ScanType::OpenRedirect],
            ScanModule::Sast     => vec![ScanType::Sast],
            ScanModule::Ssrf     => vec![ScanType::Ssrf],
            ScanModule::Xxe      => vec![ScanType::Xxe],
            ScanModule::Csrf     => vec![ScanType::Csrf],
            ScanModule::Upload   => vec![ScanType::Upload],
            ScanModule::Crawler  => vec![ScanType::Crawler],
            ScanModule::DirBruteforce => vec![ScanType::DirBruteforce],
            ScanModule::DomXss   => vec![ScanType::DomXss],
            ScanModule::Graphql  => vec![ScanType::Graphql],
            ScanModule::Waf      => vec![ScanType::WafDetector],
            ScanModule::Cloud    => vec![ScanType::CloudScanner],
            ScanModule::ApiFuzzer => vec![ScanType::ApiFuzzer],
            ScanModule::Ctf      => vec![ScanType::CtfScan],
            ScanModule::Asset    => vec![ScanType::AssetDiscovery],
            ScanModule::Recon    => vec![ScanType::Recon],
        }).collect()
    };

    let port_range = match cli.ports {
        PortScanRange::Common   => PortRange::Common,
        PortScanRange::Extended => PortRange::Extended,
        PortScanRange::Full     => PortRange::Full,
    };

    let request = ScanRequest {
        target_url: cli.target.clone(),
        scan_types,
        options: ScanOptions {
            rate_limit: cli.rate_limit,
            timeout_secs: cli.timeout,
            port_range,
            allow_invalid_certs: cli.allow_invalid_certs,
            ..Default::default()
        },
    };

    info!("Scanning: {}", cli.target);
    if !cli.json {
        println!("\n🔍 Security Scanner v0.1.0");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Target : {}", cli.target);
        println!("Modules: {:?}", request.scan_types.len());
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }

    let orchestrator = ScanOrchestrator::new();
    let result = orchestrator.run(request).await?;

    if cli.json {
        // JSON output for API integration
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        // Human-readable output
        print_results(&result);
    }

    Ok(())
}

fn print_results(result: &scanner_lib::models::scan::ScanResult) {
    let s = &result.summary;

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📊 SCAN COMPLETE");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Risk Score : {:.1}/10.0", s.risk_score);
    println!("Open Ports : {}", result.port_results.len());
    println!();
    println!("Vulnerabilities Found: {}", s.total_vulnerabilities);
    println!("  🔴 Critical : {}", s.critical);
    println!("  🟠 High     : {}", s.high);
    println!("  🟡 Medium   : {}", s.medium);
    println!("  🟢 Low      : {}", s.low);
    println!("  ℹ️  Info     : {}", s.info);
    println!();

    if !result.vulnerabilities.is_empty() {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("🚨 VULNERABILITIES");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        for (i, vuln) in result.vulnerabilities.iter().enumerate() {
            let icon = match vuln.severity {
                scanner_lib::models::scan::Severity::Critical => "🔴",
                scanner_lib::models::scan::Severity::High     => "🟠",
                scanner_lib::models::scan::Severity::Medium   => "🟡",
                scanner_lib::models::scan::Severity::Low      => "🟢",
                scanner_lib::models::scan::Severity::Info     => "ℹ️ ",
            };

            println!(
                "\n[{}] {} {} (CVSS: {:.1})",
                i + 1,
                icon,
                vuln.title,
                vuln.cvss_score
            );
            println!("    URL        : {}", vuln.affected_url);
            println!("    Severity   : {}", vuln.severity.as_str());
            if let Some(owasp) = &vuln.owasp_category {
                println!("    OWASP      : {}", owasp.as_str());
            }
            if let Some(cwe) = vuln.cwe_id {
                println!("    CWE        : CWE-{}", cwe);
            }
            println!("    Description: {}", &vuln.description[..vuln.description.len().min(120)]);
        }
    }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✅ Scan ID: {}", result.scan_id);
    println!("Completed: {}", result.completed_at.map(|t| t.to_string()).unwrap_or_default());
}
