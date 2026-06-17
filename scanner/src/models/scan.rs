use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use super::vulnerability::Vulnerability;

/// Scan request from the API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub target_url: String,
    pub scan_types: Vec<ScanType>,
    pub options: ScanOptions,
}

/// Types of scans to perform
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    PortScan,
    SslAnalysis,
    HttpHeaders,
    DirectoryEnum,
    SqlInjection,
    Xss,
    CorsCheck,
    SecurityHeaders,
    JwtAnalysis,
    ApiSecurity,
    InfoDisclosure,
    OpenRedirect,
    CtfScan,
    Sast,
    Ssrf,
    Xxe,
    Csrf,
    Upload,
    Crawler,
    DirBruteforce,
    DomXss,
    Graphql,
    WafDetector,
    CloudScanner,
    ApiFuzzer,
    AssetDiscovery,
    Recon,
}

/// Options to control scan behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Max requests per second (rate limiting)
    pub rate_limit: u32,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Follow redirects
    pub follow_redirects: bool,
    /// Custom headers to send
    pub custom_headers: Vec<(String, String)>,
    /// Max depth for directory enumeration
    pub max_depth: u32,
    /// Port range to scan
    pub port_range: PortRange,
    /// Allow invalid TLS certificates
    pub allow_invalid_certs: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            rate_limit: 10,
            timeout_secs: 30,
            follow_redirects: true,
            custom_headers: vec![],
            max_depth: 3,
            port_range: PortRange::Common,
            allow_invalid_certs: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortRange {
    Common,           // Top 100 ports
    Extended,         // Top 1000 ports
    Full,             // All 65535 ports
    Custom(Vec<u16>), // Specific ports
}

/// Full scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: Uuid,
    pub target_url: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: ScanStatus,
    pub port_results: Vec<PortResult>,
    pub ssl_result: Option<SslResult>,
    pub header_result: Option<HeaderResult>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub summary: ScanSummary,
    pub discovered_assets: Option<Vec<crate::modules::asset_discovery::DiscoveredAsset>>,
    pub recon_data: Option<crate::modules::recon_engine::ReconData>,
}

impl ScanResult {
    pub fn new(target_url: String) -> Self {
        Self {
            scan_id: Uuid::new_v4(),
            target_url,
            started_at: Utc::now(),
            completed_at: None,
            status: ScanStatus::Running,
            port_results: vec![],
            ssl_result: None,
            header_result: None,
            vulnerabilities: vec![],
            summary: ScanSummary::default(),
            discovered_assets: None,
            recon_data: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed(String),
}

/// Open port information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// SSL/TLS analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslResult {
    pub valid: bool,
    pub issuer: String,
    pub subject: String,
    pub valid_from: String,
    pub valid_until: String,
    pub days_until_expiry: i64,
    pub protocol_version: String,
    pub cipher_suite: String,
    pub weak_ciphers: Vec<String>,
    pub certificate_chain: Vec<String>,
    pub hsts_enabled: bool,
    pub issues: Vec<SslIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslIssue {
    pub severity: Severity,
    pub description: String,
}

/// HTTP Security Headers analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderResult {
    pub headers_found: Vec<SecurityHeader>,
    pub headers_missing: Vec<MissingHeader>,
    pub dangerous_headers: Vec<DangerousHeader>,
    pub server_info: Option<String>,
    pub x_powered_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeader {
    pub name: String,
    pub value: String,
    pub is_properly_configured: bool,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingHeader {
    pub name: String,
    pub severity: Severity,
    pub description: String,
    pub recommended_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousHeader {
    pub name: String,
    pub value: String,
    pub reason: String,
}

/// Severity levels (maps to CVSS)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn cvss_score(&self) -> f32 {
        match self {
            Severity::Info => 0.0,
            Severity::Low => 3.9,
            Severity::Medium => 6.9,
            Severity::High => 8.9,
            Severity::Critical => 10.0,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// Overall scan summary
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanSummary {
    pub total_vulnerabilities: u32,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
    pub risk_score: f32,    // 0.0 - 10.0
    pub open_ports: u32,
    pub ssl_issues: u32,
}

impl ScanSummary {
    pub fn calculate_from_vulns(vulns: &[Vulnerability]) -> Self {
        let mut summary = ScanSummary::default();
        summary.total_vulnerabilities = vulns.len() as u32;

        for vuln in vulns {
            match vuln.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High     => summary.high += 1,
                Severity::Medium   => summary.medium += 1,
                Severity::Low      => summary.low += 1,
                Severity::Info     => summary.info += 1,
            }
        }

        // Risk score: weighted average
        summary.risk_score = if summary.total_vulnerabilities > 0 {
            (summary.critical as f32 * 10.0
                + summary.high as f32 * 7.5
                + summary.medium as f32 * 5.0
                + summary.low as f32 * 2.5)
                / summary.total_vulnerabilities as f32
        } else {
            0.0
        };

        summary
    }
}
