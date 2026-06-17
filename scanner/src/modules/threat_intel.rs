use tracing::info;
use crate::models::vulnerability::Vulnerability;

/// [FIX #38] Removed the debug string leak.
/// Previous code appended "[LOCAL TAG] Secret detected. Awaiting backend Threat Intel
/// correlation." to vulnerability descriptions — an internal implementation detail
/// that was visible to end users in the dashboard.
///
/// The Rust scanner delegates all threat correlation to the NestJS API backend.
/// This module is intentionally a no-op stub with a clear log message.
pub struct ThreatIntel;

impl ThreatIntel {
    pub fn new() -> Self {
        Self
    }

    /// Threat intel enrichment is handled by the NestJS API's ThreatIntelService.
    /// The Rust scanner focuses on detection; correlation happens post-scan in the backend.
    pub async fn enrich_vulnerabilities(&self, vulns: &mut Vec<Vulnerability>) {
        info!(
            "Threat Intel enrichment delegated to NestJS backend for {} vulnerabilities.",
            vulns.len()
        );
        // No local processing — do NOT modify vulnerability descriptions here.
        // The NestJS ResultAggregatorProcessor calls ThreatIntelService.enrichVulnerability()
        // for each finding after the scanner exits.
    }
}
