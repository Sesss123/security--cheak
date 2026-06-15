use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use super::scan::ScanSummary;
use super::vulnerability::Vulnerability;

/// Full AI-enhanced security report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub title: String,
    pub target: String,
    pub generated_at: DateTime<Utc>,
    pub executive_summary: String,      // AI generated
    pub risk_rating: RiskRating,
    pub scan_summary: ScanSummary,
    pub vulnerabilities: Vec<EnrichedVulnerability>,
    pub recommendations: Vec<Recommendation>,
    pub methodology: String,
    pub disclaimer: String,
}

/// Vulnerability enriched with AI analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedVulnerability {
    pub vulnerability: Vulnerability,
    pub ai_explanation: String,         // Claude AI explanation
    pub business_impact: String,        // Claude AI business impact
    pub remediation_steps: Vec<String>, // Claude AI step-by-step fix
    pub code_example: Option<String>,   // Fix code example
    pub priority: u8,                   // 1-10 fix priority
}

/// Remediation recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub title: String,
    pub description: String,
    pub priority: RecommendationPriority,
    pub effort: Effort,
    pub impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationPriority {
    Immediate,   // Fix within 24 hours
    Short,       // Fix within 1 week
    Medium,      // Fix within 1 month
    Long,        // Fix within 3 months
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Effort {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskRating {
    Critical,
    High,
    Medium,
    Low,
    Minimal,
}

impl RiskRating {
    pub fn from_score(score: f32) -> Self {
        match score as u8 {
            8..=10 => RiskRating::Critical,
            6..=7  => RiskRating::High,
            4..=5  => RiskRating::Medium,
            1..=3  => RiskRating::Low,
            _      => RiskRating::Minimal,
        }
    }
}
