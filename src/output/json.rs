use serde::{Deserialize, Serialize};

use crate::detectors::Finding;
use crate::error::AnalyzerWarning;

/// Versioned JSON report schema.
/// Schema version is bumped on any breaking change.
pub const SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonReport {
    /// Schema version for backward compatibility.
    pub schema_version: String,
    /// ISO 8601 timestamp of when the analysis ran.
    pub generated_at: String,
    /// Analyzer version.
    pub analyzer_version: String,
    /// Source artifact(s) that were analysed.
    pub sources: Vec<String>,
    /// All findings.
    pub findings: Vec<Finding>,
    /// Non-fatal analysis warnings.
    pub warnings: Vec<JsonWarning>,
    /// Summary statistics.
    pub summary: Summary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonWarning {
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Summary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl JsonReport {
    pub fn build(
        findings: &[Finding],
        warnings: &[AnalyzerWarning],
        sources: Vec<String>,
    ) -> Self {
        use crate::detectors::Severity;

        let summary = Summary {
            total: findings.len(),
            critical: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
            high: findings.iter().filter(|f| f.severity == Severity::High).count(),
            medium: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
            low: findings.iter().filter(|f| f.severity == Severity::Low).count(),
            info: findings.iter().filter(|f| f.severity == Severity::Info).count(),
        };

        let json_warnings = warnings
            .iter()
            .map(|w| JsonWarning {
                kind: format!("{:?}", w.kind),
                message: w.message.clone(),
            })
            .collect();

        let generated_at = chrono_now();

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            generated_at,
            analyzer_version: env!("CARGO_PKG_VERSION").to_string(),
            sources,
            findings: findings.to_vec(),
            warnings: json_warnings,
            summary,
        }
    }

    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

fn chrono_now() -> String {
    // Use UNIX timestamp since we don't depend on chrono
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{secs}")
}
