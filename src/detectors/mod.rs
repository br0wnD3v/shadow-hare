use serde::{Deserialize, Serialize};

use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

pub mod events;
pub mod felt252_overflow;
pub mod integer_overflow;
pub mod l1_handler;
pub mod library_call;
pub mod precision;
pub mod reentrancy;
pub mod storage_access;
pub mod tx_origin;
pub mod u256_underflow;
pub mod unused;
pub mod upgrade;

// ── Finding model ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

/// A single finding produced by a detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique detector identifier (e.g. "u256_underflow").
    pub detector_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Human-readable title.
    pub title: String,
    /// Detailed description of the finding.
    pub description: String,
    /// Location information (function name, statement index, etc.).
    pub location: Location,
    /// SHA-256 fingerprint for baseline deduplication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// Source file (artifact path).
    pub file: String,
    /// Function name.
    pub function: String,
    /// Statement index in the Sierra program.
    pub statement_idx: Option<usize>,
    /// Source line (if debug info available).
    pub line: Option<u32>,
    /// Source column (if debug info available).
    pub col: Option<u32>,
}

impl Finding {
    pub fn new(
        detector_id: &str,
        severity: Severity,
        confidence: Confidence,
        title: &str,
        description: String,
        location: Location,
    ) -> Self {
        let fingerprint = compute_fingerprint(detector_id, &location);
        Self {
            detector_id: detector_id.to_string(),
            severity,
            confidence,
            title: title.to_string(),
            description,
            location,
            fingerprint: Some(fingerprint),
        }
    }
}

fn compute_fingerprint(detector_id: &str, loc: &Location) -> String {
    use sha2::{Digest, Sha256};
    let input = format!(
        "{detector_id}:{}:{}:{}",
        loc.function,
        loc.statement_idx.unwrap_or(0),
        loc.file
    );
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(&hash[..8])
}

// ── Detector trait ───────────────────────────────────────────────────────────

/// Requirements for a detector to run.
#[derive(Debug, Clone)]
pub struct DetectorRequirements {
    /// Minimum compatibility tier.
    pub min_tier: CompatibilityTier,
    /// Requires cairo-annotations debug info to be useful.
    pub requires_debug_info: bool,
    /// Whether this is a source-aware detector (skips without debug info).
    pub source_aware: bool,
}

impl Default for DetectorRequirements {
    fn default() -> Self {
        Self {
            min_tier: CompatibilityTier::Tier3,
            requires_debug_info: false,
            source_aware: false,
        }
    }
}

/// The detector trait. All detectors implement this.
pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn confidence(&self) -> Confidence;
    fn description(&self) -> &'static str;
    fn requirements(&self) -> DetectorRequirements;

    /// Run the detector against the program IR.
    /// Returns (findings, warnings).
    fn run(&self, program: &ProgramIR) -> (Vec<Finding>, Vec<AnalyzerWarning>);
}

// ── DetectorRegistry ─────────────────────────────────────────────────────────

pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    /// Build with all built-in detectors in deterministic order.
    pub fn all() -> Self {
        Self {
            detectors: vec![
                // High severity
                Box::new(u256_underflow::U256Underflow),
                Box::new(l1_handler::UncheckedL1Handler),
                Box::new(reentrancy::Reentrancy),
                Box::new(felt252_overflow::Felt252Overflow),
                Box::new(library_call::ControlledLibraryCall),
                Box::new(upgrade::UnprotectedUpgrade),
                Box::new(integer_overflow::UncheckedIntegerOverflow),
                // Medium severity
                Box::new(tx_origin::TxOriginAuth),
                Box::new(precision::DivideBeforeMultiply),
                Box::new(storage_access::TaintedStorageKey),
                // Low severity
                Box::new(unused::UnusedReturn),
                Box::new(events::MissingEventEmission),
                // Info
                Box::new(unused::DeadCode),
            ],
        }
    }

    pub fn run_all(
        &self,
        program: &ProgramIR,
        config: &crate::config::AnalyzerConfig,
    ) -> (Vec<Finding>, Vec<AnalyzerWarning>) {
        use rayon::prelude::*;

        let results: Vec<(Vec<Finding>, Vec<AnalyzerWarning>)> = self
            .detectors
            .par_iter()
            .filter(|d| config.detectors.should_run(d.id()))
            .filter(|d| {
                let reqs = d.requirements();
                // Skip if tier is below minimum
                if program.compatibility < reqs.min_tier {
                    return false;
                }
                // Skip source-aware detectors if no debug info
                if reqs.source_aware && !program.has_debug_info {
                    return false;
                }
                true
            })
            .map(|d| d.run(program))
            .collect();

        let mut all_findings = Vec::new();
        let mut all_warnings = Vec::new();

        for (mut findings, warnings) in results {
            // Apply suppressions
            findings.retain(|f| !is_suppressed(f, &config.suppressions));
            // Apply severity threshold
            findings.retain(|f| f.severity >= config.min_severity);

            all_findings.extend(findings);
            all_warnings.extend(warnings);
        }

        // Sort deterministically: severity desc, then detector_id, then fingerprint
        all_findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(a.detector_id.cmp(&b.detector_id))
                .then(a.fingerprint.cmp(&b.fingerprint))
        });

        (all_findings, all_warnings)
    }
}

fn is_suppressed(
    finding: &Finding,
    suppressions: &[crate::config::Suppression],
) -> bool {
    suppressions.iter().any(|s| {
        s.detector_id == finding.detector_id
            && match &s.location_hash {
                None => true, // suppress all findings from this detector
                Some(h) => finding.fingerprint.as_deref() == Some(h.as_str()),
            }
    })
}
