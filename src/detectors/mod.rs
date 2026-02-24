use serde::{Deserialize, Serialize};

use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

pub mod account_execute_v0_block;
pub mod account_interface_compliance;
pub mod account_validate_syscalls;
pub mod address_cast;
pub mod array_access;
pub mod boolean_equality;
pub mod cache_array_length;
pub mod calls_loop;
pub mod costly_loop;
pub mod deploy_tainted_class_hash;
pub mod erc20_interface;
pub mod erc721_interface;
pub mod events;
pub mod events_access_control;
pub mod events_arithmetic;
pub mod felt252_overflow;
pub mod hardcoded;
pub mod initializer_replay;
pub mod integer_overflow;
pub mod l1_amount;
pub mod l1_handler;
pub mod l1_message;
pub mod l1_selector;
pub mod l1_storage;
pub mod l2l1_amount;
pub mod l2l1_dest;
pub mod l2l1_double;
pub mod library_call;
pub mod multi_call;
pub mod nonce;
pub mod oracle;
pub mod precision;
pub mod pyth;
pub mod reentrancy;
pub mod reentrancy_events;
pub mod rtlo;
pub mod shadowing_builtin;
pub mod shadowing_local;
pub mod shadowing_state;
pub mod signature_replay;
pub mod storage_access;
pub mod tautology;
pub mod tautology_condition;
pub mod timestamp;
pub mod token_transfer;
pub mod truncation;
pub mod tx_origin;
pub mod u256_underflow;
pub mod unchecked_transfer;
pub mod unchecked_write;
pub mod unindexed_event;
pub mod unused;
pub mod unused_state;
pub mod upgrade;
pub mod view_state_modification;
pub mod weak_prng;
pub mod write_after_write;
pub mod zero_address;

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
                Box::new(deploy_tainted_class_hash::DeploySyscallTaintedClassHash),
                Box::new(upgrade::UnprotectedUpgrade),
                Box::new(account_interface_compliance::AccountInterfaceCompliance),
                Box::new(account_validate_syscalls::AccountValidateForbiddenSyscalls),
                Box::new(account_execute_v0_block::AccountExecuteMissingV0Block),
                Box::new(initializer_replay::InitializerReplayOrMissingGuard),
                Box::new(integer_overflow::UncheckedIntegerOverflow),
                Box::new(truncation::IntegerTruncation),
                Box::new(address_cast::UncheckedAddressCast),
                Box::new(array_access::UncheckedArrayAccess),
                Box::new(oracle::OraclePriceManipulation),
                Box::new(nonce::MissingNonceValidation),
                Box::new(signature_replay::SignatureReplay),
                Box::new(token_transfer::ArbitraryTokenTransfer),
                Box::new(unchecked_write::WriteWithoutCallerCheck),
                Box::new(unchecked_transfer::UncheckedTransfer),
                Box::new(rtlo::Rtlo),
                // L1<->L2 messaging — High
                Box::new(l2l1_dest::L2ToL1TaintedDestination),
                Box::new(l1_amount::L1HandlerUncheckedAmount),
                Box::new(l1_storage::L1HandlerPayloadToStorage),
                Box::new(l1_selector::L1HandlerUncheckedSelector),
                Box::new(l2l1_amount::L2ToL1UnverifiedAmount),
                // Medium severity
                Box::new(tx_origin::TxOriginAuth),
                Box::new(precision::DivideBeforeMultiply),
                Box::new(storage_access::TaintedStorageKey),
                Box::new(hardcoded::HardcodedAddress),
                Box::new(timestamp::BlockTimestampDependence),
                Box::new(weak_prng::WeakPrng),
                Box::new(pyth::PythUncheckedConfidence),
                Box::new(pyth::PythUncheckedPublishtime),
                Box::new(pyth::PythDeprecatedFunction),
                Box::new(tautology::TautologicalCompare),
                Box::new(tautology_condition::TautologyCondition),
                Box::new(multi_call::MultipleExternalCalls),
                Box::new(l1_message::UncheckedL1Message),
                Box::new(view_state_modification::ViewStateModification),
                Box::new(erc20_interface::IncorrectErc20Interface),
                Box::new(erc721_interface::IncorrectErc721Interface),
                // L1<->L2 messaging — Medium
                Box::new(l2l1_double::L2ToL1DoubleSend),
                // Low severity
                Box::new(calls_loop::CallsLoop),
                Box::new(write_after_write::WriteAfterWrite),
                Box::new(reentrancy_events::ReentrancyEvents),
                Box::new(unused::UnusedReturn),
                Box::new(events::MissingEventEmission),
                Box::new(events_access_control::MissingEventsAccessControl),
                Box::new(events_arithmetic::MissingEventsArithmetic),
                Box::new(zero_address::MissingZeroAddressCheck),
                Box::new(shadowing_builtin::ShadowingBuiltin),
                Box::new(shadowing_local::ShadowingLocal),
                Box::new(shadowing_state::ShadowingState),
                // Info
                Box::new(boolean_equality::BooleanEquality),
                Box::new(costly_loop::CostlyLoop),
                Box::new(cache_array_length::CacheArrayLength),
                Box::new(unindexed_event::UnindexedEvent),
                Box::new(unused_state::UnusedState),
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
            .map(|d| {
                let reqs = d.requirements();
                // Skip if tier is below minimum.
                if program.compatibility < reqs.min_tier {
                    return (
                        Vec::new(),
                        vec![AnalyzerWarning::detector_skipped(
                            d.id(),
                            &format!(
                                "requires min compatibility {}, got {}",
                                reqs.min_tier, program.compatibility
                            ),
                        )],
                    );
                }

                // Enforce debug-info requirement globally.
                if reqs.requires_debug_info && !program.has_debug_info {
                    return (
                        Vec::new(),
                        vec![AnalyzerWarning::missing_debug_info(d.id())],
                    );
                }

                // Skip source-aware detectors if no debug info.
                if reqs.source_aware && !program.has_debug_info {
                    return (
                        Vec::new(),
                        vec![AnalyzerWarning::detector_skipped(
                            d.id(),
                            "source-aware detector requires debug info",
                        )],
                    );
                }

                d.run(program)
            })
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

    pub fn iter(&self) -> impl Iterator<Item = &dyn Detector> {
        self.detectors.iter().map(|d| d.as_ref())
    }
}

fn is_suppressed(finding: &Finding, suppressions: &[crate::config::Suppression]) -> bool {
    suppressions.iter().any(|s| {
        s.detector_id == finding.detector_id
            && match &s.location_hash {
                None => true, // suppress all findings from this detector
                Some(h) => finding.fingerprint.as_deref() == Some(h.as_str()),
            }
    })
}
