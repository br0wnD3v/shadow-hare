use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::components::{DetectedComponents, OzComponent};
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects protocol contracts that have external state-modifying functions
/// but no observable pause mechanism.
///
/// Pausable functionality is a safety net for DeFi contracts, allowing
/// operators to halt operations during exploits or emergencies.
pub struct MissingPausable;

const PAUSE_KEYWORDS: &[&str] = &[
    "pause",
    "unpause",
    "is_paused",
    "paused",
    "Pausable",
    "when_not_paused",
    "assert_not_paused",
    "emergency_stop",
    "freeze",
    "frozen",
    "circuit_breaker",
];

impl Detector for MissingPausable {
    fn id(&self) -> &'static str {
        "missing_pausable"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Contract has state-modifying external functions but no observable pause \
         mechanism. Pausability is recommended for DeFi contracts to halt \
         operations during exploits."
    }

    fn requirements(&self) -> DetectorRequirements {
        DetectorRequirements {
            min_tier: CompatibilityTier::Tier3,
            requires_debug_info: true,
            source_aware: false,
        }
    }

    fn run(&self, program: &ProgramIR) -> (Vec<Finding>, Vec<AnalyzerWarning>) {
        let mut findings = Vec::new();
        let warnings = Vec::new();

        // Check if any function name or libfunc references pause keywords.
        let has_pause_mechanism = program
            .all_functions()
            .any(|f| PAUSE_KEYWORDS.iter().any(|k| f.name.contains(k)));

        if has_pause_mechanism {
            return (findings, warnings);
        }

        // OZ Pausable component detected via component awareness.
        let oz = DetectedComponents::detect(program);
        if oz.has(OzComponent::Pausable) {
            return (findings, warnings);
        }

        // Account contracts don't need pause mechanisms — they're user wallets.
        let is_account = program.all_functions().any(|f| {
            f.name.contains("__execute__") || f.name.contains("__validate__")
        });
        if is_account {
            return (findings, warnings);
        }

        // Also check if any libfunc debug_name references pause keywords.
        // For function_call libfuncs, generic_id is just "function_call",
        // so we check the debug_name which contains the callee:
        //   "function_call<user@module::PausableImpl::assert_not_paused>"
        let has_pause_libfunc = program.statements.iter().any(|stmt| {
            stmt.as_invocation()
                .map(|inv| {
                    // Check debug_name first (more informative for function_call).
                    let debug = inv.libfunc_id.debug_name.as_deref().unwrap_or("");
                    if PAUSE_KEYWORDS.iter().any(|k| debug.contains(k)) {
                        return true;
                    }
                    // Also check generic_id for non-function_call libfuncs.
                    let generic = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .unwrap_or("");
                    PAUSE_KEYWORDS.iter().any(|k| generic.contains(k))
                })
                .unwrap_or(false)
        });

        if has_pause_libfunc {
            return (findings, warnings);
        }

        // Count state-modifying external functions.
        let state_modifying_count = program
            .external_functions()
            .filter(|func| {
                let (start, end) = program.function_statement_range(func.idx);
                if start >= end {
                    return false;
                }
                program.statements[start..end.min(program.statements.len())]
                    .iter()
                    .any(|stmt| {
                        stmt.as_invocation()
                            .map(|inv| program.libfunc_registry.is_storage_write(&inv.libfunc_id))
                            .unwrap_or(false)
                    })
            })
            .count();

        // Only flag if there are multiple state-modifying externals (likely DeFi).
        if state_modifying_count >= 5 {
            findings.push(Finding::new(
                self.id(),
                self.severity(),
                self.confidence(),
                "No pause mechanism found",
                format!(
                    "Contract has {state_modifying_count} state-modifying external functions \
                     but no observable pause mechanism. Consider adding Pausable for \
                     emergency response."
                ),
                Location {
                    file: program.source.display().to_string(),
                    function: String::new(),
                    statement_idx: None,
                    line: None,
                    col: None,
                },
            ));
        }

        (findings, warnings)
    }
}
