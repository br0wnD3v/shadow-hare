use crate::analysis::reentrancy::check_reentrancy;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::components::{DetectedComponents, OzComponent};
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects the classic reentrancy pattern: storage read -> external call -> storage write.
///
/// This is a Sierra-level detector. It does NOT require source-level debug info.
/// The pattern is conservative: any external call (call_contract_syscall or
/// library_call_syscall) between a storage read and a storage write is flagged.
///
/// When the read and write target the same storage slot, the finding is reported
/// with High confidence. When slots differ (or cannot be resolved), Medium
/// confidence is used.
///
/// Per-function reentrancy guard detection: instead of globally suppressing ALL
/// findings when a guard exists anywhere in the contract, the detector checks
/// whether the specific function being analyzed calls the guard.
pub struct Reentrancy;

impl Detector for Reentrancy {
    fn id(&self) -> &'static str {
        "reentrancy"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Storage read followed by external call followed by storage write. \
         Potential reentrancy: the external contract can re-enter before the write commits."
    }

    fn requirements(&self) -> DetectorRequirements {
        DetectorRequirements {
            min_tier: CompatibilityTier::Tier3,
            requires_debug_info: false,
            source_aware: false,
        }
    }

    fn run(&self, program: &ProgramIR) -> (Vec<Finding>, Vec<AnalyzerWarning>) {
        let mut findings = Vec::new();
        let warnings = Vec::new();

        // Detect global ReentrancyGuard component.
        let oz = DetectedComponents::detect(program);
        let has_global_guard = oz.has(OzComponent::ReentrancyGuard);

        for func in program.all_functions() {
            // Only check entrypoints -- internal functions are less interesting
            // because they're typically called in a context we already analysed.
            if !func.is_entrypoint() {
                continue;
            }

            // Check if THIS function uses a reentrancy guard (not just the contract globally).
            let func_has_guard =
                has_global_guard || function_has_reentrancy_guard(program, func.idx);

            if func_has_guard {
                continue;
            }

            let evidence_list = check_reentrancy(program, func.idx);

            for evidence in evidence_list {
                let confidence = if evidence.same_slot {
                    Confidence::High
                } else {
                    Confidence::Medium
                };

                let slot_info = if evidence.same_slot {
                    " (same storage slot read and written)"
                } else {
                    ""
                };

                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    confidence,
                    "Potential reentrancy",
                    format!(
                        "Function '{}': storage read at stmt {}, external call at stmt {}, \
                         storage write at stmt {}{}. An external contract could re-enter \
                         this function before state is committed.",
                        evidence.func_name,
                        evidence.read_before_call,
                        evidence.external_call,
                        evidence.write_after_call,
                        slot_info,
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: evidence.func_name,
                        statement_idx: Some(evidence.external_call),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}

/// Check if a specific function references a reentrancy guard pattern.
///
/// This is more precise than the global check: it scans only the statements
/// belonging to the given function for guard invocations.
fn function_has_reentrancy_guard(program: &ProgramIR, func_idx: usize) -> bool {
    let (start, end) = program.function_statement_range(func_idx);
    if start >= end {
        return false;
    }
    let end = end.min(program.statements.len());

    for stmt in &program.statements[start..end] {
        if let Some(inv) = stmt.as_invocation() {
            let name = inv.libfunc_id.debug_name.as_deref().unwrap_or("");
            if name.contains("reentrancy_guard")
                || name.contains("ReentrancyGuard")
                || name.contains("nonReentrant")
                || name.contains("non_reentrant")
                || name.contains("start_reentrancy_guard")
            {
                return true;
            }
            // Also check generic_id for non-debug cases.
            let generic = program
                .libfunc_registry
                .generic_id(&inv.libfunc_id)
                .unwrap_or("");
            if generic.contains("reentrancy_guard") || generic.contains("ReentrancyGuard") {
                return true;
            }
        }
    }
    false
}
