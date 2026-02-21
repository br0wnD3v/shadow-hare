use crate::analysis::reentrancy::check_reentrancy;
use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects the classic reentrancy pattern: storage read → external call → storage write.
///
/// This is a Sierra-level detector. It does NOT require source-level debug info.
/// The pattern is conservative: any external call (call_contract_syscall or
/// library_call_syscall) between a storage read and a storage write is flagged.
///
/// False positives are possible in functions where the write is intentional
/// after the call. Suppress specific locations in Scarb.toml if confirmed safe.
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

        for func in program.all_functions() {
            // Only check entrypoints — internal functions are less interesting
            // because they're typically called in a context we already analysed.
            if !func.is_entrypoint() {
                continue;
            }

            let evidence_list = check_reentrancy(program, func.idx);

            for evidence in evidence_list {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Potential reentrancy",
                    format!(
                        "Function '{}': storage read at stmt {}, external call at stmt {}, \
                         storage write at stmt {}. An external contract could re-enter \
                         this function before state is committed.",
                        evidence.func_name,
                        evidence.read_before_call,
                        evidence.external_call,
                        evidence.write_after_call,
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
