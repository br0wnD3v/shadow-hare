use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects external functions that make three or more external calls AND
/// also write to storage.
///
/// High external call counts in a single state-mutating function expand the
/// reentrancy attack surface dramatically: every call is a potential
/// re-entry point, and the risk compounds with each additional call.
/// Functions with N external calls have N reentrancy windows.
///
/// This is a medium-confidence indicator. Account execute functions are
/// excluded because they are designed to dispatch multiple calls.
pub struct MultipleExternalCalls;

/// Minimum number of external calls to trigger this detector.
const CALL_THRESHOLD: usize = 3;

impl Detector for MultipleExternalCalls {
    fn id(&self) -> &'static str {
        "multiple_external_calls"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "External function makes 3 or more external calls and also writes to storage. \
         Each call is a reentrancy window; the attack surface grows with call count."
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

        for func in program.external_functions() {
            // Account execute functions are intentionally multi-call
            if func.is_account_entrypoint() {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let mut call_count = 0usize;
            let mut has_storage_write = false;
            let mut first_call_site = 0usize;

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let inv = match stmt.as_invocation() {
                    Some(inv) => inv,
                    None => continue,
                };

                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if libfunc_name.contains("call_contract_syscall")
                    || libfunc_name.contains("call_contract")
                {
                    if call_count == 0 {
                        first_call_site = start + local_idx;
                    }
                    call_count += 1;
                }

                if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                    has_storage_write = true;
                }
            }

            if call_count >= CALL_THRESHOLD && has_storage_write {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Multiple external calls with storage mutation",
                    format!(
                        "Function '{}': {} external calls detected (first at stmt {}), \
                         combined with storage writes. Each call is a reentrancy window. \
                         Consider splitting into smaller, CEI-compliant functions.",
                        func.name, call_count, first_call_site
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(first_call_site),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}
