use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects `__execute__` functions that do not increment a nonce (no
/// storage_write_syscall in the function body).
///
/// Account contracts must increment a nonce after each successful execution
/// to prevent replay attacks. If the nonce is not written, the same
/// transaction can be replayed indefinitely.
///
/// This detector targets functions whose debug name contains `__execute__`.
/// False positives are possible for contracts that manage nonces in a helper
/// function rather than inline — suppress per location if confirmed safe.
pub struct MissingNonceValidation;

impl Detector for MissingNonceValidation {
    fn id(&self) -> &'static str {
        "missing_nonce_validation"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "__execute__ function has no storage write — nonce is not incremented. \
         Transactions can be replayed indefinitely against this account."
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

        for func in program.all_functions() {
            // Only flag __execute__ entry points
            if !func.name.contains("__execute__") && !func.name.ends_with("__execute") {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let has_storage_write = stmts.iter().any(|stmt| {
                stmt.as_invocation()
                    .map(|inv| program.libfunc_registry.is_storage_write(&inv.libfunc_id))
                    .unwrap_or(false)
            });

            if !has_storage_write {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Missing nonce increment in __execute__",
                    format!(
                        "Function '{}' is an execute entrypoint but contains no \
                         storage_write_syscall. The nonce is not incremented, allowing \
                         transaction replay attacks.",
                        func.name
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(start),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}
