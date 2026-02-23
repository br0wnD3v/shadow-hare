use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects token transfer calls where the returned status/value is ignored.
pub struct UncheckedTransfer;

const TRANSFER_LIBFUNCS: &[&str] = &[
    "transfer",
    "transfer_from",
    "safe_transfer",
    "safe_transfer_from",
    "erc20_transfer",
    "erc20_transfer_from",
];

impl Detector for UncheckedTransfer {
    fn id(&self) -> &'static str {
        "unchecked_transfer"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Token transfer-style call return value appears unused; failures may be ignored silently."
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
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if !TRANSFER_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                    continue;
                }

                let produced: Vec<u64> = inv
                    .branches
                    .iter()
                    .flat_map(|b| b.results.iter().copied())
                    .collect();
                if produced.is_empty() {
                    continue;
                }

                let mut used_later = false;
                for later in stmts.iter().skip(local_idx + 1) {
                    let Some(later_inv) = later.as_invocation() else {
                        continue;
                    };
                    if later_inv.args.iter().any(|a| produced.contains(a)) {
                        used_later = true;
                        break;
                    }
                }

                if !used_later {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Unchecked token transfer return value",
                        format!(
                            "Function '{}': '{}' at stmt {} returns a status/value that is never used. \
                             Transfer failure paths may be silently ignored.",
                            func.name,
                            libfunc_name,
                            start + local_idx
                        ),
                        Location {
                            file: program.source.display().to_string(),
                            function: func.name.clone(),
                            statement_idx: Some(start + local_idx),
                            line: None,
                            col: None,
                        },
                    ));
                }
            }
        }

        (findings, warnings)
    }
}
