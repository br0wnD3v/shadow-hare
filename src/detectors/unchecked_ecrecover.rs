use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects ECDSA signature verification calls without checking the return value.
///
/// `ecdsa_recover` and `verify_ecdsa_signature` return a result that must be
/// checked. Ignoring the return value means invalid signatures are accepted.
pub struct UncheckedEcrecover;

const ECDSA_LIBFUNCS: &[&str] = &[
    "ecdsa_recover",
    "verify_ecdsa_signature",
    "check_ecdsa_signature",
    "secp256k1",
    "secp256r1",
];

impl Detector for UncheckedEcrecover {
    fn id(&self) -> &'static str {
        "unchecked_ecrecover"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "ECDSA verification result is not checked. Invalid signatures may be \
         accepted, bypassing authentication."
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
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if !ECDSA_LIBFUNCS.iter().any(|k| name.contains(k)) {
                    continue;
                }

                // Check if result is used: look at result variables and see if
                // they appear in any subsequent statement's args.
                let result_vars: Vec<u64> = inv
                    .branches
                    .iter()
                    .flat_map(|b| b.results.iter().copied())
                    .collect();

                if result_vars.is_empty() {
                    continue;
                }

                // Scan forward for any use of the result variables.
                let remaining = &stmts[local_idx + 1..];
                let result_used = remaining.iter().any(|s| {
                    s.as_invocation()
                        .map(|inv2| inv2.args.iter().any(|a| result_vars.contains(a)))
                        .unwrap_or(false)
                });

                if !result_used {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "ECDSA verification result unchecked",
                        format!(
                            "Function '{}': '{}' at stmt {} — result is not used. \
                             Invalid signatures may be silently accepted.",
                            func.name,
                            name,
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
