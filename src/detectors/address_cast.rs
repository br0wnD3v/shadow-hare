use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects fallible address/hash casts where the failure branch is not
/// handled.
///
/// `contract_address_try_from_felt252` and `class_hash_try_from_felt252`
/// are fallible operations: they produce two branches (success / failure).
/// If the Sierra statement has only one branch (Fallthrough), the invalid-
/// input case is silently ignored and the function continues with an
/// uninitialized or zero-value address.
///
/// Attackers can supply `felt252` values that are not valid contract addresses
/// or class hashes, causing the contract to operate on garbage data.
pub struct UncheckedAddressCast;

const TRY_CAST_LIBFUNCS: &[&str] = &[
    "contract_address_try_from_felt252",
    "class_hash_try_from_felt252",
    "storage_address_try_from_felt252",
];

impl Detector for UncheckedAddressCast {
    fn id(&self) -> &'static str {
        "unchecked_address_cast"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "Fallible address or class-hash cast with only one branch — the invalid-input \
         case is not handled. An attacker-supplied value that fails validation will \
         produce a zero or garbage address."
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
                let inv = match stmt.as_invocation() {
                    Some(inv) => inv,
                    None => continue,
                };

                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                let is_try_cast =
                    TRY_CAST_LIBFUNCS.iter().any(|p| libfunc_name.contains(p));

                if is_try_cast && inv.branches.len() == 1 {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Unchecked fallible address cast",
                        format!(
                            "Function '{}': '{}' at stmt {} has only 1 branch — the \
                             invalid-address failure case is not handled. Supply of an \
                             invalid felt252 will silently produce a zero address.",
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
