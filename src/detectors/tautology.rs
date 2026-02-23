use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects tautological comparisons where the same value is compared to itself.
///
/// Examples:
/// - `assert_eq(x, x)` is always true and likely dead logic.
/// - `assert_ne(x, x)` is always false and always reverts.
pub struct TautologicalCompare;

const COMPARISON_LIBFUNCS: &[&str] = &[
    "assert_eq",
    "assert_ne",
    "felt252_eq",
    "u8_eq",
    "u16_eq",
    "u32_eq",
    "u64_eq",
    "u128_eq",
    "u256_eq",
    "contract_address_eq",
];

impl Detector for TautologicalCompare {
    fn id(&self) -> &'static str {
        "tautological_compare"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "A value is compared to itself (always true/false), indicating dead or broken guard logic."
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

            for (local_idx, stmt) in program.statements[start..end.min(program.statements.len())]
                .iter()
                .enumerate()
            {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                if inv.args.len() < 2 {
                    continue;
                }

                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if !COMPARISON_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                    continue;
                }

                if inv.args[0] != inv.args[1] {
                    continue;
                }

                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Tautological self-comparison",
                    format!(
                        "Function '{}': '{}' at stmt {} compares the same value on both sides. \
                         This condition is constant and may hide broken authorization or validation logic.",
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

        (findings, warnings)
    }
}
