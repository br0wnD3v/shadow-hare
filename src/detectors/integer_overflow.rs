use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects integer overflow/underflow on bounded integer types (u128, u64, u32,
/// u16, u8) where the overflow branch is never handled.
///
/// In Sierra, `u128_overflowing_add` and similar libfuncs produce two branches:
///   Branch 0 (Fallthrough): success — result value
///   Branch 1 (Statement N): overflow — wraps or truncates
///
/// If only one branch is present the overflow case is silently dropped.
/// This is the same detection strategy as `u256_underflow` extended to all
/// fixed-width integer types.
pub struct UncheckedIntegerOverflow;

/// Libfunc patterns that can silently overflow/underflow on bounded integers.
const OVERFLOW_LIBFUNCS: &[&str] = &[
    "u128_overflowing_add",
    "u128_overflowing_sub",
    "u64_overflowing_add",
    "u64_overflowing_sub",
    "u32_overflowing_add",
    "u32_overflowing_sub",
    "u16_overflowing_add",
    "u16_overflowing_sub",
    "u8_overflowing_add",
    "u8_overflowing_sub",
    // Multiplication overflow variants
    "u128_mul_guarantee_verify",
    "u64_overflowing_mul",
    "u32_overflowing_mul",
];

impl Detector for UncheckedIntegerOverflow {
    fn id(&self) -> &'static str {
        "unchecked_integer_overflow"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "Integer arithmetic operation (u128/u64/u32/u16/u8) with no overflow branch. \
         The overflow case is silently discarded, producing incorrect results."
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

                let is_overflow_op = OVERFLOW_LIBFUNCS
                    .iter()
                    .any(|p| libfunc_name.contains(p));

                if !is_overflow_op {
                    continue;
                }

                // Safe usage: 2+ branches means the overflow case is handled
                // (typically branch 0 = success, branch 1 = overflow/panic)
                if inv.branches.len() >= 2 {
                    continue;
                }

                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Unchecked integer overflow",
                    format!(
                        "Function '{}': '{}' at stmt {} has only {} branch(es). \
                         The overflow/underflow case is not handled — \
                         use checked arithmetic or assert the result.",
                        func.name,
                        libfunc_name,
                        start + local_idx,
                        inv.branches.len()
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
