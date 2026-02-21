use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects u256 subtraction operations where the underflow/overflow result
/// is not checked, leading to silent arithmetic errors.
///
/// In Sierra, unchecked u256 subtraction uses `u256_overflowing_sub` which
/// returns (result, overflow_flag). If the overflow flag variable is never
/// used in a branch condition, the underflow is silently ignored.
pub struct U256Underflow;

// Libfunc patterns to detect
const UNDERFLOW_LIBFUNCS: &[&str] = &[
    "u256_overflowing_sub",
    "u256_sub",
    "u128_overflowing_sub",
    "u64_overflowing_sub",
    "u32_overflowing_sub",
    "u16_overflowing_sub",
    "u8_overflowing_sub",
];

// Libfuncs that consume the overflow flag (meaning the code IS checking)
const CHECK_LIBFUNCS: &[&str] = &[
    "branch_align",
    "felt252_is_zero",
    "bool_not_impl",
    "unwrap_nz",
    // Panic-on-overflow variants already have built-in checking
    "u256_safe_divmod",
];

impl Detector for U256Underflow {
    fn id(&self) -> &'static str {
        "u256_underflow"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Unchecked u256 subtraction may underflow silently. \
         Use checked subtraction or assert the overflow flag."
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

            // Collect all variables that hold overflow flags from subtraction ops
            // and track which ones are used in subsequent checks.
            let overflow_vars: Vec<(u64, usize)> = Vec::new(); // (var_id, stmt_idx)
            let mut checked_vars: std::collections::HashSet<u64> = std::collections::HashSet::new();

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

                // Check if this invocation uses an overflow var (i.e., checks it)
                for arg in &inv.args {
                    if overflow_vars.iter().any(|(v, _)| v == arg) {
                        checked_vars.insert(*arg);
                    }
                }

                // Detect subtraction libfuncs that produce overflow flags
                if UNDERFLOW_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                    // The overflow flag is typically the last result of the first branch.
                    // In Sierra's `u256_overflowing_sub`, the branches are:
                    //   branch[0] (ok): results = [low, high]
                    //   branch[1] (overflow): results = [low, high]
                    // The overflow is indicated by which branch is taken, not a flag variable.
                    // However, if there is only ONE branch (Fallthrough), it's unchecked.

                    let num_branches = inv.branches.len();
                    if num_branches <= 1 {
                        // Only fallthrough — no overflow check
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Unchecked integer underflow",
                            format!(
                                "Function '{}': libfunc '{}' at stmt {} performs subtraction \
                                 with only one branch — overflow condition is never checked.",
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
                    // If num_branches == 2, the overflow IS structurally checked via the branch.
                    // We do NOT flag two-branch subtractions — they are safe.
                }
            }
        }

        (findings, warnings)
    }
}
