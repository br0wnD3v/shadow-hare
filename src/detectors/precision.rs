use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects division-before-multiplication: the result of an integer division
/// is used as an operand in a subsequent multiplication.
///
/// Integer division truncates towards zero. When the quotient is then
/// multiplied, the truncation error is amplified. This is a general integer
/// precision-loss class in on-chain arithmetic, independent of any specific
/// protocol implementation.
///
/// Pattern:
///   v_quot = u256_safe_divmod(a, b)      // quotient is truncated
///   v_scaled = u256_wide_mul(v_quot, c)  // error amplified
///
/// Safe pattern: multiply first, then divide.
///
/// Scope note:
/// This detector currently targets divide-then-multiply ordering on fixed-width
/// integer paths. Other precision-risk families (fixed-point scaling mistakes,
/// rounding policy bugs, etc.) should be covered by dedicated detectors.
pub struct DivideBeforeMultiply;

/// Division libfuncs that produce truncated integer quotients.
const DIV_LIBFUNCS: &[&str] = &[
    "u256_safe_divmod",
    "u128_safe_divmod",
    "u64_safe_divmod",
    "u32_safe_divmod",
    "u8_safe_divmod",
];

/// Multiplication libfuncs that represent *business-logic* multiplications.
///
/// Note: `u128_mul_guarantee_verify` is intentionally excluded here.
/// It is an internal Sierra verification step emitted as part of every u256/u128
/// division implementation (it proves quotient * divisor + remainder == dividend).
/// Including it would cause every call to `safe_math::div` to appear as a
/// divide-before-multiply false positive.
const MUL_LIBFUNCS: &[&str] = &[
    "u256_wide_mul",
    "u128_wide_mul",
    "u64_wide_mul",
    "u32_wide_mul",
    "felt252_mul",
    "u256_mul",
    "u128_overflowing_mul",
    "u64_overflowing_mul",
    "u32_overflowing_mul",
];

impl Detector for DivideBeforeMultiply {
    fn id(&self) -> &'static str {
        "divide_before_multiply"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Division result used in a subsequent multiplication. Integer division \
         truncates, and the error is amplified when multiplied. \
         Reorder to multiply first, then divide."
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

            // Track vars that are quotient results from division ops
            // (first result from each division branch = the quotient)
            let mut div_result_vars: HashSet<u64> = HashSet::new();

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

                // Check if this is a multiplication using a tainted (divided) var
                let is_mul = MUL_LIBFUNCS.iter().any(|p| libfunc_name.contains(p));
                if is_mul && inv.args.iter().any(|a| div_result_vars.contains(a)) {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Divide-before-multiply precision loss",
                        format!(
                            "Function '{}': '{}' at stmt {} multiplies a value that was \
                             previously divided. Integer truncation error is amplified — \
                             reorder to multiply first, then divide.",
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

                // Record quotient results from division ops
                let is_div = DIV_LIBFUNCS.iter().any(|p| libfunc_name.contains(p));
                if is_div {
                    // First result var from the success branch is the quotient
                    if let Some(branch) = inv.branches.first() {
                        if let Some(&quot_var) = branch.results.first() {
                            div_result_vars.insert(quot_var);
                        }
                    }
                }

                // Propagate division taint through intermediate ops
                // (e.g. store_temp, rename — neutral transformations)
                if inv.args.iter().any(|a| div_result_vars.contains(a)) {
                    let lname = libfunc_name;
                    // Only propagate through pass-through ops, not comparisons or stores
                    if lname.contains("store_temp")
                        || lname.contains("rename")
                        || lname.contains("dup")
                        || lname.contains("snapshot")
                        || lname.contains("into")
                        || lname.contains("try_into")
                        || lname.contains("upcast")
                        || lname.contains("downcast")
                    {
                        for branch in &inv.branches {
                            for r in &branch.results {
                                div_result_vars.insert(*r);
                            }
                        }
                    }
                }
            }
        }

        (findings, warnings)
    }
}
