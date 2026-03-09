use std::collections::HashSet;

use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects division-before-multiplication: the result of an integer division
/// is used as an operand in a subsequent multiplication.
///
/// Integer division truncates towards zero. When the quotient is then
/// multiplied, the truncation error is amplified. This is a general integer
/// precision-loss class in on-chain arithmetic.
///
/// Uses CFG-based taint to propagate quotient variables through branches,
/// detecting div-then-mul even across control flow paths.
///
/// Pattern:
///   v_quot = u256_safe_divmod(a, b)      // quotient is truncated
///   v_scaled = u256_wide_mul(v_quot, c)  // error amplified
///
/// Safe pattern: multiply first, then divide.
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

        // Only check external functions — internal helpers often implement
        // legitimate fixed-point math or verification patterns (div then mul).
        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let end_clamped = end.min(program.statements.len());

            // Collect division quotient vars as taint seeds.
            let mut div_seeds: HashSet<u64> = HashSet::new();

            for stmt in &program.statements[start..end_clamped] {
                let inv = match stmt.as_invocation() {
                    Some(inv) => inv,
                    None => continue,
                };
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if DIV_LIBFUNCS.iter().any(|p| name.contains(p)) {
                    // First result var from the success branch is the quotient.
                    if let Some(branch) = inv.branches.first() {
                        if let Some(&quot_var) = branch.results.first() {
                            div_seeds.insert(quot_var);
                        }
                    }
                }
            }

            if div_seeds.is_empty() {
                continue;
            }

            // Propagate quotient taint through CFG. Don't sanitize with
            // hashes/constants — we want to track the truncated value.
            // Only sanitize with storage_read (value replaced from storage).
            let sanitizers: Vec<&str> = crate::analysis::sanitizers::CONST_PRODUCERS
                .iter()
                .chain(crate::analysis::sanitizers::STORAGE_READ.iter())
                .copied()
                .collect();

            let (cfg, block_taint) = run_taint_analysis(
                program,
                func.idx,
                div_seeds,
                &sanitizers,
                &["function_call"],
            );

            let mut found = false;
            for block_id in cfg.topological_order() {
                if found {
                    break;
                }
                let block = &cfg.blocks[block_id];
                let tainted = block_taint.get(&block_id);

                for &stmt_idx in &block.stmts {
                    let stmt = &program.statements[stmt_idx];
                    let inv = match stmt {
                        Statement::Invocation(inv) => inv,
                        _ => continue,
                    };

                    let name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or(inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");

                    let is_mul = MUL_LIBFUNCS.iter().any(|p| name.contains(p));
                    if !is_mul {
                        continue;
                    }

                    let uses_quotient = inv
                        .args
                        .iter()
                        .any(|a| tainted.is_some_and(|t| t.contains(a)));

                    if uses_quotient {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Divide-before-multiply precision loss",
                            format!(
                                "Function '{}': '{}' at stmt {} multiplies a value that was \
                                 previously divided. Integer truncation error is amplified — \
                                 reorder to multiply first, then divide.",
                                func.name, name, stmt_idx
                            ),
                            Location {
                                file: program.source.display().to_string(),
                                function: func.name.clone(),
                                statement_idx: Some(stmt_idx),
                                line: None,
                                col: None,
                            },
                        ));
                        found = true;
                        break;
                    }
                }
            }
        }

        (findings, warnings)
    }
}
