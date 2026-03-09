use std::collections::HashSet;

use crate::analysis::cfg::Cfg;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects unsafe u256 → felt252 conversion that silently truncates the high
/// 128 bits.
///
/// `u256_to_felt252` discards the high word if the value exceeds the felt252
/// prime. Code that assumes the conversion is lossless will compute wrong
/// results (balance accounting, price calculations, etc.).
///
/// Safe patterns (suppressed):
/// - High word is checked via `u128_eq`, `felt252_is_zero`, or assertion
///   before the conversion
/// - The u256 was constructed from a felt252 (round-trip)
/// - The conversion is in an internal/compiler-generated function
pub struct IntegerTruncation;

const TRUNCATION_LIBFUNCS: &[&str] = &["u256_to_felt252"];

/// Libfuncs that indicate a bounds check on the high word.
const HIGH_WORD_CHECK_LIBFUNCS: &[&str] = &[
    "u128_eq",
    "u128_is_zero",
    "felt252_is_zero",
    "u128_overflowing_sub",
    "u128_le",
    "u128_lt",
    "assert_eq",
    "assert_ne",
];

/// Libfuncs that produce a u256 from a bounded source (safe round-trip).
const BOUNDED_SOURCE_LIBFUNCS: &[&str] = &[
    "felt252_to_u256",
    "u128_to_felt252",
    "u64_to_felt252",
    "u32_to_felt252",
    "u16_to_felt252",
    "u8_to_felt252",
];

impl Detector for IntegerTruncation {
    fn id(&self) -> &'static str {
        "integer_truncation"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "u256 converted to felt252 via u256_to_felt252 without an observable \
         high-word bounds check. The high 128 bits are silently discarded if \
         the value exceeds the field prime."
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
            let end = end.min(program.statements.len());
            let cfg = Cfg::build(&program.statements, start, end);

            // Collect all truncation sites and their input vars.
            let mut truncation_sites: Vec<(usize, u64)> = Vec::new();
            // Collect vars that are high-word-checked or bounded-source.
            let mut guarded_vars: HashSet<u64> = HashSet::new();
            // Collect vars from bounded sources (round-trip safe).
            let mut bounded_vars: HashSet<u64> = HashSet::new();

            // Single pass through blocks in topo order.
            for block_id in cfg.topological_order() {
                let block = &cfg.blocks[block_id];

                for &stmt_idx in &block.stmts {
                    let inv = match &program.statements[stmt_idx] {
                        Statement::Invocation(inv) => inv,
                        _ => continue,
                    };

                    let name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or(inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");

                    // Track bounded source vars.
                    if BOUNDED_SOURCE_LIBFUNCS.iter().any(|p| name.contains(p)) {
                        for branch in &inv.branches {
                            for &r in &branch.results {
                                bounded_vars.insert(r);
                            }
                        }
                    }

                    // Track struct_deconstruct outputs — propagate bounded
                    // status from input struct to extracted fields.
                    if name.contains("struct_deconstruct") {
                        let input_bounded = inv.args.iter().any(|a| bounded_vars.contains(a));
                        if input_bounded {
                            for branch in &inv.branches {
                                for &r in &branch.results {
                                    bounded_vars.insert(r);
                                }
                            }
                        }
                    }

                    // Track struct_construct — if inputs are bounded, output is
                    // bounded.
                    if name.contains("struct_construct") {
                        let all_bounded = !inv.args.is_empty()
                            && inv.args.iter().all(|a| bounded_vars.contains(a));
                        if all_bounded {
                            for branch in &inv.branches {
                                for &r in &branch.results {
                                    bounded_vars.insert(r);
                                }
                            }
                        }
                    }

                    // Track high-word checks.
                    if HIGH_WORD_CHECK_LIBFUNCS.iter().any(|p| name.contains(p)) {
                        for arg in &inv.args {
                            guarded_vars.insert(*arg);
                        }
                    }

                    // Record truncation sites.
                    if TRUNCATION_LIBFUNCS.iter().any(|p| name.contains(p)) {
                        if let Some(&input_var) = inv.args.first() {
                            truncation_sites.push((stmt_idx, input_var));
                        }
                    }

                    // Propagate bounded/guarded through pass-through ops.
                    if name.contains("store_temp")
                        || name.contains("rename")
                        || name.contains("dup")
                        || name.contains("snapshot_take")
                    {
                        let any_bounded = inv.args.iter().any(|a| bounded_vars.contains(a));
                        let any_guarded = inv.args.iter().any(|a| guarded_vars.contains(a));
                        for branch in &inv.branches {
                            for &r in &branch.results {
                                if any_bounded {
                                    bounded_vars.insert(r);
                                }
                                if any_guarded {
                                    guarded_vars.insert(r);
                                }
                            }
                        }
                    }
                }
            }

            // Filter: only flag truncations where the input is NOT from a
            // bounded source and NOT preceded by a high-word check.
            for &(stmt_idx, input_var) in &truncation_sites {
                if bounded_vars.contains(&input_var) {
                    continue; // Safe round-trip
                }
                if guarded_vars.contains(&input_var) {
                    continue; // High-word was checked
                }

                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Unsafe u256 to felt252 truncation",
                    format!(
                        "Function '{}': u256_to_felt252 at stmt {} converts \
                         u256 to felt252 without an observable high-word bounds \
                         check. Values exceeding the field prime will be \
                         silently truncated.",
                        func.name, stmt_idx
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(stmt_idx),
                        line: None,
                        col: None,
                    },
                ));
                break; // One finding per function
            }
        }

        (findings, warnings)
    }
}
