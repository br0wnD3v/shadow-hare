use std::collections::HashSet;

use crate::analysis::sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects L1 handler functions that use payload amounts (params[2+]) in
/// arithmetic operations or external calls without any prior bounds check.
///
/// Uses CFG-based taint analysis: seeds taint from payload params, sanitizes
/// with comparison operators. If taint survives to arithmetic or storage_write
/// sinks, the amount was used without validation.
///
/// When an L1 message carries a token amount (e.g. a deposit), the Cairo
/// handler MUST validate that the amount is within sane bounds before:
/// - Passing it to token.mint() or transfer()
/// - Writing it directly to storage as a balance
pub struct L1HandlerUncheckedAmount;

/// Libfunc patterns that represent arithmetic use — sinks for unchecked amounts.
const ARITHMETIC_SINKS: &[&str] = &[
    "u256_add",
    "u256_sub",
    "u256_mul",
    "u128_overflowing_add",
    "u128_overflowing_sub",
    "felt252_add",
    "felt252_sub",
    "felt252_mul",
];

/// Comparison/bounds-check libfuncs that sanitize payload taint.
const COMPARISON_SANITIZERS: &[&str] = &[
    "felt252_is_zero",
    "u256_is_zero",
    "u128_is_zero",
    "u256_lt",
    "u256_le",
    "u128_lt",
    "u128_le",
    "u64_lt",
    "u64_le",
    "felt252_lt",
    "assert_eq",
    "assert_ne",
    "assert_lt",
    "assert_le",
    "assert_le_felt252",
    "assert_lt_felt252",
    "u128_from_felt252",
    "u256_from_felt252",
];

impl Detector for L1HandlerUncheckedAmount {
    fn id(&self) -> &'static str {
        "l1_handler_unchecked_amount"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "L1 handler uses payload amount in arithmetic or external call without \
         a prior bounds check. A compromised L1 contract can mint unbounded \
         tokens or manipulate L2 accounting."
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

        // Build sanitizer set: comparison ops + standard const/hash/identity.
        // When payload amount flows into a comparison, it's being validated.
        let mut amount_sanitizers: Vec<&str> = sanitizers::all_general_sanitizers();
        for s in COMPARISON_SANITIZERS {
            if !amount_sanitizers.contains(s) {
                amount_sanitizers.push(s);
            }
        }

        for func in program.l1_handler_functions() {
            // L1 handler param layout:
            //   param[0]: System (implicit)
            //   param[1]: from_address: felt252
            //   param[2+]: message payload (amounts, addresses, etc.)
            if func.raw.params.len() < 3 {
                continue;
            }

            // Seed taint from payload params (skip system + from_address).
            let payload_seeds: HashSet<u64> =
                func.raw.params.iter().skip(2).map(|(id, _)| *id).collect();

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }

            // Run CFG-based taint analysis with comparison sanitizers.
            let (cfg, block_taint) = run_taint_analysis(
                program,
                func.idx,
                payload_seeds,
                &amount_sanitizers,
                &["function_call"],
            );

            // Check if payload taint reaches arithmetic or storage sinks.
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

                    let is_arith_sink = ARITHMETIC_SINKS.iter().any(|p| name.contains(p));
                    let is_storage_sink =
                        program.libfunc_registry.is_storage_write(&inv.libfunc_id);
                    let is_call_sink = name.contains("call_contract");

                    if !is_arith_sink && !is_storage_sink && !is_call_sink {
                        continue;
                    }

                    let uses_tainted = inv
                        .args
                        .iter()
                        .any(|a| tainted.is_some_and(|t| t.contains(a)));

                    if uses_tainted {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "L1 handler amount used without bounds check",
                            format!(
                                "Function '{}': L1 payload amount reaches '{}' at stmt {} \
                                 without prior bounds validation. \
                                 Validate: amount > 0 and amount <= MAX_DEPOSIT.",
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
