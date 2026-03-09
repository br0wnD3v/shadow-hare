use std::collections::HashSet;

use crate::analysis::sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects L1 handler functions that do not validate the `from_address` parameter.
///
/// L1 handlers in Starknet receive messages from Ethereum. The first parameter
/// is always `from_address: felt252` — the Ethereum address that sent the message.
/// Failing to check this allows any Ethereum address to trigger the handler,
/// which is a critical access-control vulnerability.
///
/// Detection strategy (CFG + taint):
/// 1. Find functions classified as L1_HANDLER.
/// 2. Seed taint from from_address (param[1], the first felt252).
/// 3. Use `run_taint_analysis` with sanitizers that include comparison ops.
/// 4. If taint reaches a storage write or external call without being sanitized
///    by a comparison, report.
///
/// Unlike the old direct-var-usage approach, this propagates taint through
/// intermediate computations and respects CFG branching.
pub struct UncheckedL1Handler;

/// Libfunc patterns that represent comparison / validation operations.
/// When from_address flows into one of these, it's being validated.
const VALIDATION_SANITIZERS: &[&str] = &[
    "felt252_is_zero",
    "assert_eq",
    "assert_ne",
    "assert_le",
    "assert_lt",
    "u128_eq",
    "u64_eq",
    "u32_eq",
    "u16_eq",
    "u8_eq",
    "u256_eq",
    "contract_address_to_felt252",
];

impl Detector for UncheckedL1Handler {
    fn id(&self) -> &'static str {
        "unchecked_l1_handler"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "L1 handler does not validate the from_address parameter. \
         Any Ethereum address can trigger this handler, bypassing access control."
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

        // Build sanitizer set: comparisons + standard const/hash/identity producers.
        // When from_address flows into a comparison or is hashed for storage lookup,
        // it's being validated.
        let mut from_addr_sanitizers = sanitizers::all_general_sanitizers();
        for s in VALIDATION_SANITIZERS {
            if !from_addr_sanitizers.contains(s) {
                from_addr_sanitizers.push(s);
            }
        }

        for func in program.l1_handler_functions() {
            // L1 handler param layout:
            //   param[0]: System (implicit)
            //   param[1]: from_address: felt252
            //   param[2+]: message payload
            //
            // We taint only from_address — the first felt252 param.
            let from_address_var = find_from_address_var(&func.raw.params, program);
            let from_address_var = match from_address_var {
                Some(v) => v,
                None => continue,
            };

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }

            let seeds: HashSet<u64> = [from_address_var].into_iter().collect();

            let (cfg, block_taint) = run_taint_analysis(
                program,
                func.idx,
                seeds,
                &from_addr_sanitizers,
                &["function_call"],
            );

            // Check if from_address taint is sanitized (comparison reached).
            // If taint survives to any storage_write or call_contract, from_address
            // was used without validation.
            let mut found_unsanitized_use = false;

            for block_id in cfg.topological_order() {
                if found_unsanitized_use {
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

                    let libfunc_name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or(inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");

                    // If from_address is still tainted at a sensitive sink,
                    // it wasn't validated.
                    let is_sensitive = libfunc_name.contains("call_contract")
                        || program.libfunc_registry.is_storage_write(&inv.libfunc_id);

                    if is_sensitive {
                        let from_still_tainted =
                            tainted.is_some_and(|t| t.contains(&from_address_var));
                        if from_still_tainted {
                            findings.push(Finding::new(
                                self.id(),
                                self.severity(),
                                self.confidence(),
                                "Unchecked L1 handler from_address",
                                format!(
                                    "L1 handler '{}': from_address (var {}) is never compared \
                                     or validated before sensitive operation at stmt {}. \
                                     Any Ethereum address can call this handler.",
                                    func.name, from_address_var, stmt_idx
                                ),
                                Location {
                                    file: program.source.display().to_string(),
                                    function: func.name.clone(),
                                    statement_idx: Some(stmt_idx),
                                    line: None,
                                    col: None,
                                },
                            ));
                            found_unsanitized_use = true;
                            break;
                        }
                    }
                }
            }

            // Fallback: if no sensitive sinks but from_address is never sanitized
            // anywhere in the function, still flag it.
            if !found_unsanitized_use {
                let any_block_sanitized =
                    block_taint.values().any(|t| !t.contains(&from_address_var));
                if !any_block_sanitized && !block_taint.is_empty() {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Unchecked L1 handler from_address",
                        format!(
                            "L1 handler '{}': from_address (var {}) is never compared \
                             or validated. Any Ethereum address can call this handler.",
                            func.name, from_address_var
                        ),
                        Location {
                            file: program.source.display().to_string(),
                            function: func.name.clone(),
                            statement_idx: Some(start),
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

fn find_from_address_var(
    params: &[(u64, crate::loader::SierraId)],
    program: &ProgramIR,
) -> Option<u64> {
    // Look for the first felt252 param. In L1 handlers:
    //   - implicit: System (context pointer)
    //   - explicit[0]: from_address: felt252
    for (var_id, ty) in params {
        if program.type_registry.is_felt252(ty) {
            return Some(*var_id);
        }
    }
    // Fallback: second param if no type info
    params.get(1).map(|(id, _)| *id)
}
