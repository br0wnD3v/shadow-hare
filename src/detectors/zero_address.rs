use std::collections::HashSet;

use crate::analysis::cfg::Cfg;
use crate::analysis::reentrancy::build_stmt_to_block_map;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Invocation, SierraId};

/// Detects externally supplied address values used as call targets
/// without an observable zero-address check in the function body.
///
/// Uses CFG-based analysis:
///   1. Taint propagation from ContractAddress-typed params
///   2. Dominator-based guard verification: a zero-check block must dominate
///      the call_contract block for the address to be considered checked
pub struct MissingZeroAddressCheck;

const ZERO_CHECK_LIBFUNCS: &[&str] = &[
    "contract_address_is_zero",
    "felt252_is_zero",
    "assert_not_zero",
    "assert_nn",
    "assert_ne",
    "contract_address_eq",
];

impl Detector for MissingZeroAddressCheck {
    fn id(&self) -> &'static str {
        "missing_zero_address_check"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Address-like external input is used as call target without observable zero-address validation."
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

            // Collect seeds: ContractAddress-typed params
            let mut seeds: HashSet<u64> = HashSet::new();
            for (var, ty) in &func.raw.params {
                if is_contract_address_type(ty) {
                    seeds.insert(*var);
                }
            }
            if seeds.is_empty() {
                continue;
            }

            // Run taint analysis to track address propagation (no zero-check sanitizers —
            // we use dominator-based guard checking instead)
            let general_sanitizers = crate::analysis::sanitizers::all_general_sanitizers();
            let (cfg, block_taint) = run_taint_analysis(
                program,
                func.idx,
                seeds.clone(),
                &general_sanitizers,
                &["function_call"],
            );

            let stmt_to_block = build_stmt_to_block_map(&cfg, start);
            let idom = cfg.dominators();

            // Find guard blocks: blocks containing zero-check libfuncs on address-tainted args
            let mut guard_blocks: HashSet<usize> = HashSet::new();
            for block in &cfg.blocks {
                let Some(tainted) = block_taint.get(&block.id) else {
                    continue;
                };
                for &stmt_idx in &block.stmts {
                    let Some(stmt) = program.statements.get(stmt_idx) else {
                        continue;
                    };
                    let Some(inv) = stmt.as_invocation() else {
                        continue;
                    };
                    let libfunc_name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or(inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");

                    let is_zero_check =
                        ZERO_CHECK_LIBFUNCS.iter().any(|p| libfunc_name.contains(p));
                    if is_zero_check && inv.args.iter().any(|a| tainted.contains(a)) {
                        guard_blocks.insert(block.id);
                    }
                }
            }

            // Check call_contract sinks: if the target arg is tainted AND no
            // guard block dominates the call block → finding
            for block in &cfg.blocks {
                let Some(tainted) = block_taint.get(&block.id) else {
                    continue;
                };
                for &stmt_idx in &block.stmts {
                    let Some(stmt) = program.statements.get(stmt_idx) else {
                        continue;
                    };
                    let Some(inv) = stmt.as_invocation() else {
                        continue;
                    };

                    let libfunc_name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or(inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");

                    let is_call_target = libfunc_name.contains("call_contract_syscall")
                        || libfunc_name.contains("call_contract");
                    if !is_call_target {
                        continue;
                    }

                    let target_var = infer_call_target_arg(inv, tainted);
                    let target_is_tainted =
                        target_var.map(|v| tainted.contains(&v)).unwrap_or(false);

                    if !target_is_tainted {
                        continue;
                    }

                    // Check if any guard block dominates this call block
                    let is_guarded = guard_blocks
                        .iter()
                        .any(|&gb| Cfg::dominates_with(&idom, gb, block.id));

                    if !is_guarded {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Potential missing zero-address check",
                            format!(
                                "Function '{}': external address input reaches call target at stmt {} \
                                 without observable zero-address validation.",
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
                    }
                }
            }
        }

        (findings, warnings)
    }
}

fn infer_call_target_arg(inv: &Invocation, tainted: &HashSet<u64>) -> Option<u64> {
    // Typical Starknet call layouts place target near the front; try these first.
    for idx in [1usize, 2, 3] {
        if let Some(v) = inv.args.get(idx).copied() {
            if tainted.contains(&v) {
                return Some(v);
            }
        }
    }
    inv.args.iter().copied().find(|v| tainted.contains(v))
}

fn is_contract_address_type(ty: &SierraId) -> bool {
    ty.debug_name
        .as_deref()
        .map(|name| name.contains("ContractAddress") || name.contains("contract_address"))
        .unwrap_or(false)
}
