use std::collections::HashSet;

use crate::analysis::sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects authentication via `get_tx_info` (transaction origin) instead of
/// `get_caller_address`, which is the Starknet equivalent of Ethereum's
/// `tx.origin` vs `msg.sender` bug.
///
/// Using the transaction origin for authentication is vulnerable because
/// any intermediate contract in the call chain shares the same tx_info.
///
/// This detector:
/// - Seeds taint from get_tx_info results
/// - Only flags when tx_info flows into auth comparisons (assert_eq, etc.)
/// - Suppresses if get_caller_address is ALSO used (proper pattern)
/// - Excludes benign tx_info uses like nonce, max_fee, chain_id reads
pub struct TxOriginAuth;

const TX_INFO_LIBFUNCS: &[&str] = &["get_tx_info"];

const AUTH_LIBFUNCS: &[&str] = &[
    "assert_eq",
    "assert_ne",
    "felt252_is_zero",
    "felt252_sub",
    "contract_address_to_felt252",
];

impl Detector for TxOriginAuth {
    fn id(&self) -> &'static str {
        "tx_origin_auth"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Authentication using transaction origin (get_tx_info) instead of caller address \
         is unsafe. Use get_caller_address for access control."
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
        let all_sanitizers = sanitizers::all_general_sanitizers();

        for func in program
            .external_functions()
            .filter(|f| !f.is_account_entrypoint())
        {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let end = end.min(program.statements.len());

            // First pass: check if get_caller_address is present.
            // If so, the developer is using the correct pattern alongside tx_info
            // (likely for logging/fee estimation) — suppress.
            let has_caller_address = program.statements[start..end]
                .iter()
                .filter_map(|stmt| stmt.as_invocation())
                .any(|inv| {
                    let name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or(inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");
                    name.contains("get_caller_address")
                });

            if has_caller_address {
                continue;
            }

            // Find tx_info call sites and seed taint from their results.
            let mut tx_info_seeds: HashSet<u64> = HashSet::new();
            let mut tx_info_site: Option<usize> = None;

            for stmt in &program.statements[start..end] {
                let inv = match stmt.as_invocation() {
                    Some(inv) => inv,
                    None => continue,
                };

                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if TX_INFO_LIBFUNCS.iter().any(|p| name.contains(p)) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            tx_info_seeds.insert(*r);
                        }
                    }
                    if tx_info_site.is_none() {
                        // Find the absolute index
                        tx_info_site = program.statements[start..end]
                            .iter()
                            .position(|s| std::ptr::eq(s, stmt))
                            .map(|i| start + i);
                    }
                }
            }

            if tx_info_seeds.is_empty() {
                continue;
            }

            // Run taint from tx_info results, using general sanitizers.
            let (cfg, block_taint) = run_taint_analysis(
                program,
                func.idx,
                tx_info_seeds,
                &all_sanitizers,
                &["function_call"],
            );

            // Check if tx_info taint reaches an auth comparison.
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

                    let is_auth = AUTH_LIBFUNCS.iter().any(|p| name.contains(p));
                    if !is_auth {
                        continue;
                    }

                    let uses_tx_taint = inv
                        .args
                        .iter()
                        .any(|a| tainted.is_some_and(|t| t.contains(a)));

                    if uses_tx_taint {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Transaction origin used for authentication",
                            format!(
                                "Function '{}': value from get_tx_info (stmt {}) is used in \
                                 an authentication check at stmt {}. Use get_caller_address instead.",
                                func.name,
                                tx_info_site.unwrap_or(start),
                                stmt_idx
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
