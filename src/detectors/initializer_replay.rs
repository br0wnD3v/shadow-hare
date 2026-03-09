use std::collections::HashSet;

use crate::analysis::cfg::Cfg;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects initializer-like external entrypoints that write storage without an
/// observable initialization guard read/check before the first write.
///
/// Uses CFG to verify that the guard check block dominates the write block,
/// not just that it appears earlier in linear order.
///
/// Typical one-time init protection pattern:
/// - read an `initialized`-style storage slot
/// - assert it is not already set
/// - then perform writes
pub struct InitializerReplayOrMissingGuard;

const GUARD_CHECK_LIBFUNCS: &[&str] = &[
    "assert_eq",
    "assert_ne",
    "felt252_is_zero",
    "u128_eq",
    "u256_eq",
    "u128_is_zero",
    "u256_is_zero",
    "contract_address_eq",
];

impl Detector for InitializerReplayOrMissingGuard {
    fn id(&self) -> &'static str {
        "initializer_replay_or_missing_guard"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Initializer-like external function writes storage without an observable \
         one-time initialization guard."
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
            if !is_initializer_like_name(&func.name) {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let end = end.min(program.statements.len());

            // Build CFG for the function.
            let cfg = Cfg::build(&program.statements, start, end);

            // Find blocks containing storage writes and guard checks.
            let mut write_blocks: Vec<(usize, usize)> = Vec::new(); // (block_id, stmt_idx)
            let mut guard_blocks: Vec<usize> = Vec::new();

            // Track storage-derived variables for guard check verification.
            let mut storage_derived: HashSet<u64> = HashSet::new();

            for (block_id, block) in cfg.blocks.iter().enumerate() {
                for &stmt_idx in &block.stmts {
                    let stmt = &program.statements[stmt_idx];
                    let inv = match stmt {
                        Statement::Invocation(inv) => inv,
                        _ => continue,
                    };

                    // Track storage read results.
                    if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
                        for branch in &inv.branches {
                            for r in &branch.results {
                                storage_derived.insert(*r);
                            }
                        }
                    }

                    // Propagate storage-derived through pass-through ops.
                    let name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or(inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");

                    if (name.contains("store_temp")
                        || name.contains("rename")
                        || name.contains("dup")
                        || name.contains("snapshot_take"))
                        && inv.args.iter().any(|a| storage_derived.contains(a))
                    {
                        for branch in &inv.branches {
                            for r in &branch.results {
                                storage_derived.insert(*r);
                            }
                        }
                    }

                    // Check for guard: comparison using storage-derived value.
                    if GUARD_CHECK_LIBFUNCS.iter().any(|p| name.contains(p))
                        && inv.args.iter().any(|a| storage_derived.contains(a))
                        && !guard_blocks.contains(&block_id)
                    {
                        guard_blocks.push(block_id);
                    }

                    // Record storage write sites.
                    if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                        write_blocks.push((block_id, stmt_idx));
                    }
                }
            }

            if write_blocks.is_empty() {
                continue;
            }

            // Compute dominator tree once, check all pairs.
            let idom = cfg.dominators();
            let has_dominating_guard = if guard_blocks.is_empty() {
                false
            } else {
                write_blocks.iter().all(|&(write_block, _)| {
                    guard_blocks
                        .iter()
                        .any(|&guard_block| Cfg::dominates_with(&idom, guard_block, write_block))
                })
            };

            if !has_dominating_guard {
                let first_write_stmt = write_blocks[0].1;
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Initializer may be re-invocable",
                    format!(
                        "Function '{}': storage write at stmt {} is not dominated by \
                         a storage-backed initialization guard check. Repeated \
                         calls may reconfigure privileged state.",
                        func.name, first_write_stmt
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(first_write_stmt),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}

fn is_initializer_like_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("initialize") || n.contains("initializer")
}
