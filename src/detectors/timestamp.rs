use std::collections::HashSet;

use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects use of block timestamp or block number in security-critical
/// comparisons.
///
/// On Starknet, sequencers control block timestamps within a window of
/// seconds-to-minutes. Code that uses `get_block_timestamp` or
/// `get_block_number` for access control, randomness, or deadline logic
/// is vulnerable to sequencer manipulation.
///
/// This detector:
/// - Uses CFG-based taint from block_info sources
/// - Flags equality checks (strict comparisons vulnerable to manipulation)
/// - Suppresses benign bookkeeping (storage writes for logging/tracking)
pub struct BlockTimestampDependence;

const BLOCK_INFO_LIBFUNCS: &[&str] = &["get_block_timestamp", "get_block_number", "get_block_info"];

/// Strict equality/comparison ops — vulnerable to sequencer manipulation.
/// Ordering comparisons (<=, <) are less exploitable for timelocks.
const ATTACK_PATTERN_LIBFUNCS: &[&str] = &[
    "felt252_is_zero",
    "assert_eq",
    "assert_ne",
    // Equality comparisons on integer types
    "u128_eq",
    "u64_eq",
    "u32_eq",
    "u16_eq",
    "u8_eq",
];

impl Detector for BlockTimestampDependence {
    fn id(&self) -> &'static str {
        "block_timestamp_dependence"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Block timestamp or block number used in a security comparison. \
         Starknet sequencers can manipulate timestamps within a bounded window, \
         making deadline/randomness logic unreliable."
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
            let end = end.min(program.statements.len());

            // Find block info call sites and seed taint from their results.
            let mut block_seeds: HashSet<u64> = HashSet::new();
            let mut block_info_site: Option<usize> = None;

            for (i, stmt) in program.statements[start..end].iter().enumerate() {
                let inv = match stmt.as_invocation() {
                    Some(inv) => inv,
                    None => continue,
                };
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if BLOCK_INFO_LIBFUNCS.iter().any(|p| name.contains(p)) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            block_seeds.insert(*r);
                        }
                    }
                    if block_info_site.is_none() {
                        block_info_site = Some(start + i);
                    }
                }
            }

            if block_seeds.is_empty() {
                continue;
            }

            // Run taint from block info. Sanitize with constants, identity
            // producers, and storage reads (bookkeeping pattern).
            let sanitizers: Vec<&str> = crate::analysis::sanitizers::CONST_PRODUCERS
                .iter()
                .chain(crate::analysis::sanitizers::IDENTITY_PRODUCERS.iter())
                .chain(crate::analysis::sanitizers::HASH_SANITIZERS.iter())
                .chain(crate::analysis::sanitizers::STORAGE_READ.iter())
                .copied()
                .collect();

            let (cfg, block_taint) = run_taint_analysis(
                program,
                func.idx,
                block_seeds,
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

                    // Only flag attack-pattern comparisons, not benign storage writes
                    let is_attack_pattern =
                        ATTACK_PATTERN_LIBFUNCS.iter().any(|p| name.contains(p));

                    if !is_attack_pattern {
                        continue;
                    }

                    let uses_block_taint = inv
                        .args
                        .iter()
                        .any(|a| tainted.is_some_and(|t| t.contains(a)));

                    if uses_block_taint {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Block timestamp/number used in security check",
                            format!(
                                "Function '{}': block info obtained at stmt {} is used in \
                                 a comparison at stmt {}. Sequencers can manipulate block \
                                 timestamps within a window, making this check unreliable.",
                                func.name,
                                block_info_site.unwrap_or(start),
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
