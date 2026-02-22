use std::collections::HashSet;

use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects use of block timestamp or block number in security-critical
/// comparisons.
///
/// On Starknet, sequencers control block timestamps within a window of
/// seconds-to-minutes. Code that uses `get_block_timestamp` or
/// `get_block_number` for access control, randomness, or deadline logic
/// is vulnerable to sequencer manipulation.
///
/// Affected patterns:
/// - Deadline / expiry checks based on timestamp
/// - Randomness seeded from block number/timestamp
/// - Access windows (e.g., "only callable after block N")
///
/// Safe alternative: use an off-chain VRF for randomness, or Starknet's
/// sequencer-agnostic time oracle where available.
pub struct BlockTimestampDependence;

const BLOCK_INFO_LIBFUNCS: &[&str] = &[
    "get_block_timestamp",
    "get_block_number",
    "get_block_info",
];

const COMPARISON_LIBFUNCS: &[&str] = &[
    "felt252_is_zero",
    "u128_eq",
    "u64_eq",
    "u32_eq",
    "u16_eq",
    "u8_eq",
    "felt252_sub",
    "u128_overflowing_sub",
    "u64_overflowing_sub",
    "assert_eq",
    "assert_ne",
    "assert_le",
    "assert_lt",
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
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let mut block_vars: HashSet<u64> = HashSet::new();
            let mut block_info_site: Option<usize> = None;

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

                // Track block info syscall results
                let is_block_info =
                    BLOCK_INFO_LIBFUNCS.iter().any(|p| libfunc_name.contains(p));

                if is_block_info {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            block_vars.insert(*r);
                        }
                    }
                    if block_info_site.is_none() {
                        block_info_site = Some(start + local_idx);
                    }
                    continue;
                }

                if block_vars.is_empty() {
                    continue;
                }

                // Propagate block taint
                if inv.args.iter().any(|a| block_vars.contains(a)) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            block_vars.insert(*r);
                        }
                    }
                }

                // Fire when block-tainted var reaches a comparison
                let is_comparison =
                    COMPARISON_LIBFUNCS.iter().any(|p| libfunc_name.contains(p));

                if is_comparison && inv.args.iter().any(|a| block_vars.contains(a)) {
                    if let Some(site) = block_info_site {
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
                                site,
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
                        // Reset to avoid duplicate findings for the same function
                        block_info_site = None;
                        block_vars.clear();
                    }
                }
            }
        }

        (findings, warnings)
    }
}
