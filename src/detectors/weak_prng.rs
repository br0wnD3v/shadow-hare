use std::collections::HashSet;

use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects pseudo-randomness derived from block/environment values.
///
/// Narrowed sink set: only flags env-derived values that reach external calls
/// or hash-then-branch patterns (actual PRNG usage). Arithmetic like felt252_add
/// and felt252_mul are excluded as they cause too many FPs from benign
/// bookkeeping operations.
pub struct WeakPrng;

const ENV_ENTROPY_LIBFUNCS: &[&str] = &[
    "get_block_hash",
    "get_block_info",
    "get_block_timestamp",
    "get_block_number",
];

/// Narrow sinks: external calls, L1 messages, and storage writes where
/// predictable randomness has security impact.
const PRNG_SINK_LIBFUNCS: &[&str] = &[
    "call_contract",
    "send_message_to_l1",
    "storage_write_syscall",
];

/// Hash functions used to derive randomness from env values.
const HASH_LIBFUNCS: &[&str] = &["pedersen", "poseidon", "hades_permutation"];

impl Detector for WeakPrng {
    fn id(&self) -> &'static str {
        "weak_prng"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Randomness appears derived from sequencer/block metadata, which is predictable/manipulable."
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

            // Find env entropy sources and seed taint from their results.
            let mut entropy_seeds: HashSet<u64> = HashSet::new();

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

                if ENV_ENTROPY_LIBFUNCS.iter().any(|p| name.contains(p)) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            entropy_seeds.insert(*r);
                        }
                    }
                }
            }

            if entropy_seeds.is_empty() {
                continue;
            }

            // Run taint from env sources. Don't sanitize with hashes — hashing
            // env values is exactly the PRNG pattern we want to detect.
            // Only break taint on constants and identity (caller_address, etc.).
            let sanitizers: Vec<&str> = crate::analysis::sanitizers::CONST_PRODUCERS
                .iter()
                .chain(crate::analysis::sanitizers::IDENTITY_PRODUCERS.iter())
                .chain(crate::analysis::sanitizers::STORAGE_READ.iter())
                .copied()
                .collect();

            let (cfg, block_taint) = run_taint_analysis(
                program,
                func.idx,
                entropy_seeds,
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

                    // Check for env->hash pattern (PRNG) or sensitive sinks
                    let is_hash = HASH_LIBFUNCS.iter().any(|p| name.contains(p));
                    let is_sink = PRNG_SINK_LIBFUNCS.iter().any(|p| name.contains(p))
                        || program.libfunc_registry.is_storage_write(&inv.libfunc_id);

                    if (is_hash || is_sink)
                        && inv
                            .args
                            .iter()
                            .any(|a| tainted.is_some_and(|t| t.contains(a)))
                    {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Weak pseudo-randomness source",
                            format!(
                                "Function '{}': env-derived value reaches '{}' at stmt {}. \
                                 Block/sequencer metadata is not a secure randomness source.",
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
