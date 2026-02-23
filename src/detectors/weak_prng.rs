use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects pseudo-randomness derived from block/environment values.
pub struct WeakPrng;

const ENV_ENTROPY_LIBFUNCS: &[&str] = &[
    "get_block_hash",
    "get_block_info",
    "get_execution_info",
    "get_block_timestamp",
    "get_block_number",
];

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

            let mut entropy_vars: HashSet<u64> = HashSet::new();

            for (local_idx, stmt) in program.statements[start..end.min(program.statements.len())]
                .iter()
                .enumerate()
            {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let abs = start + local_idx;

                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if ENV_ENTROPY_LIBFUNCS.iter().any(|p| name.contains(p)) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            entropy_vars.insert(*r);
                        }
                    }
                    continue;
                }

                let uses_entropy = inv.args.iter().any(|a| entropy_vars.contains(a));
                if uses_entropy {
                    let reaches_sensitive_sink =
                        program.libfunc_registry.is_storage_write(&inv.libfunc_id)
                            || name.contains("call_contract")
                            || name.contains("send_message_to_l1")
                            || name.contains("pedersen")
                            || name.contains("poseidon")
                            || name.contains("felt252_add")
                            || name.contains("felt252_mul");

                    if reaches_sensitive_sink {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Weak pseudo-randomness source",
                            format!(
                                "Function '{}': env-derived value reaches '{}' at stmt {}. \
                                 Block/sequencer metadata is not a secure randomness source.",
                                func.name, name, abs
                            ),
                            Location {
                                file: program.source.display().to_string(),
                                function: func.name.clone(),
                                statement_idx: Some(abs),
                                line: None,
                                col: None,
                            },
                        ));
                        break;
                    }

                    for branch in &inv.branches {
                        for r in &branch.results {
                            entropy_vars.insert(*r);
                        }
                    }
                }
            }
        }

        (findings, warnings)
    }
}
