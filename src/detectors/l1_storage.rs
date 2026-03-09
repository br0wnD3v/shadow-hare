use std::collections::HashSet;

use crate::analysis::sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects L1 handler functions that write raw L1 payload data directly into
/// contract storage without any transformation or validation.
///
/// L1 message payload params are externally-controlled data (from Ethereum).
/// Writing them verbatim to storage slots lets an L1-side attacker overwrite
/// arbitrary L2 state.
pub struct L1HandlerPayloadToStorage;

impl Detector for L1HandlerPayloadToStorage {
    fn id(&self) -> &'static str {
        "l1_handler_payload_to_storage"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "L1 handler stores raw payload data directly in contract storage. \
         A compromised L1 contract can overwrite any L2 state variable, \
         including admin keys, configuration, and exchange rates."
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
        let hash_sanitizers = sanitizers::hash_only_sanitizers();

        for func in program.l1_handler_functions() {
            if func.raw.params.len() < 3 {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }

            // Taint seed: payload params (index 2+).
            let seeds: HashSet<u64> = func.raw.params.iter().skip(2).map(|(id, _)| *id).collect();

            let (cfg, block_taint) = run_taint_analysis(
                program,
                func.idx,
                seeds,
                &hash_sanitizers,
                &["function_call"],
            );

            for block_id in cfg.topological_order() {
                let block = &cfg.blocks[block_id];
                let tainted = block_taint.get(&block_id);

                for &stmt_idx in &block.stmts {
                    let stmt = &program.statements[stmt_idx];
                    let inv = match stmt {
                        Statement::Invocation(inv) => inv,
                        _ => continue,
                    };

                    if !program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                        continue;
                    }

                    // Sink: storage_write — check if VALUE arg (arg[2]) is tainted.
                    let value_tainted = inv
                        .args
                        .get(2)
                        .is_some_and(|v| tainted.is_some_and(|t| t.contains(v)));

                    if value_tainted {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Raw L1 payload written to storage",
                            format!(
                                "Function '{}': at stmt {} raw L1 message payload \
                                 is stored directly in contract storage. \
                                 A malicious L1 contract can overwrite critical L2 state.",
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
