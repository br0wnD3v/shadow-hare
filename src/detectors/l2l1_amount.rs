use std::collections::HashSet;

use crate::analysis::sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects L2->L1 messages where the amount/payload is supplied directly by
/// the caller without being read from (and thus validated against) contract storage.
pub struct L2ToL1UnverifiedAmount;

impl Detector for L2ToL1UnverifiedAmount {
    fn id(&self) -> &'static str {
        "l2_to_l1_unverified_amount"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "L2->L1 message payload contains an amount derived directly from function \
         parameters without reading from contract storage. The L2 contract does \
         not verify that the claimed amount is backed by on-chain state, enabling \
         arbitrary token claims on L1."
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

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let end = end.min(program.statements.len());

            // Seed taint from non-system function params.
            let seeds: HashSet<u64> = func
                .raw
                .params
                .iter()
                .filter_map(|(id, ty)| {
                    let ty_name = ty.debug_name.as_deref().unwrap_or("");
                    if ty_name == "System" {
                        None
                    } else {
                        Some(*id)
                    }
                })
                .collect();

            // Check if any storage read exists in the function.
            // If storage is read, amounts may be validated — suppress finding.
            let has_storage_read = program.statements[start..end]
                .iter()
                .filter_map(|stmt| stmt.as_invocation())
                .any(|inv| program.libfunc_registry.is_storage_read(&inv.libfunc_id));

            if has_storage_read {
                continue;
            }

            let (cfg, block_taint) = run_taint_analysis(
                program,
                func.idx,
                seeds,
                &all_sanitizers,
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

                    let libfunc_name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or(inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");

                    if !libfunc_name.contains("send_message_to_l1") {
                        continue;
                    }

                    // Payload starts at arg[2].
                    let payload_tainted = inv
                        .args
                        .iter()
                        .skip(2)
                        .any(|a| tainted.is_some_and(|t| t.contains(a)));

                    if payload_tainted {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "L1 message payload amount not backed by storage",
                            format!(
                                "Function '{}': at stmt {} send_message_to_l1 payload \
                                 derives from function parameters with no storage_read \
                                 in this function. The claimed amount is unverified.",
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
                        break; // One finding per function is enough.
                    }
                }
            }
        }

        (findings, warnings)
    }
}
