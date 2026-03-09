use crate::analysis::cfg::Cfg;
use crate::analysis::reentrancy::forward_reachable_blocks;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects functions that invoke `send_message_to_l1_syscall` more than once
/// on the same executable path, using CFG-based reachability.
///
/// Two send calls in different if/else branches are NOT flagged — only one
/// executes per transaction. But two sends where one is forward-reachable
/// from the other (both execute in the same path) are flagged.
///
/// Duplicate L2->L1 messages cause double L1 processing, double token
/// releases, or fee waste.
pub struct L2ToL1DoubleSend;

const SEND_L1_LIBFUNCS: &[&str] = &["send_message_to_l1_syscall", "send_message_to_l1"];

impl Detector for L2ToL1DoubleSend {
    fn id(&self) -> &'static str {
        "l2_to_l1_double_send"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Function sends more than one L2->L1 message on the same executable path. \
         This usually indicates a logic error that causes duplicate L1 processing, \
         double token releases, or fee waste."
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
            let end_clamped = end.min(program.statements.len());

            let cfg = Cfg::build(&program.statements, start, end_clamped);

            // Find all blocks containing send_message_to_l1.
            let mut send_blocks: Vec<(usize, usize)> = Vec::new(); // (block_id, stmt_idx)

            for block in &cfg.blocks {
                for &stmt_idx in &block.stmts {
                    let Some(inv) = program.statements[stmt_idx].as_invocation() else {
                        continue;
                    };
                    let name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or(inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");

                    if SEND_L1_LIBFUNCS.iter().any(|p| name.contains(p)) {
                        send_blocks.push((block.id, stmt_idx));
                    }
                }
            }

            if send_blocks.len() < 2 {
                continue;
            }

            // Check if any two send blocks are on the same path.
            // A pair (A, B) is on the same path if B is forward-reachable from A.
            let mut found_pair = false;
            for i in 0..send_blocks.len() {
                if found_pair {
                    break;
                }
                let (block_a, stmt_a) = send_blocks[i];
                let forward = forward_reachable_blocks(&cfg, block_a);

                for &(block_b, stmt_b) in &send_blocks[(i + 1)..] {
                    if forward.contains(&block_b) || block_a == block_b {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Multiple L1 messages on same execution path",
                            format!(
                                "Function '{}': send_message_to_l1 at stmt {} and stmt {} \
                                 are on the same executable path. Duplicate messages cause \
                                 double L1 processing and fee waste.",
                                func.name, stmt_a, stmt_b
                            ),
                            Location {
                                file: program.source.display().to_string(),
                                function: func.name.clone(),
                                statement_idx: Some(stmt_a),
                                line: None,
                                col: None,
                            },
                        ));
                        found_pair = true;
                        break;
                    }
                }
            }
        }

        (findings, warnings)
    }
}
