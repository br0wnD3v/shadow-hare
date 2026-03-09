use crate::analysis::cfg::Cfg;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects external functions that send L1 messages without verifying the
/// caller's identity, using CFG dominator analysis.
///
/// `send_message_to_l1_syscall` triggers an L1 message visible to Ethereum.
/// If any address can call the function, an attacker can spam the L1 bridge
/// with arbitrary messages.
///
/// The dominator-based check verifies that a `get_caller_address` block
/// structurally dominates the `send_message_to_l1` block — not just that
/// caller check appears somewhere in the function.
pub struct UncheckedL1Message;

const SEND_L1_LIBFUNCS: &[&str] = &["send_message_to_l1_syscall", "send_message_to_l1"];
const CALLER_CHECK_LIBFUNCS: &[&str] = &["get_caller_address", "get_execution_info"];

impl Detector for UncheckedL1Message {
    fn id(&self) -> &'static str {
        "unchecked_l1_message"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "External function sends an L1 message without verifying the caller. \
         Any account can trigger arbitrary L1-side effects or spam the bridge."
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

            // Find blocks containing send_l1 and caller checks.
            let mut send_block = None;
            let mut send_stmt = 0usize;
            let mut caller_check_blocks = Vec::new();

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

                    if SEND_L1_LIBFUNCS.iter().any(|p| name.contains(p)) && send_block.is_none() {
                        send_block = Some(block.id);
                        send_stmt = stmt_idx;
                    }
                    if CALLER_CHECK_LIBFUNCS.iter().any(|p| name.contains(p)) {
                        caller_check_blocks.push(block.id);
                    }
                }
            }

            let Some(send_blk) = send_block else {
                continue;
            };

            // Verify a caller check block dominates the send block.
            let has_dominating_check = caller_check_blocks
                .iter()
                .any(|&cb| cfg.dominates(cb, send_blk));

            if !has_dominating_check {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "L1 message sent without caller verification",
                    format!(
                        "Function '{}': send_message_to_l1 at stmt {} has no dominating \
                         get_caller_address check. Any account can trigger this L1 message.",
                        func.name, send_stmt
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(send_stmt),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}
