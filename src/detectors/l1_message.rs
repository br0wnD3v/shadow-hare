use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects external functions that send L1 messages without verifying the
/// caller's identity.
///
/// `send_message_to_l1_syscall` triggers an L1 message that is visible to
/// Ethereum. If any address can call the function, an attacker can spam
/// the L1 bridge with arbitrary messages, potentially:
/// - Exhausting the bridge's message queue
/// - Triggering unintended L1 side-effects (token releases, withdrawals)
/// - Causing off-chain systems to process fraudulent messages
///
/// Safe pattern: check `get_caller_address` against a whitelist or the
/// contract's stored owner before sending.
pub struct UncheckedL1Message;

const SEND_L1_LIBFUNCS: &[&str] = &["send_message_to_l1_syscall", "send_message_to_l1"];

const CALLER_CHECK_LIBFUNCS: &[&str] = &["get_caller_address", "get_execution_info"];

impl Detector for UncheckedL1Message {
    fn id(&self) -> &'static str {
        "unchecked_l1_message"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
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
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let mut has_send_l1 = false;
            let mut has_caller_check = false;
            let mut send_site = 0usize;

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

                if SEND_L1_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                    if !has_send_l1 {
                        send_site = start + local_idx;
                    }
                    has_send_l1 = true;
                }

                if CALLER_CHECK_LIBFUNCS
                    .iter()
                    .any(|p| libfunc_name.contains(p))
                {
                    has_caller_check = true;
                }
            }

            if has_send_l1 && !has_caller_check {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "L1 message sent without caller verification",
                    format!(
                        "Function '{}': send_message_to_l1 at stmt {} has no preceding \
                         get_caller_address check. Any account can trigger this L1 message.",
                        func.name, send_site
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(send_site),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}
