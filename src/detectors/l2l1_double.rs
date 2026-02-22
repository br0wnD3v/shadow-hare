use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects functions that invoke `send_message_to_l1_syscall` more than once
/// in the same execution path.
///
/// Sending duplicate L2->L1 messages in a single transaction is almost always
/// a logic error and causes:
///
/// 1. **Double processing on L1**: if the L1 bridge processes each message
///    independently, this can result in double token releases, double votes,
///    or duplicate withdrawals.
///
/// 2. **Fee waste**: every L2->L1 message consumes L1 gas when consumed on
///    Ethereum. Sending two identical messages doubles the operator cost.
///
/// 3. **L1 queue griefing**: an attacker can spam the message queue with
///    duplicate messages if this function is callable without restrictions.
///
/// Typical false positive scenarios to be aware of:
/// - One message per asset in a multi-asset withdrawal (intentional)
/// - Success/failure message pair (also intentional)
/// In those cases, a `// @suppress(l2_to_l1_double_send)` annotation is appropriate.
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
        "Function sends more than one L2->L1 message in a single transaction. \
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
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let mut send_sites: Vec<usize> = Vec::new();

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
                    send_sites.push(start + local_idx);
                }
            }

            if send_sites.len() >= 2 {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Multiple L1 messages sent in single transaction",
                    format!(
                        "Function '{}': {} send_message_to_l1 calls found (first at \
                         stmt {}, second at stmt {}). Duplicate messages cause double \
                         L1 processing and fee waste.",
                        func.name,
                        send_sites.len(),
                        send_sites[0],
                        send_sites[1]
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(send_sites[0]),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}
