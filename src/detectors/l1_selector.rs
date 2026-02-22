use std::collections::HashSet;

use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects L1 handler functions where the message payload controls the
/// function selector passed to `call_contract_syscall` (selector injection).
///
/// This is a critical vulnerability: an L1 message effectively tells the L2
/// contract "call function X on contract Y with these args". If the selector
/// comes from the L1 payload and is not validated against a whitelist, an
/// attacker who controls the L1 side (or can send forged L1 messages if
/// `from_address` is also unchecked) can:
///
/// - Call `transfer(attacker_addr, max_amount)` on the token contract
/// - Trigger `self_destruct()` or `set_owner(attacker)` on any target
/// - Bypass role checks by routing to an unguarded internal path
///
/// Vulnerable pattern:
///   @l1_handler fn relay(from_address, target, selector, calldata) {
///     call_contract(target, selector, calldata);   // selector from L1!
///   }
///
/// Safe pattern: maintain a whitelist of allowed selectors in storage and
/// assert `selector == ALLOWED_SELECTORS[i]` before delegating.
pub struct L1HandlerUncheckedSelector;

/// Pass-through libfuncs that preserve taint.
const PASS_THROUGH: &[&str] = &["store_temp", "rename", "dup", "snapshot_take"];

/// Libfuncs that produce clean (non-payload) values.
const CLEAN_SOURCES: &[&str] = &[
    "felt252_const",
    "contract_address_const",
    "class_hash_const",
    "storage_read_syscall",
    "storage_base_address_const",
];

impl Detector for L1HandlerUncheckedSelector {
    fn id(&self) -> &'static str {
        "l1_handler_unchecked_selector"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "L1 handler uses a payload parameter as a function selector in \
         call_contract_syscall. An attacker controlling the L1 message can \
         invoke arbitrary functions on the target contract (selector injection)."
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

        for func in program.l1_handler_functions() {
            // Need at least 3 params (System + from_address + at least one payload param)
            if func.raw.params.len() < 3 {
                continue;
            }

            // Taint seed: payload params (params[2+]).
            // System (param[0]) and from_address (param[1]) are not treated as
            // attacker-controlled for the selector, though a missing from_address
            // check is a separate issue (unchecked_l1_handler).
            let mut tainted: HashSet<u64> = func
                .raw
                .params
                .iter()
                .skip(2)
                .map(|(id, _)| *id)
                .collect();

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

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

                // Clean sources — results not tainted
                if CLEAN_SOURCES.iter().any(|p| libfunc_name.contains(p)) {
                    continue;
                }

                // Pass-through: propagate taint
                if PASS_THROUGH.iter().any(|p| libfunc_name.contains(p)) {
                    if inv.args.iter().any(|a| tainted.contains(a)) {
                        for branch in &inv.branches {
                            for r in &branch.results {
                                tainted.insert(*r);
                            }
                        }
                    }
                    continue;
                }

                // Sink: call_contract_syscall
                // arg layout: [system, contract_address, selector, calldata...]
                // arg[2] = entry_point_selector
                let is_call_contract = libfunc_name.contains("call_contract");
                if is_call_contract {
                    let selector_is_tainted = inv
                        .args
                        .get(2)
                        .map(|v| tainted.contains(v))
                        .unwrap_or(false);

                    if selector_is_tainted {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "L1 payload controls call_contract selector",
                            format!(
                                "Function '{}': at stmt {} the function selector passed \
                                 to call_contract_syscall derives from an L1 message \
                                 payload parameter. An attacker can invoke arbitrary \
                                 functions on the target contract.",
                                func.name,
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
                    }
                    continue;
                }

                // Other ops: propagate taint
                if inv.args.iter().any(|a| tainted.contains(a)) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            tainted.insert(*r);
                        }
                    }
                }
            }
        }

        (findings, warnings)
    }
}
