use std::collections::HashSet;

use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects L2->L1 messages where the amount/payload is supplied directly by
/// the caller without being read from (and thus validated against) contract storage.
///
/// In a bridge withdrawal:
///   1. The user calls `withdraw(amount, l1_recipient)`
///   2. The contract MUST read the user's stored balance first
///   3. The contract MUST deduct that balance from storage
///   4. Only then send the L1 message with the verified amount
///
/// If step 2 is skipped — i.e. the `amount` argument flows directly into
/// `send_message_to_l1_syscall` without passing through a `storage_read_syscall`
/// result — the L2 contract allows arbitrary amounts to be claimed on L1
/// without any on-chain backing.
///
/// Vulnerable pattern:
///   fn withdraw(amount, l1_addr) {       // amount is a param
///     send_message_to_l1(l1_addr, amount);  // amount unverified ← bug
///   }
///
/// Safe pattern:
///   fn withdraw(amount, l1_addr) {
///     let balance = storage_read(BALANCE_SLOT);
///     assert(amount <= balance);
///     storage_write(BALANCE_SLOT, balance - amount);
///     send_message_to_l1(l1_addr, amount);
///   }
pub struct L2ToL1UnverifiedAmount;

/// Pass-through libfuncs — taint propagates.
const PASS_THROUGH: &[&str] = &["store_temp", "rename", "dup", "snapshot_take"];

/// Libfuncs that produce clean (storage-backed or constant) values.
const CLEAN_SOURCES: &[&str] = &[
    "storage_read_syscall",
    "felt252_const",
    "contract_address_const",
    "class_hash_const",
    "storage_base_address_const",
    "u64_const",
    "u128_const",
    "get_contract_address",
    "get_caller_address",
    "get_execution_info",
];

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

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Seed taint from non-system function params
            let mut tainted: HashSet<u64> = func
                .raw
                .params
                .iter()
                .filter_map(|(id, ty)| {
                    let ty_name = ty.debug_name.as_deref().unwrap_or("");
                    if ty_name == "System" { None } else { Some(*id) }
                })
                .collect();

            let mut has_storage_read = false;
            let mut send_site: Option<usize> = None;
            let mut tainted_payload_at_send = false;

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

                // Track storage reads — if any storage is read, assume amounts
                // may be validated (conservative: reduces FPs on read+check patterns)
                if libfunc_name.contains("storage_read") {
                    has_storage_read = true;
                    // Results from storage reads are clean / trusted
                    continue;
                }

                // Clean sources: results not tainted
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

                // Sink: send_message_to_l1_syscall
                // arg layout: [system, to_address, payload_values...]
                // payload starts at arg[2]
                if libfunc_name.contains("send_message_to_l1") {
                    let payload_tainted = inv
                        .args
                        .iter()
                        .skip(2)
                        .any(|a| tainted.contains(a));

                    if payload_tainted && send_site.is_none() {
                        send_site = Some(start + local_idx);
                        tainted_payload_at_send = true;
                    }
                    continue;
                }

                // Any other op: propagate taint
                if inv.args.iter().any(|a| tainted.contains(a)) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            tainted.insert(*r);
                        }
                    }
                }
            }

            // Fire if: L1 message sent with tainted payload AND no storage read
            // (no storage read means the amount was never backed by on-chain state)
            if let Some(site) = send_site {
                if tainted_payload_at_send && !has_storage_read {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "L1 message payload amount not backed by storage",
                        format!(
                            "Function '{}': at stmt {} send_message_to_l1 payload \
                             derives from function parameters with no storage_read \
                             in this function. The claimed amount is unverified — \
                             any caller can claim arbitrary amounts on L1.",
                            func.name, site
                        ),
                        Location {
                            file: program.source.display().to_string(),
                            function: func.name.clone(),
                            statement_idx: Some(site),
                            line: None,
                            col: None,
                        },
                    ));
                }
            }
        }

        (findings, warnings)
    }
}
