use std::collections::HashSet;

use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects L2->L1 messages where the L1 destination address is controlled by
/// function parameters (caller-supplied input).
///
/// When `send_message_to_l1_syscall(to_address, payload...)` is called and
/// `to_address` derives from user-supplied function arguments, an attacker can
/// redirect the message to an arbitrary L1 contract. This is critical in:
///
/// - Bridge contracts: attacker redirects withdrawals to their own L1 address
/// - Oracle relays:   attacker routes price data to a malicious L1 consumer
/// - Governance:      attacker captures the L1 vote receipt
///
/// Safe pattern: `to_address` must come from contract storage or a hardcoded
/// constant, never directly from function parameters.
pub struct L2ToL1TaintedDestination;

/// Libfuncs that pass a value through without transformation.
const PASS_THROUGH: &[&str] = &["store_temp", "rename", "dup", "snapshot_take"];

/// Libfuncs whose results are considered clean (not user-tainted).
const CLEAN_SOURCES: &[&str] = &[
    "storage_read_syscall",
    "felt252_const",
    "contract_address_const",
    "class_hash_const",
    "storage_base_address_const",
    "u64_const",
    "u128_const",
    "get_contract_address",
];

impl Detector for L2ToL1TaintedDestination {
    fn id(&self) -> &'static str {
        "l2_to_l1_tainted_destination"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "L2->L1 message destination address controlled by function parameters. \
         An attacker can redirect the message to an arbitrary L1 contract, \
         enabling bridge theft or fraudulent oracle/governance messages."
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

            // Seed taint: all non-system function parameters are user-controlled.
            // System param (type "System") is always param[0]; skip it.
            let mut tainted: HashSet<u64> = func
                .raw
                .params
                .iter()
                .filter_map(|(id, ty)| {
                    let ty_name = ty.debug_name.as_deref().unwrap_or("");
                    if ty_name == "System" { None } else { Some(*id) }
                })
                .collect();

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

                // Clean-source: results are NOT tainted
                if CLEAN_SOURCES.iter().any(|p| libfunc_name.contains(p)) {
                    // Don't propagate taint from clean results
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
                // arg layout: [system, to_address, payload...]
                // arg[1] is the L1 destination address
                let is_send_l1 = libfunc_name.contains("send_message_to_l1");
                if is_send_l1 {
                    let dest_is_tainted = inv
                        .args
                        .get(1)
                        .map(|v| tainted.contains(v))
                        .unwrap_or(false);

                    if dest_is_tainted {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "L1 message destination controlled by caller",
                            format!(
                                "Function '{}': at stmt {} the to_address of \
                                 send_message_to_l1 derives from a function parameter. \
                                 An attacker can redirect this message to any L1 address.",
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

                // Any other op that consumes tainted args propagates taint to results.
                // (Arithmetic, casting, etc. keep taint alive — user can compute an address.)
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
