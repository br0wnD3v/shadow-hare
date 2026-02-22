use std::collections::HashSet;

use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects L1 handler functions that write raw L1 payload data directly into
/// contract storage without any transformation or validation.
///
/// L1 message payload params are externally-controlled data (from Ethereum).
/// Writing them verbatim to storage slots lets an L1-side attacker (or a
/// compromised/upgraded L1 contract) overwrite arbitrary L2 state:
///
/// - Overwrite the stored owner/admin address
/// - Replace a configuration value (fee rate, cap, pause flag)
/// - Poison an exchange rate used in subsequent calculations
///
/// Vulnerable pattern:
///   @l1_handler fn update_config(from_address, new_owner) {
///     storage_write(OWNER_SLOT, new_owner);   // raw L1 input stored
///   }
///
/// Safe pattern: validate new_owner (e.g. check it != 0 and against an ACL)
/// before writing, or require a 2-of-2 confirmation via governance.
///
/// Note: this fires only when the STORED VALUE (storage_write arg[2]) derives
/// from payload. Writing payload to a non-critical slot via a hash function is
/// considered safe (the hash function acts as a sanitizer).
pub struct L1HandlerPayloadToStorage;

/// Pass-through libfuncs: taint propagates unchanged.
const PASS_THROUGH: &[&str] = &["store_temp", "rename", "dup", "snapshot_take"];

/// Sanitizer libfuncs: outputs are not considered raw L1 data anymore.
/// Hash functions transform the input, breaking the direct L1->storage link.
const SANITIZERS: &[&str] = &[
    "pedersen",
    "poseidon",
    "hades_permutation",
    "felt252_const",
    "storage_base_address_const",
    "u64_const",
    "u128_const",
    // Comparisons / zero-checks don't sanitize the VALUE — they just branch.
    // Arithmetic doesn't sanitize (value is still attacker-influenced).
];

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

        for func in program.l1_handler_functions() {
            // Need at least 3 params (System + from_address + payload[0])
            if func.raw.params.len() < 3 {
                continue;
            }

            // Taint seed: payload params (index 2+)
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

                // Sanitizers: results are clean
                if SANITIZERS.iter().any(|p| libfunc_name.contains(p)) {
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

                // Sink: storage_write — check if VALUE arg (arg[2]) is tainted
                if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                    let value_tainted = inv
                        .args
                        .get(2)
                        .map(|v| tainted.contains(v))
                        .unwrap_or(false);

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

                // Any other op: propagate taint through results
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
