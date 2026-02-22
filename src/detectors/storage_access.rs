use std::collections::HashSet;

use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects when a user-controlled input (external function parameter) is used
/// directly as a storage address key in storage_read_syscall or
/// storage_write_syscall without going through a known-safe transformation
/// (hash, constant-base-address, etc.).
///
/// In Starknet, storage keys are computed from slot names at compile time via
/// `storage_base_address_const<N>`. Allowing an attacker to supply the raw
/// storage address directly lets them read or overwrite any storage slot,
/// including the contract owner slot.
///
/// Vulnerable pattern:
///   external fn(user_addr: felt252)
///   → storage_base_address_from_felt252(user_addr) → addr_var
///   → storage_read_syscall(sys, addr_var)  ← attacker-controlled slot
///
/// Safe pattern: use storage_base_address_const<SLOT_HASH> from contract code,
/// then optionally storage_address_from_base_and_offset for mappings.
pub struct TaintedStorageKey;

/// Libfuncs that convert a felt252 into a StorageBaseAddress.
/// If a user-param passes through one of these it becomes a tainted storage key.
const STORAGE_KEY_FROM_FELT_LIBFUNCS: &[&str] = &[
    "storage_base_address_from_felt252",
    "storage_address_from_base",
    "storage_address_from_base_and_offset",
];

/// Libfuncs that sanitize a value so it is no longer tainted.
/// These are hardcoded constants or cryptographic hash functions.
const SANITIZER_LIBFUNCS: &[&str] = &[
    "storage_base_address_const",
    "pedersen",
    "poseidon",
    "hades_permutation",
    "felt252_const",
];

impl Detector for TaintedStorageKey {
    fn id(&self) -> &'static str {
        "tainted_storage_key"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "User-controlled input used directly as a storage address key without \
         hash or constant-base transformation. An attacker can read or write \
         arbitrary storage slots, including privileged ones."
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

            // Start taint from all external params
            let mut tainted: HashSet<u64> =
                func.raw.params.iter().map(|(id, _)| *id).collect();

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

                // Sanitizers break the taint chain — results are no longer tainted
                if SANITIZER_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                    // Do NOT propagate taint through sanitizers
                    continue;
                }

                // If this libfunc converts a tainted felt252 into a storage address,
                // its results are tainted storage keys
                let is_key_conversion = STORAGE_KEY_FROM_FELT_LIBFUNCS
                    .iter()
                    .any(|p| libfunc_name.contains(p));

                if is_key_conversion && inv.args.iter().any(|a| tainted.contains(a)) {
                    // Results are tainted storage address vars
                    for branch in &inv.branches {
                        for r in &branch.results {
                            tainted.insert(*r);
                        }
                    }
                    continue;
                }

                // Check if the storage key argument (arg[1]) is tainted for
                // storage_read_syscall and storage_write_syscall
                let is_storage_op = program.libfunc_registry.is_storage_read(&inv.libfunc_id)
                    || program.libfunc_registry.is_storage_write(&inv.libfunc_id);

                if is_storage_op {
                    // arg[0] = system, arg[1] = storage_address (the key)
                    let key_is_tainted = inv
                        .args
                        .get(1)
                        .map(|k| tainted.contains(k))
                        .unwrap_or(false);

                    if key_is_tainted {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "User-controlled storage key",
                            format!(
                                "Function '{}': storage operation at stmt {} uses a key \
                                 derived from user-controlled input. An attacker can \
                                 read or overwrite arbitrary storage slots.",
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
                }

                // Propagate taint through other ops
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
