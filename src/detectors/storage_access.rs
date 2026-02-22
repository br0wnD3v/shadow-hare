use std::collections::HashSet;

use crate::analysis::callgraph::{CallGraph, FunctionSummaries};
use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects when a user-controlled input is used as a RAW storage address
/// (i.e., the attacker supplies the slot offset directly via
/// `storage_base_address_from_felt252`).
///
/// The common SAFE mapping pattern:
///   storage_base_address_const<SLOT_HASH>() → const_base   (NOT tainted)
///   storage_address_from_base_and_offset(const_base, user_offset) → addr
///   storage_write_syscall(sys, addr, value)
///
/// This is the compiled form of `self.balances.write(user_key, value)` and
/// is NOT flagged — the base is a compile-time constant and the offset cannot
/// escape the mapping's namespace.
///
/// The DANGEROUS pattern:
///   external fn(raw_key: felt252)
///   → storage_base_address_from_felt252(raw_key) → addr  ← raw conversion!
///   → storage_write_syscall(sys, addr, value)             ← arbitrary slot write
///
/// This allows an attacker to overwrite any storage slot (owner, total_supply, …).
/// Only `storage_base_address_from_felt252` with a tainted input triggers a finding.
pub struct TaintedStorageKey;

/// Libfuncs that convert a felt252 directly into a raw StorageBaseAddress.
/// This is the dangerous path — the user controls the slot namespace.
/// `storage_address_from_base_and_offset` is intentionally NOT included here:
/// when its base argument is a constant (from `storage_base_address_const`),
/// the result is a safe mapping key, not an arbitrary slot access.
const RAW_STORAGE_ADDR_LIBFUNCS: &[&str] = &[
    "storage_base_address_from_felt252",
];

/// Vars produced by these libfuncs are considered "trusted" (not attacker-controlled).
/// A value derived from `get_caller_address` is the caller — always valid as a mapping key.
/// A value derived from `storage_base_address_const` is a compile-time constant.
const SANITIZER_LIBFUNCS: &[&str] = &[
    "storage_base_address_const",
    "pedersen",
    "poseidon",
    "hades_permutation",
    "felt252_const",
    "contract_address_const",
    // get_caller_address and get_contract_address produce trusted identities
    // (not attacker-supplied), so their results are not propagated as taint.
    "get_caller_address",
    "get_contract_address",
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
        "User-controlled input passed to storage_base_address_from_felt252, allowing \
         an attacker to construct an arbitrary storage key. This can expose or overwrite \
         any storage slot, including privileged ones (owner, total_supply, etc.). \
         Use storage_base_address_const + storage_address_from_base_and_offset for mappings."
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

        // Build inter-procedural call graph and function summaries.
        // These allow the detector to flag cases where a called helper function
        // internally performs storage_base_address_from_felt252 with user input,
        // even though the dangerous conversion isn't visible in the entry point's
        // own statement range.
        let callgraph = CallGraph::build(program);
        let summaries = FunctionSummaries::compute(program, &callgraph);

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

                // Detect the DANGEROUS raw-address-from-felt conversion:
                //   storage_base_address_from_felt252(user_input) → raw_addr
                // Only this pattern produces a tainted storage key.
                // storage_address_from_base_and_offset is intentionally NOT tracked
                // here — when used with a constant base it represents safe mapping access.
                let is_raw_addr_conv = RAW_STORAGE_ADDR_LIBFUNCS
                    .iter()
                    .any(|p| libfunc_name.contains(p));

                if is_raw_addr_conv && inv.args.iter().any(|a| tainted.contains(a)) {
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
                    // The storage address position varies by Sierra version and syscall type.
                    //
                    // Old Sierra (2-arg read):   [system, storage_addr]         → addr at [1]
                    // Mid Sierra (3-arg read):   [gas, system, storage_addr]    → addr at [2]
                    // New Sierra (4-arg read):   [gas, sys, domain, addr]       → addr at [3]
                    //
                    // For storage_read_syscall: StorageAddress is always the LAST arg.
                    //
                    // Old Sierra (3-arg write):  [system, storage_addr, value]  → addr at [1]
                    // Mid Sierra (4-arg write):  [gas, sys, storage_addr, val]  → addr at [2]
                    // New Sierra (5-arg write):  [gas, sys, domain, addr, val]  → addr at [3]
                    //
                    // For storage_write_syscall: StorageAddress is always SECOND-TO-LAST.
                    //
                    // Using positional heuristics avoids needing type information.
                    let key_var: Option<u64> = if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
                        inv.args.last().copied()
                    } else {
                        // storage_write: second-to-last arg is the address, last is the value
                        let n = inv.args.len();
                        if n >= 2 { inv.args.get(n - 2).copied() } else { None }
                    };

                    let key_is_tainted = key_var
                        .map(|k| tainted.contains(&k))
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

                // Special case: storage_address_from_base_and_offset(base, offset)
                // This is the compiled form of a mapping access: `map.read(key)`.
                // The result is only tainted if the BASE argument (arg[0]) is tainted.
                // If only the OFFSET (arg[1]) is tainted, the result is safe because
                // the access is bounded to the specific mapping's namespace.
                if libfunc_name.contains("storage_address_from_base_and_offset") {
                    let base_is_tainted = inv.args.first().map(|a| tainted.contains(a)).unwrap_or(false);
                    if base_is_tainted {
                        for branch in &inv.branches {
                            for r in &branch.results {
                                tainted.insert(*r);
                            }
                        }
                    }
                    // If only offset is tainted but base is constant → safe, don't propagate
                    continue;
                }

                // function_call libfuncs: do not propagate general taint through
                // opaque function boundaries, EXCEPT when inter-procedural summaries
                // tell us the callee is known to produce raw storage addresses from
                // its tainted inputs.
                //
                // Without this exception, a pattern like:
                //   external_fn(user_key):
                //     raw_addr = helper(user_key)  ← function_call: was silently skipped
                //     storage_write(raw_addr, val)  ← not flagged (raw_addr not tainted)
                //
                // where `helper` internally calls `storage_base_address_from_felt252(user_key)`
                // would be missed entirely. The summary propagation below closes that gap.
                if libfunc_name == "function_call" {
                    if inv.args.iter().any(|a| tainted.contains(a)) {
                        if let Some(callee_idx) =
                            callgraph.callee_of(&inv.libfunc_id, &program.libfunc_registry)
                        {
                            if summaries
                                .has_raw_storage_from_tainted_param
                                .get(callee_idx)
                                .copied()
                                .unwrap_or(false)
                            {
                                // Callee is known to produce a raw storage address from its
                                // tainted input. Propagate taint to its return values so the
                                // subsequent storage_read/write check fires correctly.
                                for branch in &inv.branches {
                                    for r in &branch.results {
                                        tainted.insert(*r);
                                    }
                                }
                            }
                        }
                    }
                    continue;
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
