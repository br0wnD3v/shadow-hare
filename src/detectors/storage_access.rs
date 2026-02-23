use std::collections::{HashMap, HashSet};

use crate::analysis::callgraph::{CallGraph, FunctionSummaries};
use crate::analysis::cfg::{BlockIdx, Cfg};
use crate::analysis::dataflow::{run_forward, ForwardAnalysis};
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
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
const RAW_STORAGE_ADDR_LIBFUNCS: &[&str] = &["storage_base_address_from_felt252"];

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

struct StorageKeyTaintAnalysis<'a> {
    program: &'a ProgramIR,
    callgraph: &'a CallGraph,
    summaries: &'a FunctionSummaries,
    seeds: HashSet<u64>,
}

impl<'a> ForwardAnalysis for StorageKeyTaintAnalysis<'a> {
    type Domain = HashSet<u64>;

    fn bottom(&self) -> Self::Domain {
        self.seeds.clone()
    }

    fn transfer_stmt(
        &self,
        tainted: &Self::Domain,
        stmt: &crate::loader::Statement,
    ) -> Self::Domain {
        let inv = match stmt.as_invocation() {
            Some(inv) => inv,
            None => return tainted.clone(),
        };

        let libfunc_name = self
            .program
            .libfunc_registry
            .generic_id(&inv.libfunc_id)
            .or_else(|| inv.libfunc_id.debug_name.as_deref())
            .unwrap_or("");

        // Sanitizers break the taint chain — results are no longer tainted.
        if SANITIZER_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
            return tainted.clone();
        }

        let mut next = tainted.clone();

        // Dangerous raw-address conversion only taints when the key arg is tainted.
        let is_raw_addr_conv = RAW_STORAGE_ADDR_LIBFUNCS
            .iter()
            .any(|p| libfunc_name.contains(p));
        if is_raw_addr_conv {
            let key_is_tainted = inv
                .args
                .last()
                .map(|a| tainted.contains(a))
                .unwrap_or(false);
            if key_is_tainted {
                for branch in &inv.branches {
                    for r in &branch.results {
                        next.insert(*r);
                    }
                }
            }
            return next;
        }

        // Mapping pattern: only the BASE carries storage namespace authority.
        if libfunc_name.contains("storage_address_from_base_and_offset") {
            let base_is_tainted = inv
                .args
                .first()
                .map(|a| tainted.contains(a))
                .unwrap_or(false);
            if base_is_tainted {
                for branch in &inv.branches {
                    for r in &branch.results {
                        next.insert(*r);
                    }
                }
            }
            return next;
        }

        // Opaque call boundary: propagate only when summaries prove the callee
        // can produce raw storage addresses from tainted inputs.
        if libfunc_name == "function_call" {
            if inv.args.iter().any(|a| tainted.contains(a)) {
                if let Some(callee_idx) = self
                    .callgraph
                    .callee_of(&inv.libfunc_id, &self.program.libfunc_registry)
                {
                    let produces_raw_storage = self
                        .summaries
                        .has_raw_storage_from_tainted_param
                        .get(callee_idx)
                        .copied()
                        .unwrap_or(false);
                    let returns_storage_addr =
                        function_returns_storage_address(callee_idx, self.program);
                    if produces_raw_storage && returns_storage_addr {
                        for branch in &inv.branches {
                            for r in &branch.results {
                                next.insert(*r);
                            }
                        }
                    }
                }
            }
            return next;
        }

        // Default propagation for regular libfuncs.
        if inv.args.iter().any(|a| tainted.contains(a)) {
            for branch in &inv.branches {
                for r in &branch.results {
                    next.insert(*r);
                }
            }
        }

        next
    }

    fn join(&self, a: &Self::Domain, b: &Self::Domain) -> Self::Domain {
        a.union(b).copied().collect()
    }
}

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

            let seeds: HashSet<u64> = func.raw.params.iter().map(|(id, _)| *id).collect();
            let analysis = StorageKeyTaintAnalysis {
                program,
                callgraph: &callgraph,
                summaries: &summaries,
                seeds,
            };
            let cfg = Cfg::build(
                &program.statements,
                start,
                end.min(program.statements.len()),
            );
            let block_out = run_forward(&analysis, &cfg, &program.statements);

            for block_id in cfg.topological_order() {
                let block = &cfg.blocks[block_id];
                let mut tainted = block_entry_state(&analysis, &cfg, block_id, &block_out);

                for &stmt_idx in &block.stmts {
                    let stmt = &program.statements[stmt_idx];
                    if let Some(inv) = stmt.as_invocation() {
                        // Check if the storage key argument is tainted for
                        // storage_read_syscall and storage_write_syscall.
                        let is_storage_op =
                            program.libfunc_registry.is_storage_read(&inv.libfunc_id)
                                || program.libfunc_registry.is_storage_write(&inv.libfunc_id);

                        if is_storage_op {
                            let key_var: Option<u64> =
                                if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
                                    inv.args.last().copied()
                                } else {
                                    // storage_write: second-to-last arg is the address, last is the value
                                    let n = inv.args.len();
                                    if n >= 2 {
                                        inv.args.get(n - 2).copied()
                                    } else {
                                        None
                                    }
                                };

                            let key_is_tainted =
                                key_var.map(|k| tainted.contains(&k)).unwrap_or(false);

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
                                        func.name, stmt_idx
                                    ),
                                    Location {
                                        file: program.source.display().to_string(),
                                        function: func.name.clone(),
                                        statement_idx: Some(stmt_idx),
                                        line: None,
                                        col: None,
                                    },
                                ));
                            }
                        }
                    }

                    tainted = analysis.transfer_stmt(&tainted, stmt);
                }
            }
        }

        (findings, warnings)
    }
}

fn block_entry_state<A: ForwardAnalysis>(
    analysis: &A,
    cfg: &Cfg,
    block_id: BlockIdx,
    block_out: &HashMap<BlockIdx, A::Domain>,
) -> A::Domain {
    if block_id == cfg.entry {
        return analysis.bottom();
    }

    let Some(preds) = cfg.predecessors.get(&block_id) else {
        return analysis.bottom();
    };
    if preds.is_empty() {
        return analysis.bottom();
    }

    let mut it = preds.iter();
    let first = it.next().expect("preds is non-empty");
    let mut acc = block_out
        .get(first)
        .cloned()
        .unwrap_or_else(|| analysis.bottom());
    for pred in it {
        let pred_out = block_out
            .get(pred)
            .cloned()
            .unwrap_or_else(|| analysis.bottom());
        acc = analysis.join(&acc, &pred_out);
    }
    acc
}

fn function_returns_storage_address(func_idx: usize, program: &ProgramIR) -> bool {
    let func = match program.functions.get(func_idx) {
        Some(f) => f,
        None => return false,
    };
    func.raw
        .ret_types
        .iter()
        .any(|ty| is_storage_address_type(ty, program))
}

fn is_storage_address_type(ty: &crate::loader::SierraId, program: &ProgramIR) -> bool {
    let looks_like_storage = |name: &str| {
        name.contains("StorageAddress")
            || name.contains("StorageBaseAddress")
            || name.contains("storage_address")
            || name.contains("storage_base_address")
    };

    if let Some(name) = ty.debug_name.as_deref() {
        if looks_like_storage(name) {
            return true;
        }
    }

    if let Some(decl) = program.type_registry.lookup(ty) {
        if looks_like_storage(&decl.generic_id) {
            return true;
        }
        if let Some(name) = decl.id.debug_name.as_deref() {
            if looks_like_storage(name) {
                return true;
            }
        }
    }

    false
}
