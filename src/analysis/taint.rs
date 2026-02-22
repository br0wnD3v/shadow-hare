use std::collections::HashSet;

use crate::analysis::dataflow::ForwardAnalysis;
use crate::ir::type_registry::LibfuncRegistry;
use crate::loader::Statement;

/// Taint domain: a set of variable IDs that are tainted.
/// An empty set means nothing is tainted.
pub type TaintSet = HashSet<u64>;

/// Taint analysis: propagates taint from user-controlled inputs to sinks.
///
/// A variable is tainted if:
/// - It is an initial taint seed (e.g. L1 from_address, user-supplied calldata).
/// - It is produced by an invocation where at least one argument is tainted,
///   unless that invocation matches a sanitizer pattern.
///
/// Sanitizers break the taint chain — their outputs are not tainted even when
/// their inputs are. Use this for libfuncs that produce trusted values regardless
/// of their inputs (e.g. `get_caller_address`, `storage_base_address_const`,
/// `pedersen`, `felt252_const`).
///
/// Skipped libfuncs do not propagate taint at all — use this for opaque calls
/// whose taint semantics are handled externally (e.g. `function_call`).
pub struct TaintAnalysis<'a> {
    pub libfuncs: &'a LibfuncRegistry,
    /// Variables that are taint seeds (controlled by adversary).
    pub seeds: HashSet<u64>,
    /// Libfunc name substrings whose outputs should NOT be tainted,
    /// even if their inputs are. (Sanitizers — trusted value producers.)
    pub sanitizers: &'a [&'a str],
    /// Libfunc name substrings that should be skipped entirely — taint
    /// is neither propagated to outputs nor blocked; the invocation is a no-op
    /// for taint purposes. Use for function_call and other opaque boundaries.
    pub skip_libfuncs: &'a [&'a str],
}

impl<'a> ForwardAnalysis for TaintAnalysis<'a> {
    type Domain = TaintSet;

    fn bottom(&self) -> TaintSet {
        self.seeds.clone()
    }

    fn transfer_stmt(&self, tainted: &TaintSet, stmt: &Statement) -> TaintSet {
        match stmt {
            Statement::Return(_) => tainted.clone(),
            Statement::Invocation(inv) => {
                let name = self
                    .libfuncs
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                // Skip libfuncs: no taint change at all
                if self.skip_libfuncs.iter().any(|p| name.contains(p)) {
                    return tainted.clone();
                }

                let any_arg_tainted = inv.args.iter().any(|a| tainted.contains(a));

                if any_arg_tainted {
                    // Sanitizers: break the chain — don't taint outputs
                    if self.sanitizers.iter().any(|p| name.contains(p)) {
                        return tainted.clone();
                    }

                    let mut next = tainted.clone();
                    for branch in &inv.branches {
                        for result in &branch.results {
                            next.insert(*result);
                        }
                    }
                    next
                } else {
                    tainted.clone()
                }
            }
        }
    }

    fn join(&self, a: &TaintSet, b: &TaintSet) -> TaintSet {
        a.union(b).copied().collect()
    }
}

/// Check whether a variable is ever used as an argument to a matching libfunc.
/// Returns the statement index where the tainted value reaches the sink.
pub fn taint_reaches_sink(
    tainted_vars: &TaintSet,
    stmts: &[crate::loader::Statement],
    libfunc_pattern: &str,
    libfuncs: &LibfuncRegistry,
) -> Vec<usize> {
    let mut sink_sites = Vec::new();
    for (idx, stmt) in stmts.iter().enumerate() {
        if let Statement::Invocation(inv) = stmt {
            if libfuncs.matches(&inv.libfunc_id, libfunc_pattern) {
                if inv.args.iter().any(|a| tainted_vars.contains(a)) {
                    sink_sites.push(idx);
                }
            }
        }
    }
    sink_sites
}
