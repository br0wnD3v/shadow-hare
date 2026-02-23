use std::collections::{HashMap, HashSet};

use crate::ir::program::ProgramIR;
use crate::ir::type_registry::LibfuncRegistry;
use crate::loader::sierra_loader::RawGenericArg;
use crate::loader::{SierraId, Statement};

/// Directed call graph for a Sierra program.
///
/// An edge (caller → callee) exists when a function contains a
/// `function_call<callee>` libfunc invocation. The graph drives
/// bottom-up summary computation for inter-procedural taint.
pub struct CallGraph {
    /// caller function_idx → unique callee function_idxs
    pub edges: HashMap<usize, Vec<usize>>,
    pub n_funcs: usize,
    /// function numeric ID → index in program.functions
    fn_by_id: HashMap<u64, usize>,
    /// function debug name → index in program.functions
    fn_by_debug: HashMap<String, usize>,
}

impl CallGraph {
    /// Build the call graph by scanning every function's statement range for
    /// `function_call` libfunc invocations.
    ///
    /// Two callee resolution strategies are tried in order:
    ///   1. `generic_args[0]` as `UserType { id: N }` — present in JSON artifacts
    ///   2. `debug_name` like `"function_call<user@module::fn>"` — when debug info is present
    ///
    /// Functions that cannot be resolved are silently skipped (graceful degradation).
    pub fn build(program: &ProgramIR) -> Self {
        let n_funcs = program.functions.len();

        let fn_by_id: HashMap<u64, usize> = program
            .functions
            .iter()
            .enumerate()
            .filter_map(|(i, f)| f.raw.id.id.map(|id| (id, i)))
            .collect();

        let fn_by_debug: HashMap<String, usize> = program
            .functions
            .iter()
            .enumerate()
            .filter_map(|(i, f)| f.raw.id.debug_name.clone().map(|n| (n, i)))
            .collect();

        let mut edges: HashMap<usize, Vec<usize>> = (0..n_funcs).map(|i| (i, Vec::new())).collect();

        for func in &program.functions {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];
            let mut seen: HashSet<usize> = HashSet::new();

            for stmt in stmts {
                let inv = match stmt {
                    Statement::Invocation(inv) => inv,
                    _ => continue,
                };

                // Only interested in function_call libfuncs
                if program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .map(|g| g != "function_call")
                    .unwrap_or(true)
                {
                    continue;
                }

                if let Some(callee_idx) = resolve_callee(
                    &inv.libfunc_id,
                    &program.libfunc_registry,
                    &fn_by_id,
                    &fn_by_debug,
                ) {
                    if callee_idx < n_funcs && seen.insert(callee_idx) {
                        edges.entry(func.idx).or_default().push(callee_idx);
                    }
                }
            }
        }

        Self {
            edges,
            n_funcs,
            fn_by_id,
            fn_by_debug,
        }
    }

    /// Resolve a `function_call` libfunc_id to the callee's function index.
    /// Returns `None` if the callee cannot be identified.
    pub fn callee_of(&self, libfunc_id: &SierraId, registry: &LibfuncRegistry) -> Option<usize> {
        resolve_callee(libfunc_id, registry, &self.fn_by_id, &self.fn_by_debug)
    }

    /// Returns function indices in bottom-up order (callees before callers).
    ///
    /// Implemented as a post-order DFS on the call graph. Back-edges (caused by
    /// direct or mutual recursion) are safely ignored — the partially-computed
    /// summary of a recursive function defaults to `false`, which is conservative
    /// (may miss FPs inside recursive chains, never introduces false negatives
    /// for the linear-call-chain pattern that constitutes almost all Cairo code).
    pub fn bottom_up_order(&self) -> Vec<usize> {
        let mut visited = vec![false; self.n_funcs];
        let mut order = Vec::with_capacity(self.n_funcs);

        for start in 0..self.n_funcs {
            if !visited[start] {
                self.dfs_post(start, &mut visited, &mut order);
            }
        }

        order
    }

    fn dfs_post(&self, node: usize, visited: &mut Vec<bool>, order: &mut Vec<usize>) {
        if visited[node] {
            return;
        }
        visited[node] = true;

        if let Some(callees) = self.edges.get(&node) {
            for &callee in callees {
                if callee < self.n_funcs {
                    self.dfs_post(callee, visited, order);
                }
            }
        }

        order.push(node);
    }
}

fn resolve_callee(
    libfunc_id: &SierraId,
    registry: &LibfuncRegistry,
    fn_by_id: &HashMap<u64, usize>,
    fn_by_debug: &HashMap<String, usize>,
) -> Option<usize> {
    let decl = registry.lookup(libfunc_id)?;

    // Strategy 1: generic_args[0] as UserType { "id": N }
    // Present in JSON-deserialized .sierra.json and .contract_class.json artifacts.
    if let Some(RawGenericArg::UserType { user_type }) = decl.generic_args.first() {
        if let Some(callee_id) = user_type.get("id").and_then(|v| v.as_u64()) {
            if let Some(&idx) = fn_by_id.get(&callee_id) {
                return Some(idx);
            }
        }
    }

    // Strategy 2: debug_name like "function_call<user@module::Contract::fn>"
    // Available when artifacts carry debug info.
    let debug = decl.id.debug_name.as_deref()?;
    let inner = debug
        .strip_prefix("function_call<user@")
        .and_then(|s| s.strip_suffix('>'))?;
    fn_by_debug.get(inner).copied()
}

// =============================================================================
// Function-level taint summaries
// =============================================================================

/// Libfuncs that convert a user-supplied felt252 directly into a raw StorageBaseAddress.
/// These are the dangerous "arbitrary slot" conversions.
const RAW_ADDR_LIBFUNCS: &[&str] = &["storage_base_address_from_felt252"];

/// Libfuncs that perform felt252 arithmetic — wraps silently modulo the field prime.
const FELT252_ARITH_LIBFUNCS: &[&str] = &["felt252_add", "felt252_sub", "felt252_mul"];

/// Libfuncs that act as range checks, sanitising a felt252 value into a bounded integer.
/// Their presence in a function means the felt252 arithmetic there is intentional/guarded.
const FELT252_RANGE_CHECK_LIBFUNCS: &[&str] = &[
    "felt252_is_zero",
    "u128_from_felt252",
    "u256_from_felt252",
    "assert_le_felt252",
    "assert_lt_felt252",
];

/// Libfuncs whose outputs are NOT considered tainted even if inputs are.
/// These produce trusted or constant values.
const SUMMARY_SANITIZERS: &[&str] = &[
    "storage_base_address_const",
    "pedersen",
    "poseidon",
    "hades_permutation",
    "felt252_const",
    "contract_address_const",
    "get_caller_address",
    "get_contract_address",
];

/// Per-function boolean summaries computed in bottom-up call graph order.
///
/// Each summary encodes a specific reachability property over the function's
/// transitive call tree. Callee summaries are folded in before the caller's
/// summary is finalised.
pub struct FunctionSummaries {
    /// `has_raw_storage_from_tainted_param[i]` is `true` if:
    ///
    /// When function `i` is called with ANY tainted (user-controlled) parameter,
    /// it (or any function it transitively calls) invokes
    /// `storage_base_address_from_felt252` with that tainted value.
    ///
    /// Detectors use this to propagate taint through `function_call` invocations:
    /// if a callee has this property and the caller passes tainted args, the
    /// callee's return values are treated as potentially-tainted storage addresses,
    /// allowing the subsequent `storage_read/write` check to fire correctly.
    pub has_raw_storage_from_tainted_param: Vec<bool>,

    /// `has_unsafe_felt252_arith_on_param[i]` is `true` if:
    ///
    /// When function `i` is called with ANY tainted parameter, it (or any function
    /// it transitively calls) performs felt252_add/sub/mul on that tainted value
    /// WITHOUT a preceding range check (felt252_is_zero, u128_from_felt252, etc.).
    ///
    /// Detectors use this to flag inter-procedural felt252 arithmetic on user input
    /// that bypasses the range-check gate — e.g. a helper that does unchecked
    /// felt252_mul on a parameter passed from an external entry point.
    pub has_unsafe_felt252_arith_on_param: Vec<bool>,

    /// Representative inter-procedural taint chain for raw storage-address
    /// conversion. Each entry is an ordered list of steps from a tainted
    /// parameter to the dangerous sink class.
    pub raw_storage_taint_chains: Vec<Vec<String>>,

    /// Representative inter-procedural taint chain for unchecked felt252
    /// arithmetic. Each entry is an ordered list of steps from a tainted
    /// parameter to the arithmetic operation.
    pub felt252_taint_chains: Vec<Vec<String>>,
}

impl FunctionSummaries {
    /// Compute summaries over all functions in bottom-up call graph order.
    pub fn compute(program: &ProgramIR, callgraph: &CallGraph) -> Self {
        let n = program.functions.len();
        let mut has_raw = vec![false; n];
        let mut has_felt_arith = vec![false; n];
        let mut raw_chains: Vec<Vec<String>> = vec![Vec::new(); n];
        let mut felt_chains: Vec<Vec<String>> = vec![Vec::new(); n];

        for func_idx in callgraph.bottom_up_order() {
            if func_idx >= n {
                continue;
            }

            let func = &program.functions[func_idx];
            let (start, end) = program.function_statement_range(func_idx);
            if start >= end {
                continue;
            }

            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Seed taint from all parameter variables
            let mut tainted: HashSet<u64> = func.raw.params.iter().map(|(id, _)| *id).collect();

            let mut found_raw = false;
            let mut found_felt_arith = false;
            let mut raw_chain: Option<Vec<String>> = None;
            let mut felt_chain: Option<Vec<String>> = None;
            // Whether a range check appeared BEFORE each arith op — tracked globally
            // for the function (conservative: any range check anywhere in the function
            // suppresses the flag, consistent with the intra-procedural detector).
            let mut has_range_check = false;

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let inv = match stmt {
                    Statement::Invocation(inv) => inv,
                    _ => continue,
                };

                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                // Range checks suppress felt252 arithmetic findings
                if FELT252_RANGE_CHECK_LIBFUNCS
                    .iter()
                    .any(|s| libfunc_name.contains(s))
                {
                    has_range_check = true;
                }

                // Sanitizers: do not propagate taint through these
                if SUMMARY_SANITIZERS.iter().any(|s| libfunc_name.contains(s)) {
                    continue;
                }

                let any_arg_tainted = inv.args.iter().any(|a| tainted.contains(a));

                // Detect: raw storage address conversion with tainted argument
                if any_arg_tainted && RAW_ADDR_LIBFUNCS.iter().any(|s| libfunc_name.contains(s)) {
                    found_raw = true;
                    if raw_chain.is_none() {
                        raw_chain = Some(vec![format!("{}@{}", libfunc_name, start + local_idx)]);
                    }
                    for branch in &inv.branches {
                        for r in &branch.results {
                            tainted.insert(*r);
                        }
                    }
                    continue;
                }

                // Detect: felt252 arithmetic on tainted value without range check
                if any_arg_tainted
                    && !has_range_check
                    && FELT252_ARITH_LIBFUNCS
                        .iter()
                        .any(|s| libfunc_name.contains(s))
                {
                    found_felt_arith = true;
                    if felt_chain.is_none() {
                        felt_chain = Some(vec![format!("{}@{}", libfunc_name, start + local_idx)]);
                    }
                }

                // Inter-procedural: function_call — fold callee summaries
                if libfunc_name == "function_call" {
                    if any_arg_tainted {
                        if let Some(callee_idx) =
                            callgraph.callee_of(&inv.libfunc_id, &program.libfunc_registry)
                        {
                            if callee_idx < n {
                                if has_raw[callee_idx] {
                                    // Callee produces raw storage addresses from tainted input.
                                    found_raw = true;
                                    if raw_chain.is_none() {
                                        let callee_name = program
                                            .functions
                                            .get(callee_idx)
                                            .map(|f| f.name.clone())
                                            .unwrap_or_else(|| format!("func_{callee_idx}"));
                                        let mut chain = vec![format!(
                                            "function_call->{}@{}",
                                            callee_name,
                                            start + local_idx
                                        )];
                                        if let Some(callee_chain) = raw_chains.get(callee_idx) {
                                            chain.extend(callee_chain.iter().cloned());
                                        }
                                        raw_chain = Some(chain);
                                    }
                                    for branch in &inv.branches {
                                        for r in &branch.results {
                                            tainted.insert(*r);
                                        }
                                    }
                                }
                                if has_felt_arith[callee_idx] && !has_range_check {
                                    // Callee performs unchecked felt252 arithmetic on user input.
                                    found_felt_arith = true;
                                    if felt_chain.is_none() {
                                        let callee_name = program
                                            .functions
                                            .get(callee_idx)
                                            .map(|f| f.name.clone())
                                            .unwrap_or_else(|| format!("func_{callee_idx}"));
                                        let mut chain = vec![format!(
                                            "function_call->{}@{}",
                                            callee_name,
                                            start + local_idx
                                        )];
                                        if let Some(callee_chain) = felt_chains.get(callee_idx) {
                                            chain.extend(callee_chain.iter().cloned());
                                        }
                                        felt_chain = Some(chain);
                                    }
                                }
                            }
                        }
                    }
                    // Do not propagate general taint through opaque function_call
                    continue;
                }

                // General taint propagation through all other libfuncs
                if any_arg_tainted {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            tainted.insert(*r);
                        }
                    }
                }
            }

            has_raw[func_idx] = found_raw;
            has_felt_arith[func_idx] = found_felt_arith;
            raw_chains[func_idx] = raw_chain.unwrap_or_default();
            felt_chains[func_idx] = felt_chain.unwrap_or_default();
        }

        Self {
            has_raw_storage_from_tainted_param: has_raw,
            has_unsafe_felt252_arith_on_param: has_felt_arith,
            raw_storage_taint_chains: raw_chains,
            felt252_taint_chains: felt_chains,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bottom_up_order_empty() {
        let cg = CallGraph {
            edges: HashMap::new(),
            n_funcs: 0,
            fn_by_id: HashMap::new(),
            fn_by_debug: HashMap::new(),
        };
        let order: Vec<usize> = cg.bottom_up_order();
        assert!(order.is_empty());
    }

    #[test]
    fn bottom_up_order_linear_chain() {
        // 0 → 1 → 2  (0 calls 1, 1 calls 2)
        // Expected bottom-up: [2, 1, 0]
        let mut edges = HashMap::new();
        edges.insert(0usize, vec![1usize]);
        edges.insert(1usize, vec![2usize]);
        edges.insert(2usize, vec![]);
        let cg = CallGraph {
            edges,
            n_funcs: 3,
            fn_by_id: HashMap::new(),
            fn_by_debug: HashMap::new(),
        };
        let order = cg.bottom_up_order();
        // 2 must come before 1, 1 before 0
        let pos: HashMap<usize, usize> = order.iter().enumerate().map(|(i, &f)| (f, i)).collect();
        assert!(pos[&2] < pos[&1]);
        assert!(pos[&1] < pos[&0]);
    }

    #[test]
    fn bottom_up_order_cycle_does_not_panic() {
        // 0 → 1 → 0 (direct cycle)
        let mut edges = HashMap::new();
        edges.insert(0usize, vec![1usize]);
        edges.insert(1usize, vec![0usize]);
        let cg = CallGraph {
            edges,
            n_funcs: 2,
            fn_by_id: HashMap::new(),
            fn_by_debug: HashMap::new(),
        };
        let order = cg.bottom_up_order();
        assert_eq!(order.len(), 2); // both nodes visited, no panic
    }
}
