use std::collections::{HashMap, HashSet};

use tracing::debug;

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

        let edge_count: usize = edges.values().map(|v| v.len()).sum();
        debug!(functions = n_funcs, edges = edge_count, "Call graph built");

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

    /// `has_library_call_from_tainted_param[i]` is `true` if:
    ///
    /// When function `i` is called with ANY tainted parameter, it (or any
    /// function it transitively calls) invokes `library_call_syscall` with
    /// a tainted class hash or entry point. Used by the `library_call` detector
    /// for inter-procedural taint propagation.
    pub has_library_call_from_tainted_param: Vec<bool>,

    /// `has_nonce_increment[i]` is `true` if function `i` reads a storage slot,
    /// performs arithmetic on the result, and writes back to the same slot
    /// (nonce read-increment-write pattern). Used by the `nonce` detector.
    pub has_nonce_increment: Vec<bool>,

    /// `has_caller_check[i]` is `true` if function `i` calls
    /// `get_caller_address` and subsequently branches on the result.
    /// Used by detectors that check for caller authentication (upgrade, unchecked_write).
    pub has_caller_check: Vec<bool>,
}

impl FunctionSummaries {
    /// Compute summaries over all functions in bottom-up call graph order.
    pub fn compute(program: &ProgramIR, callgraph: &CallGraph) -> Self {
        let n = program.functions.len();
        let mut has_raw = vec![false; n];
        let mut has_felt_arith = vec![false; n];
        let mut raw_chains: Vec<Vec<String>> = vec![Vec::new(); n];
        let mut felt_chains: Vec<Vec<String>> = vec![Vec::new(); n];
        let mut has_libcall = vec![false; n];
        let mut has_nonce = vec![false; n];
        let mut has_caller = vec![false; n];

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
            let mut found_libcall = false;
            let mut raw_chain: Option<Vec<String>> = None;
            let mut felt_chain: Option<Vec<String>> = None;

            // Track caller check: get_caller_address result flows into a branch.
            let mut caller_address_vars: HashSet<u64> = HashSet::new();
            let mut found_caller_check = false;

            // Track nonce increment: storage_read -> arith -> storage_write.
            // We track storage-read-derived vars AND the storage address vars
            // used in the read, so we can verify the write targets the same slot.
            let mut storage_read_vars: HashSet<u64> = HashSet::new();
            let mut storage_addr_vars: HashSet<u64> = HashSet::new(); // addr args from storage_read
            let mut read_then_arith = false;
            let mut arith_result_vars: HashSet<u64> = HashSet::new();
            let mut found_nonce_incr = false;
            // Per-variable tracking of which variable IDs have been range-checked.
            // Only the specific variables that pass through a range-check libfunc
            // are considered sanitised — other tainted variables remain unchecked.
            let mut range_checked_vars: HashSet<u64> = HashSet::new();

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let inv = match stmt {
                    Statement::Invocation(inv) => inv,
                    _ => continue,
                };

                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                // Range checks: track which specific variables are range-checked
                if FELT252_RANGE_CHECK_LIBFUNCS
                    .iter()
                    .any(|s| libfunc_name.contains(s))
                {
                    for &arg in &inv.args {
                        range_checked_vars.insert(arg);
                    }
                    // Also propagate: the outputs of a range check are "checked" versions
                    for branch in &inv.branches {
                        for &r in &branch.results {
                            range_checked_vars.insert(r);
                        }
                    }
                }

                // Caller check detection: get_caller_address result flows into a
                // comparison/assertion. We track the actual variable to avoid
                // flagging unrelated branches as caller checks.
                if libfunc_name.contains("get_caller_address") {
                    for branch in &inv.branches {
                        for &r in &branch.results {
                            caller_address_vars.insert(r);
                        }
                    }
                }
                // Propagate caller address through pass-through ops.
                if (libfunc_name.contains("store_temp")
                    || libfunc_name.contains("rename")
                    || libfunc_name.contains("dup")
                    || libfunc_name.contains("snapshot_take"))
                    && inv.args.iter().any(|a| caller_address_vars.contains(a))
                {
                    for branch in &inv.branches {
                        for &r in &branch.results {
                            caller_address_vars.insert(r);
                        }
                    }
                }
                // If a comparison/assertion uses a caller-address-derived variable,
                // this function has a caller check.
                if !found_caller_check
                    && (libfunc_name.contains("_is_zero")
                        || libfunc_name.contains("assert_eq")
                        || libfunc_name.contains("assert_ne")
                        || libfunc_name.contains("contract_address_try_from"))
                    && inv.args.iter().any(|a| caller_address_vars.contains(a))
                {
                    found_caller_check = true;
                }
                // Also detect OZ access control patterns via function_call debug names.
                // Common patterns: assert_only_owner, assert_only_role, _check_role,
                // OwnableImpl::assert_only_owner, AccessControlImpl::assert_only_role
                if !found_caller_check && libfunc_name == "function_call" {
                    let debug = inv.libfunc_id.debug_name.as_deref().unwrap_or("");
                    if debug.contains("assert_only_owner")
                        || debug.contains("assert_only_role")
                        || debug.contains("_check_role")
                        || debug.contains("only_owner")
                        || debug.contains("assert_owner")
                        || debug.contains("assert_caller")
                        || debug.contains("OwnableImpl")
                        || debug.contains("AccessControlImpl")
                    {
                        found_caller_check = true;
                    }
                }

                // Nonce increment detection: storage_read → arith → storage_write.
                // Track variables from storage reads. If arithmetic is performed
                // on a storage-read-derived value and then a storage_write occurs,
                // this is the classic nonce read-increment-write pattern.
                if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
                    // Track the storage address argument (first arg)
                    if let Some(&addr) = inv.args.first() {
                        storage_addr_vars.insert(addr);
                    }
                    for branch in &inv.branches {
                        for &r in &branch.results {
                            storage_read_vars.insert(r);
                        }
                    }
                }
                // Propagate storage-read-derived vars and arith-derived vars through pass-through ops.
                if libfunc_name.contains("store_temp")
                    || libfunc_name.contains("rename")
                    || libfunc_name.contains("dup")
                    || libfunc_name.contains("snapshot_take")
                {
                    let has_read = inv.args.iter().any(|a| storage_read_vars.contains(a));
                    let has_arith = inv.args.iter().any(|a| arith_result_vars.contains(a));
                    let has_addr = inv.args.iter().any(|a| storage_addr_vars.contains(a));
                    if has_read || has_arith || has_addr {
                        for branch in &inv.branches {
                            for &r in &branch.results {
                                if has_read { storage_read_vars.insert(r); }
                                if has_arith { arith_result_vars.insert(r); }
                                if has_addr { storage_addr_vars.insert(r); }
                            }
                        }
                    }
                }
                // Propagate range-checked status through pass-through ops.
                if (libfunc_name.contains("store_temp")
                    || libfunc_name.contains("rename")
                    || libfunc_name.contains("dup")
                    || libfunc_name.contains("snapshot_take"))
                    && inv.args.iter().any(|a| range_checked_vars.contains(a))
                {
                    for branch in &inv.branches {
                        for &r in &branch.results {
                            range_checked_vars.insert(r);
                        }
                    }
                }
                // Arithmetic on a storage-read-derived value.
                if (libfunc_name.contains("felt252_add")
                    || libfunc_name.contains("u128_overflowing_add")
                    || libfunc_name.contains("u64_overflowing_add")
                    || libfunc_name.contains("u32_overflowing_add")
                    || libfunc_name.contains("u256_add"))
                    && inv.args.iter().any(|a| storage_read_vars.contains(a))
                {
                    read_then_arith = true;
                    // Track the arithmetic result for same-slot write verification
                    for branch in &inv.branches {
                        for &r in &branch.results {
                            arith_result_vars.insert(r);
                        }
                    }
                }
                // Write after read+arith = nonce increment pattern.
                // Additionally verify: the write uses either an arith-derived value
                // OR the same storage address as the read (stronger same-slot signal).
                if read_then_arith && program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                    let write_uses_arith = inv.args.iter().any(|a| arith_result_vars.contains(a));
                    let write_uses_same_addr = inv.args.iter().any(|a| storage_addr_vars.contains(a));
                    if write_uses_arith || write_uses_same_addr {
                        found_nonce_incr = true;
                    }
                }

                // Library call detection: library_call_syscall with tainted args.
                if libfunc_name.contains("library_call") {
                    let any_tainted = inv.args.iter().any(|a| tainted.contains(a));
                    if any_tainted {
                        found_libcall = true;
                    }
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
                    && FELT252_ARITH_LIBFUNCS
                        .iter()
                        .any(|s| libfunc_name.contains(s))
                {
                    // Only flag if at least one tainted argument has NOT been range-checked
                    let has_unchecked_tainted_arg = inv
                        .args
                        .iter()
                        .any(|a| tainted.contains(a) && !range_checked_vars.contains(a));

                    if has_unchecked_tainted_arg {
                        found_felt_arith = true;
                        if felt_chain.is_none() {
                            felt_chain =
                                Some(vec![format!("{}@{}", libfunc_name, start + local_idx)]);
                        }
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
                                if has_felt_arith[callee_idx] {
                                    // Check if caller has unchecked tainted args flowing into the callee
                                    let has_unchecked_caller_arg = inv
                                        .args
                                        .iter()
                                        .any(|a| tainted.contains(a) && !range_checked_vars.contains(a));
                                    if has_unchecked_caller_arg {
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
                                // Fold new summaries from callee.
                                if has_libcall[callee_idx] {
                                    found_libcall = true;
                                }
                                if has_caller[callee_idx] {
                                    found_caller_check = true;
                                }
                                if has_nonce[callee_idx] {
                                    found_nonce_incr = true;
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
            has_libcall[func_idx] = found_libcall;
            has_nonce[func_idx] = found_nonce_incr;
            has_caller[func_idx] = found_caller_check;
            raw_chains[func_idx] = raw_chain.unwrap_or_default();
            felt_chains[func_idx] = felt_chain.unwrap_or_default();
        }

        Self {
            has_raw_storage_from_tainted_param: has_raw,
            has_unsafe_felt252_arith_on_param: has_felt_arith,
            raw_storage_taint_chains: raw_chains,
            felt252_taint_chains: felt_chains,
            has_library_call_from_tainted_param: has_libcall,
            has_nonce_increment: has_nonce,
            has_caller_check: has_caller,
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
