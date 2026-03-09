use std::collections::HashSet;

use crate::analysis::cfg::{BlockIdx, Cfg};
use crate::analysis::defuse::DefUseMap;
use crate::analysis::storage::{find_external_calls, find_storage_accesses, StorageAccess};
use crate::ir::program::ProgramIR;

/// Evidence of a reentrancy pattern in a single function.
#[derive(Debug, Clone)]
pub struct ReentrancyEvidence {
    pub func_idx: usize,
    pub func_name: String,
    /// Statement index of the storage read before the external call.
    pub read_before_call: usize,
    /// Statement index of the external call.
    pub external_call: usize,
    /// Statement index of the storage write after the external call.
    pub write_after_call: usize,
    /// Storage base address variable for the read (if determinable).
    pub read_storage_var: Option<u64>,
    /// Storage base address variable for the write (if determinable).
    pub write_storage_var: Option<u64>,
    /// Whether read and write target the same storage slot.
    pub same_slot: bool,
}

/// Analyse a single function for the read-call-write reentrancy pattern
/// using CFG-based reachability.
///
/// For each external call block, verifies:
///   1. A storage read block is backward-reachable from the call block.
///   2. A storage write block is forward-reachable from the call block.
///
/// This is more precise than linear scan because it respects control flow:
/// a write in a branch not reachable from the call is not flagged.
///
/// Additionally tracks storage address variables to determine whether the
/// read and write target the same storage slot, enabling the detector to
/// assign higher confidence when slots match.
pub fn check_reentrancy(program: &ProgramIR, func_idx: usize) -> Vec<ReentrancyEvidence> {
    let (start, end) = program.function_statement_range(func_idx);
    if start >= end || end > program.statements.len() {
        return Vec::new();
    }

    let stmts = &program.statements[start..end];

    let storage = find_storage_accesses(stmts, &program.libfunc_registry);
    let calls = find_external_calls(stmts, &program.libfunc_registry);

    if calls.is_empty() {
        return Vec::new();
    }

    // Build CFG for this function.
    let cfg = Cfg::build(&program.statements, start, end);

    // Map local statement indices to block indices.
    let stmt_to_block = build_stmt_to_block_map(&cfg, start);

    // Build def-use map for storage address tracing.
    let defuse = DefUseMap::for_function(program, func_idx);

    // Classify blocks by their storage access patterns.
    let read_blocks: HashSet<BlockIdx> = storage
        .iter()
        .filter_map(|a| match a {
            StorageAccess::Read { stmt_idx, .. } => stmt_to_block.get(stmt_idx).copied(),
            _ => None,
        })
        .collect();

    let write_blocks: HashSet<BlockIdx> = storage
        .iter()
        .filter_map(|a| match a {
            StorageAccess::Write { stmt_idx, .. } => stmt_to_block.get(stmt_idx).copied(),
            _ => None,
        })
        .collect();

    let func_name = program.functions[func_idx].name.clone();
    let mut results = Vec::new();

    for &call_local in &calls {
        let Some(&call_block) = stmt_to_block.get(&call_local) else {
            continue;
        };

        // Check backward reachability: is there a storage read block
        // that can reach the call block?
        let backward_reachable = backward_reachable_blocks(&cfg, call_block);
        let has_read_before = read_blocks.iter().any(|rb| backward_reachable.contains(rb));

        // Check forward reachability: is there a storage write block
        // reachable from the call block?
        let forward_reachable = forward_reachable_blocks(&cfg, call_block);
        let has_write_after = write_blocks.iter().any(|wb| forward_reachable.contains(wb));

        if has_read_before && has_write_after {
            // Find the specific read access for reporting.
            let read_access = storage
                .iter()
                .find(|a| match a {
                    StorageAccess::Read { stmt_idx, .. } => {
                        stmt_to_block
                            .get(stmt_idx)
                            .map(|block| backward_reachable.contains(block))
                            .unwrap_or(false)
                    }
                    _ => false,
                });

            let write_access = storage
                .iter()
                .find(|a| match a {
                    StorageAccess::Write { stmt_idx, .. } => {
                        stmt_to_block
                            .get(stmt_idx)
                            .map(|block| forward_reachable.contains(block))
                            .unwrap_or(false)
                    }
                    _ => false,
                });

            let (read_stmt, read_addr) = match read_access {
                Some(StorageAccess::Read { stmt_idx, addr_var }) => (*stmt_idx, *addr_var),
                _ => (0, None),
            };

            let (write_stmt, write_addr) = match write_access {
                Some(StorageAccess::Write { stmt_idx, addr_var }) => (*stmt_idx, *addr_var),
                _ => (0, None),
            };

            // Resolve storage base addresses by tracing through def-use chains.
            let read_base = read_addr.and_then(|v| resolve_storage_base(&defuse, v, program, start));
            let write_base = write_addr.and_then(|v| resolve_storage_base(&defuse, v, program, start));

            // Determine if the read and write target the same storage slot.
            let same_slot = match (read_base, write_base) {
                (Some(r), Some(w)) => r == w,
                _ => false,
            };

            results.push(ReentrancyEvidence {
                func_idx,
                func_name: func_name.clone(),
                read_before_call: start + read_stmt,
                external_call: start + call_local,
                write_after_call: start + write_stmt,
                read_storage_var: read_base,
                write_storage_var: write_base,
                same_slot,
            });
        }
    }

    results
}

/// Trace a storage address variable back through the def-use chain to find
/// the underlying `storage_base_address_const` value.
///
/// Sierra storage accesses typically look like:
///   storage_base_address_const<SLOT_ID> → addr_var
///   storage_read_syscall(addr_var, ...)
///
/// The address variable may pass through `store_temp`, `rename`, `dup`, etc.
/// We follow the def chain through pass-through libfuncs until we find a
/// `storage_base_address_const` and return its variable ID as the canonical
/// slot identifier.
fn resolve_storage_base(
    defuse: &DefUseMap,
    addr_var: u64,
    program: &ProgramIR,
    _func_start: usize,
) -> Option<u64> {
    let mut current = addr_var;

    for _ in 0..20 {
        // If the variable is a parameter, we cannot resolve further.
        if defuse.params.contains(&current) {
            return None;
        }

        let def_idx = defuse.defining_stmt(current)?;
        let stmt = program.statements.get(def_idx)?;
        let inv = stmt.as_invocation()?;

        let name = program.get_libfunc_name(&inv.libfunc_id).unwrap_or("");

        // Found the storage base address constant — return its result variable
        // as the canonical identifier for this slot.
        if name.contains("storage_base_address_const") {
            return Some(current);
        }

        // For address-related operations (storage_address_from_base, etc.),
        // trace through to the first argument.
        if name.contains("storage_address_from_base")
            || name.contains("storage_base_address_from")
        {
            if inv.args.is_empty() {
                return None;
            }
            current = inv.args[0];
            continue;
        }

        // Pass-through libfuncs: store_temp, rename, dup, snapshot, etc.
        if name.contains("store_temp")
            || name.contains("rename")
            || name.contains("dup")
            || name.contains("snapshot")
            || name.contains("into_box")
            || name.contains("unbox")
        {
            if inv.args.is_empty() {
                return None;
            }
            current = inv.args[0];
            continue;
        }

        // If we hit a struct/enum constructor or other non-pass-through operation,
        // we cannot resolve further. Still return the addr_var as a best-effort
        // identifier -- two accesses using the same addr_var likely target the
        // same slot even if we cannot fully resolve.
        break;
    }

    // Fallback: return the original addr_var so that direct comparisons still
    // work when two accesses share the same variable.
    Some(addr_var)
}

/// Build a map from local statement index to block index.
pub fn build_stmt_to_block_map(
    cfg: &Cfg,
    start: usize,
) -> std::collections::HashMap<usize, BlockIdx> {
    let mut map = std::collections::HashMap::new();
    for block in &cfg.blocks {
        for &stmt_idx in &block.stmts {
            // Convert absolute stmt_idx back to local.
            if stmt_idx >= start {
                map.insert(stmt_idx - start, block.id);
            }
        }
    }
    map
}

/// BFS backward: find all blocks that can reach `target` (including target itself).
pub fn backward_reachable_blocks(cfg: &Cfg, target: BlockIdx) -> HashSet<BlockIdx> {
    let mut visited = HashSet::new();
    let mut queue = vec![target];

    while let Some(b) = queue.pop() {
        if !visited.insert(b) {
            continue;
        }
        if let Some(preds) = cfg.predecessors.get(&b) {
            for &pred in preds {
                if !visited.contains(&pred) {
                    queue.push(pred);
                }
            }
        }
    }

    visited
}

/// BFS forward: find all blocks reachable from `source` (including source itself).
pub fn forward_reachable_blocks(cfg: &Cfg, source: BlockIdx) -> HashSet<BlockIdx> {
    let mut visited = HashSet::new();
    let mut queue = vec![source];

    while let Some(b) = queue.pop() {
        if !visited.insert(b) {
            continue;
        }
        for succ in cfg.successors(b) {
            if !visited.contains(&succ) {
                queue.push(succ);
            }
        }
    }

    visited
}
