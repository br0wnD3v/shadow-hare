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
}

/// Analyse a single function for the read-call-write reentrancy pattern.
///
/// Pattern: storage read → external call → storage write
/// in sequential program order (not just dominance — conservative).
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

    let func_name = program.functions[func_idx].name.clone();
    let mut results = Vec::new();

    for &call_local in &calls {
        // Look for any storage read before this call
        let read_before = storage
            .iter()
            .find(|a| matches!(a, StorageAccess::Read { stmt_idx } if *stmt_idx < call_local));

        // Look for any storage write after this call
        let write_after = storage
            .iter()
            .find(|a| matches!(a, StorageAccess::Write { stmt_idx } if *stmt_idx > call_local));

        if let (Some(read), Some(write)) = (read_before, write_after) {
            let (read_idx, write_idx) = match (read, write) {
                (StorageAccess::Read { stmt_idx: r }, StorageAccess::Write { stmt_idx: w }) => {
                    (start + r, start + w)
                }
                _ => unreachable!(),
            };

            results.push(ReentrancyEvidence {
                func_idx,
                func_name: func_name.clone(),
                read_before_call: read_idx,
                external_call: start + call_local,
                write_after_call: write_idx,
            });
        }
    }

    results
}
