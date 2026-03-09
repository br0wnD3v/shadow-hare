use crate::loader::Statement;

/// Storage access classification for a single statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageAccess {
    Read {
        stmt_idx: usize,
        /// The first argument (storage address variable) of the syscall, if available.
        addr_var: Option<u64>,
    },
    Write {
        stmt_idx: usize,
        /// The first argument (storage address variable) of the syscall, if available.
        addr_var: Option<u64>,
    },
}

/// Classify all storage accesses in a function's statement range.
pub fn find_storage_accesses(
    stmts: &[Statement],
    libfuncs: &crate::ir::type_registry::LibfuncRegistry,
) -> Vec<StorageAccess> {
    stmts
        .iter()
        .enumerate()
        .filter_map(|(idx, stmt)| {
            let inv = stmt.as_invocation()?;
            if libfuncs.is_storage_read(&inv.libfunc_id) {
                let addr_var = inv.args.first().copied();
                Some(StorageAccess::Read { stmt_idx: idx, addr_var })
            } else if libfuncs.is_storage_write(&inv.libfunc_id) {
                let addr_var = inv.args.first().copied();
                Some(StorageAccess::Write { stmt_idx: idx, addr_var })
            } else {
                None
            }
        })
        .collect()
}

/// Find all external call statement indices.
pub fn find_external_calls(
    stmts: &[Statement],
    libfuncs: &crate::ir::type_registry::LibfuncRegistry,
) -> Vec<usize> {
    stmts
        .iter()
        .enumerate()
        .filter(|(_, stmt)| {
            stmt.as_invocation()
                .map(|inv| libfuncs.is_external_call(&inv.libfunc_id))
                .unwrap_or(false)
        })
        .map(|(idx, _)| idx)
        .collect()
}
