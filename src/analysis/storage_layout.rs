use std::collections::HashMap;

use crate::ir::program::ProgramIR;
use crate::loader::Statement;

/// A single storage slot identified in the contract.
#[derive(Debug, Clone)]
pub struct StorageSlot {
    /// The raw constant value from `storage_base_address_const<VALUE>`.
    pub address_const: String,
    /// Statement index where this slot constant is defined.
    pub defined_at: usize,
    /// Variable ID that receives the storage base address.
    pub var_id: Option<u64>,
    /// Human-readable name inferred from debug info (if available).
    pub name: Option<String>,
}

/// Storage layout extracted from a program's Sierra IR.
#[derive(Debug, Clone)]
pub struct StorageLayout {
    pub slots: Vec<StorageSlot>,
    /// Map from address constant string → list of slot indices.
    by_address: HashMap<String, Vec<usize>>,
    /// Map from variable ID → slot index (for the defining var).
    by_var: HashMap<u64, usize>,
}

impl StorageLayout {
    /// Extract storage layout from a ProgramIR by scanning for
    /// `storage_base_address_const` libfuncs.
    pub fn extract(program: &ProgramIR) -> Self {
        let mut slots = Vec::new();
        let mut by_address: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_var: HashMap<u64, usize> = HashMap::new();

        for (stmt_idx, stmt) in program.statements.iter().enumerate() {
            let inv = match stmt {
                Statement::Invocation(inv) => inv,
                _ => continue,
            };

            let name = program
                .libfunc_registry
                .generic_id(&inv.libfunc_id)
                .or(inv.libfunc_id.debug_name.as_deref())
                .unwrap_or("");

            if !name.contains("storage_base_address_const") {
                continue;
            }

            // Extract the constant value from the libfunc name.
            // Pattern: "storage_base_address_const<VALUE>"
            let address_const = extract_const_value(name).unwrap_or_else(|| name.to_string());

            // The result variable is in the first branch's results.
            let var_id = inv
                .branches
                .first()
                .and_then(|b| b.results.first().copied());

            // Try to infer a name from nearby debug info or source locations.
            let slot_name = infer_slot_name(program, stmt_idx);

            let slot_idx = slots.len();
            slots.push(StorageSlot {
                address_const: address_const.clone(),
                defined_at: stmt_idx,
                var_id,
                name: slot_name,
            });

            by_address.entry(address_const).or_default().push(slot_idx);
            if let Some(vid) = var_id {
                by_var.insert(vid, slot_idx);
            }
        }

        Self {
            slots,
            by_address,
            by_var,
        }
    }

    /// Get all slots with the same address constant. Multiple entries
    /// indicate the same slot is accessed at multiple locations.
    pub fn slots_for_address(&self, address_const: &str) -> &[usize] {
        self.by_address
            .get(address_const)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Find the slot associated with a variable ID (the defining var of the
    /// storage base address constant).
    pub fn slot_for_var(&self, var_id: u64) -> Option<&StorageSlot> {
        self.by_var.get(&var_id).map(|&idx| &self.slots[idx])
    }

    /// Detect potential storage collisions — multiple distinct const values
    /// that hash to the same slot are flagged by the Starknet compiler, but
    /// multiple usages of the SAME const across different functions is normal.
    /// This returns address constants that appear in multiple distinct function
    /// contexts, which can help verify nonce slot identity.
    pub fn unique_slot_addresses(&self) -> Vec<&str> {
        self.by_address.keys().map(|s| s.as_str()).collect()
    }

    /// Check if two statement indices use the same storage slot.
    pub fn same_slot(&self, stmt_a: usize, stmt_b: usize) -> bool {
        let slot_a = self.slots.iter().find(|s| s.defined_at == stmt_a);
        let slot_b = self.slots.iter().find(|s| s.defined_at == stmt_b);
        match (slot_a, slot_b) {
            (Some(a), Some(b)) => a.address_const == b.address_const,
            _ => false,
        }
    }
}

/// Extract the value from a pattern like `storage_base_address_const<12345>`.
fn extract_const_value(name: &str) -> Option<String> {
    let start = name.find('<')?;
    let end = name.find('>')?;
    if end > start + 1 {
        Some(name[start + 1..end].to_string())
    } else {
        None
    }
}

/// Try to infer a human-readable name for a storage slot from debug info.
/// Looks at nearby statements for function_call debug names that reference
/// storage variable names (e.g. `contract::balance::read`).
fn infer_slot_name(program: &ProgramIR, stmt_idx: usize) -> Option<String> {
    let scan_start = stmt_idx.saturating_sub(3);
    let scan_end = (stmt_idx + 8).min(program.statements.len());
    for idx in scan_start..scan_end {
        if let Some(inv) = program.statements[idx].as_invocation() {
            let name = program
                .libfunc_registry
                .generic_id(&inv.libfunc_id)
                .or(inv.libfunc_id.debug_name.as_deref())
                .unwrap_or("");
            // function_call libfuncs carry the callee path in the debug name.
            if name.contains("function_call") {
                if let Some(ref debug_name) = inv.libfunc_id.debug_name {
                    if let Some(storage_name) = extract_storage_name_from_function(debug_name) {
                        return Some(storage_name);
                    }
                }
            }
        }
    }

    None
}

/// Extract a storage variable name from a function path like
/// `contract::storage::balance::read` → "balance".
fn extract_storage_name_from_function(func_name: &str) -> Option<String> {
    let parts: Vec<&str> = func_name.split("::").collect();
    // Look for patterns like `Module::storage_var_name::read/write/address`
    for (i, part) in parts.iter().enumerate() {
        if (*part == "read" || *part == "write" || *part == "address") && i > 0 {
            return Some(parts[i - 1].to_string());
        }
    }
    None
}
