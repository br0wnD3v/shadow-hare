use std::collections::HashMap;

use crate::loader::{LibfuncDeclaration, SierraId, TypeDeclaration};

/// Non-panicking type registry. All lookups return Option<T>.
/// Unknown types produce a warning, never a panic.
#[derive(Debug, Default)]
pub struct TypeRegistry {
    /// Map from type ID (numeric or named) → declaration index.
    by_id: HashMap<u64, usize>,
    /// Map from debug name → declaration index.
    by_name: HashMap<String, usize>,
    pub declarations: Vec<TypeDeclaration>,
}

impl TypeRegistry {
    pub fn build(declarations: Vec<TypeDeclaration>) -> Self {
        let mut by_id = HashMap::new();
        let mut by_name = HashMap::new();

        for (idx, decl) in declarations.iter().enumerate() {
            if let Some(id) = decl.id.id {
                by_id.insert(id, idx);
            }
            if let Some(name) = &decl.id.debug_name {
                by_name.insert(name.clone(), idx);
            }
            // Also index by generic_id (e.g. "felt252", "u256", etc.)
            by_name.insert(decl.generic_id.clone(), idx);
        }

        Self {
            by_id,
            by_name,
            declarations,
        }
    }

    pub fn lookup(&self, id: &SierraId) -> Option<&TypeDeclaration> {
        if let Some(num_id) = id.id {
            if let Some(&idx) = self.by_id.get(&num_id) {
                return Some(&self.declarations[idx]);
            }
        }
        if let Some(name) = &id.debug_name {
            if let Some(&idx) = self.by_name.get(name) {
                return Some(&self.declarations[idx]);
            }
        }
        None
    }

    pub fn lookup_by_name(&self, name: &str) -> Option<&TypeDeclaration> {
        self.by_name.get(name).map(|&idx| &self.declarations[idx])
    }

    pub fn is_integer_type(&self, id: &SierraId) -> bool {
        let name = id.debug_name.as_deref().unwrap_or("");
        name.contains("u256")
            || name.contains("u128")
            || name.contains("u64")
            || name.contains("u32")
            || name.contains("u16")
            || name.contains("u8")
            || name.contains("felt252")
            || name.contains("i128")
    }

    pub fn is_felt252(&self, id: &SierraId) -> bool {
        id.debug_name
            .as_deref()
            .map(|n| n.contains("felt252"))
            .unwrap_or(false)
    }

    pub fn is_u256(&self, id: &SierraId) -> bool {
        id.debug_name
            .as_deref()
            .map(|n| n.contains("u256"))
            .unwrap_or(false)
    }
}

/// Non-panicking libfunc registry.
#[derive(Debug, Default)]
pub struct LibfuncRegistry {
    by_id: HashMap<u64, usize>,
    by_name: HashMap<String, usize>,
    pub declarations: Vec<LibfuncDeclaration>,
}

impl LibfuncRegistry {
    pub fn build(declarations: Vec<LibfuncDeclaration>) -> Self {
        let mut by_id = HashMap::new();
        let mut by_name = HashMap::new();

        for (idx, decl) in declarations.iter().enumerate() {
            if let Some(id) = decl.id.id {
                by_id.insert(id, idx);
            }
            if let Some(name) = &decl.id.debug_name {
                by_name.insert(name.clone(), idx);
            }
            by_name.insert(decl.generic_id.clone(), idx);
        }

        Self {
            by_id,
            by_name,
            declarations,
        }
    }

    pub fn lookup(&self, id: &SierraId) -> Option<&LibfuncDeclaration> {
        if let Some(num_id) = id.id {
            if let Some(&idx) = self.by_id.get(&num_id) {
                return Some(&self.declarations[idx]);
            }
        }
        if let Some(name) = &id.debug_name {
            if let Some(&idx) = self.by_name.get(name) {
                return Some(&self.declarations[idx]);
            }
        }
        None
    }

    /// Resolve the generic_id (function family name) for a Sierra ID.
    pub fn generic_id(&self, id: &SierraId) -> Option<&str> {
        self.lookup(id).map(|d| d.generic_id.as_str())
    }

    /// Check whether a libfunc ID matches a known pattern by generic name.
    pub fn matches(&self, id: &SierraId, pattern: &str) -> bool {
        // First try the debug_name on the ID itself
        if let Some(name) = &id.debug_name {
            if name.contains(pattern) {
                return true;
            }
        }
        // Then look up in declarations
        if let Some(decl) = self.lookup(id) {
            if decl.generic_id.contains(pattern) {
                return true;
            }
        }
        false
    }

    /// Returns true if the libfunc is a syscall.
    pub fn is_syscall(&self, id: &SierraId) -> bool {
        self.matches(id, "syscall")
    }

    /// Returns true if the libfunc is a storage_read or storage_write.
    pub fn is_storage_read(&self, id: &SierraId) -> bool {
        self.matches(id, "storage_read")
    }

    pub fn is_storage_write(&self, id: &SierraId) -> bool {
        self.matches(id, "storage_write")
    }

    /// Returns true if the libfunc is a cross-contract call.
    pub fn is_external_call(&self, id: &SierraId) -> bool {
        self.matches(id, "call_contract") || self.matches(id, "library_call")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::SierraId;

    fn make_id(id: u64, name: &str) -> SierraId {
        SierraId {
            id: Some(id),
            debug_name: Some(name.to_string()),
        }
    }

    #[test]
    fn type_registry_lookup_by_id() {
        use crate::loader::TypeDeclaration;
        let decls = vec![TypeDeclaration {
            id: make_id(0, "felt252"),
            generic_id: "felt252".to_string(),
            generic_args: vec![],
            info: None,
        }];
        let reg = TypeRegistry::build(decls);
        let id = make_id(0, "felt252");
        assert!(reg.lookup(&id).is_some());
    }

    #[test]
    fn type_registry_unknown_returns_none() {
        let reg = TypeRegistry::build(vec![]);
        let id = SierraId {
            id: Some(999),
            debug_name: Some("unknown_type".to_string()),
        };
        assert!(reg.lookup(&id).is_none()); // must not panic
    }

    #[test]
    fn libfunc_matches_pattern() {
        use crate::loader::LibfuncDeclaration;
        let decls = vec![LibfuncDeclaration {
            id: make_id(0, "u256_overflowing_sub"),
            generic_id: "u256_overflowing_sub".to_string(),
            generic_args: vec![],
        }];
        let reg = LibfuncRegistry::build(decls);
        let id = make_id(0, "u256_overflowing_sub");
        assert!(reg.matches(&id, "u256_overflowing_sub"));
        assert!(reg.matches(&id, "u256"));
        assert!(!reg.matches(&id, "call_contract"));
    }
}
