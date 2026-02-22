use crate::loader::{EntryPoints, Function};

/// Classified function kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionKind {
    External,
    L1Handler,
    Constructor,
    Internal,
    /// View function (read-only external).
    View,
}

impl std::fmt::Display for FunctionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::External => write!(f, "external"),
            Self::L1Handler => write!(f, "l1_handler"),
            Self::Constructor => write!(f, "constructor"),
            Self::Internal => write!(f, "internal"),
            Self::View => write!(f, "view"),
        }
    }
}

/// A function enriched with classification and source location (if available).
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub idx: usize,
    pub raw: Function,
    pub kind: FunctionKind,
    /// Human-readable name derived from debug info.
    pub name: String,
}

impl FunctionInfo {
    /// Classify all functions given the entry point lists.
    pub fn classify_all(functions: &[Function], entry_points: &EntryPoints) -> Vec<Self> {
        functions
            .iter()
            .enumerate()
            .map(|(idx, f)| {
                let kind = classify_function(idx, f, entry_points);
                let name = f.id.debug_name.clone().unwrap_or_else(|| format!("func_{idx}"));
                Self { idx, raw: f.clone(), kind, name }
            })
            .collect()
    }

    pub fn is_entrypoint(&self) -> bool {
        matches!(
            self.kind,
            FunctionKind::External | FunctionKind::L1Handler | FunctionKind::Constructor | FunctionKind::View
        )
    }

    pub fn is_l1_handler(&self) -> bool {
        self.kind == FunctionKind::L1Handler
    }

    pub fn is_external(&self) -> bool {
        matches!(self.kind, FunctionKind::External | FunctionKind::View)
    }

    /// Returns true for account contract entry points that legitimately use
    /// `get_tx_info` for signature verification. These should be excluded from
    /// the `tx_origin_auth` detector to avoid false positives.
    pub fn is_account_entrypoint(&self) -> bool {
        let name = &self.name;
        name.contains("__execute__")
            || name.contains("__validate__")
            || name.contains("__validate_declare__")
            || name.contains("__validate_deploy__")
    }
}

fn classify_function(idx: usize, func: &Function, entry_points: &EntryPoints) -> FunctionKind {
    if entry_points.l1_handler.iter().any(|ep| ep.function_idx == idx) {
        return FunctionKind::L1Handler;
    }
    if entry_points.constructor.iter().any(|ep| ep.function_idx == idx) {
        return FunctionKind::Constructor;
    }
    if entry_points.external.iter().any(|ep| ep.function_idx == idx) {
        return FunctionKind::External;
    }

    // Heuristic classification when no entry points are provided (raw Sierra mode):
    // look at debug names for well-known patterns.
    let name = func.id.debug_name.as_deref().unwrap_or("");

    if name.contains("::__external") || name.ends_with("_external") {
        return FunctionKind::External;
    }
    if name.contains("::__l1_handler") || name.ends_with("_l1_handler") {
        return FunctionKind::L1Handler;
    }
    if name.contains("::__constructor") || name.ends_with("constructor") {
        return FunctionKind::Constructor;
    }
    if name.contains("::__view") || name.ends_with("_view") {
        return FunctionKind::View;
    }
    // Starknet account protocol entry points are External even without
    // the ::__external:: prefix in their debug name.
    if name.ends_with("__execute__")
        || name.ends_with("__validate__")
        || name.ends_with("__validate_declare__")
        || name.ends_with("__validate_deploy__")
    {
        return FunctionKind::External;
    }

    FunctionKind::Internal
}
