use crate::ir::function::FunctionInfo;
use crate::ir::type_registry::{LibfuncRegistry, TypeRegistry};
use crate::loader::{
    CompatibilityTier, EntryPoints, LoadedArtifact, SierraId, Statement,
};
use std::path::PathBuf;

/// The primary IR used by all detectors and analysis passes.
///
/// Wraps a loaded Sierra artifact and provides ergonomic access
/// to functions, types, libfuncs, and statements.
#[derive(Debug)]
pub struct ProgramIR {
    pub source: PathBuf,
    pub compatibility: CompatibilityTier,
    pub has_debug_info: bool,

    pub type_registry: TypeRegistry,
    pub libfunc_registry: LibfuncRegistry,
    pub functions: Vec<FunctionInfo>,
    pub statements: Vec<Statement>,
    pub entry_points: EntryPoints,
}

impl ProgramIR {
    /// Build a ProgramIR from a loaded artifact.
    pub fn from_artifact(artifact: LoadedArtifact) -> Self {
        let has_debug_info = artifact
            .program
            .functions
            .iter()
            .any(|f| f.id.debug_name.is_some());

        let type_registry = TypeRegistry::build(artifact.program.type_declarations);
        let libfunc_registry = LibfuncRegistry::build(artifact.program.libfunc_declarations);
        let functions =
            FunctionInfo::classify_all(&artifact.program.functions, &artifact.entry_points);

        Self {
            source: artifact.source_path,
            compatibility: artifact.compatibility,
            has_debug_info,
            type_registry,
            libfunc_registry,
            functions,
            statements: artifact.program.statements,
            entry_points: artifact.entry_points,
        }
    }

    /// Iterate over all statements in a function's body (from entry_point to end).
    /// Returns (statement_index, statement) pairs.
    pub fn function_statements(&self, func_idx: usize) -> FunctionStatements<'_> {
        let entry = self.functions[func_idx].raw.entry_point;
        FunctionStatements {
            program: self,
            func_idx,
            current: entry,
        }
    }

    /// Return all statements belonging to a function as a slice.
    /// Conservative: returns from entry_point to the next function's entry_point.
    pub fn function_statement_range(&self, func_idx: usize) -> (usize, usize) {
        let start = self.functions[func_idx].raw.entry_point;
        let end = self
            .functions
            .iter()
            .filter(|f| f.raw.entry_point > start)
            .map(|f| f.raw.entry_point)
            .min()
            .unwrap_or(self.statements.len());
        (start, end)
    }

    pub fn get_libfunc_name<'a>(&'a self, id: &'a SierraId) -> Option<&'a str> {
        self.libfunc_registry.generic_id(id).or_else(|| id.debug_name.as_deref())
    }

    pub fn external_functions(&self) -> impl Iterator<Item = &FunctionInfo> {
        self.functions.iter().filter(|f| f.is_external())
    }

    pub fn l1_handler_functions(&self) -> impl Iterator<Item = &FunctionInfo> {
        self.functions.iter().filter(|f| f.is_l1_handler())
    }

    pub fn all_functions(&self) -> impl Iterator<Item = &FunctionInfo> {
        self.functions.iter()
    }
}

/// Iterator over statements in a function. Stops at a Return or when reaching
/// another function's entry point.
pub struct FunctionStatements<'a> {
    program: &'a ProgramIR,
    func_idx: usize,
    current: usize,
}

impl<'a> Iterator for FunctionStatements<'a> {
    type Item = (usize, &'a Statement);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.program.statements.len() {
            return None;
        }

        // Stop if we've entered another function's territory
        let other_entry = self
            .program
            .functions
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != self.func_idx)
            .any(|(_, f)| f.raw.entry_point == self.current);

        if other_entry && self.current != self.program.functions[self.func_idx].raw.entry_point {
            return None;
        }

        let stmt = &self.program.statements[self.current];
        let idx = self.current;
        self.current += 1;

        // Stop after Return
        if matches!(stmt, Statement::Return(_)) {
            self.current = usize::MAX; // exhaust the iterator
        }

        Some((idx, stmt))
    }
}
