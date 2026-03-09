use std::collections::{HashMap, HashSet};

use crate::ir::ProgramIR;
use crate::loader::Statement;

/// A step in a backward trace: (statement_index, libfunc_name).
pub type TraceStep = (usize, String);

/// Def-Use chains for a single function.
///
/// Sierra is quasi-SSA: each variable ID is defined exactly once. This map
/// exploits that property to enable efficient queries like "trace backward
/// from this variable to its root sources" without per-detector re-scanning.
#[derive(Debug, Clone)]
pub struct DefUseMap {
    /// var_id → defining statement index.
    pub defs: HashMap<u64, usize>,
    /// var_id → consuming statement indices.
    pub uses: HashMap<u64, Vec<usize>>,
    /// All parameter variable IDs (function entry points).
    pub params: HashSet<u64>,
}

impl DefUseMap {
    /// Build def-use chains for a function's statement range.
    ///
    /// `param_vars` are the function's parameter variable IDs — they have no
    /// defining statement (they are "defined" at function entry).
    pub fn build(
        statements: &[Statement],
        start: usize,
        end: usize,
        param_vars: &[(u64, crate::loader::SierraId)],
    ) -> Self {
        let mut defs: HashMap<u64, usize> = HashMap::new();
        let mut uses: HashMap<u64, Vec<usize>> = HashMap::new();
        let params: HashSet<u64> = param_vars.iter().map(|(id, _)| *id).collect();

        let end = end.min(statements.len());
        for (idx, stmt) in statements.iter().enumerate().take(end).skip(start) {
            match stmt {
                Statement::Invocation(inv) => {
                    // Arguments are uses.
                    for &arg in &inv.args {
                        uses.entry(arg).or_default().push(idx);
                    }
                    // Branch results are definitions.
                    for branch in &inv.branches {
                        for &result in &branch.results {
                            defs.insert(result, idx);
                        }
                    }
                }
                Statement::Return(vars) => {
                    for &v in vars {
                        uses.entry(v).or_default().push(idx);
                    }
                }
            }
        }

        Self { defs, uses, params }
    }

    /// Build def-use chains for a specific function by index.
    pub fn for_function(program: &ProgramIR, func_idx: usize) -> Self {
        let func = &program.functions[func_idx];
        let (start, end) = program.function_statement_range(func_idx);
        Self::build(&program.statements, start, end, &func.raw.params)
    }

    /// Trace backward from `var` through at most `max_depth` defining statements.
    ///
    /// Returns an ordered list of (statement_index, libfunc_name) steps from
    /// the given variable back toward its root definition(s).
    pub fn trace_backward(
        &self,
        var: u64,
        max_depth: usize,
        statements: &[Statement],
        program: &ProgramIR,
    ) -> Vec<TraceStep> {
        let mut trace = Vec::new();
        let mut current = var;

        for _ in 0..max_depth {
            let Some(&def_idx) = self.defs.get(&current) else {
                break; // parameter or constant — no further definition
            };

            let name = match &statements[def_idx] {
                Statement::Invocation(inv) => program
                    .get_libfunc_name(&inv.libfunc_id)
                    .unwrap_or("")
                    .to_string(),
                Statement::Return(_) => break,
            };

            trace.push((def_idx, name));

            // Continue tracing through the first argument of the defining statement
            // (for pass-through libfuncs like store_temp, rename, dup, this follows
            // the data dependency chain).
            match &statements[def_idx] {
                Statement::Invocation(inv) if !inv.args.is_empty() => {
                    current = inv.args[0];
                }
                _ => break,
            }
        }

        trace
    }

    /// Find all root sources of a variable — parameters, constants, or
    /// identity producers (get_caller_address, storage reads, etc.).
    ///
    /// Traverses the def chain breadth-first, collecting variables that have
    /// no defining statement (params) or whose defining libfunc is a "source"
    /// (constants, syscalls that produce fresh values).
    pub fn root_sources(
        &self,
        var: u64,
        statements: &[Statement],
        program: &ProgramIR,
    ) -> HashSet<u64> {
        let mut roots = HashSet::new();
        let mut visited = HashSet::new();
        let mut worklist = vec![var];

        while let Some(v) = worklist.pop() {
            if !visited.insert(v) {
                continue;
            }

            // If it's a parameter, it's a root.
            if self.params.contains(&v) {
                roots.insert(v);
                continue;
            }

            let Some(&def_idx) = self.defs.get(&v) else {
                // No defining statement (shouldn't happen in well-formed IR, but
                // treat as a root).
                roots.insert(v);
                continue;
            };

            let stmt = &statements[def_idx];
            match stmt {
                Statement::Invocation(inv) => {
                    let name = program.get_libfunc_name(&inv.libfunc_id).unwrap_or("");

                    // Constants and identity producers are root sources.
                    if is_source_libfunc(name) {
                        roots.insert(v);
                    } else {
                        // Trace through all arguments.
                        for &arg in &inv.args {
                            worklist.push(arg);
                        }
                    }
                }
                Statement::Return(_) => {
                    roots.insert(v);
                }
            }
        }

        roots
    }

    /// Check if a variable is defined by any libfunc matching the pattern.
    pub fn defined_by(
        &self,
        var: u64,
        pattern: &str,
        statements: &[Statement],
        program: &ProgramIR,
    ) -> bool {
        let Some(&def_idx) = self.defs.get(&var) else {
            return false;
        };
        match &statements[def_idx] {
            Statement::Invocation(inv) => {
                let name = program.get_libfunc_name(&inv.libfunc_id).unwrap_or("");
                name.contains(pattern)
            }
            Statement::Return(_) => false,
        }
    }

    /// Get the defining statement index for a variable.
    pub fn defining_stmt(&self, var: u64) -> Option<usize> {
        self.defs.get(&var).copied()
    }

    /// Get all statement indices where a variable is consumed.
    pub fn use_sites(&self, var: u64) -> &[usize] {
        self.uses.get(&var).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// Returns true if the libfunc is a "source" — it produces a fresh value
/// independent of its inputs (constants, syscalls, etc.).
fn is_source_libfunc(name: &str) -> bool {
    // Constants
    name.contains("_const")
        // Identity syscalls
        || name.contains("get_caller_address")
        || name.contains("get_contract_address")
        || name.contains("get_execution_info")
        || name.contains("get_block_timestamp")
        || name.contains("get_block_number")
        || name.contains("get_tx_info")
        // Storage reads
        || name.contains("storage_read")
        || name.contains("storage_base_address_const")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::{BranchInfo, BranchTarget, Invocation, SierraId};

    fn make_sierra_id(name: &str) -> SierraId {
        SierraId {
            id: Some(0),
            debug_name: Some(name.to_string()),
        }
    }

    fn inv(name: &str, args: Vec<u64>, results: Vec<u64>) -> Statement {
        Statement::Invocation(Invocation {
            libfunc_id: make_sierra_id(name),
            args,
            branches: vec![BranchInfo {
                target: BranchTarget::Fallthrough,
                results,
            }],
        })
    }

    #[test]
    fn build_captures_defs_and_uses() {
        let stmts = vec![
            inv("felt252_const<42>", vec![], vec![0]),
            inv("felt252_add", vec![0, 1], vec![2]),
            Statement::Return(vec![2]),
        ];
        let params = vec![(1, make_sierra_id("p"))];
        let map = DefUseMap::build(&stmts, 0, stmts.len(), &params);

        assert_eq!(map.defs.get(&0), Some(&0));
        assert_eq!(map.defs.get(&2), Some(&1));
        assert!(!map.defs.contains_key(&1)); // param has no def
        assert!(map.params.contains(&1));
        assert_eq!(map.uses.get(&0).unwrap(), &[1]);
        assert_eq!(map.uses.get(&2).unwrap(), &[2]); // return
    }

    #[test]
    fn use_sites_empty_for_unused_var() {
        let stmts = vec![
            inv("felt252_const<42>", vec![], vec![0]),
            Statement::Return(vec![]),
        ];
        let map = DefUseMap::build(&stmts, 0, stmts.len(), &[]);
        assert!(map.use_sites(0).is_empty());
    }
}
