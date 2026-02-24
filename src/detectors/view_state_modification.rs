use std::collections::{HashMap, HashSet};

use crate::analysis::callgraph::CallGraph;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::function::FunctionKind;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects view-like functions that perform storage writes.
///
/// View/read-only entrypoints must not mutate state. A storage write from a
/// view function indicates a broken mutability contract and can mislead
/// integrators, indexers, and auditors.
pub struct ViewStateModification;

impl Detector for ViewStateModification {
    fn id(&self) -> &'static str {
        "view_state_modification"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "View-like function performs storage_write_syscall, violating read-only semantics."
    }

    fn requirements(&self) -> DetectorRequirements {
        DetectorRequirements {
            min_tier: CompatibilityTier::Tier3,
            requires_debug_info: true,
            source_aware: false,
        }
    }

    fn run(&self, program: &ProgramIR) -> (Vec<Finding>, Vec<AnalyzerWarning>) {
        let mut findings = Vec::new();
        let warnings = Vec::new();
        let callgraph = CallGraph::build(program);
        let mut write_site_cache: HashMap<usize, Option<(usize, usize)>> = HashMap::new();

        for func in program.all_functions() {
            if !is_view_like_entrypoint(func.kind, func.is_external(), &func.name) {
                continue;
            }
            if let Some((stmt_idx, culprit_idx)) = find_storage_write_site(
                func.idx,
                program,
                &callgraph,
                &mut write_site_cache,
                &mut HashSet::new(),
            ) {
                let culprit_name = program
                    .functions
                    .get(culprit_idx)
                    .map(|f| f.name.as_str())
                    .unwrap_or("<unknown>");
                let description = if culprit_idx == func.idx {
                    format!(
                        "Function '{}' is classified as view/read-only but performs \
                         storage_write_syscall at stmt {}.",
                        func.name, stmt_idx
                    )
                } else {
                    format!(
                        "Function '{}' is classified as view/read-only but reaches \
                         storage_write_syscall at stmt {} via helper '{}'.",
                        func.name, stmt_idx, culprit_name
                    )
                };

                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "State write in view-like function",
                    description,
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(stmt_idx),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}

fn is_view_like_entrypoint(kind: FunctionKind, is_external: bool, name: &str) -> bool {
    if kind == FunctionKind::View {
        return true;
    }
    is_external && (name.contains("::__view") || name.ends_with("_view"))
}

fn find_storage_write_site(
    func_idx: usize,
    program: &ProgramIR,
    callgraph: &CallGraph,
    cache: &mut HashMap<usize, Option<(usize, usize)>>,
    visiting: &mut HashSet<usize>,
) -> Option<(usize, usize)> {
    if let Some(cached) = cache.get(&func_idx) {
        return *cached;
    }
    if !visiting.insert(func_idx) {
        return None;
    }

    let (start, end) = program.function_statement_range(func_idx);
    if start >= end {
        visiting.remove(&func_idx);
        cache.insert(func_idx, None);
        return None;
    }

    for (local_idx, stmt) in program.statements[start..end.min(program.statements.len())]
        .iter()
        .enumerate()
    {
        let Some(inv) = stmt.as_invocation() else {
            continue;
        };

        if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
            let site = (start + local_idx, func_idx);
            visiting.remove(&func_idx);
            cache.insert(func_idx, Some(site));
            return Some(site);
        }

        let is_function_call = program
            .libfunc_registry
            .generic_id(&inv.libfunc_id)
            .map(|name| name == "function_call")
            .unwrap_or(false);
        if !is_function_call {
            continue;
        }
        if let Some(callee_idx) = callgraph.callee_of(&inv.libfunc_id, &program.libfunc_registry) {
            if let Some(site) =
                find_storage_write_site(callee_idx, program, callgraph, cache, visiting)
            {
                visiting.remove(&func_idx);
                cache.insert(func_idx, Some(site));
                return Some(site);
            }
        }
    }

    visiting.remove(&func_idx);
    cache.insert(func_idx, None);
    None
}
