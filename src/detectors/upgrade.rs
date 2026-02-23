use std::collections::{HashMap, HashSet};

use crate::analysis::callgraph::CallGraph;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{BranchTarget, CompatibilityTier, Invocation, Statement};

/// Detects `replace_class_syscall` in external functions that lack an owner
/// check before the upgrade call.
///
/// Upgradeable contracts must gate `replace_class` behind structural access
/// control, not naming conventions.
///
/// This detector considers an upgrade protected only when, before the first
/// `replace_class` in the function, there is a check/branch whose operands are
/// dataflow-derived from BOTH:
/// - caller identity (`get_caller_address` / `get_execution_info`)
/// - storage reads (owner/admin slot fetch path)
///
/// If no such structural guard exists, the upgrade is treated as effectively
/// permissionless.
pub struct UnprotectedUpgrade;

const REPLACE_CLASS_LIBFUNCS: &[&str] = &["replace_class_syscall", "replace_class"];

const OWNER_CHECK_LIBFUNCS: &[&str] = &[
    "felt252_is_zero",
    "contract_address_eq",
    "assert_eq",
    "assert_ne",
    "u128_eq",
];

const TAG_CALLER: u8 = 0b01;
const TAG_STORAGE: u8 = 0b10;

impl Detector for UnprotectedUpgrade {
    fn id(&self) -> &'static str {
        "unprotected_upgrade"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "replace_class_syscall in an external function with no apparent owner check. \
         Any caller can upgrade the contract to an arbitrary implementation."
    }

    fn requirements(&self) -> DetectorRequirements {
        DetectorRequirements {
            min_tier: CompatibilityTier::Tier3,
            requires_debug_info: false,
            source_aware: false,
        }
    }

    fn run(&self, program: &ProgramIR) -> (Vec<Finding>, Vec<AnalyzerWarning>) {
        let mut findings = Vec::new();
        let warnings = Vec::new();
        let callgraph = CallGraph::build(program);
        let mut guard_cache: HashMap<usize, bool> = HashMap::new();
        let mut storage_return_cache: HashMap<usize, bool> = HashMap::new();

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Find replace_class invocations
            let replace_sites: Vec<usize> = stmts
                .iter()
                .enumerate()
                .filter_map(|(local_idx, stmt)| {
                    let inv = stmt.as_invocation()?;
                    let is_replace = REPLACE_CLASS_LIBFUNCS
                        .iter()
                        .any(|p| program.libfunc_registry.matches(&inv.libfunc_id, p));
                    if is_replace {
                        Some(local_idx)
                    } else {
                        None
                    }
                })
                .collect();

            if replace_sites.is_empty() {
                continue;
            }

            // Check if any storage_read result flows into an owner-check libfunc
            // before the replace_class call.
            let has_owner_check = has_storage_backed_check(
                func.idx,
                start,
                end.min(program.statements.len()),
                stmts,
                &replace_sites,
                program,
                &callgraph,
                &mut guard_cache,
                &mut storage_return_cache,
            );

            if !has_owner_check {
                for local_idx in replace_sites {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Unprotected contract upgrade",
                        format!(
                            "Function '{}': replace_class_syscall at stmt {} has no \
                             owner/access-control check. Any caller can replace the \
                             contract implementation.",
                            func.name,
                            start + local_idx
                        ),
                        Location {
                            file: program.source.display().to_string(),
                            function: func.name.clone(),
                            statement_idx: Some(start + local_idx),
                            line: None,
                            col: None,
                        },
                    ));
                }
            }
        }

        (findings, warnings)
    }
}

/// Returns true if a check/branch before the first `replace_class` consumes
/// values that are jointly derived from caller identity and storage.
fn has_storage_backed_check(
    func_idx: usize,
    func_start: usize,
    func_end: usize,
    stmts: &[Statement],
    replace_sites: &[usize],
    program: &ProgramIR,
    callgraph: &CallGraph,
    guard_cache: &mut HashMap<usize, bool>,
    storage_return_cache: &mut HashMap<usize, bool>,
) -> bool {
    let first_replace = replace_sites.iter().copied().min().unwrap_or(usize::MAX);

    // Variable provenance tags:
    // - TAG_CALLER: value derived from caller identity
    // - TAG_STORAGE: value derived from storage reads
    let mut tags: HashMap<u64, u8> = HashMap::new();

    for (local_idx, stmt) in stmts.iter().enumerate() {
        if local_idx >= first_replace {
            break;
        }
        let inv = match stmt.as_invocation() {
            Some(inv) => inv,
            None => continue,
        };

        let mut arg_union = 0u8;
        let mut has_caller_arg = false;
        let mut has_storage_arg = false;
        for arg in &inv.args {
            let tag = tags.get(arg).copied().unwrap_or(0);
            arg_union |= tag;
            if tag & TAG_CALLER != 0 {
                has_caller_arg = true;
            }
            if tag & TAG_STORAGE != 0 {
                has_storage_arg = true;
            }
        }

        let is_check = OWNER_CHECK_LIBFUNCS
            .iter()
            .any(|p| program.libfunc_registry.matches(&inv.libfunc_id, p));
        let is_branch_guard = is_guarding_branch(inv, program, func_start, func_end);
        let has_mixed_arg = arg_union & (TAG_CALLER | TAG_STORAGE) == (TAG_CALLER | TAG_STORAGE);

        if (is_check || is_branch_guard) && (has_mixed_arg || (has_caller_arg && has_storage_arg)) {
            return true;
        }

        let is_function_call = program
            .libfunc_registry
            .generic_id(&inv.libfunc_id)
            .map(|name| name == "function_call")
            .unwrap_or(false);
        let mut call_produced_tag = 0u8;
        if is_function_call {
            if let Some(callee_idx) =
                callgraph.callee_of(&inv.libfunc_id, &program.libfunc_registry)
            {
                let mut visiting: HashSet<usize> = [func_idx].into_iter().collect();
                if function_has_structural_guard(
                    callee_idx,
                    program,
                    callgraph,
                    guard_cache,
                    storage_return_cache,
                    &mut visiting,
                ) {
                    return true;
                }

                let mut visiting_storage: HashSet<usize> = [func_idx].into_iter().collect();
                if function_returns_storage_derived(
                    callee_idx,
                    program,
                    callgraph,
                    storage_return_cache,
                    &mut visiting_storage,
                ) {
                    call_produced_tag |= TAG_STORAGE;
                }
            }
        }

        let is_storage_read = program.libfunc_registry.is_storage_read(&inv.libfunc_id);
        let is_caller_source = program
            .libfunc_registry
            .matches(&inv.libfunc_id, "get_caller_address")
            || program
                .libfunc_registry
                .matches(&inv.libfunc_id, "get_execution_info");

        let mut produced_tag = arg_union | call_produced_tag;
        if is_storage_read {
            produced_tag |= TAG_STORAGE;
        }
        if is_caller_source {
            produced_tag |= TAG_CALLER;
        }

        if produced_tag == 0 {
            continue;
        }
        for branch in &inv.branches {
            for r in &branch.results {
                let entry = tags.entry(*r).or_insert(0);
                *entry |= produced_tag;
            }
        }
    }

    false
}

fn function_has_structural_guard(
    func_idx: usize,
    program: &ProgramIR,
    callgraph: &CallGraph,
    guard_cache: &mut HashMap<usize, bool>,
    storage_return_cache: &mut HashMap<usize, bool>,
    visiting: &mut HashSet<usize>,
) -> bool {
    if let Some(cached) = guard_cache.get(&func_idx) {
        return *cached;
    }
    if !visiting.insert(func_idx) {
        return false;
    }

    let (start, end) = program.function_statement_range(func_idx);
    if start >= end {
        visiting.remove(&func_idx);
        guard_cache.insert(func_idx, false);
        return false;
    }
    let stmts = &program.statements[start..end.min(program.statements.len())];

    let mut tags: HashMap<u64, u8> = HashMap::new();
    let mut found = false;

    for stmt in stmts {
        let inv = match stmt.as_invocation() {
            Some(inv) => inv,
            None => continue,
        };

        let mut arg_union = 0u8;
        let mut has_caller_arg = false;
        let mut has_storage_arg = false;
        for arg in &inv.args {
            let tag = tags.get(arg).copied().unwrap_or(0);
            arg_union |= tag;
            if tag & TAG_CALLER != 0 {
                has_caller_arg = true;
            }
            if tag & TAG_STORAGE != 0 {
                has_storage_arg = true;
            }
        }

        let is_check = OWNER_CHECK_LIBFUNCS
            .iter()
            .any(|p| program.libfunc_registry.matches(&inv.libfunc_id, p));
        let is_branch_guard = is_guarding_branch(inv, program, start, end);
        let has_mixed_arg = arg_union & (TAG_CALLER | TAG_STORAGE) == (TAG_CALLER | TAG_STORAGE);
        if (is_check || is_branch_guard) && (has_mixed_arg || (has_caller_arg && has_storage_arg)) {
            found = true;
            break;
        }

        let is_function_call = program
            .libfunc_registry
            .generic_id(&inv.libfunc_id)
            .map(|name| name == "function_call")
            .unwrap_or(false);
        let mut call_produced_tag = 0u8;
        if is_function_call {
            if let Some(callee_idx) =
                callgraph.callee_of(&inv.libfunc_id, &program.libfunc_registry)
            {
                if function_has_structural_guard(
                    callee_idx,
                    program,
                    callgraph,
                    guard_cache,
                    storage_return_cache,
                    visiting,
                ) {
                    found = true;
                    break;
                }

                let mut visiting_storage: HashSet<usize> = [func_idx].into_iter().collect();
                if function_returns_storage_derived(
                    callee_idx,
                    program,
                    callgraph,
                    storage_return_cache,
                    &mut visiting_storage,
                ) {
                    call_produced_tag |= TAG_STORAGE;
                }
            }
        }

        let is_storage_read = program.libfunc_registry.is_storage_read(&inv.libfunc_id);
        let is_caller_source = program
            .libfunc_registry
            .matches(&inv.libfunc_id, "get_caller_address")
            || program
                .libfunc_registry
                .matches(&inv.libfunc_id, "get_execution_info");

        let mut produced_tag = arg_union | call_produced_tag;
        if is_storage_read {
            produced_tag |= TAG_STORAGE;
        }
        if is_caller_source {
            produced_tag |= TAG_CALLER;
        }
        if produced_tag == 0 {
            continue;
        }
        for branch in &inv.branches {
            for r in &branch.results {
                let entry = tags.entry(*r).or_insert(0);
                *entry |= produced_tag;
            }
        }
    }

    visiting.remove(&func_idx);
    guard_cache.insert(func_idx, found);
    found
}

/// Returns true when an invocation's branching shape represents a control
/// decision (authorization guard), not a generic multi-result operation.
///
/// A branch is considered guard-like when either:
/// - at least one branch target reaches a non-returning path (panic/revert), or
/// - one branch is Fallthrough and another is an explicit jump target.
fn is_guarding_branch(
    inv: &Invocation,
    program: &ProgramIR,
    func_start: usize,
    func_end: usize,
) -> bool {
    if inv.branches.len() < 2 {
        return false;
    }

    let has_fallthrough = inv
        .branches
        .iter()
        .any(|b| matches!(b.target, BranchTarget::Fallthrough));
    let has_non_fallthrough = inv
        .branches
        .iter()
        .any(|b| matches!(b.target, BranchTarget::Statement(_)));
    let mixed_fallthrough_shape = has_fallthrough && has_non_fallthrough;

    let has_non_returning_branch = inv.branches.iter().any(|b| match b.target {
        BranchTarget::Fallthrough => false,
        BranchTarget::Statement(target_idx) => {
            branch_target_is_non_returning(target_idx, program, func_start, func_end)
        }
    });

    has_non_returning_branch || mixed_fallthrough_shape
}

fn branch_target_is_non_returning(
    target_idx: usize,
    program: &ProgramIR,
    func_start: usize,
    func_end: usize,
) -> bool {
    if target_idx < func_start || target_idx >= func_end || target_idx >= program.statements.len() {
        return false;
    }

    // Inspect a short forward window. Panic/revert paths are usually immediate.
    let scan_end = target_idx.saturating_add(4).min(func_end);
    for idx in target_idx..scan_end {
        match &program.statements[idx] {
            Statement::Return(_) => return false,
            Statement::Invocation(inv) => {
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");
                if name.contains("panic") || name.contains("revert") || name.contains("abort") {
                    return true;
                }
            }
        }
    }

    false
}

fn function_returns_storage_derived(
    func_idx: usize,
    program: &ProgramIR,
    callgraph: &CallGraph,
    storage_return_cache: &mut HashMap<usize, bool>,
    visiting: &mut HashSet<usize>,
) -> bool {
    if let Some(cached) = storage_return_cache.get(&func_idx) {
        return *cached;
    }
    if !visiting.insert(func_idx) {
        return false;
    }

    let (start, end) = program.function_statement_range(func_idx);
    if start >= end {
        visiting.remove(&func_idx);
        storage_return_cache.insert(func_idx, false);
        return false;
    }

    let mut tags: HashMap<u64, u8> = HashMap::new();
    let mut returns_storage = false;

    for stmt in &program.statements[start..end.min(program.statements.len())] {
        match stmt {
            Statement::Return(vars) => {
                if vars
                    .iter()
                    .any(|v| tags.get(v).copied().unwrap_or(0) & TAG_STORAGE != 0)
                {
                    returns_storage = true;
                    break;
                }
            }
            Statement::Invocation(inv) => {
                let mut arg_union = 0u8;
                for arg in &inv.args {
                    arg_union |= tags.get(arg).copied().unwrap_or(0);
                }

                let mut produced_tag = arg_union;
                if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
                    produced_tag |= TAG_STORAGE;
                }

                let is_function_call = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .map(|name| name == "function_call")
                    .unwrap_or(false);
                if is_function_call {
                    if let Some(callee_idx) =
                        callgraph.callee_of(&inv.libfunc_id, &program.libfunc_registry)
                    {
                        if function_returns_storage_derived(
                            callee_idx,
                            program,
                            callgraph,
                            storage_return_cache,
                            visiting,
                        ) {
                            produced_tag |= TAG_STORAGE;
                        }
                    }
                }

                if produced_tag == 0 {
                    continue;
                }
                for branch in &inv.branches {
                    for r in &branch.results {
                        let entry = tags.entry(*r).or_insert(0);
                        *entry |= produced_tag;
                    }
                }
            }
        }
    }

    visiting.remove(&func_idx);
    storage_return_cache.insert(func_idx, returns_storage);
    returns_storage
}
