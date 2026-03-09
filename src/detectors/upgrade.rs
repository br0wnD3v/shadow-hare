use std::collections::{HashMap, HashSet};

use crate::analysis::callgraph::CallGraph;
use crate::analysis::cfg::Cfg;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::components::DetectedComponents;
use crate::ir::program::ProgramIR;
use crate::loader::{BranchTarget, CompatibilityTier, Invocation, Statement};

/// Detects `replace_class_syscall` in external functions that lack an owner
/// check before the upgrade call.
///
/// Upgradeable contracts must gate `replace_class` behind structural access
/// control, not naming conventions.
///
/// This detector uses CFG + dominator analysis: an upgrade is protected only
/// when a guard block (containing a check whose operands derive from BOTH
/// caller identity and storage) dominates ALL replace_class blocks.
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

        // If OZ Upgradeable + access control are both detected, the upgrade
        // is governed by the component's internal guard. Suppress findings.
        let oz = DetectedComponents::detect(program);
        if oz.has_guarded_upgrade() {
            return (findings, warnings);
        }

        let callgraph = CallGraph::build(program);
        let mut guard_cache: HashMap<usize, bool> = HashMap::new();
        let mut storage_return_cache: HashMap<usize, bool> = HashMap::new();

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let end = end.min(program.statements.len());

            // Build CFG for dominance analysis.
            let cfg = Cfg::build(&program.statements, start, end);

            // Find blocks containing replace_class invocations.
            let mut replace_blocks: Vec<(usize, usize)> = Vec::new(); // (block_id, stmt_idx)
                                                                      // Find blocks containing guard checks (caller + storage derived).
            let mut guard_blocks: Vec<usize> = Vec::new();

            // Tag propagation per block (simplified: process blocks in topo order).
            let mut tags: HashMap<u64, u8> = HashMap::new();

            for block_id in cfg.topological_order() {
                let block = &cfg.blocks[block_id];

                for &stmt_idx in &block.stmts {
                    let stmt = &program.statements[stmt_idx];
                    let inv = match stmt {
                        Statement::Invocation(inv) => inv,
                        _ => continue,
                    };

                    // Check for replace_class.
                    let is_replace = REPLACE_CLASS_LIBFUNCS
                        .iter()
                        .any(|p| program.libfunc_registry.matches(&inv.libfunc_id, p));
                    if is_replace {
                        replace_blocks.push((block_id, stmt_idx));
                    }

                    // Tag propagation.
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
                    let has_mixed_arg =
                        arg_union & (TAG_CALLER | TAG_STORAGE) == (TAG_CALLER | TAG_STORAGE);

                    if (is_check || is_branch_guard)
                        && (has_mixed_arg || (has_caller_arg && has_storage_arg))
                        && !guard_blocks.contains(&block_id)
                    {
                        guard_blocks.push(block_id);
                    }

                    // Inter-procedural: check callees for guards.
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
                            let mut visiting: HashSet<usize> = [func.idx].into_iter().collect();
                            if function_has_structural_guard(
                                callee_idx,
                                program,
                                &callgraph,
                                &mut guard_cache,
                                &mut storage_return_cache,
                                &mut visiting,
                            ) {
                                // Callee has a guard — treat as if this block has a guard.
                                if !guard_blocks.contains(&block_id) {
                                    guard_blocks.push(block_id);
                                }
                            }

                            let mut visiting_storage: HashSet<usize> =
                                [func.idx].into_iter().collect();
                            if function_returns_storage_derived(
                                callee_idx,
                                program,
                                &callgraph,
                                &mut storage_return_cache,
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

                    if produced_tag != 0 {
                        for branch in &inv.branches {
                            for r in &branch.results {
                                let entry = tags.entry(*r).or_insert(0);
                                *entry |= produced_tag;
                            }
                        }
                    }
                }
            }

            if replace_blocks.is_empty() {
                continue;
            }

            // Compute dominator tree once, then check all pairs.
            let idom = cfg.dominators();
            let has_dominating_guard = if guard_blocks.is_empty() {
                false
            } else {
                replace_blocks.iter().all(|&(replace_block, _)| {
                    guard_blocks
                        .iter()
                        .any(|&guard_block| Cfg::dominates_with(&idom, guard_block, replace_block))
                })
            };

            if !has_dominating_guard {
                for &(_, stmt_idx) in &replace_blocks {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Unprotected contract upgrade",
                        format!(
                            "Function '{}': replace_class_syscall at stmt {} has no \
                             owner/access-control check. Any caller can replace the \
                             contract implementation.",
                            func.name, stmt_idx
                        ),
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
        }

        (findings, warnings)
    }
}

/// Returns true if a check/branch in the function consumes values that are
/// jointly derived from caller identity and storage.
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

    let scan_end = target_idx.saturating_add(4).min(func_end);
    for idx in target_idx..scan_end {
        match &program.statements[idx] {
            Statement::Return(_) => return false,
            Statement::Invocation(inv) => {
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
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
