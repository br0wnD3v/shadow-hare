use std::collections::{HashMap, HashSet};

use crate::analysis::callgraph::CallGraph;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects account `__execute__` paths that do not show an observable
/// transaction-version guard, which can leave legacy invoke-v0 execution
/// unblocked.
///
/// The analysis is inter-procedural over `function_call` edges and tracks
/// `get_tx_info` / `get_execution_info` flow into guard-like checks.
pub struct AccountExecuteMissingV0Block;

const TAG_TX_INFO: u8 = 0b01;

const TX_INFO_LIBFUNCS: &[&str] = &["get_tx_info", "get_execution_info"];
const GUARD_COMPARE_LIBFUNCS: &[&str] = &[
    "assert",
    "assert_eq",
    "assert_ne",
    "felt252_is_zero",
    "u128_eq",
    "u256_eq",
    "contract_address_eq",
];

#[derive(Debug, Default, Clone)]
struct V0GuardSummary {
    has_tx_info: bool,
    has_v0_guard: bool,
    returns_tx_info_derived: bool,
}

impl Detector for AccountExecuteMissingV0Block {
    fn id(&self) -> &'static str {
        "account_execute_missing_v0_block"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Account __execute__ path does not show an observable tx-version guard \
         (legacy invoke-v0 may remain callable)."
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

        if !is_account_like_contract(program) {
            return (findings, warnings);
        }

        let callgraph = CallGraph::build(program);
        let mut cache: HashMap<usize, V0GuardSummary> = HashMap::new();

        for func in program.all_functions() {
            if !is_execute_entrypoint(&func.name) {
                continue;
            }

            let summary = summarize_function(
                func.idx,
                program,
                &callgraph,
                &mut cache,
                &mut HashSet::new(),
            );

            if summary.has_v0_guard {
                continue;
            }

            let (start, _) = program.function_statement_range(func.idx);
            let reason = if summary.has_tx_info {
                "tx-info flow is present in the execute call tree but no guard-like compare/assert is observed on that flow."
            } else {
                "no tx-info/version guard signal is observed in the execute call tree."
            };

            findings.push(Finding::new(
                self.id(),
                self.severity(),
                self.confidence(),
                "Missing execute v0 transaction guard",
                format!(
                    "Function '{}': {} Add an explicit transaction-version check to \
                     reject legacy invoke-v0 execution paths.",
                    func.name, reason
                ),
                Location {
                    file: program.source.display().to_string(),
                    function: func.name.clone(),
                    statement_idx: Some(start),
                    line: None,
                    col: None,
                },
            ));
        }

        (findings, warnings)
    }
}

fn summarize_function(
    func_idx: usize,
    program: &ProgramIR,
    callgraph: &CallGraph,
    cache: &mut HashMap<usize, V0GuardSummary>,
    visiting: &mut HashSet<usize>,
) -> V0GuardSummary {
    if let Some(cached) = cache.get(&func_idx) {
        return cached.clone();
    }
    if !visiting.insert(func_idx) {
        return V0GuardSummary::default();
    }

    let mut summary = V0GuardSummary::default();
    if is_tx_version_guard_name(&program.functions[func_idx].name) {
        summary.has_v0_guard = true;
    }

    let (start, end) = program.function_statement_range(func_idx);
    if start < end {
        let mut tags: HashMap<u64, u8> = HashMap::new();

        for stmt in &program.statements[start..end.min(program.statements.len())] {
            match stmt {
                Statement::Return(vars) => {
                    if vars
                        .iter()
                        .any(|v| tags.get(v).copied().unwrap_or(0) & TAG_TX_INFO != 0)
                    {
                        summary.returns_tx_info_derived = true;
                    }
                }
                Statement::Invocation(inv) => {
                    let libfunc_name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or_else(|| inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");

                    let mut arg_union = 0u8;
                    let mut has_tx_info_arg = false;
                    for arg in &inv.args {
                        let tag = tags.get(arg).copied().unwrap_or(0);
                        arg_union |= tag;
                        if tag & TAG_TX_INFO != 0 {
                            has_tx_info_arg = true;
                        }
                    }

                    if is_tx_info_libfunc(libfunc_name) {
                        summary.has_tx_info = true;
                        arg_union |= TAG_TX_INFO;
                    }

                    if is_tx_version_guard_name(libfunc_name)
                        || (has_tx_info_arg && is_guard_compare_libfunc(libfunc_name))
                    {
                        summary.has_v0_guard = true;
                    }

                    if let Some(callee_idx) =
                        callgraph.callee_of(&inv.libfunc_id, &program.libfunc_registry)
                    {
                        let callee =
                            summarize_function(callee_idx, program, callgraph, cache, visiting);
                        summary.has_tx_info |= callee.has_tx_info;
                        summary.has_v0_guard |= callee.has_v0_guard;
                        if has_tx_info_arg && callee.returns_tx_info_derived {
                            arg_union |= TAG_TX_INFO;
                        }
                    }

                    if arg_union != 0 {
                        for branch in &inv.branches {
                            for r in &branch.results {
                                tags.insert(*r, arg_union);
                            }
                        }
                    }
                }
            }
        }
    }

    visiting.remove(&func_idx);
    cache.insert(func_idx, summary.clone());
    summary
}

fn is_execute_entrypoint(name: &str) -> bool {
    name.contains("__execute__") || name.ends_with("__execute")
}

fn is_account_like_contract(program: &ProgramIR) -> bool {
    let has_execute = program
        .all_functions()
        .any(|f| is_execute_entrypoint(&f.name));
    let has_validate = program.all_functions().any(|f| {
        f.name.contains("__validate__")
            || f.name.contains("__validate_declare__")
            || f.name.contains("__validate_deploy__")
    });
    let has_signature = program
        .all_functions()
        .any(|f| f.name.contains("is_valid_signature") || f.name.contains("isValidSignature"));
    has_execute && (has_validate || has_signature)
}

fn is_tx_info_libfunc(name: &str) -> bool {
    TX_INFO_LIBFUNCS.iter().any(|p| name.contains(p))
}

fn is_guard_compare_libfunc(name: &str) -> bool {
    GUARD_COMPARE_LIBFUNCS.iter().any(|p| name.contains(p))
}

fn is_tx_version_guard_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    // Covers common helper naming in account contracts:
    // `is_tx_version_valid`, `assert_tx_version`, `invalid_tx_version`, etc.
    n.contains("tx_version")
        && (n.contains("valid")
            || n.contains("check")
            || n.contains("assert")
            || n.contains("invalid"))
}
