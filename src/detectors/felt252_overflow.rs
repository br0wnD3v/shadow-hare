use std::collections::{HashMap, HashSet};

use crate::analysis::callgraph::{CallGraph, FunctionSummaries};
use crate::analysis::cfg::{BlockIdx, Cfg};
use crate::analysis::dataflow::{run_forward, ForwardAnalysis};
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects arithmetic on felt252 values where overflow semantics may be unexpected.
///
/// felt252 arithmetic wraps silently modulo P (the field prime). Code that
/// expects overflow to produce a carry bit or panic is incorrect.
///
/// Heuristic: flag functions that perform felt252 arithmetic on values derived
/// from user input (external function parameters) without explicit range checks.
pub struct Felt252Overflow;

const FELT252_ARITH_LIBFUNCS: &[&str] = &["felt252_add", "felt252_sub", "felt252_mul"];
const RANGE_CHECK_LIBFUNCS: &[&str] = &[
    "felt252_is_zero",
    "u128_from_felt252",
    "u256_from_felt252",
    "assert_le_felt252",
    "assert_lt_felt252",
];
const SANITIZER_LIBFUNCS: &[&str] = &[
    "storage_base_address_const",
    "pedersen",
    "poseidon",
    "hades_permutation",
    "felt252_const",
    "contract_address_const",
    "get_caller_address",
    "get_contract_address",
];

#[derive(Clone, Eq, PartialEq)]
struct FeltFlowState {
    tainted: HashSet<u64>,
    has_range_check: bool,
}

struct Felt252TaintAnalysis<'a> {
    program: &'a ProgramIR,
    callgraph: &'a CallGraph,
    summaries: &'a FunctionSummaries,
    seeds: HashSet<u64>,
}

impl<'a> ForwardAnalysis for Felt252TaintAnalysis<'a> {
    type Domain = FeltFlowState;

    fn bottom(&self) -> Self::Domain {
        FeltFlowState {
            tainted: self.seeds.clone(),
            has_range_check: false,
        }
    }

    fn transfer_stmt(&self, state: &Self::Domain, stmt: &crate::loader::Statement) -> Self::Domain {
        let inv = match stmt.as_invocation() {
            Some(inv) => inv,
            None => return state.clone(),
        };

        let libfunc_name = self
            .program
            .libfunc_registry
            .generic_id(&inv.libfunc_id)
            .or_else(|| inv.libfunc_id.debug_name.as_deref())
            .unwrap_or("");

        let mut next = state.clone();
        if RANGE_CHECK_LIBFUNCS
            .iter()
            .any(|p| libfunc_name.contains(p))
        {
            next.has_range_check = true;
        }

        if SANITIZER_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
            return next;
        }

        let any_arg_tainted = inv.args.iter().any(|a| next.tainted.contains(a));

        if libfunc_name == "function_call" {
            if any_arg_tainted {
                if let Some(callee_idx) = self
                    .callgraph
                    .callee_of(&inv.libfunc_id, &self.program.libfunc_registry)
                {
                    if self
                        .summaries
                        .has_unsafe_felt252_arith_on_param
                        .get(callee_idx)
                        .copied()
                        .unwrap_or(false)
                    {
                        for branch in &inv.branches {
                            for result in &branch.results {
                                next.tainted.insert(*result);
                            }
                        }
                    }
                }
            }
            return next;
        }

        if any_arg_tainted {
            for branch in &inv.branches {
                for result in &branch.results {
                    next.tainted.insert(*result);
                }
            }
        }

        next
    }

    fn join(&self, a: &Self::Domain, b: &Self::Domain) -> Self::Domain {
        FeltFlowState {
            tainted: a.tainted.union(&b.tainted).copied().collect(),
            // Preserve prior detector semantics: any observed range check in the
            // function suppresses the heuristic.
            has_range_check: a.has_range_check || b.has_range_check,
        }
    }
}

impl Detector for Felt252Overflow {
    fn id(&self) -> &'static str {
        "felt252_overflow"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Arithmetic on felt252 wraps silently modulo the field prime. \
         Ensure range checks are in place if integer overflow semantics are assumed."
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

        // Build inter-procedural summaries first so function_call edges can carry
        // taint evidence from helper functions.
        let callgraph = CallGraph::build(program);
        let summaries = FunctionSummaries::compute(program, &callgraph);

        // Run only on entry-point functions to avoid helper-level FP inflation.
        for func in program.functions.iter().filter(|f| f.is_entrypoint()) {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let end = end.min(program.statements.len());

            // Preserve legacy suppression behavior: any range-check libfunc
            // present in the function body suppresses this heuristic entirely.
            let has_any_range_check = program.statements[start..end]
                .iter()
                .filter_map(|stmt| stmt.as_invocation())
                .any(|inv| {
                    let name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or_else(|| inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");
                    RANGE_CHECK_LIBFUNCS.iter().any(|p| name.contains(p))
                });
            if has_any_range_check {
                continue;
            }

            let seeds: HashSet<u64> = func.raw.params.iter().map(|(id, _)| *id).collect();
            let analysis = Felt252TaintAnalysis {
                program,
                callgraph: &callgraph,
                summaries: &summaries,
                seeds,
            };
            let cfg = Cfg::build(&program.statements, start, end);
            let block_out = run_forward(&analysis, &cfg, &program.statements);

            let mut felt252_arith_sites: Vec<(usize, String)> = Vec::new();
            for block_id in cfg.topological_order() {
                let block = &cfg.blocks[block_id];
                let mut state = block_entry_state(&analysis, &cfg, block_id, &block_out);

                for &stmt_idx in &block.stmts {
                    let stmt = &program.statements[stmt_idx];
                    if let Some(inv) = stmt.as_invocation() {
                        let libfunc_name = program
                            .libfunc_registry
                            .generic_id(&inv.libfunc_id)
                            .or_else(|| inv.libfunc_id.debug_name.as_deref())
                            .unwrap_or("");
                        let any_arg_tainted = inv.args.iter().any(|a| state.tainted.contains(a));

                        if any_arg_tainted && !state.has_range_check {
                            if FELT252_ARITH_LIBFUNCS
                                .iter()
                                .any(|p| libfunc_name.contains(p))
                            {
                                felt252_arith_sites.push((stmt_idx, libfunc_name.to_string()));
                            } else if libfunc_name == "function_call" {
                                if let Some(callee_idx) =
                                    callgraph.callee_of(&inv.libfunc_id, &program.libfunc_registry)
                                {
                                    if summaries
                                        .has_unsafe_felt252_arith_on_param
                                        .get(callee_idx)
                                        .copied()
                                        .unwrap_or(false)
                                    {
                                        let callee_name = program
                                            .functions
                                            .get(callee_idx)
                                            .map(|f| f.name.clone())
                                            .unwrap_or_else(|| format!("func_{callee_idx}"));
                                        let chain = summaries
                                            .felt252_taint_chains
                                            .get(callee_idx)
                                            .cloned()
                                            .unwrap_or_default();
                                        let evidence = if chain.is_empty() {
                                            format!("function_call[callee={}]", callee_name)
                                        } else {
                                            format!(
                                                "function_call[callee={}] chain={}",
                                                callee_name,
                                                chain.join(" -> ")
                                            )
                                        };
                                        felt252_arith_sites.push((stmt_idx, evidence));
                                    }
                                }
                            }
                        }
                    }
                    state = analysis.transfer_stmt(&state, stmt);
                }
            }

            for (stmt_idx, evidence) in felt252_arith_sites {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "felt252 arithmetic without range check",
                    format!(
                        "Function '{}': '{}' at stmt {} performs felt252 arithmetic on \
                         user-controlled input without a proven range check on every path. \
                         felt252 wraps silently modulo the field prime.",
                        func.name, evidence, stmt_idx
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

        (findings, warnings)
    }
}

fn block_entry_state<A: ForwardAnalysis>(
    analysis: &A,
    cfg: &Cfg,
    block_id: BlockIdx,
    block_out: &HashMap<BlockIdx, A::Domain>,
) -> A::Domain {
    if block_id == cfg.entry {
        return analysis.bottom();
    }

    let Some(preds) = cfg.predecessors.get(&block_id) else {
        return analysis.bottom();
    };
    if preds.is_empty() {
        return analysis.bottom();
    }

    let mut it = preds.iter();
    let first = it.next().expect("preds is non-empty");
    let mut acc = block_out
        .get(first)
        .cloned()
        .unwrap_or_else(|| analysis.bottom());
    for pred in it {
        let pred_out = block_out
            .get(pred)
            .cloned()
            .unwrap_or_else(|| analysis.bottom());
        acc = analysis.join(&acc, &pred_out);
    }
    acc
}
