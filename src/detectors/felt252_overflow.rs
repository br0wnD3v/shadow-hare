use crate::analysis::callgraph::{CallGraph, FunctionSummaries};
use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
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

        // Build inter-procedural call graph and function summaries so that we
        // flag entry points that delegate felt252 arithmetic to helper functions.
        // Without this, a pattern like:
        //   external_fn(user_val) → helper(user_val) → felt252_mul(user_val, …)
        // would be silently missed (the arith doesn't appear in the entry-point
        // statement range, and function_call was previously skipped).
        let callgraph = CallGraph::build(program);
        let summaries = FunctionSummaries::compute(program, &callgraph);

        // Run only on entry-point functions (External, L1Handler, Constructor, View).
        //
        // Rationale: internal helper functions (e.g. safe_math::mul, hash utilities)
        // also perform felt252 arithmetic on their parameters, but those parameters
        // come from their callers — not directly from the user. Running on all functions
        // causes massive FP inflation because every anonymous arithmetic helper fires
        // independently with all params treated as tainted.
        //
        // Restricting to entry points means we only flag arithmetic visible at the
        // trust boundary. Inter-procedural summaries close the gap for helpers.
        for func in program.functions.iter().filter(|f| f.is_entrypoint()) {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }

            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Collect parameter variable IDs (potential user-controlled inputs)
            let mut tainted: std::collections::HashSet<u64> =
                func.raw.params.iter().map(|(id, _)| *id).collect();

            // Track whether any range check is performed in this function
            let mut has_range_check = false;
            let mut felt252_arith_sites: Vec<(usize, String)> = Vec::new();

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let inv = match stmt.as_invocation() {
                    Some(inv) => inv,
                    None => continue,
                };

                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                // Check for range-check libfuncs — suppress felt252 arith findings
                if RANGE_CHECK_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                    has_range_check = true;
                }

                // Inter-procedural: when we call a helper that is known to do unchecked
                // felt252 arithmetic on its tainted parameters, propagate taint to the
                // call's results so downstream checks can fire, and record an arith site.
                if libfunc_name == "function_call" {
                    let any_arg_tainted = inv.args.iter().any(|a| tainted.contains(a));
                    if any_arg_tainted && !has_range_check {
                        if let Some(callee_idx) =
                            callgraph.callee_of(&inv.libfunc_id, &program.libfunc_registry)
                        {
                            if summaries
                                .has_unsafe_felt252_arith_on_param
                                .get(callee_idx)
                                .copied()
                                .unwrap_or(false)
                            {
                                felt252_arith_sites.push((
                                    start + local_idx,
                                    format!("function_call[callee={}]", callee_idx),
                                ));
                                for branch in &inv.branches {
                                    for r in &branch.results {
                                        tainted.insert(*r);
                                    }
                                }
                            }
                        }
                    }
                    // Do not propagate general taint through opaque function boundaries
                    continue;
                }

                let any_arg_tainted = inv.args.iter().any(|a| tainted.contains(a));

                // Detect felt252 arithmetic on tainted (user-input) values
                if FELT252_ARITH_LIBFUNCS.iter().any(|p| libfunc_name.contains(p))
                    && any_arg_tainted
                {
                    felt252_arith_sites.push((start + local_idx, libfunc_name.to_string()));
                }

                // Propagate taint through other libfuncs
                if any_arg_tainted {
                    for branch in &inv.branches {
                        for result in &branch.results {
                            tainted.insert(*result);
                        }
                    }
                }
            }

            // Only flag if there's arithmetic on user input AND no range checks
            if !has_range_check {
                for (stmt_idx, libfunc) in felt252_arith_sites {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "felt252 arithmetic without range check",
                        format!(
                            "Function '{}': '{}' at stmt {} performs felt252 arithmetic on \
                             user-controlled input without a prior range check. \
                             felt252 wraps silently modulo the field prime.",
                            func.name, libfunc, stmt_idx
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
