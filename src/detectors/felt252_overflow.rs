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
        Severity::High
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

        // Run on all functions: internal helpers that take felt252 params are
        // equally dangerous when called with user-controlled values.
        for func in program.all_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }

            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Collect parameter variable IDs (potential user-controlled inputs)
            let param_vars: std::collections::HashSet<u64> =
                func.raw.params.iter().map(|(id, _)| *id).collect();

            // Taint propagation: track which vars are derived from user input
            let mut tainted: std::collections::HashSet<u64> = param_vars.clone();

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

                // Check for range-check libfuncs
                if RANGE_CHECK_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                    has_range_check = true;
                }

                // Detect felt252 arithmetic on tainted (user-input) values
                if FELT252_ARITH_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                    if inv.args.iter().any(|a| tainted.contains(a)) {
                        felt252_arith_sites.push((start + local_idx, libfunc_name.to_string()));
                    }
                }

                // Propagate taint
                if inv.args.iter().any(|a| tainted.contains(a)) {
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
