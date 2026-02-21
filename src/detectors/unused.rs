use std::collections::HashSet;

use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects invocations whose return values are never used.
///
/// In Sierra, every Invocation produces result variables via its branches.
/// If those result variables are never referenced by any subsequent statement,
/// the return values are silently discarded — potentially hiding errors.
pub struct UnusedReturn;

impl Detector for UnusedReturn {
    fn id(&self) -> &'static str {
        "unused_return"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "Return value of a function call is never used. This may hide errors or \
         important status codes."
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

        for func in program.all_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Collect all variable reads (args used anywhere in the function)
            let mut used_vars: HashSet<u64> = HashSet::new();
            for stmt in stmts {
                match stmt {
                    Statement::Return(vars) => {
                        used_vars.extend(vars.iter().copied());
                    }
                    Statement::Invocation(inv) => {
                        used_vars.extend(inv.args.iter().copied());
                    }
                }
            }

            // Find invocations that produce results that go entirely unused
            for (local_idx, stmt) in stmts.iter().enumerate() {
                let inv = match stmt.as_invocation() {
                    Some(inv) => inv,
                    None => continue,
                };

                // Skip libfuncs that are expected to have unused results
                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if should_skip_libfunc(libfunc_name) {
                    continue;
                }

                // Check if all result variables from all branches are unused
                let all_results: Vec<u64> = inv
                    .branches
                    .iter()
                    .flat_map(|b| b.results.iter().copied())
                    .collect();

                if !all_results.is_empty()
                    && all_results.iter().all(|r| !used_vars.contains(r))
                {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Unused return value",
                        format!(
                            "Function '{}': return value of '{}' at stmt {} is never used.",
                            func.name, libfunc_name, start + local_idx
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

fn should_skip_libfunc(name: &str) -> bool {
    // These libfuncs are expected to have results that may not be used directly.
    // Gas/builtin management libfuncs thread state implicitly through the runtime
    // and their return values are never "used" by user code — always skip them.
    matches!(
        name,
        "branch_align"
            | "drop"
            | "alloc_local"
            | "finalize_locals"
            | "store_temp"
            | "rename"
            | "nop"
            | "redeposit_gas"
            | "get_builtin_costs"
            | "revoke_ap_tracking"
    ) || name.starts_with("store_local")
        || name.starts_with("felt252_dict")
        || name.starts_with("store_temp")
        || name.contains("emit_event")
        || name.contains("send_message_to_l1")
        || name.contains("snapshot_take")
}

// ── Dead code detector ───────────────────────────────────────────────────────

/// Detects functions that are never called and are not entry points.
pub struct DeadCode;

impl Detector for DeadCode {
    fn id(&self) -> &'static str {
        "dead_code"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Function is never called and is not an entry point. Consider removing it."
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

        // Build the call graph: which functions are referenced in invocations?
        let mut called_functions: HashSet<String> = HashSet::new();

        for stmt in &program.statements {
            if let Statement::Invocation(inv) = stmt {
                // function_call libfuncs reference another function by ID/name
                if let Some(name) = &inv.libfunc_id.debug_name {
                    if name.contains("function_call") || name.starts_with("call") {
                        // The function being called is typically encoded in generic args
                        // For now, mark the libfunc itself as "called" so we don't
                        // produce FP on internal Sierra builtins.
                        called_functions.insert(name.clone());
                    }
                }
            }
        }

        for func in program.all_functions() {
            // Skip entry points — they're called externally
            if func.is_entrypoint() {
                continue;
            }

            // Skip well-known generated functions
            let name = &func.name;
            if is_generated_function(name) {
                continue;
            }

            // If no other code references this function name, it's dead
            // This is a best-effort heuristic — Sierra function calls go through
            // the function_call libfunc with the function id in generic args.
            let is_referenced = program.statements.iter().any(|s| {
                if let Statement::Invocation(inv) = s {
                    inv.libfunc_id
                        .debug_name
                        .as_deref()
                        .map(|n| n.contains(name.as_str()))
                        .unwrap_or(false)
                } else {
                    false
                }
            });

            if !is_referenced && !name.is_empty() && program.has_debug_info {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Dead code — unreferenced function",
                    format!(
                        "Function '{}' is never called and is not an entry point.",
                        name
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: name.clone(),
                        statement_idx: Some(func.raw.entry_point),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}

fn is_generated_function(name: &str) -> bool {
    name.contains("__wrapper")
        || name.contains("__generated")
        || name.contains("__default")
        || name.contains("drop_")
        || name.contains("snapshot_")
        || name.starts_with("core::")
        || name.starts_with("starknet::")
}
