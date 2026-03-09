use std::collections::HashSet;

use crate::analysis::callgraph::CallGraph;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
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
                    .or(inv.libfunc_id.debug_name.as_deref())
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

                if !all_results.is_empty() && all_results.iter().all(|r| !used_vars.contains(r)) {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Unused return value",
                        format!(
                            "Function '{}': return value of '{}' at stmt {} is never used.",
                            func.name,
                            libfunc_name,
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
            | "disable_ap_tracking"
            | "enable_ap_tracking"
            | "withdraw_gas"
            | "withdraw_gas_all"
    ) || name.starts_with("store_local")
        || name.starts_with("felt252_dict")
        || name.starts_with("store_temp")
        || name.contains("emit_event")
        || name.contains("send_message_to_l1")
        || name.contains("snapshot_take")
        || name.contains("storage_write")
        || name.contains("array_append")
        || name.contains("struct_construct")
        || name.contains("struct_deconstruct")
        || name.contains("enum_init")
        || name.contains("_into_box")
        || name.contains("_unbox")
        || name.contains("_dup")
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

        // Use the CallGraph for reliable function reference detection.
        // It resolves function_call targets via numeric IDs and debug names.
        let cg = CallGraph::build(program);

        // Collect all function indices that are called by any function.
        let mut called: HashSet<usize> = HashSet::new();
        for callees in cg.edges.values() {
            for &callee in callees {
                called.insert(callee);
            }
        }

        for func in program.all_functions() {
            // Skip entry points — they're called externally.
            if func.is_entrypoint() {
                continue;
            }

            // Skip well-known generated/framework functions.
            if is_generated_function(&func.name) {
                continue;
            }

            // If this function is referenced in the call graph, it's live.
            if called.contains(&func.idx) {
                continue;
            }

            // Only report when debug info is available (otherwise names are meaningless).
            if !func.name.is_empty() && program.has_debug_info {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Dead code — unreferenced function",
                    format!(
                        "Function '{}' is never called and is not an entry point.",
                        func.name
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
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
    let lower = name.to_ascii_lowercase();
    // Compiler-generated / framework wrappers
    name.contains("__wrapper")
        || name.contains("__generated")
        || name.contains("__default")
        || name.contains("__external")
        || name.contains("__l1_handler")
        || name.contains("__constructor")
        // Standard library and framework implementations
        || name.starts_with("core::")
        || name.starts_with("starknet::")
        || name.starts_with("openzeppelin::")
        || name.starts_with("alexandria_")
        // Trait implementations (Drop, Destruct, PartialEq, Serde, etc.)
        // These are generated by derive macros and referenced indirectly.
        || lower.contains("drop_")
        || lower.contains("destruct_")
        || lower.contains("snapshot_")
        || lower.contains("serde")
        || lower.contains("partial_eq")
        || lower.contains("partial_ord")
        || lower.contains("into_")
        || lower.contains("try_into_")
        || lower.contains("from_")
        || lower.contains("hash_")
        || lower.contains("print_")
        || lower.contains("display_")
        || lower.contains("debug_")
        // Component internals (OZ patterns)
        || name.contains("::InternalImpl")
        || name.contains("::InternalTrait")
        || name.contains("::HasComponent")
        || name.contains("::ComponentState")
        || name.contains("::StorageImpl")
        || name.contains("::EventImpl")
        // Test functions
        || name.contains("::__test::")
}
