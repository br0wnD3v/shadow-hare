use crate::analysis::callgraph::{CallGraph, FunctionSummaries};
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects `__execute__` functions that do not increment a nonce.
///
/// Account contracts must increment a nonce after each successful execution
/// to prevent replay attacks. A proper nonce increment is:
///   storage_read → arithmetic (add 1) → storage_write to the SAME slot.
///
/// This detector checks for the nonce increment pattern both inline and
/// transitively through called helper functions (via CallGraph summaries).
pub struct MissingNonceValidation;

impl Detector for MissingNonceValidation {
    fn id(&self) -> &'static str {
        "missing_nonce_validation"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "__execute__ function has no nonce increment pattern (storage read + arithmetic + \
         storage write). Transactions can be replayed indefinitely against this account."
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

        // Build call graph + summaries for inter-procedural nonce increment detection.
        let cg = CallGraph::build(program);
        let summaries = FunctionSummaries::compute(program, &cg);

        for func in program.all_functions() {
            // Only flag __execute__ entry points
            if !func.name.contains("__execute__") && !func.name.ends_with("__execute") {
                continue;
            }

            let (start, _end) = program.function_statement_range(func.idx);

            // Check inline: verify a connected read → arith → write chain exists
            let inline_nonce = check_inline_nonce_pattern(program, func.idx);

            // Check inter-procedurally: does any called function have nonce increment?
            let interprocedural_nonce = summaries
                .has_nonce_increment
                .get(func.idx)
                .copied()
                .unwrap_or(false);

            if !inline_nonce && !interprocedural_nonce {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Missing nonce increment in __execute__",
                    format!(
                        "Function '{}' is an execute entrypoint but has no nonce increment \
                         pattern (storage read + arithmetic + storage write). \
                         Transaction replay attacks are possible.",
                        func.name
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
        }

        (findings, warnings)
    }
}

/// Check for a connected nonce increment chain: storage_read result flows
/// into arithmetic, and arithmetic result flows into storage_write.
fn check_inline_nonce_pattern(program: &ProgramIR, func_idx: usize) -> bool {
    use std::collections::HashSet;

    let (start, end) = program.function_statement_range(func_idx);
    if start >= end {
        return false;
    }
    let stmts = &program.statements[start..end.min(program.statements.len())];

    // Track variables produced by storage reads
    let mut read_vars: HashSet<u64> = HashSet::new();
    // Track variables produced by arithmetic on read vars
    let mut arith_vars: HashSet<u64> = HashSet::new();

    for stmt in stmts {
        let Some(inv) = stmt.as_invocation() else {
            continue;
        };
        let name = program
            .libfunc_registry
            .generic_id(&inv.libfunc_id)
            .or(inv.libfunc_id.debug_name.as_deref())
            .unwrap_or("");

        // Collect storage read results
        if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
            for branch in &inv.branches {
                for &r in &branch.results {
                    read_vars.insert(r);
                }
            }
            continue;
        }

        // Propagate through pass-through ops
        if name.contains("store_temp")
            || name.contains("rename")
            || name.contains("dup")
            || name.contains("snapshot_take")
        {
            let has_read = inv.args.iter().any(|a| read_vars.contains(a));
            let has_arith = inv.args.iter().any(|a| arith_vars.contains(a));
            for branch in &inv.branches {
                for &r in &branch.results {
                    if has_read {
                        read_vars.insert(r);
                    }
                    if has_arith {
                        arith_vars.insert(r);
                    }
                }
            }
            continue;
        }

        // Check if arithmetic operates on a read-derived value
        let is_arith = name.contains("felt252_add")
            || name.contains("u128_overflowing_add")
            || name.contains("u64_overflowing_add")
            || name.contains("u32_overflowing_add")
            || name.contains("u256_add");

        if is_arith && inv.args.iter().any(|a| read_vars.contains(a)) {
            for branch in &inv.branches {
                for &r in &branch.results {
                    arith_vars.insert(r);
                }
            }
            continue;
        }

        // Check if storage write uses an arithmetic-derived value
        if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
            if inv.args.iter().any(|a| arith_vars.contains(a)) {
                return true;
            }
        }
    }

    false
}
