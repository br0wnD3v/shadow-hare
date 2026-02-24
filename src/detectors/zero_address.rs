use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{BranchTarget, CompatibilityTier, Invocation, SierraId};

/// Detects externally supplied address values used as call targets
/// without an observable zero-address check in the function body.
///
/// Conservative scope:
/// - only external functions
/// - only `call_contract[_syscall]` target argument usage
/// - only parameters typed like `ContractAddress`
pub struct MissingZeroAddressCheck;

const ZERO_CHECK_LIBFUNCS: &[&str] = &[
    "contract_address_is_zero",
    "felt252_is_zero",
    "assert_not_zero",
    "assert_nn",
    "assert_ne",
    "contract_address_eq",
];

impl Detector for MissingZeroAddressCheck {
    fn id(&self) -> &'static str {
        "missing_zero_address_check"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Address-like external input is used as call target without observable zero-address validation."
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

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let mut tainted_addr_vars: HashSet<u64> = HashSet::new();
            for (var, ty) in &func.raw.params {
                if is_contract_address_type(ty) {
                    tainted_addr_vars.insert(*var);
                }
            }
            if tainted_addr_vars.is_empty() {
                continue;
            }

            let mut checked_addr_vars: HashSet<u64> = HashSet::new();

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
                let any_tainted_addr_arg = inv.args.iter().any(|a| tainted_addr_vars.contains(a));

                // Structural zero-check signal:
                // 1) explicit zero-check libfuncs on tainted address vars, or
                // 2) guard-like branching over tainted address vars before sink.
                let is_zero_check = ZERO_CHECK_LIBFUNCS.iter().any(|p| libfunc_name.contains(p));
                let is_guard = is_guarding_branch(inv, program, start, end);
                if any_tainted_addr_arg && (is_zero_check || is_guard) {
                    for arg in &inv.args {
                        if tainted_addr_vars.contains(arg) {
                            checked_addr_vars.insert(*arg);
                        }
                    }
                    for branch in &inv.branches {
                        for r in &branch.results {
                            checked_addr_vars.insert(*r);
                        }
                    }
                }

                // Detect external call target usage. Prefer common target slots,
                // but gracefully fall back to any tainted address-like arg.
                let is_call_target = libfunc_name.contains("call_contract_syscall")
                    || libfunc_name.contains("call_contract");
                if is_call_target {
                    let target_var = infer_call_target_arg(inv, &tainted_addr_vars);
                    let target_is_tainted_addr = target_var
                        .map(|v| tainted_addr_vars.contains(&v))
                        .unwrap_or(false);
                    let target_is_checked = target_var
                        .map(|v| checked_addr_vars.contains(&v))
                        .unwrap_or(false);

                    if target_is_tainted_addr && !target_is_checked {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Potential missing zero-address check",
                            format!(
                                "Function '{}': external address input reaches call target at stmt {} \
                                 without observable zero-address validation.",
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

                // Taint propagation.
                if any_tainted_addr_arg {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            tainted_addr_vars.insert(*r);
                        }
                    }
                }
                if inv.args.iter().any(|a| checked_addr_vars.contains(a)) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            checked_addr_vars.insert(*r);
                        }
                    }
                }
            }
        }

        (findings, warnings)
    }
}

fn infer_call_target_arg(inv: &Invocation, tainted_addr_vars: &HashSet<u64>) -> Option<u64> {
    // Typical Starknet call layouts place target near the front; try these first.
    for idx in [1usize, 2, 3] {
        if let Some(v) = inv.args.get(idx).copied() {
            if tainted_addr_vars.contains(&v) {
                return Some(v);
            }
        }
    }
    inv.args
        .iter()
        .copied()
        .find(|v| tainted_addr_vars.contains(v))
}

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
            crate::loader::Statement::Return(_) => return false,
            crate::loader::Statement::Invocation(inv) => {
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

fn is_contract_address_type(ty: &SierraId) -> bool {
    ty.debug_name
        .as_deref()
        .map(|name| name.contains("ContractAddress") || name.contains("contract_address"))
        .unwrap_or(false)
}
