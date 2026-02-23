use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, SierraId};

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

                // Detect basic zero-check patterns.
                let is_zero_check = ZERO_CHECK_LIBFUNCS.iter().any(|p| libfunc_name.contains(p));
                if is_zero_check {
                    if inv.args.iter().any(|a| tainted_addr_vars.contains(a)) {
                        for branch in &inv.branches {
                            for r in &branch.results {
                                checked_addr_vars.insert(*r);
                            }
                        }
                    }
                }

                // Target argument for call_contract[_syscall] is arg[1].
                let is_call_target = libfunc_name.contains("call_contract_syscall")
                    || libfunc_name.contains("call_contract");
                if is_call_target {
                    let target_var = inv.args.get(1).copied();
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
                if inv.args.iter().any(|a| tainted_addr_vars.contains(a)) {
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

fn is_contract_address_type(ty: &SierraId) -> bool {
    ty.debug_name
        .as_deref()
        .map(|name| name.contains("ContractAddress") || name.contains("contract_address"))
        .unwrap_or(false)
}
