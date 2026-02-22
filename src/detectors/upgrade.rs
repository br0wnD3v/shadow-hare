use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects `replace_class_syscall` in external functions that lack an owner
/// check before the upgrade call.
///
/// Upgradeable contracts must gate `replace_class` behind an ownership check.
/// The expected Sierra pattern is:
///   storage_read_syscall (owner slot)
///   → comparison libfunc on the stored value vs get_caller_address
///   → replace_class_syscall
///
/// If `replace_class_syscall` is present but the function body contains no
/// storage-read value used in a comparison/auth operation, the upgrade is
/// effectively permissionless.
pub struct UnprotectedUpgrade;

const REPLACE_CLASS_LIBFUNCS: &[&str] = &["replace_class_syscall", "replace_class"];

const OWNER_CHECK_LIBFUNCS: &[&str] = &[
    "felt252_is_zero",
    "contract_address_eq",
    "assert_eq",
    "assert_ne",
    "felt252_sub",
    "contract_address_to_felt252",
    "u128_eq",
    "felt252_add",
];

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

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Find replace_class invocations
            let replace_sites: Vec<usize> = stmts
                .iter()
                .enumerate()
                .filter_map(|(local_idx, stmt)| {
                    let inv = stmt.as_invocation()?;
                    let is_replace = REPLACE_CLASS_LIBFUNCS
                        .iter()
                        .any(|p| program.libfunc_registry.matches(&inv.libfunc_id, p));
                    if is_replace { Some(local_idx) } else { None }
                })
                .collect();

            if replace_sites.is_empty() {
                continue;
            }

            // Check if any storage_read result flows into an owner-check libfunc
            // before the replace_class call.
            let has_owner_check = has_storage_backed_check(stmts, &replace_sites, program);

            if !has_owner_check {
                for local_idx in replace_sites {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Unprotected contract upgrade",
                        format!(
                            "Function '{}': replace_class_syscall at stmt {} has no \
                             owner/access-control check. Any caller can replace the \
                             contract implementation.",
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
        }

        (findings, warnings)
    }
}

/// Returns true if the function body contains a storage_read whose result is
/// used in an owner-check libfunc before the first replace_class invocation.
fn has_storage_backed_check(
    stmts: &[Statement],
    replace_sites: &[usize],
    program: &ProgramIR,
) -> bool {
    let first_replace = replace_sites.iter().copied().min().unwrap_or(usize::MAX);

    // Collect vars produced by storage_read and get_caller_address syscalls
    let mut privileged_vars: std::collections::HashSet<u64> = std::collections::HashSet::new();

    for (local_idx, stmt) in stmts.iter().enumerate() {
        if local_idx >= first_replace {
            break;
        }
        let inv = match stmt.as_invocation() {
            Some(inv) => inv,
            None => continue,
        };

        let is_storage_read = program.libfunc_registry.is_storage_read(&inv.libfunc_id);
        let is_caller = program.libfunc_registry.matches(&inv.libfunc_id, "get_caller_address");
        let is_tx_info = program
            .libfunc_registry
            .matches(&inv.libfunc_id, "get_execution_info");

        if is_storage_read || is_caller || is_tx_info {
            for branch in &inv.branches {
                for r in &branch.results {
                    privileged_vars.insert(*r);
                }
            }
        }

        // Also propagate taint from privileged vars
        if inv.args.iter().any(|a| privileged_vars.contains(a)) {
            for branch in &inv.branches {
                for r in &branch.results {
                    privileged_vars.insert(*r);
                }
            }
        }

        // Check if a privileged var is used in an owner-check libfunc
        let is_check = OWNER_CHECK_LIBFUNCS
            .iter()
            .any(|p| program.libfunc_registry.matches(&inv.libfunc_id, p));

        if is_check && inv.args.iter().any(|a| privileged_vars.contains(a)) {
            return true;
        }

        // A branch with 2+ outcomes on a privileged var is also an implicit check
        if inv.branches.len() >= 2 && inv.args.iter().any(|a| privileged_vars.contains(a)) {
            return true;
        }
    }

    false
}
