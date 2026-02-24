use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects side-effectful syscalls in account validation entrypoints.
///
/// Account validation paths (`__validate__`, `__validate_declare__`,
/// `__validate_deploy__`) should be pure verification logic. Invoking
/// side-effectful syscalls in validation can break account invariants and
/// transaction acceptance guarantees.
pub struct AccountValidateForbiddenSyscalls;

const FORBIDDEN_VALIDATE_LIBFUNCS: &[&str] = &[
    "call_contract_syscall",
    "call_contract",
    "library_call_syscall",
    "library_call",
    "deploy_syscall",
    "deploy",
    "replace_class_syscall",
    "replace_class",
    "send_message_to_l1_syscall",
    "send_message_to_l1",
    "storage_write_syscall",
    "storage_write",
];

impl Detector for AccountValidateForbiddenSyscalls {
    fn id(&self) -> &'static str {
        "account_validate_forbidden_syscalls"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "Account validation entrypoint performs a side-effectful syscall. \
         Validation should be pure verification logic."
    }

    fn requirements(&self) -> DetectorRequirements {
        DetectorRequirements {
            min_tier: CompatibilityTier::Tier3,
            // This detector relies on account validation naming conventions.
            requires_debug_info: true,
            source_aware: false,
        }
    }

    fn run(&self, program: &ProgramIR) -> (Vec<Finding>, Vec<AnalyzerWarning>) {
        let mut findings = Vec::new();
        let warnings = Vec::new();

        for func in program.external_functions() {
            if !is_validate_entrypoint_name(&func.name) {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }

            for (local_idx, stmt) in program.statements[start..end.min(program.statements.len())]
                .iter()
                .enumerate()
            {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };

                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if !FORBIDDEN_VALIDATE_LIBFUNCS
                    .iter()
                    .any(|p| libfunc_name.contains(p))
                {
                    continue;
                }

                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Side-effectful syscall in account validation",
                    format!(
                        "Function '{}': validation path invokes '{}' at stmt {}. \
                         Account validation should not perform side-effectful \
                         syscalls.",
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

        (findings, warnings)
    }
}

fn is_validate_entrypoint_name(name: &str) -> bool {
    name.contains("__validate__")
        || name.contains("__validate_declare__")
        || name.contains("__validate_deploy__")
}
