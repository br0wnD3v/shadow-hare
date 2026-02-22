use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects external functions that write to storage without any caller
/// identity check AND without a prior storage read (which would indicate
/// an ownership lookup).
///
/// A "blind setter" — one that writes to storage with no `get_caller_address`,
/// no `get_execution_info`, and no `storage_read_syscall` — can be called by
/// anyone to overwrite critical contract state (owner, fee, parameters, etc.).
///
/// This is a low-confidence, broad detector. It will fire on permissionless
/// initializers and open vaults. Use context to triage: functions with names
/// like `set_`, `update_`, `initialize_`, or `mint_` are higher priority.
pub struct WriteWithoutCallerCheck;

const CALLER_CHECK_LIBFUNCS: &[&str] = &[
    "get_caller_address",
    "get_execution_info",
    "get_contract_address",
];

impl Detector for WriteWithoutCallerCheck {
    fn id(&self) -> &'static str {
        "write_without_caller_check"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "External function writes to storage without any caller identity check and \
         without a prior storage read. Any account can call this function and overwrite \
         critical state."
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
            // Skip constructors — they legitimately write without a caller check
            if func.name.contains("constructor") || func.name.contains("__constructor") {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let mut has_storage_write = false;
            let mut has_caller_check = false;
            let mut has_storage_read = false;
            let mut first_write_site = 0usize;

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

                if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                    if !has_storage_write {
                        first_write_site = start + local_idx;
                    }
                    has_storage_write = true;
                }

                if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
                    has_storage_read = true;
                }

                if CALLER_CHECK_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                    has_caller_check = true;
                }
            }

            // Only flag functions that write storage with NO caller check AND
            // NO storage read (a storage read usually implies an ownership lookup).
            if has_storage_write && !has_caller_check && !has_storage_read {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Storage write without caller check",
                    format!(
                        "Function '{}': writes to storage (first write at stmt {}) \
                         without get_caller_address, get_execution_info, or a prior \
                         storage read. Any caller can overwrite this state.",
                        func.name, first_write_site
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(first_write_site),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}
