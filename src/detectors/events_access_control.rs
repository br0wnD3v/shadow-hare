use std::collections::HashMap;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects privileged state mutations without event emission.
///
/// Structural model:
/// - state mutation exists (`storage_write`)
/// - mutation is behind an access-control-like guard (caller+storage-derived data
///   reaches a check/branch before first write)
/// - no `emit_event` in the same function
pub struct MissingEventsAccessControl;

const TAG_CALLER: u8 = 0b01;
const TAG_STORAGE: u8 = 0b10;

const CHECK_LIBFUNCS: &[&str] = &[
    "assert_eq",
    "assert_ne",
    "contract_address_eq",
    "felt252_is_zero",
    "u128_eq",
    "u256_eq",
];

impl Detector for MissingEventsAccessControl {
    fn id(&self) -> &'static str {
        "missing_events_access_control"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Privileged-like state mutation has no corresponding event emission."
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

            let mut first_write: Option<usize> = None;
            let mut has_event = false;
            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");
                if name.contains("emit_event") {
                    has_event = true;
                }
                if program.libfunc_registry.is_storage_write(&inv.libfunc_id)
                    && first_write.is_none()
                {
                    first_write = Some(start + local_idx);
                }
            }

            let Some(write_site) = first_write else {
                continue;
            };

            let has_structural_guard =
                function_has_structural_guard_before_write(program, start, write_site);
            if has_structural_guard && !has_event {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Privileged state change without event",
                    format!(
                        "Function '{}': caller/storage-backed authorization guard precedes storage write at stmt {}, but no event is emitted.",
                        func.name,
                        write_site
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(write_site),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}

fn function_has_structural_guard_before_write(
    program: &ProgramIR,
    func_start: usize,
    write_site: usize,
) -> bool {
    let mut tags: HashMap<u64, u8> = HashMap::new();

    for (abs_idx, stmt) in program.statements.iter().enumerate() {
        if abs_idx < func_start {
            continue;
        }
        if abs_idx >= write_site {
            break;
        }
        let Some(inv) = stmt.as_invocation() else {
            continue;
        };

        let name = program
            .libfunc_registry
            .generic_id(&inv.libfunc_id)
            .or_else(|| inv.libfunc_id.debug_name.as_deref())
            .unwrap_or("");

        let mut arg_union = 0u8;
        let mut has_caller_arg = false;
        let mut has_storage_arg = false;
        for arg in &inv.args {
            let tag = tags.get(arg).copied().unwrap_or(0);
            arg_union |= tag;
            if tag & TAG_CALLER != 0 {
                has_caller_arg = true;
            }
            if tag & TAG_STORAGE != 0 {
                has_storage_arg = true;
            }
        }

        let is_check = CHECK_LIBFUNCS
            .iter()
            .any(|p| program.libfunc_registry.matches(&inv.libfunc_id, p));
        let is_branch_guard = inv.branches.len() >= 2
            && (name.contains("assert")
                || name.contains("_eq")
                || name.contains("is_zero")
                || name.contains("match"));
        let has_mixed_arg = arg_union & (TAG_CALLER | TAG_STORAGE) == (TAG_CALLER | TAG_STORAGE);
        if (is_check || is_branch_guard) && (has_mixed_arg || (has_caller_arg && has_storage_arg)) {
            return true;
        }

        let is_storage_read = program.libfunc_registry.is_storage_read(&inv.libfunc_id);
        let is_caller_source = program
            .libfunc_registry
            .matches(&inv.libfunc_id, "get_caller_address")
            || program
                .libfunc_registry
                .matches(&inv.libfunc_id, "get_execution_info");

        let mut produced_tag = arg_union;
        if is_storage_read {
            produced_tag |= TAG_STORAGE;
        }
        if is_caller_source {
            produced_tag |= TAG_CALLER;
        }
        if produced_tag == 0 {
            continue;
        }

        for branch in &inv.branches {
            for r in &branch.results {
                let entry = tags.entry(*r).or_insert(0);
                *entry |= produced_tag;
            }
        }
    }

    false
}
