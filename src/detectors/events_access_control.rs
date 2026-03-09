use std::collections::HashMap;

use crate::analysis::cfg::{BlockIdx, Cfg};
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects privileged state mutations without event emission.
///
/// Uses CFG dominator analysis to verify that the access-control guard
/// structurally dominates the storage write (not just appears earlier by index).
///
/// Structural model:
/// - state mutation exists (`storage_write`)
/// - mutation is behind an access-control-like guard (caller+storage-derived data
///   reaches a check/branch) that dominates the write block
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
            let end_clamped = end.min(program.statements.len());

            // Build CFG.
            let cfg = Cfg::build(&program.statements, start, end_clamped);

            // Find first storage write block and check for emit_event.
            let mut first_write_block: Option<BlockIdx> = None;
            let mut first_write_stmt: Option<usize> = None;
            let mut has_event = false;

            for block in &cfg.blocks {
                for &stmt_idx in &block.stmts {
                    let Some(inv) = program.statements[stmt_idx].as_invocation() else {
                        continue;
                    };
                    let name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or(inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");
                    if name.contains("emit_event") {
                        has_event = true;
                    }
                    if program.libfunc_registry.is_storage_write(&inv.libfunc_id)
                        && first_write_block.is_none()
                    {
                        first_write_block = Some(block.id);
                        first_write_stmt = Some(stmt_idx);
                    }
                }
            }

            let Some(write_block) = first_write_block else {
                continue;
            };
            let write_stmt = first_write_stmt.unwrap_or(start);

            // Find guard blocks using taint-tag propagation.
            let guard_block = find_guard_block_in_cfg(program, &cfg, start, end_clamped);

            let has_structural_guard = match guard_block {
                Some(gb) => cfg.dominates(gb, write_block),
                None => false,
            };

            if has_structural_guard && !has_event {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Privileged state change without event",
                    format!(
                        "Function '{}': caller/storage-backed authorization guard dominates \
                         storage write at stmt {}, but no event is emitted.",
                        func.name, write_stmt
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(write_stmt),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}

/// Find the block containing an access-control guard (caller+storage-derived check).
/// Returns the block ID of the guard, if found.
fn find_guard_block_in_cfg(
    program: &ProgramIR,
    cfg: &Cfg,
    _start: usize,
    _end: usize,
) -> Option<BlockIdx> {
    let mut tags: HashMap<u64, u8> = HashMap::new();

    for block in &cfg.blocks {
        for &stmt_idx in &block.stmts {
            let Some(inv) = program.statements[stmt_idx].as_invocation() else {
                continue;
            };

            let name = program
                .libfunc_registry
                .generic_id(&inv.libfunc_id)
                .or(inv.libfunc_id.debug_name.as_deref())
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
            let has_mixed_arg =
                arg_union & (TAG_CALLER | TAG_STORAGE) == (TAG_CALLER | TAG_STORAGE);
            if (is_check || is_branch_guard)
                && (has_mixed_arg || (has_caller_arg && has_storage_arg))
            {
                return Some(block.id);
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
    }

    None
}
