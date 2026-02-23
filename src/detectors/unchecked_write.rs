use std::collections::HashMap;

use crate::analysis::cfg::{BlockIdx, Cfg};
use crate::analysis::dataflow::{run_forward, ForwardAnalysis};
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
struct WriteGuardState {
    has_caller_check: bool,
    has_storage_read: bool,
}

struct WriteGuardAnalysis<'a> {
    program: &'a ProgramIR,
}

impl<'a> ForwardAnalysis for WriteGuardAnalysis<'a> {
    type Domain = WriteGuardState;

    fn bottom(&self) -> Self::Domain {
        WriteGuardState::default()
    }

    fn transfer_stmt(&self, state: &Self::Domain, stmt: &crate::loader::Statement) -> Self::Domain {
        let inv = match stmt.as_invocation() {
            Some(inv) => inv,
            None => return *state,
        };

        let libfunc_name = self
            .program
            .libfunc_registry
            .generic_id(&inv.libfunc_id)
            .or_else(|| inv.libfunc_id.debug_name.as_deref())
            .unwrap_or("");

        let mut next = *state;
        if CALLER_CHECK_LIBFUNCS
            .iter()
            .any(|p| libfunc_name.contains(p))
        {
            next.has_caller_check = true;
        }
        if self
            .program
            .libfunc_registry
            .is_storage_read(&inv.libfunc_id)
        {
            next.has_storage_read = true;
        }
        next
    }

    fn join(&self, a: &Self::Domain, b: &Self::Domain) -> Self::Domain {
        WriteGuardState {
            // Keep true only if every incoming path established the guard.
            has_caller_check: a.has_caller_check && b.has_caller_check,
            has_storage_read: a.has_storage_read && b.has_storage_read,
        }
    }
}

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
            let end = end.min(program.statements.len());

            let analysis = WriteGuardAnalysis { program };
            let cfg = Cfg::build(&program.statements, start, end);
            let block_out = run_forward(&analysis, &cfg, &program.statements);

            let mut first_unchecked_write_site: Option<usize> = None;
            for block_id in cfg.topological_order() {
                let block = &cfg.blocks[block_id];
                let mut state = block_entry_state(&analysis, &cfg, block_id, &block_out);

                for &stmt_idx in &block.stmts {
                    let stmt = &program.statements[stmt_idx];
                    if let Some(inv) = stmt.as_invocation() {
                        if program.libfunc_registry.is_storage_write(&inv.libfunc_id)
                            && !state.has_caller_check
                            && !state.has_storage_read
                        {
                            first_unchecked_write_site = Some(match first_unchecked_write_site {
                                Some(existing) => existing.min(stmt_idx),
                                None => stmt_idx,
                            });
                        }
                    }
                    state = analysis.transfer_stmt(&state, stmt);
                }
            }

            if let Some(first_write_site) = first_unchecked_write_site {
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

fn block_entry_state<A: ForwardAnalysis>(
    analysis: &A,
    cfg: &Cfg,
    block_id: BlockIdx,
    block_out: &HashMap<BlockIdx, A::Domain>,
) -> A::Domain {
    if block_id == cfg.entry {
        return analysis.bottom();
    }

    let Some(preds) = cfg.predecessors.get(&block_id) else {
        return analysis.bottom();
    };
    if preds.is_empty() {
        return analysis.bottom();
    }

    let mut it = preds.iter();
    let first = it.next().expect("preds is non-empty");
    let mut acc = block_out
        .get(first)
        .cloned()
        .unwrap_or_else(|| analysis.bottom());
    for pred in it {
        let pred_out = block_out
            .get(pred)
            .cloned()
            .unwrap_or_else(|| analysis.bottom());
        acc = analysis.join(&acc, &pred_out);
    }
    acc
}
