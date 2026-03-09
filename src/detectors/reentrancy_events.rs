use std::collections::HashSet;

use crate::analysis::cfg::Cfg;
use crate::analysis::reentrancy::{backward_reachable_blocks, forward_reachable_blocks};
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects event emission after external call but before final storage commit,
/// using CFG-based reachability analysis.
///
/// In branching code, the linear index comparison (event > call && event < write)
/// gives wrong results. This CFG-aware version checks: for each block with
/// emit_event, is there a call block backward-reachable AND a write block
/// forward-reachable? This respects actual control flow paths.
pub struct ReentrancyEvents;

impl Detector for ReentrancyEvents {
    fn id(&self) -> &'static str {
        "reentrancy_events"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Event emitted between an external call and a subsequent storage write on \
         a reachable CFG path. A reentrant call could cause emitted events to \
         reflect intermediate state rather than the final committed state."
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

            // Skip if this function uses a reentrancy guard
            let stmts_slice = &program.statements[start..end_clamped];
            let has_guard = stmts_slice.iter().any(|stmt| {
                stmt.as_invocation()
                    .map(|inv| {
                        let debug = inv.libfunc_id.debug_name.as_deref().unwrap_or("");
                        debug.contains("reentrancy_guard")
                            || debug.contains("ReentrancyGuard")
                            || debug.contains("nonReentrant")
                            || debug.contains("non_reentrant")
                    })
                    .unwrap_or(false)
            });
            if has_guard {
                continue;
            }

            // Build CFG for this function.
            let cfg = Cfg::build(&program.statements, start, end_clamped);

            // Classify blocks by what they contain.
            let mut call_blocks: HashSet<usize> = HashSet::new();
            let mut event_blocks: Vec<(usize, usize)> = Vec::new(); // (block_id, stmt_idx)
            let mut write_blocks: HashSet<usize> = HashSet::new();

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

                    if name.contains("call_contract") || name.contains("library_call") {
                        call_blocks.insert(block.id);
                    }
                    if name.contains("emit_event") {
                        event_blocks.push((block.id, stmt_idx));
                    }
                    if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                        write_blocks.insert(block.id);
                    }
                }
            }

            if call_blocks.is_empty() || event_blocks.is_empty() || write_blocks.is_empty() {
                continue;
            }

            // For each event block, check CFG reachability.
            for (event_block_id, event_stmt_idx) in &event_blocks {
                // Is there a call block backward-reachable from this event block?
                let backward = backward_reachable_blocks(&cfg, *event_block_id);
                let has_call_before = call_blocks.iter().any(|cb| backward.contains(cb));

                if !has_call_before {
                    continue;
                }

                // Is there a write block forward-reachable from this event block?
                let forward = forward_reachable_blocks(&cfg, *event_block_id);
                let has_write_after = write_blocks.iter().any(|wb| forward.contains(wb));

                if !has_write_after {
                    continue;
                }

                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Event emitted before post-call state commit",
                    format!(
                        "Function '{}': event at stmt {} is reachable from an external call \
                         and precedes a storage write on an executable path. \
                         Reentrancy can cause emitted events to diverge from final state.",
                        func.name, event_stmt_idx
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(*event_stmt_idx),
                        line: None,
                        col: None,
                    },
                ));
                // One finding per function is enough.
                break;
            }
        }

        (findings, warnings)
    }
}
