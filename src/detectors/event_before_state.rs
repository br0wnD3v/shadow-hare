use std::collections::HashSet;

use crate::analysis::cfg::Cfg;
use crate::analysis::reentrancy::forward_reachable_blocks;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects event emissions that occur before the state change they describe
/// is finalized, using CFG-based forward reachability.
///
/// In branching code, a linear index comparison gives wrong results. This
/// version checks: for each emit_event block, is there a storage_write block
/// forward-reachable? This means the event is on an executable path before
/// the state is committed.
///
/// Pattern: emit_event → storage_write (risky ordering)
/// Safe pattern: storage_write → emit_event
pub struct EventBeforeStateChange;

impl Detector for EventBeforeStateChange {
    fn id(&self) -> &'static str {
        "event_before_state_change"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Event emitted before the state change it describes is finalized. \
         If the transaction reverts after the event, indexers will be inconsistent."
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

            let cfg = Cfg::build(&program.statements, start, end_clamped);

            // Classify blocks.
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

                    if name.contains("emit_event") {
                        event_blocks.push((block.id, stmt_idx));
                    }
                    if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                        write_blocks.insert(block.id);
                    }
                }
            }

            if event_blocks.is_empty() || write_blocks.is_empty() {
                continue;
            }

            // For each event block, check if a write block is forward-reachable.
            for (event_block_id, event_stmt_idx) in &event_blocks {
                let forward = forward_reachable_blocks(&cfg, *event_block_id);
                // Exclude the event's own block — if emit_event and storage_write
                // are in the same block, the ordering within the block matters.
                // But since we only check forward reachability across blocks,
                // same-block cases need intra-block ordering check.
                let has_write_after = write_blocks.iter().any(|wb| {
                    if *wb == *event_block_id {
                        // Same block: check if any storage_write stmt comes after event
                        let block = &cfg.blocks[*wb];
                        let mut seen_event = false;
                        for &si in &block.stmts {
                            if si == *event_stmt_idx {
                                seen_event = true;
                            }
                            if seen_event
                                && program.statements[si].as_invocation().is_some_and(|inv| {
                                    program.libfunc_registry.is_storage_write(&inv.libfunc_id)
                                })
                                && si != *event_stmt_idx
                            {
                                return true;
                            }
                        }
                        false
                    } else {
                        forward.contains(wb)
                    }
                });

                if has_write_after {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Event emitted before state change",
                        format!(
                            "Function '{}': event emitted at stmt {} precedes a storage write \
                             on an executable path. Emit events after state changes.",
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
                    // One finding per function.
                    break;
                }
            }
        }

        (findings, warnings)
    }
}
