use std::collections::HashSet;

use crate::analysis::reentrancy::{build_stmt_to_block_map, forward_reachable_blocks};
use crate::analysis::sanitizers::all_general_sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects arithmetic-driven state updates without event emission.
pub struct MissingEventsArithmetic;

const ARITH_HINTS: &[&str] = &[
    "felt252_add",
    "felt252_sub",
    "felt252_mul",
    "u8_overflowing_add",
    "u16_overflowing_add",
    "u32_overflowing_add",
    "u64_overflowing_add",
    "u128_overflowing_add",
    "u256_add",
    "u256_sub",
    "u256_safe_divmod",
];

impl Detector for MissingEventsArithmetic {
    fn id(&self) -> &'static str {
        "missing_events_arithmetic"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Arithmetic-driven storage update has no corresponding event emission."
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

        let sanitizers = all_general_sanitizers();

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Phase 1: Collect taint seeds from arithmetic operation results
            let mut seeds: HashSet<u64> = HashSet::new();
            for stmt in stmts {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if ARITH_HINTS.iter().any(|p| name.contains(p)) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            seeds.insert(*r);
                        }
                    }
                }
            }

            if seeds.is_empty() {
                continue;
            }

            // Phase 2: Run CFG-based taint analysis
            let (cfg, block_taint) =
                run_taint_analysis(program, func.idx, seeds, &sanitizers, &["function_call"]);

            let stmt_to_block = build_stmt_to_block_map(&cfg, start);

            // Phase 3: Find storage_write blocks where tainted (arithmetic-derived) value is written
            let mut write_site: Option<usize> = None;
            let mut write_block: Option<usize> = None;

            for block in &cfg.blocks {
                let Some(tainted) = block_taint.get(&block.id) else {
                    continue;
                };
                for &stmt_idx in &block.stmts {
                    let Some(stmt) = program.statements.get(stmt_idx) else {
                        continue;
                    };
                    let Some(inv) = stmt.as_invocation() else {
                        continue;
                    };

                    if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                        let value_is_arith = inv
                            .args
                            .last()
                            .map(|v| tainted.contains(v))
                            .unwrap_or(false);
                        if value_is_arith && write_site.is_none() {
                            write_site = Some(stmt_idx);
                            write_block = Some(block.id);
                        }
                    }
                }
            }

            // Phase 4: Check if emit_event is forward-reachable from the write block
            if let (Some(site), Some(wb)) = (write_site, write_block) {
                let reachable = forward_reachable_blocks(&cfg, wb);
                let has_event_on_path = cfg.blocks.iter().any(|block| {
                    if !reachable.contains(&block.id) {
                        return false;
                    }
                    block.stmts.iter().any(|&si| {
                        let Some(stmt) = program.statements.get(si) else {
                            return false;
                        };
                        let Some(inv) = stmt.as_invocation() else {
                            return false;
                        };
                        let name = program
                            .libfunc_registry
                            .generic_id(&inv.libfunc_id)
                            .or(inv.libfunc_id.debug_name.as_deref())
                            .unwrap_or("");
                        name.contains("emit_event")
                    })
                });

                if !has_event_on_path {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Arithmetic state update without event",
                        format!(
                            "Function '{}': arithmetic-derived value stored at stmt {} without event emission.",
                            func.name, site
                        ),
                        Location {
                            file: program.source.display().to_string(),
                            function: func.name.clone(),
                            statement_idx: Some(site),
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
