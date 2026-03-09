use crate::analysis::cfg::Cfg;
use crate::analysis::reentrancy::forward_reachable_blocks;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects unbounded loops in external functions where the iteration count
/// could be controlled by an external caller, enabling gas griefing.
///
/// Uses CFG natural loop detection: for each loop with array iteration in its
/// body, checks if external call blocks are forward-reachable from within the
/// loop body.
pub struct GasGriefing;

const LOOP_LIBFUNCS: &[&str] = &[
    "array_len",
    "array_get",
    "array_pop_front",
    "array_snapshot_pop_front",
];

impl Detector for GasGriefing {
    fn id(&self) -> &'static str {
        "gas_griefing"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "External function contains loop-like array iteration that may be \
         controlled by external callers. Gas griefing is possible with \
         unbounded input arrays."
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
            // Skip compiler-generated wrappers — they contain serde code
            // (array iteration for deserializing calldata), not business logic.
            if func.name.contains("__wrapper__") || func.name.contains("__external__") {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }

            // Build CFG and detect natural loops
            let cfg = Cfg::build(&program.statements, start, end);
            let loops = cfg.natural_loops();

            if loops.is_empty() {
                continue;
            }

            let mut emitted = false;

            // For each loop, check if it has array iteration AND an external call
            // is forward-reachable from within the loop body
            for lp in &loops {
                // Check if loop body has array iteration
                let mut iteration_site: Option<usize> = None;
                for &block_id in &lp.body {
                    let block = &cfg.blocks[block_id];
                    for &stmt_idx in &block.stmts {
                        let Some(stmt) = program.statements.get(stmt_idx) else {
                            continue;
                        };
                        let Some(inv) = stmt.as_invocation() else {
                            continue;
                        };
                        let name = program
                            .libfunc_registry
                            .generic_id(&inv.libfunc_id)
                            .or(inv.libfunc_id.debug_name.as_deref())
                            .unwrap_or("");

                        if LOOP_LIBFUNCS.iter().any(|k| name.contains(k)) {
                            iteration_site = Some(stmt_idx);
                            break;
                        }
                    }
                    if iteration_site.is_some() {
                        break;
                    }
                }

                let Some(site) = iteration_site else {
                    continue;
                };

                // Check if external call is reachable from any loop body block
                let mut has_call_in_loop = false;
                for &block_id in &lp.body {
                    let reachable = forward_reachable_blocks(&cfg, block_id);
                    for &reachable_block in &reachable {
                        // Only consider blocks that are also in the loop body
                        if !lp.body.contains(&reachable_block) {
                            continue;
                        }
                        let block = &cfg.blocks[reachable_block];
                        for &stmt_idx in &block.stmts {
                            let Some(stmt) = program.statements.get(stmt_idx) else {
                                continue;
                            };
                            let Some(inv) = stmt.as_invocation() else {
                                continue;
                            };
                            let name = program
                                .libfunc_registry
                                .generic_id(&inv.libfunc_id)
                                .or(inv.libfunc_id.debug_name.as_deref())
                                .unwrap_or("");

                            if name.contains("call_contract") || name.contains("library_call") {
                                has_call_in_loop = true;
                                break;
                            }
                        }
                        if has_call_in_loop {
                            break;
                        }
                    }
                    if has_call_in_loop {
                        break;
                    }
                }

                if has_call_in_loop {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Potential gas griefing via unbounded loop",
                        format!(
                            "Function '{}': array iteration at stmt {} within natural loop \
                             (header block {}) combined with external calls. Callers can pass \
                             large arrays to consume excessive gas.",
                            func.name, site, lp.header
                        ),
                        Location {
                            file: program.source.display().to_string(),
                            function: func.name.clone(),
                            statement_idx: Some(site),
                            line: None,
                            col: None,
                        },
                    ));
                    emitted = true;
                    break;
                }
            }
        }

        (findings, warnings)
    }
}
