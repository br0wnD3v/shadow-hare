use crate::analysis::cfg::Cfg;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects storage access performed within loop ranges.
pub struct CostlyLoop;

impl Detector for CostlyLoop {
    fn id(&self) -> &'static str {
        "costly_loop"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Storage access occurs inside a loop; repeated storage ops can significantly increase execution cost."
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

        for func in program.all_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }

            // Build CFG and detect natural loops
            let cfg = Cfg::build(&program.statements, start, end);
            let loops = cfg.natural_loops();

            let mut emitted = false;

            // For each loop, check if any block in the body contains storage read/write
            for lp in &loops {
                for &block_id in &lp.body {
                    let block = &cfg.blocks[block_id];
                    for &stmt_idx in &block.stmts {
                        let Some(stmt) = program.statements.get(stmt_idx) else {
                            continue;
                        };
                        let Some(inv) = stmt.as_invocation() else {
                            continue;
                        };

                        let has_storage = program
                            .libfunc_registry
                            .is_storage_read(&inv.libfunc_id)
                            || program
                                .libfunc_registry
                                .is_storage_write(&inv.libfunc_id);

                        if has_storage {
                            findings.push(Finding::new(
                                self.id(),
                                self.severity(),
                                self.confidence(),
                                "Storage access inside loop",
                                format!(
                                    "Function '{}': natural loop (header block {}) encloses \
                                     storage access at stmt {}.",
                                    func.name, lp.header, stmt_idx
                                ),
                                Location {
                                    file: program.source.display().to_string(),
                                    function: func.name.clone(),
                                    statement_idx: Some(stmt_idx),
                                    line: None,
                                    col: None,
                                },
                            ));
                            emitted = true;
                            break;
                        }
                    }
                    if emitted {
                        break;
                    }
                }
                if emitted {
                    break;
                }
            }
        }

        (findings, warnings)
    }
}
