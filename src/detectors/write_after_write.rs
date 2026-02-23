use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects consecutive storage writes with no intervening storage read.
pub struct WriteAfterWrite;

impl Detector for WriteAfterWrite {
    fn id(&self) -> &'static str {
        "write_after_write"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Multiple storage writes occur without an intervening storage read; this may indicate redundant or overwritten state transitions."
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

            let mut last_write: Option<usize> = None;
            let mut saw_read_since_last_write = true;

            for (local_idx, stmt) in program.statements[start..end.min(program.statements.len())]
                .iter()
                .enumerate()
            {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let abs = start + local_idx;

                if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
                    saw_read_since_last_write = true;
                }

                if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                    if let Some(prev_write) = last_write {
                        if !saw_read_since_last_write {
                            findings.push(Finding::new(
                                self.id(),
                                self.severity(),
                                self.confidence(),
                                "Write-after-write storage pattern",
                                format!(
                                    "Function '{}': storage writes at stmts {} and {} with no intervening storage read. \
                                     Later write may silently override earlier state updates.",
                                    func.name,
                                    prev_write,
                                    abs
                                ),
                                Location {
                                    file: program.source.display().to_string(),
                                    function: func.name.clone(),
                                    statement_idx: Some(abs),
                                    line: None,
                                    col: None,
                                },
                            ));
                        }
                    }
                    last_write = Some(abs);
                    saw_read_since_last_write = false;
                }
            }
        }

        (findings, warnings)
    }
}
