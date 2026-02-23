use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects storage reads whose loaded state is never consumed.
pub struct UnusedState;

impl Detector for UnusedState {
    fn id(&self) -> &'static str {
        "unused_state"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "Storage value is loaded but never used by subsequent logic in the function."
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
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let mut read_results: Vec<(usize, Vec<u64>)> = Vec::new();
            let mut used_vars: HashSet<u64> = HashSet::new();

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };

                for arg in &inv.args {
                    used_vars.insert(*arg);
                }

                if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
                    let produced: Vec<u64> = inv
                        .branches
                        .iter()
                        .flat_map(|b| b.results.iter().copied())
                        .collect();
                    if !produced.is_empty() {
                        read_results.push((start + local_idx, produced));
                    }
                }
            }

            for (stmt_idx, produced) in read_results {
                if produced.iter().all(|v| !used_vars.contains(v)) {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Unused storage read",
                        format!(
                            "Function '{}': storage_read result at stmt {} is never consumed.",
                            func.name, stmt_idx
                        ),
                        Location {
                            file: program.source.display().to_string(),
                            function: func.name.clone(),
                            statement_idx: Some(stmt_idx),
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
