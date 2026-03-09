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

            // First pass: collect storage read sites and their produced variables.
            let mut read_results: Vec<(usize, usize, Vec<u64>)> = Vec::new(); // (local_idx, abs_idx, vars)

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };

                if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
                    let produced: Vec<u64> = inv
                        .branches
                        .iter()
                        .flat_map(|b| b.results.iter().copied())
                        .collect();
                    if !produced.is_empty() {
                        read_results.push((local_idx, start + local_idx, produced));
                    }
                }
            }

            // Second pass: for each read, check if its produced vars are used
            // in any SUBSEQUENT statement (not before the read).
            for (read_local_idx, abs_idx, produced) in &read_results {
                let produced_set: HashSet<u64> = produced.iter().copied().collect();
                let mut any_used = false;

                for stmt in stmts.iter().skip(read_local_idx + 1) {
                    let Some(inv) = stmt.as_invocation() else {
                        // Return statements also consume vars
                        if let crate::loader::Statement::Return(vars) = stmt {
                            if vars.iter().any(|v| produced_set.contains(v)) {
                                any_used = true;
                                break;
                            }
                        }
                        continue;
                    };
                    if inv.args.iter().any(|a| produced_set.contains(a)) {
                        any_used = true;
                        break;
                    }
                }

                if !any_used {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Unused storage read",
                        format!(
                            "Function '{}': storage_read result at stmt {} is never consumed.",
                            func.name, abs_idx
                        ),
                        Location {
                            file: program.source.display().to_string(),
                            function: func.name.clone(),
                            statement_idx: Some(*abs_idx),
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
