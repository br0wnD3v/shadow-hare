use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects branch/assert conditions driven purely by boolean constants.
pub struct TautologyCondition;

impl Detector for TautologyCondition {
    fn id(&self) -> &'static str {
        "tautology"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Control-flow condition is derived from a constant boolean; branch is effectively always-taken or never-taken."
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

            let mut bool_const_vars: HashSet<u64> = HashSet::new();

            for (local_idx, stmt) in program.statements[start..end.min(program.statements.len())]
                .iter()
                .enumerate()
            {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if name.contains("bool_const")
                    || name.contains("bool_true")
                    || name.contains("bool_false")
                {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            bool_const_vars.insert(*r);
                        }
                    }
                    continue;
                }

                let is_conditional =
                    inv.branches.len() >= 2 || name.contains("assert") || name.contains("match");
                if !is_conditional {
                    continue;
                }

                if inv.args.iter().any(|a| bool_const_vars.contains(a)) {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Tautological constant condition",
                        format!(
                            "Function '{}': condition-like invocation '{}' at stmt {} uses a constant boolean value.",
                            func.name,
                            name,
                            start + local_idx
                        ),
                        Location {
                            file: program.source.display().to_string(),
                            function: func.name.clone(),
                            statement_idx: Some(start + local_idx),
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
