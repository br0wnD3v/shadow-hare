use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects explicit comparisons to boolean constants.
pub struct BooleanEquality;

const BOOL_EQ_LIBFUNCS: &[&str] = &["bool_eq", "assert_eq", "assert_ne"];

impl Detector for BooleanEquality {
    fn id(&self) -> &'static str {
        "boolean_equality"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "Boolean compared to a literal true/false value; expression can usually be simplified."
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

                if !BOOL_EQ_LIBFUNCS.iter().any(|p| name.contains(p)) || inv.args.len() < 2 {
                    continue;
                }

                let lhs_const = bool_const_vars.contains(&inv.args[0]);
                let rhs_const = bool_const_vars.contains(&inv.args[1]);
                if lhs_const ^ rhs_const {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Boolean compared to constant",
                        format!(
                            "Function '{}': '{}' at stmt {} compares boolean value to a constant. \
                             Consider simplifying condition to reduce logic complexity.",
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
