use std::collections::HashSet;

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

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }

            let mut arith_vars: HashSet<u64> = HashSet::new();
            let mut has_event = false;
            let mut write_site = None;

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

                if name.contains("emit_event") {
                    has_event = true;
                }

                if ARITH_HINTS.iter().any(|p| name.contains(p)) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            arith_vars.insert(*r);
                        }
                    }
                }

                if inv.args.iter().any(|a| arith_vars.contains(a)) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            arith_vars.insert(*r);
                        }
                    }
                }

                if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                    let value_is_arith = inv
                        .args
                        .last()
                        .map(|v| arith_vars.contains(v))
                        .unwrap_or(false);
                    if value_is_arith {
                        write_site = Some(start + local_idx);
                    }
                }
            }

            if let Some(site) = write_site {
                if !has_event {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Arithmetic state update without event",
                        format!(
                            "Function '{}': arithmetic-derived value stored at stmt {} without event emission.",
                            func.name,
                            site
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
