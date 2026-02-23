use std::collections::HashMap;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects event emissions where the keys collection appears empty.
pub struct UnindexedEvent;

const EMPTY_ARRAY_LIBFUNCS: &[&str] = &["array_new", "array_empty"];
const APPEND_LIBFUNCS: &[&str] = &["array_append", "array_push", "span_append"];

impl Detector for UnindexedEvent {
    fn id(&self) -> &'static str {
        "unindexed_event"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "emit_event appears to use an empty keys/index set, reducing off-chain queryability and monitoring quality."
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
            let stmts = &program.statements[start..end.min(program.statements.len())];

            // 0 unknown, 1 empty, 2 non-empty
            let mut array_state: HashMap<u64, u8> = HashMap::new();

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                let mut produced_state = inv
                    .args
                    .iter()
                    .filter_map(|a| array_state.get(a).copied())
                    .max()
                    .unwrap_or(0);

                if EMPTY_ARRAY_LIBFUNCS.iter().any(|p| name.contains(p)) {
                    produced_state = 1;
                }
                if APPEND_LIBFUNCS.iter().any(|p| name.contains(p)) {
                    produced_state = 2;
                }

                if name.contains("emit_event") {
                    if let Some(keys_var) = inv.args.first().copied() {
                        if array_state.get(&keys_var).copied().unwrap_or(0) == 1 {
                            findings.push(Finding::new(
                                self.id(),
                                self.severity(),
                                self.confidence(),
                                "Event emitted with empty keys",
                                format!(
                                    "Function '{}': emit_event at stmt {} appears to use an empty keys/index array.",
                                    func.name,
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

                if produced_state != 0 {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            array_state.insert(*r, produced_state);
                        }
                    }
                }
            }
        }

        (findings, warnings)
    }
}
