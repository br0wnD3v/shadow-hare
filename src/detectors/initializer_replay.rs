use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects initializer-like external entrypoints that write storage without an
/// observable initialization guard read/check before the first write.
///
/// Typical one-time init protection pattern:
/// - read an `initialized`-style storage slot
/// - assert it is not already set
/// - then perform writes
///
/// If the function writes state with no pre-write guard signal, repeated calls
/// can reinitialize privileged configuration in production.
pub struct InitializerReplayOrMissingGuard;

const GUARD_CHECK_LIBFUNCS: &[&str] = &[
    "assert_eq",
    "assert_ne",
    "felt252_is_zero",
    "u128_eq",
    "u256_eq",
    "contract_address_eq",
];

const PASS_THROUGH_LIBFUNCS: &[&str] = &["store_temp", "rename", "dup", "snapshot_take"];

impl Detector for InitializerReplayOrMissingGuard {
    fn id(&self) -> &'static str {
        "initializer_replay_or_missing_guard"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Initializer-like external function writes storage without an observable \
         one-time initialization guard."
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
            if !is_initializer_like_name(&func.name) {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let first_write_local = stmts.iter().position(|stmt| {
                stmt.as_invocation()
                    .map(|inv| program.libfunc_registry.is_storage_write(&inv.libfunc_id))
                    .unwrap_or(false)
            });
            let Some(first_write_local) = first_write_local else {
                continue;
            };

            let mut storage_derived: HashSet<u64> = HashSet::new();
            let mut has_guard_check = false;

            for stmt in stmts.iter().take(first_write_local + 1) {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };

                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                let has_storage_arg = inv.args.iter().any(|a| storage_derived.contains(a));

                if GUARD_CHECK_LIBFUNCS
                    .iter()
                    .any(|p| libfunc_name.contains(p))
                    && has_storage_arg
                {
                    has_guard_check = true;
                    break;
                }

                if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            storage_derived.insert(*r);
                        }
                    }
                    continue;
                }

                if PASS_THROUGH_LIBFUNCS
                    .iter()
                    .any(|p| libfunc_name.contains(p))
                    && has_storage_arg
                {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            storage_derived.insert(*r);
                        }
                    }
                }
            }

            if has_guard_check {
                continue;
            }

            findings.push(Finding::new(
                self.id(),
                self.severity(),
                self.confidence(),
                "Initializer may be re-invocable",
                format!(
                    "Function '{}': storage write at stmt {} is not preceded by an \
                     observable storage-backed initialization guard check. Repeated \
                     calls may reconfigure privileged state.",
                    func.name,
                    start + first_write_local
                ),
                Location {
                    file: program.source.display().to_string(),
                    function: func.name.clone(),
                    statement_idx: Some(start + first_write_local),
                    line: None,
                    col: None,
                },
            ));
        }

        (findings, warnings)
    }
}

fn is_initializer_like_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("initialize") || n.contains("initializer")
}
