use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects external functions that mutate contract state (storage_write_syscall)
/// but never emit a corresponding event (emit_event_syscall).
///
/// Events are critical for transparency: indexers, explorers, and off-chain
/// systems rely on events to track state changes. Missing events make contract
/// behaviour opaque and break standard tooling (subgraphs, block explorers,
/// wallets).
///
/// This fires on any external function that:
///   1. Contains at least one storage_write_syscall
///   2. Contains zero emit_event_syscall calls
///
/// Constructors and view functions are excluded.
pub struct MissingEventEmission;

impl Detector for MissingEventEmission {
    fn id(&self) -> &'static str {
        "missing_event_emission"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "External function modifies storage but emits no event. \
         State changes will be invisible to indexers, block explorers, \
         and off-chain listeners."
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
            // Constructors legitimately don't emit events during deployment
            if func.name.contains("constructor") || func.name.contains("__constructor") {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let mut has_storage_write = false;
            let mut has_event_emit = false;
            let mut first_write_site = 0usize;

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let inv = match stmt.as_invocation() {
                    Some(inv) => inv,
                    None => continue,
                };

                if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                    if !has_storage_write {
                        first_write_site = start + local_idx;
                    }
                    has_storage_write = true;
                }

                if program
                    .libfunc_registry
                    .matches(&inv.libfunc_id, "emit_event")
                {
                    has_event_emit = true;
                }
            }

            if has_storage_write && !has_event_emit {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "State change without event emission",
                    format!(
                        "Function '{}': storage is modified (first write at stmt {}) \
                         but no emit_event_syscall is present. \
                         Add an event so indexers and listeners can track this change.",
                        func.name, first_write_site
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(first_write_site),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}
