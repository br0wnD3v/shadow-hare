use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects view-like functions that perform storage writes.
///
/// View/read-only entrypoints must not mutate state. A storage write from a
/// view function indicates a broken mutability contract and can mislead
/// integrators, indexers, and auditors.
pub struct ViewStateModification;

impl Detector for ViewStateModification {
    fn id(&self) -> &'static str {
        "view_state_modification"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "View-like function performs storage_write_syscall, violating read-only semantics."
    }

    fn requirements(&self) -> DetectorRequirements {
        DetectorRequirements {
            min_tier: CompatibilityTier::Tier3,
            requires_debug_info: true,
            source_aware: false,
        }
    }

    fn run(&self, program: &ProgramIR) -> (Vec<Finding>, Vec<AnalyzerWarning>) {
        let mut findings = Vec::new();
        let warnings = Vec::new();

        for func in program.all_functions() {
            let is_view_like = func.kind == crate::ir::function::FunctionKind::View
                || func.name.contains("::__view")
                || func.name.ends_with("_view");
            if !is_view_like {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }

            for (local_idx, stmt) in program.statements[start..end.min(program.statements.len())]
                .iter()
                .enumerate()
            {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                if !program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                    continue;
                }

                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "State write in view-like function",
                    format!(
                        "Function '{}' is classified as view/read-only but performs \
                         storage_write_syscall at stmt {}.",
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

        (findings, warnings)
    }
}
