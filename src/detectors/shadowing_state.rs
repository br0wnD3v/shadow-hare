use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Best-effort detector for function/type leaf-name collisions.
pub struct ShadowingState;

impl Detector for ShadowingState {
    fn id(&self) -> &'static str {
        "shadowing_state"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Function symbol collides with a state/type-like symbol name, which can hide intent and increase review error rate."
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

        let mut type_leafs: HashSet<String> = HashSet::new();
        for decl in &program.type_registry.declarations {
            let Some(name) = decl.id.debug_name.as_deref() else {
                continue;
            };
            let leaf = name
                .rsplit("::")
                .next()
                .unwrap_or(name)
                .to_ascii_lowercase();
            if !leaf.is_empty() {
                type_leafs.insert(leaf);
            }
        }

        if type_leafs.is_empty() {
            return (findings, warnings);
        }

        for func in program.all_functions() {
            let leaf = func
                .name
                .rsplit("::")
                .next()
                .unwrap_or(func.name.as_str())
                .to_ascii_lowercase();
            if type_leafs.contains(&leaf) {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Potential state/type shadowing",
                    format!(
                        "Function '{}' shares leaf name '{}' with a type symbol in this program.",
                        func.name, leaf
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(func.raw.entry_point),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}
