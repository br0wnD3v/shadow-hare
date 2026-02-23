use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Best-effort detector for repeated adjacent symbol segments.
pub struct ShadowingLocal;

impl Detector for ShadowingLocal {
    fn id(&self) -> &'static str {
        "shadowing_local"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Repeated adjacent symbol segments suggest local name shadowing and reduced readability."
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
            let mut prev: Option<&str> = None;
            for seg in func.name.split("::") {
                if let Some(p) = prev {
                    if !seg.is_empty() && seg == p {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Potential local shadowing in symbol path",
                            format!(
                                "Function '{}' contains repeated adjacent segment '{}' in debug path.",
                                func.name, seg
                            ),
                            Location {
                                file: program.source.display().to_string(),
                                function: func.name.clone(),
                                statement_idx: Some(func.raw.entry_point),
                                line: None,
                                col: None,
                            },
                        ));
                        break;
                    }
                }
                prev = Some(seg);
            }
        }

        (findings, warnings)
    }
}
