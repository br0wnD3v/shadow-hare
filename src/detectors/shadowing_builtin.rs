use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Best-effort detector for user entrypoints named like Cairo builtins.
pub struct ShadowingBuiltin;

const BUILTIN_NAMES: &[&str] = &[
    "pedersen",
    "poseidon",
    "range_check",
    "segment_arena",
    "system",
    "gas_builtin",
    "ec_op",
    "bitwise",
];

impl Detector for ShadowingBuiltin {
    fn id(&self) -> &'static str {
        "shadowing_builtin"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Entrypoint name collides with a Cairo builtin name, which can reduce readability and auditability."
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
            let leaf = function_leaf(&func.name);
            let leaf_lc = leaf.to_ascii_lowercase();
            if BUILTIN_NAMES.iter().any(|b| leaf_lc == *b) {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Builtin-like symbol shadowing",
                    format!(
                        "External function '{}' uses builtin-like leaf name '{}'. Rename to avoid ambiguity in reviews.",
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

fn function_leaf(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}
