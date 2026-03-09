use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Best-effort detector for repeated adjacent symbol segments that may indicate
/// local variable shadowing at the source level.
///
/// Cairo's component architecture uses `module::module::` patterns (e.g.,
/// `erc20::erc20::`, `ownable::ownable::`) which are normal OZ conventions
/// and should not be flagged. We only flag patterns that appear in
/// user-written functions (entrypoints), excluding common component/module
/// naming patterns.
pub struct ShadowingLocal;

/// Common Cairo/OZ component and module names that use the `name::name::`
/// pattern. Repeated adjacent segments matching these are NOT shadowing.
const COMPONENT_NAMES: &[&str] = &[
    "erc20",
    "erc721",
    "erc1155",
    "ownable",
    "upgradeable",
    "pausable",
    "reentrancy_guard",
    "access_control",
    "account",
    "mintable",
    "burnable",
    "src5",
    "governance",
    "timelock",
    "multisig",
    "nonces",
    "permit",
    "votes",
    "storage",
    "events",
    "interface",
    "internals",
    "impls",
];

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
            requires_debug_info: true,
            source_aware: false,
        }
    }

    fn run(&self, program: &ProgramIR) -> (Vec<Finding>, Vec<AnalyzerWarning>) {
        let mut findings = Vec::new();
        let warnings = Vec::new();

        // Only check external functions — internal/compiler-generated functions
        // have auto-generated paths that commonly repeat segments.
        for func in program.external_functions() {
            let mut prev: Option<&str> = None;
            for seg in func.name.split("::") {
                if let Some(p) = prev {
                    if !seg.is_empty()
                        && seg == p
                        && !is_known_component_pattern(seg)
                        && !is_wrapper_function(&func.name)
                    {
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

fn is_known_component_pattern(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    COMPONENT_NAMES.iter().any(|c| lower == *c)
}

fn is_wrapper_function(name: &str) -> bool {
    name.contains("__wrapper__") || name.contains("__external__")
}
