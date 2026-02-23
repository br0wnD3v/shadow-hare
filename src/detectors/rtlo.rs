use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects Unicode bidirectional control characters in debug-visible symbols.
///
/// These characters can visually reorder source text and hide malicious logic.
pub struct Rtlo;

// Unicode bidi controls commonly abused in Trojan Source style attacks.
const BIDI_CONTROLS: [char; 9] = [
    '\u{202A}', // LRE
    '\u{202B}', // RLE
    '\u{202D}', // LRO
    '\u{202E}', // RLO
    '\u{202C}', // PDF
    '\u{2066}', // LRI
    '\u{2067}', // RLI
    '\u{2068}', // FSI
    '\u{2069}', // PDI
];

impl Detector for Rtlo {
    fn id(&self) -> &'static str {
        "rtlo"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "Bidirectional Unicode control character detected in symbol names; this can hide malicious logic via visual reordering."
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
        let mut seen: HashSet<String> = HashSet::new();

        for func in program.all_functions() {
            if let Some(ch) = first_bidi_control(&func.name) {
                let key = format!("func:{}:{}", func.idx, ch as u32);
                if seen.insert(key) {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Bidirectional control character in function name",
                        format!(
                            "Function '{}' contains bidi control U+{:04X}; review for visual spoofing risks.",
                            func.name,
                            ch as u32
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
        }

        for decl in &program.libfunc_registry.declarations {
            let name = decl
                .id
                .debug_name
                .as_deref()
                .unwrap_or(decl.generic_id.as_str());
            if let Some(ch) = first_bidi_control(name) {
                let key = format!("libfunc:{}:{}", name, ch as u32);
                if seen.insert(key) {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Bidirectional control character in libfunc name",
                        format!(
                            "Libfunc '{}' contains bidi control U+{:04X}; symbol text may be visually misleading.",
                            name,
                            ch as u32
                        ),
                        Location {
                            file: program.source.display().to_string(),
                            function: "<program>".to_string(),
                            statement_idx: None,
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

fn first_bidi_control(s: &str) -> Option<char> {
    s.chars().find(|c| BIDI_CONTROLS.contains(c))
}
