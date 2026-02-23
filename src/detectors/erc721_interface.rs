use std::collections::HashMap;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Best-effort ERC721-style interface conformance detector.
pub struct IncorrectErc721Interface;

const ERC721_METHODS: &[&str] = &[
    "balance_of",
    "owner_of",
    "approve",
    "get_approved",
    "set_approval_for_all",
    "is_approved_for_all",
    "transfer_from",
    "safe_transfer_from",
];

const CORE_METHODS: &[&str] = &["balance_of", "owner_of", "transfer_from"];

impl Detector for IncorrectErc721Interface {
    fn id(&self) -> &'static str {
        "incorrect_erc721_interface"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "NFT-like contract appears to implement an incomplete or inconsistent ERC721-style external interface."
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

        let mut methods: HashMap<String, (usize, usize)> = HashMap::new();
        for func in program.external_functions() {
            let leaf = function_leaf(&func.name).to_ascii_lowercase();
            if ERC721_METHODS.contains(&leaf.as_str()) {
                methods.insert(leaf, (func.raw.entry_point, func.raw.ret_types.len()));
            }
        }

        if methods.len() < 3 {
            return (findings, warnings);
        }

        let mut issues: Vec<String> = Vec::new();
        for m in CORE_METHODS {
            if !methods.contains_key(*m) {
                issues.push(format!("missing external method '{}'", m));
            }
        }

        if let Some((_, ret_len)) = methods.get("owner_of") {
            if *ret_len == 0 {
                issues.push("'owner_of' exposes zero return values".to_string());
            }
        }

        if !issues.is_empty() {
            let first_site = methods.values().map(|(site, _)| *site).min().unwrap_or(0);
            findings.push(Finding::new(
                self.id(),
                self.severity(),
                self.confidence(),
                "Potential ERC721 interface mismatch",
                format!(
                    "NFT-like symbol set detected, but interface checks failed: {}.",
                    issues.join(", ")
                ),
                Location {
                    file: program.source.display().to_string(),
                    function: "<program>".to_string(),
                    statement_idx: Some(first_site),
                    line: None,
                    col: None,
                },
            ));
        }

        (findings, warnings)
    }
}

fn function_leaf(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}
