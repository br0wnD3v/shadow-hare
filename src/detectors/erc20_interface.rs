use std::collections::HashMap;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Best-effort SNIP/ERC20 interface conformance detector from external symbol set.
pub struct IncorrectErc20Interface;

const ERC20_METHODS: &[&str] = &[
    "name",
    "symbol",
    "decimals",
    "total_supply",
    "balance_of",
    "allowance",
    "approve",
    "transfer",
    "transfer_from",
];

const CORE_METHODS: &[&str] = &["total_supply", "balance_of", "transfer", "transfer_from"];

impl Detector for IncorrectErc20Interface {
    fn id(&self) -> &'static str {
        "incorrect_erc20_interface"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Token-like contract appears to implement an incomplete or inconsistent ERC20/SNIP-style external interface."
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
            if ERC20_METHODS.contains(&leaf.as_str()) {
                methods.insert(leaf, (func.raw.entry_point, func.raw.ret_types.len()));
            }
        }

        // Avoid firing on non-token contracts with incidental name overlap.
        if methods.len() < 3 {
            return (findings, warnings);
        }

        let mut issues: Vec<String> = Vec::new();
        for m in CORE_METHODS {
            if !methods.contains_key(*m) {
                issues.push(format!("missing external method '{}'", m));
            }
        }

        for m in ["transfer", "transfer_from", "approve"] {
            if let Some((_, ret_len)) = methods.get(m) {
                if *ret_len == 0 {
                    issues.push(format!("'{}' exposes zero return values", m));
                }
            }
        }

        if !issues.is_empty() {
            let first_site = methods.values().map(|(site, _)| *site).min().unwrap_or(0);
            findings.push(Finding::new(
                self.id(),
                self.severity(),
                self.confidence(),
                "Potential ERC20/SNIP interface mismatch",
                format!(
                    "Token-like symbol set detected, but interface checks failed: {}.",
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
