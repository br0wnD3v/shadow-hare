use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects token transfer-from style operations where the `from` argument is
/// user-controlled and no caller/ownership gate is observed beforehand.
pub struct ArbitraryTokenTransfer;

const CALLER_CHECK_LIBFUNCS: &[&str] = &[
    "get_caller_address",
    "get_execution_info",
    "get_contract_address",
];

const TRANSFER_FROM_LIBFUNCS: &[&str] =
    &["transfer_from", "safe_transfer_from", "erc20_transfer_from"];

impl Detector for ArbitraryTokenTransfer {
    fn id(&self) -> &'static str {
        "arbitrary_token_transfer"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Token transfer-from style call appears reachable with user-controlled `from` \
         and no observable caller/ownership guard."
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
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let mut tainted: HashSet<u64> = func.raw.params.iter().map(|(id, _)| *id).collect();
            let mut has_caller_check = false;
            let mut has_storage_read = false;

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if CALLER_CHECK_LIBFUNCS
                    .iter()
                    .any(|p| libfunc_name.contains(p))
                {
                    has_caller_check = true;
                }
                if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
                    has_storage_read = true;
                }

                let is_transfer_from = TRANSFER_FROM_LIBFUNCS
                    .iter()
                    .any(|p| libfunc_name.contains(p));
                if is_transfer_from {
                    let from_is_user_controlled = inv
                        .args
                        .first()
                        .map(|arg| tainted.contains(arg))
                        .unwrap_or(false);
                    if from_is_user_controlled && !has_caller_check && !has_storage_read {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Potential arbitrary token transfer-from",
                            format!(
                                "Function '{}': '{}' at stmt {} uses user-controlled `from` \
                                 without observable caller/ownership guard. Attackers may transfer \
                                 tokens from arbitrary accounts.",
                                func.name,
                                libfunc_name,
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

                if inv.args.iter().any(|a| tainted.contains(a)) {
                    for branch in &inv.branches {
                        for result in &branch.results {
                            tainted.insert(*result);
                        }
                    }
                }
            }
        }

        (findings, warnings)
    }
}
