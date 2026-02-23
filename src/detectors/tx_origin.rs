use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects authentication via `get_tx_info` (transaction origin) instead of
/// `get_caller_address`, which is the Starknet equivalent of Ethereum's
/// `tx.origin` vs `msg.sender` bug.
///
/// Using the transaction origin for authentication is vulnerable because
/// any intermediate contract in the call chain shares the same tx_info.
pub struct TxOriginAuth;

const TX_INFO_LIBFUNCS: &[&str] = &["get_tx_info", "get_execution_info"];
const AUTH_LIBFUNCS: &[&str] = &[
    "assert_eq",
    "assert_ne",
    "felt252_is_zero",
    "felt252_sub",
    "contract_address_to_felt252",
];

impl Detector for TxOriginAuth {
    fn id(&self) -> &'static str {
        "tx_origin_auth"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Authentication using transaction origin (get_tx_info) instead of caller address \
         is unsafe. Use get_caller_address for access control."
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

        for func in program
            .external_functions()
            .filter(|f| !f.is_account_entrypoint())
        {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let mut tx_info_vars: std::collections::HashSet<u64> = std::collections::HashSet::new();
            let mut tx_info_site: Option<usize> = None;

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let inv = match stmt.as_invocation() {
                    Some(inv) => inv,
                    None => continue,
                };

                let is_tx_info = TX_INFO_LIBFUNCS
                    .iter()
                    .any(|p| program.libfunc_registry.matches(&inv.libfunc_id, p));

                if is_tx_info {
                    // Collect result variables from this syscall
                    for branch in &inv.branches {
                        for r in &branch.results {
                            tx_info_vars.insert(*r);
                        }
                    }
                    tx_info_site = Some(start + local_idx);
                }

                // Propagate tx_info taint
                if !tx_info_vars.is_empty() && inv.args.iter().any(|a| tx_info_vars.contains(a)) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            tx_info_vars.insert(*r);
                        }
                    }
                }

                // Detect tx_info value used in auth comparison
                if let Some(site) = tx_info_site {
                    let is_auth = AUTH_LIBFUNCS
                        .iter()
                        .any(|p| program.libfunc_registry.matches(&inv.libfunc_id, p));

                    if is_auth && inv.args.iter().any(|a| tx_info_vars.contains(a)) {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Transaction origin used for authentication",
                            format!(
                                "Function '{}': value from get_tx_info (stmt {}) is used in \
                                 an authentication check at stmt {}. Use get_caller_address instead.",
                                func.name, site, start + local_idx
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
            }
        }

        (findings, warnings)
    }
}
