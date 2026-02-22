use std::collections::HashSet;

use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects hardcoded contract addresses used as call targets.
///
/// Using `felt252_const` or `contract_address_const` as the target argument
/// of `call_contract_syscall` embeds a fixed address in the bytecode.
/// Hardcoded addresses:
/// - Cannot be updated when the target is upgraded or migrated
/// - Are invisible to auditors unless noted explicitly
/// - May point to deprecated/malicious contracts after a migration
///
/// Safe pattern: store the target address in contract storage and validate
/// it on write.
pub struct HardcodedAddress;

const CONST_LIBFUNCS: &[&str] = &[
    "felt252_const",
    "contract_address_const",
    "class_hash_const",
];

impl Detector for HardcodedAddress {
    fn id(&self) -> &'static str {
        "hardcoded_address"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "Hardcoded constant used as call_contract target. The address cannot be updated \
         after deployment and may point to a deprecated or migrated contract."
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
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Track variables that were produced by const libfuncs
            let mut const_vars: HashSet<u64> = HashSet::new();

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let inv = match stmt.as_invocation() {
                    Some(inv) => inv,
                    None => continue,
                };

                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                // Record const-produced vars
                if CONST_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            const_vars.insert(*r);
                        }
                    }
                    continue;
                }

                // Detect when a const var is used as the call target (arg[1])
                let is_call = libfunc_name.contains("call_contract_syscall")
                    || libfunc_name.contains("call_contract");

                if is_call {
                    let target_is_const = inv
                        .args
                        .get(1)
                        .map(|t| const_vars.contains(t))
                        .unwrap_or(false);

                    if target_is_const {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Hardcoded call target address",
                            format!(
                                "Function '{}': call_contract at stmt {} uses a hardcoded \
                                 constant as the target address. Store the address in \
                                 contract storage so it can be updated if needed.",
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
            }
        }

        (findings, warnings)
    }
}
