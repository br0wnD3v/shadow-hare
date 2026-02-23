use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects when an external call result is stored directly in contract storage
/// without any intermediate validation or arithmetic.
///
/// A single external call as the sole source of a stored value is a classic
/// price-oracle manipulation pattern: an attacker can flash-loan large amounts
/// to skew the oracle's return value, then exploit the stale/manipulated price
/// that is now in storage.
///
/// Vulnerable pattern:
///   call_contract(oracle, GET_PRICE_SEL, ...) → price
///   storage_write(sys, slot, price)           ← raw price stored
///
/// Safe pattern: apply TWAP, sanity bounds checks, or compare against a
/// secondary oracle before writing.
pub struct OraclePriceManipulation;

/// Pass-through libfuncs that move a value without transforming it.
/// Taint propagates through these without change.
const PASS_THROUGH_LIBFUNCS: &[&str] = &["store_temp", "rename", "dup", "snapshot_take"];

impl Detector for OraclePriceManipulation {
    fn id(&self) -> &'static str {
        "oracle_price_manipulation"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "External call result stored directly in contract storage without validation. \
         A flash-loan or manipulated oracle can set an arbitrary value, enabling \
         price manipulation or accounting fraud."
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

            // Track vars produced by call_contract_syscall as "oracle tainted".
            // Only propagate taint through pass-through ops — any arithmetic
            // or logic operation is considered a sanitizer for this detector.
            let mut oracle_tainted: HashSet<u64> = HashSet::new();

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

                // External call results become oracle-tainted
                let is_external_call = libfunc_name.contains("call_contract_syscall")
                    || libfunc_name.contains("call_contract");

                if is_external_call {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            oracle_tainted.insert(*r);
                        }
                    }
                    continue;
                }

                // Pass-through: propagate oracle taint unchanged
                let is_pass_through = PASS_THROUGH_LIBFUNCS
                    .iter()
                    .any(|p| libfunc_name.contains(p));

                if is_pass_through {
                    if inv.args.iter().any(|a| oracle_tainted.contains(a)) {
                        for branch in &inv.branches {
                            for r in &branch.results {
                                oracle_tainted.insert(*r);
                            }
                        }
                    }
                    continue;
                }

                // Storage write: check if the VALUE argument (arg[2]) is oracle-tainted
                let is_storage_write = program.libfunc_registry.is_storage_write(&inv.libfunc_id);

                if is_storage_write {
                    let value_is_tainted = inv
                        .args
                        .get(2)
                        .map(|v| oracle_tainted.contains(v))
                        .unwrap_or(false);

                    if value_is_tainted {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Oracle price stored without validation",
                            format!(
                                "Function '{}': at stmt {} the value written to storage \
                                 comes directly from an external call result without \
                                 intermediate validation. An attacker can manipulate \
                                 the external call's return value via flash loan.",
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
                // Arithmetic / other ops: do NOT propagate oracle taint
                // (transformation implies at least some processing)
            }
        }

        (findings, warnings)
    }
}
