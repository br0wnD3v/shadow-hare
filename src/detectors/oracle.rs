use std::collections::HashSet;

use crate::analysis::sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects when an external call result is stored directly in contract storage
/// without any intermediate validation or arithmetic.
///
/// A single external call as the sole source of a stored value is a classic
/// price-oracle manipulation pattern: an attacker can flash-loan large amounts
/// to skew the oracle's return value, then exploit the stale/manipulated price
/// that is now in storage.
///
/// Detection strategy (CFG + taint):
/// 1. For each external function, seed taint from `call_contract_syscall` results.
/// 2. Propagate taint through CFG with `run_taint_analysis`.
/// 3. Sanitize with hash operations (TWAP/aggregation) and storage reads.
/// 4. If tainted value reaches `storage_write`, report.
///
/// Unlike the previous linear-only approach, this propagates taint through
/// arithmetic (division, scaling) and respects CFG branching — catching
/// manipulation paths even after intermediate computation.
pub struct OraclePriceManipulation;

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

        // Sanitizers for oracle manipulation:
        // - Hash ops break manipulation (TWAP, aggregation)
        // - Constant producers (not oracle-derived)
        // - Storage reads (values from storage, not from oracle)
        // - Comparison/assertion ops indicate validation
        let mut oracle_sanitizers = sanitizers::hash_only_sanitizers();
        oracle_sanitizers.extend_from_slice(sanitizers::STORAGE_READ);
        // Add comparison operators as sanitizers — if the oracle value
        // is validated against bounds, that's a mitigation
        oracle_sanitizers.extend_from_slice(&[
            "felt252_is_zero",
            "assert_le",
            "assert_lt",
            "assert_eq",
            "assert_ne",
        ]);

        for func in program.external_functions() {
            // Skip compiler-generated wrappers
            if func.name.contains("__wrapper__") || func.name.contains("__external__") {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let end_clamped = end.min(program.statements.len());

            // Phase 1: Find call_contract results to seed as oracle-tainted.
            let mut oracle_seeds: HashSet<u64> = HashSet::new();
            let mut has_call_contract = false;

            for stmt in &program.statements[start..end_clamped] {
                let inv = match stmt.as_invocation() {
                    Some(inv) => inv,
                    None => continue,
                };

                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if name.contains("call_contract_syscall") || name.contains("call_contract") {
                    has_call_contract = true;
                    for branch in &inv.branches {
                        for &r in &branch.results {
                            oracle_seeds.insert(r);
                        }
                    }
                }
            }

            if !has_call_contract || oracle_seeds.is_empty() {
                continue;
            }

            // Phase 2: Run CFG-based taint analysis.
            let (cfg, block_taint) = run_taint_analysis(
                program,
                func.idx,
                oracle_seeds,
                &oracle_sanitizers,
                &["function_call"],
            );

            // Phase 3: Check if oracle taint reaches storage_write.
            let mut found = false;
            for block_id in cfg.topological_order() {
                if found {
                    break;
                }
                let block = &cfg.blocks[block_id];
                let tainted = block_taint.get(&block_id);

                for &stmt_idx in &block.stmts {
                    let stmt = &program.statements[stmt_idx];
                    let inv = match stmt {
                        Statement::Invocation(inv) => inv,
                        _ => continue,
                    };

                    if !program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                        continue;
                    }

                    // Storage write: check if the VALUE argument is oracle-tainted.
                    // Arg layout: storage_write(system, address, value)
                    let value_is_tainted = inv
                        .args
                        .get(2)
                        .map(|v| tainted.is_some_and(|t| t.contains(v)))
                        .unwrap_or(false);

                    if value_is_tainted {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Oracle price stored without validation",
                            format!(
                                "Function '{}': at stmt {} the value written to storage \
                                 derives from an external call result without adequate \
                                 validation. An attacker can manipulate the external \
                                 call's return value via flash loan.",
                                func.name, stmt_idx
                            ),
                            Location {
                                file: program.source.display().to_string(),
                                function: func.name.clone(),
                                statement_idx: Some(stmt_idx),
                                line: None,
                                col: None,
                            },
                        ));
                        found = true;
                        break;
                    }
                }
            }
        }

        (findings, warnings)
    }
}
