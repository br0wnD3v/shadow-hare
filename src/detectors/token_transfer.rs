use std::collections::HashSet;

use crate::analysis::sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects token transfer-from style operations where the `from` argument is
/// user-controlled and no caller/ownership gate is observed beforehand.
///
/// At Sierra level, token transfers appear as:
///   1. `function_call` libfuncs with debug names containing transfer patterns
///   2. External functions implementing transfer_from (the function itself)
///
/// Note: Detection via function_call debug names requires debug info in the
/// artifact. Without debug info, only the containing function name is checked.
pub struct ArbitraryTokenTransfer;

/// Patterns in function_call debug names that indicate transfer-from operations.
const TRANSFER_FROM_PATTERNS: &[&str] = &["transfer_from", "safe_transfer_from"];

/// Caller-check libfuncs that act as guards. When present, from_address taint
/// is sanitized because the caller identity has been verified.
const CALLER_GUARD_SANITIZERS: &[&str] = &["get_caller_address", "get_contract_address"];

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

        let mut transfer_sanitizers = sanitizers::all_general_sanitizers();
        for s in CALLER_GUARD_SANITIZERS {
            if !transfer_sanitizers.contains(s) {
                transfer_sanitizers.push(s);
            }
        }

        for func in program.external_functions() {
            // Skip functions that ARE implementing transfer_from — they are
            // supposed to accept a `from` parameter. The vulnerability is when
            // a function CALLS transfer_from on another contract, not when it
            // implements the standard interface.
            if TRANSFER_FROM_PATTERNS.iter().any(|p| func.name.contains(p)) {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }

            // Seed taint from non-System function params.
            let seeds: HashSet<u64> = func
                .raw
                .params
                .iter()
                .filter_map(|(id, ty)| {
                    let ty_name = ty.debug_name.as_deref().unwrap_or("");
                    if ty_name == "System" {
                        None
                    } else {
                        Some(*id)
                    }
                })
                .collect();

            if seeds.is_empty() {
                continue;
            }

            let (cfg, block_taint) = run_taint_analysis(
                program,
                func.idx,
                seeds,
                &transfer_sanitizers,
                &["function_call"],
            );

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

                    // For function_call libfuncs, check the debug_name (NOT generic_id)
                    // because generic_id is just "function_call" for all calls.
                    // Debug names look like: "function_call<user@module::ERC20::transfer_from>"
                    let is_transfer_from = is_transfer_from_call(&program.libfunc_registry, inv);

                    if !is_transfer_from {
                        continue;
                    }

                    // Check if `from` arg (first non-system arg) is tainted
                    let from_tainted = inv
                        .args
                        .first()
                        .is_some_and(|a| tainted.is_some_and(|t| t.contains(a)));

                    if from_tainted {
                        let display_name = inv
                            .libfunc_id
                            .debug_name
                            .as_deref()
                            .unwrap_or("transfer_from");
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Potential arbitrary token transfer-from",
                            format!(
                                "Function '{}': '{}' at stmt {} uses user-controlled `from` \
                                 without observable caller/ownership guard. Attackers may transfer \
                                 tokens from arbitrary accounts.",
                                func.name, display_name, stmt_idx
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

/// Check if an invocation is a function_call to a transfer_from-like function.
///
/// At Sierra level, internal function calls use the `function_call` generic libfunc.
/// The callee name is embedded in the debug_name, e.g.:
///   "function_call<user@contracts::erc20::ERC20::transfer_from>"
///
/// We check the debug_name for transfer_from patterns, which is more reliable
/// than checking generic_id (which is just "function_call" for all calls).
fn is_transfer_from_call(
    registry: &crate::ir::type_registry::LibfuncRegistry,
    inv: &crate::loader::Invocation,
) -> bool {
    // First check: debug_name of the libfunc (works with debug info).
    if let Some(debug) = inv.libfunc_id.debug_name.as_deref() {
        if TRANSFER_FROM_PATTERNS.iter().any(|p| debug.contains(p)) {
            return true;
        }
    }

    // Second check: declaration debug_name in the registry.
    if let Some(decl) = registry.lookup(&inv.libfunc_id) {
        if let Some(debug) = decl.id.debug_name.as_deref() {
            if TRANSFER_FROM_PATTERNS.iter().any(|p| debug.contains(p)) {
                return true;
            }
        }
    }

    false
}
