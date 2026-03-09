use std::collections::HashSet;

use crate::analysis::sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects L1 handler functions where the message payload controls the
/// function selector passed to `call_contract_syscall` (selector injection).
pub struct L1HandlerUncheckedSelector;

impl Detector for L1HandlerUncheckedSelector {
    fn id(&self) -> &'static str {
        "l1_handler_unchecked_selector"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "L1 handler uses a payload parameter as a function selector in \
         call_contract_syscall. An attacker controlling the L1 message can \
         invoke arbitrary functions on the target contract (selector injection)."
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
        let all_sanitizers = sanitizers::all_general_sanitizers();

        for func in program.l1_handler_functions() {
            if func.raw.params.len() < 3 {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }

            // Taint seed: payload params (params[2+]).
            let seeds: HashSet<u64> = func.raw.params.iter().skip(2).map(|(id, _)| *id).collect();

            let (cfg, block_taint) = run_taint_analysis(
                program,
                func.idx,
                seeds,
                &all_sanitizers,
                &["function_call"],
            );

            for block_id in cfg.topological_order() {
                let block = &cfg.blocks[block_id];
                let tainted = block_taint.get(&block_id);

                for &stmt_idx in &block.stmts {
                    let stmt = &program.statements[stmt_idx];
                    let inv = match stmt {
                        Statement::Invocation(inv) => inv,
                        _ => continue,
                    };

                    let libfunc_name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or(inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");

                    if !libfunc_name.contains("call_contract") {
                        continue;
                    }

                    // arg[2] = entry_point_selector.
                    let selector_is_tainted = inv
                        .args
                        .get(2)
                        .is_some_and(|v| tainted.is_some_and(|t| t.contains(v)));

                    if selector_is_tainted {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "L1 payload controls call_contract selector",
                            format!(
                                "Function '{}': at stmt {} the function selector passed \
                                 to call_contract_syscall derives from an L1 message \
                                 payload parameter. An attacker can invoke arbitrary \
                                 functions on the target contract.",
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
                    }
                }
            }
        }

        (findings, warnings)
    }
}
