use std::collections::HashSet;

use crate::analysis::sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects L2->L1 messages where the L1 destination address is controlled by
/// function parameters (caller-supplied input).
///
/// When `send_message_to_l1_syscall(to_address, payload...)` is called and
/// `to_address` derives from user-supplied function arguments, an attacker can
/// redirect the message to an arbitrary L1 contract. This is critical in:
///
/// - Bridge contracts: attacker redirects withdrawals to their own L1 address
/// - Oracle relays:   attacker routes price data to a malicious L1 consumer
/// - Governance:      attacker captures the L1 vote receipt
///
/// Safe pattern: `to_address` must come from contract storage or a hardcoded
/// constant, never directly from function parameters.
pub struct L2ToL1TaintedDestination;

impl Detector for L2ToL1TaintedDestination {
    fn id(&self) -> &'static str {
        "l2_to_l1_tainted_destination"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "L2->L1 message destination address controlled by function parameters. \
         An attacker can redirect the message to an arbitrary L1 contract, \
         enabling bridge theft or fraudulent oracle/governance messages."
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

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }

            // Seed taint: all non-system function parameters.
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

            let (cfg, block_taint) = run_taint_analysis(
                program,
                func.idx,
                seeds,
                &all_sanitizers,
                &["function_call"],
            );

            // Scan each block for send_message_to_l1 sinks with tainted destination.
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

                    if !libfunc_name.contains("send_message_to_l1") {
                        continue;
                    }

                    // arg[1] is the L1 destination address.
                    let dest_is_tainted = inv
                        .args
                        .get(1)
                        .is_some_and(|v| tainted.is_some_and(|t| t.contains(v)));

                    if dest_is_tainted {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "L1 message destination controlled by caller",
                            format!(
                                "Function '{}': at stmt {} the to_address of \
                                 send_message_to_l1 derives from a function parameter. \
                                 An attacker can redirect this message to any L1 address.",
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
