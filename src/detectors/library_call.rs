use std::collections::HashSet;

use crate::analysis::sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects library calls where the class hash is controlled by user input.
///
/// `library_call_syscall(class_hash, ...)` dispatches to arbitrary code if
/// the class_hash is not hardcoded or validated. An attacker can pass a
/// malicious class hash to execute arbitrary code in the contract's context.
pub struct ControlledLibraryCall;

const LIBRARY_CALL_LIBFUNCS: &[&str] = &["library_call", "library_call_syscall"];

impl Detector for ControlledLibraryCall {
    fn id(&self) -> &'static str {
        "controlled_library_call"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Library call with user-controlled class hash allows arbitrary code execution \
         in the contract's storage context."
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
        let hash_sanitizers = sanitizers::hash_only_sanitizers();

        for func in program.external_functions() {
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
                &hash_sanitizers,
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

                    let is_library_call = LIBRARY_CALL_LIBFUNCS
                        .iter()
                        .any(|p| program.libfunc_registry.matches(&inv.libfunc_id, p));

                    if !is_library_call {
                        continue;
                    }

                    // Check if any arg (particularly the class hash) is tainted
                    let class_hash_tainted = inv
                        .args
                        .iter()
                        .any(|a| tainted.is_some_and(|t| t.contains(a)));

                    if class_hash_tainted {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "User-controlled library call class hash",
                            format!(
                                "Function '{}': library_call at stmt {} uses a class hash \
                                 derived from user-controlled input. An attacker can \
                                 pass a malicious class hash to execute arbitrary code.",
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
                        break; // One finding per function is enough.
                    }
                }
            }
        }

        (findings, warnings)
    }
}
