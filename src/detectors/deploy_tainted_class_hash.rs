use std::collections::HashSet;

use crate::analysis::sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects deploy syscalls where class hash is derived from user-controlled
/// input in external entrypoints.
///
/// Factory/deployer contracts should gate class hash selection via allowlists
/// or trusted storage configuration. A tainted class hash can let attackers
/// deploy arbitrary implementations.
pub struct DeploySyscallTaintedClassHash;

const DEPLOY_LIBFUNCS: &[&str] = &["deploy_syscall", "deploy"];

impl Detector for DeploySyscallTaintedClassHash {
    fn id(&self) -> &'static str {
        "deploy_syscall_tainted_class_hash"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "deploy_syscall uses a class hash derived from user-controlled input \
         without an observable allowlist/guard."
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
        // Use hash_only_sanitizers: constants and hashes break taint.
        // Also add storage_read — factory allowlists store permitted class hashes.
        let mut deploy_sanitizers = sanitizers::hash_only_sanitizers();
        deploy_sanitizers.extend_from_slice(sanitizers::STORAGE_READ);

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
                &deploy_sanitizers,
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

                    if !DEPLOY_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                        continue;
                    }

                    // Syscall layout: [system, class_hash, salt, calldata, deploy_from_zero]
                    // Check if class_hash (arg[1]) is tainted.
                    let class_hash_tainted = inv
                        .args
                        .get(1)
                        .or(inv.args.first())
                        .is_some_and(|v| tainted.is_some_and(|t| t.contains(v)));

                    if class_hash_tainted {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "User-controlled class hash in deploy_syscall",
                            format!(
                                "Function '{}': deploy invocation at stmt {} uses a \
                                 class hash derived from external input. Restrict \
                                 deployable class hashes via storage-backed allowlist \
                                 or trusted constants.",
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
                        break; // One finding per function.
                    }
                }
            }
        }

        (findings, warnings)
    }
}
