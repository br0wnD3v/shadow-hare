use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects deploy syscalls where class hash is derived from user-controlled
/// input in external entrypoints.
///
/// Factory/deployer contracts should gate class hash selection via allowlists
/// or trusted storage configuration. A tainted class hash can let attackers
/// deploy arbitrary implementations.
pub struct DeploySyscallTaintedClassHash;

const DEPLOY_LIBFUNCS: &[&str] = &["deploy_syscall", "deploy"];
const CLASS_HASH_CONST_LIBFUNCS: &[&str] = &["class_hash_const"];
const PASS_THROUGH_LIBFUNCS: &[&str] = &["store_temp", "rename", "dup", "snapshot_take"];

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

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let mut tainted: HashSet<u64> = func.raw.params.iter().map(|(id, _)| *id).collect();
            let mut const_class_hash_vars: HashSet<u64> = HashSet::new();

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };

                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if CLASS_HASH_CONST_LIBFUNCS
                    .iter()
                    .any(|p| libfunc_name.contains(p))
                {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            const_class_hash_vars.insert(*r);
                        }
                    }
                    continue;
                }

                let is_deploy = DEPLOY_LIBFUNCS.iter().any(|p| libfunc_name.contains(p));
                if is_deploy {
                    // Syscall-style layout is typically:
                    // [system, class_hash, contract_address_salt, calldata, deploy_from_zero]
                    // We conservatively try arg[1], then fallback to arg[0].
                    let class_hash_var = inv.args.get(1).or_else(|| inv.args.first()).copied();

                    if let Some(ch) = class_hash_var {
                        let class_hash_tainted = tainted.contains(&ch);
                        let class_hash_const = const_class_hash_vars.contains(&ch);
                        if class_hash_tainted && !class_hash_const {
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

                let args_tainted = inv.args.iter().any(|a| tainted.contains(a));
                let args_const_hash = inv.args.iter().any(|a| const_class_hash_vars.contains(a));

                if args_tainted {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            tainted.insert(*r);
                        }
                    }
                }

                if args_const_hash
                    && PASS_THROUGH_LIBFUNCS
                        .iter()
                        .any(|p| libfunc_name.contains(p))
                {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            const_class_hash_vars.insert(*r);
                        }
                    }
                }
            }
        }

        (findings, warnings)
    }
}
