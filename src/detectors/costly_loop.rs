use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{BranchTarget, CompatibilityTier};

/// Detects storage access performed within loop ranges.
pub struct CostlyLoop;

impl Detector for CostlyLoop {
    fn id(&self) -> &'static str {
        "costly_loop"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Storage access occurs inside a loop; repeated storage ops can significantly increase execution cost."
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
            let mut emitted = false;

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let abs = start + local_idx;

                for branch in &inv.branches {
                    let BranchTarget::Statement(target) = branch.target else {
                        continue;
                    };
                    if target >= abs {
                        continue;
                    }

                    let has_storage_in_loop = (target..=abs).any(|idx| {
                        let Some(loop_stmt) = program.statements.get(idx) else {
                            return false;
                        };
                        let Some(loop_inv) = loop_stmt.as_invocation() else {
                            return false;
                        };
                        program
                            .libfunc_registry
                            .is_storage_read(&loop_inv.libfunc_id)
                            || program
                                .libfunc_registry
                                .is_storage_write(&loop_inv.libfunc_id)
                    });

                    if has_storage_in_loop {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Storage access inside loop",
                            format!(
                                "Function '{}': loop back-edge {} -> {} encloses storage access operations.",
                                func.name,
                                abs,
                                target
                            ),
                            Location {
                                file: program.source.display().to_string(),
                                function: func.name.clone(),
                                statement_idx: Some(abs),
                                line: None,
                                col: None,
                            },
                        ));
                        emitted = true;
                        break;
                    }
                }
                if emitted {
                    break;
                }
            }

            if emitted {
                continue;
            }

            // Fallback heuristic: flag when function has both loop-like control
            // and storage access, even if exact back-edge cannot be resolved.
            let mut has_loop_like = false;
            let mut storage_site: Option<usize> = None;
            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let abs = start + local_idx;
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");
                if inv.branches.len() >= 2 || name.contains("loop") || name.contains("iter") {
                    has_loop_like = true;
                }
                if program.libfunc_registry.is_storage_read(&inv.libfunc_id)
                    || program.libfunc_registry.is_storage_write(&inv.libfunc_id)
                {
                    storage_site.get_or_insert(abs);
                }
            }

            if has_loop_like {
                if let Some(site) = storage_site {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Storage access inside loop",
                        format!(
                            "Function '{}': loop-like control-flow with storage access at stmt {}.",
                            func.name, site
                        ),
                        Location {
                            file: program.source.display().to_string(),
                            function: func.name.clone(),
                            statement_idx: Some(site),
                            line: None,
                            col: None,
                        },
                    ));
                }
            }
        }

        (findings, warnings)
    }
}
