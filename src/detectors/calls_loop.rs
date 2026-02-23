use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{BranchTarget, CompatibilityTier};

/// Detects external/library calls that appear inside a loop body.
pub struct CallsLoop;

impl Detector for CallsLoop {
    fn id(&self) -> &'static str {
        "calls_loop"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "External/library call appears in a loop body; repeated calls can amplify reentrancy and gas-risk surfaces."
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

            let call_sites: Vec<usize> = stmts
                .iter()
                .enumerate()
                .filter_map(|(local_idx, stmt)| {
                    let inv = stmt.as_invocation()?;
                    let name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or_else(|| inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");
                    if name.contains("call_contract") || name.contains("library_call") {
                        Some(start + local_idx)
                    } else {
                        None
                    }
                })
                .collect();

            if call_sites.is_empty() {
                continue;
            }

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
                    if target > abs {
                        continue;
                    }
                    if let Some(call_site) = call_sites
                        .iter()
                        .copied()
                        .find(|site| *site >= target && *site <= abs)
                    {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "External call inside loop",
                            format!(
                                "Function '{}': back-edge {} -> {} encloses external call at stmt {}. \
                                 Repeated external calls in loops increase reentrancy and gas-exhaustion risk.",
                                func.name,
                                abs,
                                target,
                                call_site
                            ),
                            Location {
                                file: program.source.display().to_string(),
                                function: func.name.clone(),
                                statement_idx: Some(call_site),
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

            // Fallback heuristic for artifacts where branch targets are not
            // stable enough to recover exact back-edges: still require both a
            // call site and loop-like control-flow in the same function.
            let mut loop_like_site: Option<usize> = None;
            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");
                if inv.branches.len() >= 2 || name.contains("loop") || name.contains("iter") {
                    loop_like_site = Some(start + local_idx);
                    break;
                }
            }
            if let (Some(call_site), Some(loop_site)) =
                (call_sites.first().copied(), loop_like_site)
            {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "External call inside loop",
                    format!(
                        "Function '{}': external call at stmt {} with loop-like control-flow at stmt {}.",
                        func.name,
                        call_site,
                        loop_site
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(call_site),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}
