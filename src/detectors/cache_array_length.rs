use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{BranchTarget, CompatibilityTier};

/// Detects repeated array length reads inside loop ranges.
pub struct CacheArrayLength;

impl Detector for CacheArrayLength {
    fn id(&self) -> &'static str {
        "cache_array_length"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Array length appears repeatedly queried inside a loop; cache length before loop for lower cost."
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

                    let len_calls = (target..=abs)
                        .filter_map(|idx| program.statements.get(idx))
                        .filter_map(|s| s.as_invocation())
                        .filter(|loop_inv| {
                            let name = program
                                .libfunc_registry
                                .generic_id(&loop_inv.libfunc_id)
                                .or_else(|| loop_inv.libfunc_id.debug_name.as_deref())
                                .unwrap_or("");
                            name.contains("array_len") || name.contains("span_len")
                        })
                        .count();

                    if len_calls >= 2 {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "Repeated array length lookup in loop",
                            format!(
                                "Function '{}': loop back-edge {} -> {} contains {} array length lookups.",
                                func.name,
                                abs,
                                target,
                                len_calls
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

            // Fallback heuristic: repeated array_len/span_len plus loop-like
            // control-flow in the same function.
            let mut len_calls = 0usize;
            let mut loop_like = false;
            let mut last_len_site = None;
            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");
                if name.contains("array_len") || name.contains("span_len") {
                    len_calls += 1;
                    last_len_site = Some(start + local_idx);
                }
                if inv.branches.len() >= 2 || name.contains("loop") || name.contains("iter") {
                    loop_like = true;
                }
            }
            if len_calls >= 2 && loop_like {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Repeated array length lookup in loop",
                    format!(
                        "Function '{}': {} array length lookups observed with loop-like control-flow.",
                        func.name,
                        len_calls
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: last_len_site,
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}
