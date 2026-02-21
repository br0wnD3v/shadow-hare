use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

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

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Taint: parameters are user-controlled
            let mut tainted: std::collections::HashSet<u64> =
                func.raw.params.iter().map(|(id, _)| *id).collect();

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let inv = match stmt.as_invocation() {
                    Some(inv) => inv,
                    None => continue,
                };

                let is_library_call = LIBRARY_CALL_LIBFUNCS
                    .iter()
                    .any(|p| program.libfunc_registry.matches(&inv.libfunc_id, p));

                if is_library_call {
                    // The first meaningful arg to library_call is the class hash.
                    // If it's tainted, flag it.
                    if inv.args.iter().any(|a| tainted.contains(a)) {
                        findings.push(Finding::new(
                            self.id(),
                            self.severity(),
                            self.confidence(),
                            "User-controlled library call class hash",
                            format!(
                                "Function '{}': library_call at stmt {} uses a class hash \
                                 derived from user-controlled input. An attacker can \
                                 pass a malicious class hash to execute arbitrary code.",
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

                // Propagate taint through all invocations
                if inv.args.iter().any(|a| tainted.contains(a)) {
                    for branch in &inv.branches {
                        for result in &branch.results {
                            tainted.insert(*result);
                        }
                    }
                }
            }
        }

        (findings, warnings)
    }
}
