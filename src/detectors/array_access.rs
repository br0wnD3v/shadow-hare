use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects array operations that can fail (empty array / out-of-bounds) where
/// the failure branch is not handled.
///
/// `array_pop_front`, `array_get`, and similar operations are fallible: they
/// have a success branch and a failure branch (None / out-of-bounds). If only
/// the success branch (Fallthrough) is present in the Sierra statement, the
/// failure case panics or is undefined, which can be exploited to DoS the
/// contract or trigger unexpected state.
///
/// Safe pattern: handle both branches (Some / None) explicitly, or use
/// `unwrap_or_default` patterns.
pub struct UncheckedArrayAccess;

const ARRAY_FALLIBLE_LIBFUNCS: &[&str] = &[
    "array_pop_front",
    "array_get",
    "array_pop_front_consume",
    "span_pop_front",
    "array_snapshot_pop_front",
    "array_snapshot_pop_back",
];

impl Detector for UncheckedArrayAccess {
    fn id(&self) -> &'static str {
        "unchecked_array_access"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "Array operation (pop/get) with only one branch — the empty or out-of-bounds \
         case is not handled. An attacker supplying an empty array can cause a panic \
         or undefined behaviour."
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

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let inv = match stmt.as_invocation() {
                    Some(inv) => inv,
                    None => continue,
                };

                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                let is_fallible_array =
                    ARRAY_FALLIBLE_LIBFUNCS.iter().any(|p| libfunc_name.contains(p));

                if is_fallible_array && inv.branches.len() == 1 {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Array access without bounds check",
                        format!(
                            "Function '{}': '{}' at stmt {} has only 1 branch — the \
                             empty-array / out-of-bounds case is not handled. An attacker \
                             can supply an empty array to trigger a panic.",
                            func.name,
                            libfunc_name,
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

        (findings, warnings)
    }
}
