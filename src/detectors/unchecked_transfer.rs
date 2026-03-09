use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects token transfer calls where the returned status/value is ignored.
///
/// At Sierra level, transfer calls appear as `function_call` libfuncs.
/// The callee name is in the debug_name (e.g.,
/// `function_call<user@ERC20::transfer>`). We check debug_name rather
/// than generic_id, because generic_id is just "function_call" for all calls.
pub struct UncheckedTransfer;

/// Patterns in function_call debug names that indicate transfer operations.
const TRANSFER_PATTERNS: &[&str] = &[
    "transfer",
    "transfer_from",
    "safe_transfer",
    "safe_transfer_from",
];

impl Detector for UncheckedTransfer {
    fn id(&self) -> &'static str {
        "unchecked_transfer"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Token transfer-style call return value appears unused; failures may be ignored silently."
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

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };

                // Check debug_name for transfer patterns, NOT generic_id.
                // generic_id is just "function_call" for all internal calls,
                // while debug_name contains the callee:
                //   "function_call<user@module::ERC20Impl::transfer>"
                if !is_transfer_call(&program.libfunc_registry, inv) {
                    continue;
                }

                let produced: Vec<u64> = inv
                    .branches
                    .iter()
                    .flat_map(|b| b.results.iter().copied())
                    .collect();
                if produced.is_empty() {
                    continue;
                }

                let mut used_later = false;
                for later in stmts.iter().skip(local_idx + 1) {
                    let Some(later_inv) = later.as_invocation() else {
                        continue;
                    };
                    if later_inv.args.iter().any(|a| produced.contains(a)) {
                        used_later = true;
                        break;
                    }
                }

                if !used_later {
                    let display_name = inv.libfunc_id.debug_name.as_deref().unwrap_or("transfer");
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Unchecked token transfer return value",
                        format!(
                            "Function '{}': '{}' at stmt {} returns a status/value that is never used. \
                             Transfer failure paths may be silently ignored.",
                            func.name,
                            display_name,
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

/// Check if an invocation is a function_call to a transfer-like function.
fn is_transfer_call(
    registry: &crate::ir::type_registry::LibfuncRegistry,
    inv: &crate::loader::Invocation,
) -> bool {
    // Check debug_name of the invocation's libfunc_id.
    if let Some(debug) = inv.libfunc_id.debug_name.as_deref() {
        if TRANSFER_PATTERNS.iter().any(|p| debug.contains(p)) {
            return true;
        }
    }

    // Check declaration debug_name in the registry.
    if let Some(decl) = registry.lookup(&inv.libfunc_id) {
        if let Some(debug) = decl.id.debug_name.as_deref() {
            if TRANSFER_PATTERNS.iter().any(|p| debug.contains(p)) {
                return true;
            }
        }
    }

    false
}
