use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects unsafe u256 → felt252 conversion that silently truncates the high
/// 128 bits.
///
/// `u256_to_felt252` discards the high word if the value exceeds the felt252
/// prime. Code that assumes the conversion is lossless will compute wrong
/// results (balance accounting, price calculations, etc.).
///
/// Safe pattern: assert the high word is zero before conversion, or use
/// explicit range checks (u256_safe_divmod, etc.).
pub struct IntegerTruncation;

const TRUNCATION_LIBFUNCS: &[&str] = &["u256_to_felt252"];

impl Detector for IntegerTruncation {
    fn id(&self) -> &'static str {
        "integer_truncation"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "u256 converted to felt252 via u256_to_felt252 — the high 128 bits are \
         silently discarded if the value exceeds the field prime. \
         Verify the value fits in felt252 before conversion."
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

                if TRUNCATION_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Unsafe u256 → felt252 truncation",
                        format!(
                            "Function '{}': '{}' at stmt {} converts u256 to felt252 without \
                             verifying the high word is zero. Values exceeding the field prime \
                             will be silently truncated, corrupting arithmetic results.",
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
