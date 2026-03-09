use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects large numeric literals used directly in arithmetic or comparisons
/// without named constants. Magic numbers reduce readability and
/// maintainability.
///
/// Exempt values: 0, 1, 2, common powers of 2 (256, 1024), and storage
/// base address constants (which are hashed slot identifiers).
pub struct MagicNumbers;

/// Values that are commonly used inline and don't need named constants.
const EXEMPT_CONST_NAMES: &[&str] = &[
    "felt252_const<0>",
    "felt252_const<1>",
    "felt252_const<2>",
    "u128_const<0>",
    "u128_const<1>",
    "u128_const<2>",
    "u64_const<0>",
    "u64_const<1>",
    "u32_const<0>",
    "u32_const<1>",
    "u8_const<0>",
    "u8_const<1>",
    "bool_const<0>",
    "bool_const<1>",
    // Common powers of 2 used for bit manipulation
    "felt252_const<256>",
    "felt252_const<65536>",
    "u128_const<256>",
    "u128_const<1024>",
    "u128_const<65536>",
    "u64_const<256>",
    "u64_const<1024>",
    "u32_const<256>",
    // Common mathematical constants
    "felt252_const<10>",
    "felt252_const<100>",
    "felt252_const<1000>",
    "u128_const<10>",
    "u128_const<100>",
    "u128_const<1000>",
    // Common bit masks
    "u128_const<255>",
    "u128_const<65535>",
    "u256_const<0>",
    "u256_const<1>",
    // Storage base addresses are hashed slot IDs, not magic numbers.
    "storage_base_address_const",
    // Class hash and contract address constants are intentional.
    "class_hash_const",
    "contract_address_const",
];

impl Detector for MagicNumbers {
    fn id(&self) -> &'static str {
        "magic_numbers"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Large numeric literal used directly without a named constant. \
         Use named constants for clarity and maintainability."
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

            let mut func_magic_count = 0;

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                // Only flag _const libfuncs.
                if !name.contains("_const<") {
                    continue;
                }

                // Skip exempt constants.
                if EXEMPT_CONST_NAMES.iter().any(|e| name.contains(e)) {
                    continue;
                }

                func_magic_count += 1;

                // Limit findings per function to avoid noise.
                if func_magic_count <= 5 {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Magic number",
                        format!(
                            "Function '{}': numeric constant '{}' at stmt {} — \
                             consider extracting to a named constant.",
                            func.name,
                            name,
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
