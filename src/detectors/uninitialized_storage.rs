use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects external functions that read from storage when no observable write
/// path exists in the entire program for the storage slots accessed.
///
/// In Starknet, uninitialized storage returns zero, which may cause logic errors
/// (e.g., zero balance treated as valid, zero address used as owner).
///
/// Suppression:
/// - If a constructor writes storage, assume the program initializes its state.
/// - If any initializer-like function writes storage, same assumption.
/// - View/getter functions (read-only) are excluded: they SHOULD read without
///   writing — that's their purpose.
pub struct UninitializedStorageRead;

impl Detector for UninitializedStorageRead {
    fn id(&self) -> &'static str {
        "uninitialized_storage_read"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Storage variable is read in an external function with no storage write \
         in the program. If the slot was never initialized, the default zero \
         value may cause logic errors."
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

        // Check if ANY function in the program writes to storage.
        // If a constructor or initializer exists with writes, the program
        // likely initializes its state properly.
        let has_any_storage_write = program.all_functions().any(|f| {
            let (start, end) = program.function_statement_range(f.idx);
            if start >= end {
                return false;
            }
            program.statements[start..end.min(program.statements.len())]
                .iter()
                .any(|stmt| {
                    stmt.as_invocation()
                        .map(|inv| program.libfunc_registry.is_storage_write(&inv.libfunc_id))
                        .unwrap_or(false)
                })
        });

        // If the program has storage writes anywhere, it likely manages its
        // own initialization (constructor, initializer, or setter functions).
        if has_any_storage_write {
            return (findings, warnings);
        }

        // No storage writes in the entire program — flag external functions
        // that read storage (the data can't have been initialized).
        for func in program.external_functions() {
            // Skip view/getter functions — their names suggest read-only intent.
            if is_view_function(&func.name) {
                continue;
            }

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            let mut first_read: Option<usize> = None;

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };

                if program.libfunc_registry.is_storage_read(&inv.libfunc_id) && first_read.is_none()
                {
                    first_read = Some(start + local_idx);
                }
            }

            if let Some(read_site) = first_read {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Potentially uninitialized storage read",
                    format!(
                        "Function '{}': reads storage at stmt {} but no storage write \
                         path found anywhere in the program. Default zero value may \
                         cause logic errors.",
                        func.name, read_site
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(read_site),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}

fn is_view_function(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("get_")
        || lower.contains("view")
        || lower.contains("balance_of")
        || lower.contains("total_supply")
        || lower.contains("allowance")
        || lower.contains("is_")
        || lower.contains("owner_of")
}
