use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects event emission after external call but before final storage commit.
pub struct ReentrancyEvents;

impl Detector for ReentrancyEvents {
    fn id(&self) -> &'static str {
        "reentrancy_events"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Event is emitted after an external call but before state write; reentrancy can desynchronize event/state narratives."
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

            let mut external_call_site: Option<usize> = None;
            let mut event_site: Option<usize> = None;
            let mut write_after_call_site: Option<usize> = None;

            for (local_idx, stmt) in program.statements[start..end.min(program.statements.len())]
                .iter()
                .enumerate()
            {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let abs = start + local_idx;

                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if name.contains("call_contract") || name.contains("library_call") {
                    external_call_site.get_or_insert(abs);
                }

                if external_call_site.is_some() && name.contains("emit_event") {
                    event_site.get_or_insert(abs);
                }

                if external_call_site.is_some()
                    && program.libfunc_registry.is_storage_write(&inv.libfunc_id)
                {
                    write_after_call_site.get_or_insert(abs);
                }
            }

            if let (Some(call), Some(event), Some(write)) =
                (external_call_site, event_site, write_after_call_site)
            {
                if event > call && event < write {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Event emitted before post-call state commit",
                        format!(
                            "Function '{}': external call at stmt {}, event at stmt {}, and state write at stmt {}. \
                             Reentrancy can cause emitted events to diverge from final state.",
                            func.name,
                            call,
                            event,
                            write
                        ),
                        Location {
                            file: program.source.display().to_string(),
                            function: func.name.clone(),
                            statement_idx: Some(event),
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
