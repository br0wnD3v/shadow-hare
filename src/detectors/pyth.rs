use std::collections::HashSet;

use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Pyth oracle read without confidence interval validation.
pub struct PythUncheckedConfidence;

/// Pyth oracle read without publish-time / freshness validation.
pub struct PythUncheckedPublishtime;

/// Pyth deprecated/unsafe function usage.
pub struct PythDeprecatedFunction;

const PASS_THROUGH_LIBFUNCS: &[&str] = &["store_temp", "rename", "dup", "snapshot_take"];

const CONFIDENCE_KEYWORDS: &[&str] = &["confidence", "conf"];
const FRESHNESS_KEYWORDS: &[&str] = &[
    "publish_time",
    "older_than",
    "max_age",
    "stale",
    "timestamp",
    "age",
];
const DEPRECATED_PYTH_KEYWORDS: &[&str] =
    &["get_price_unsafe", "get_ema_price_unsafe", "deprecated"];

impl Detector for PythUncheckedConfidence {
    fn id(&self) -> &'static str {
        "pyth_unchecked_confidence"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Pyth price feed is consumed without an observable confidence-interval guard."
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

            let mut pyth_tainted: HashSet<u64> = HashSet::new();
            let mut first_fetch_site: Option<usize> = None;
            let mut has_confidence_guard = false;

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if is_pyth_price_fetch(libfunc_name) {
                    first_fetch_site.get_or_insert(start + local_idx);
                    for branch in &inv.branches {
                        for r in &branch.results {
                            pyth_tainted.insert(*r);
                        }
                    }
                    continue;
                }

                let uses_pyth_value = inv.args.iter().any(|a| pyth_tainted.contains(a));
                if uses_pyth_value && CONFIDENCE_KEYWORDS.iter().any(|k| libfunc_name.contains(k)) {
                    has_confidence_guard = true;
                }

                if uses_pyth_value
                    && PASS_THROUGH_LIBFUNCS
                        .iter()
                        .any(|k| libfunc_name.contains(k))
                {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            pyth_tainted.insert(*r);
                        }
                    }
                }
            }

            if let Some(site) = first_fetch_site {
                if !has_confidence_guard {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Pyth confidence interval not checked",
                        format!(
                            "Function '{}': Pyth price read at stmt {} has no observable confidence \
                             check before use. Validate confidence to avoid low-quality price updates.",
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

impl Detector for PythUncheckedPublishtime {
    fn id(&self) -> &'static str {
        "pyth_unchecked_publishtime"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Pyth price feed is consumed without an observable publish-time/freshness guard."
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

            let mut pyth_tainted: HashSet<u64> = HashSet::new();
            let mut first_unbounded_fetch_site: Option<usize> = None;
            let mut has_freshness_guard = false;

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if is_unbounded_pyth_fetch(libfunc_name) {
                    first_unbounded_fetch_site.get_or_insert(start + local_idx);
                    for branch in &inv.branches {
                        for r in &branch.results {
                            pyth_tainted.insert(*r);
                        }
                    }
                    continue;
                }

                let uses_pyth_value = inv.args.iter().any(|a| pyth_tainted.contains(a));
                if uses_pyth_value && FRESHNESS_KEYWORDS.iter().any(|k| libfunc_name.contains(k)) {
                    has_freshness_guard = true;
                }

                if uses_pyth_value
                    && PASS_THROUGH_LIBFUNCS
                        .iter()
                        .any(|k| libfunc_name.contains(k))
                {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            pyth_tainted.insert(*r);
                        }
                    }
                }
            }

            if let Some(site) = first_unbounded_fetch_site {
                if !has_freshness_guard {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Pyth publish-time not checked",
                        format!(
                            "Function '{}': unbounded Pyth price read at stmt {} has no observable \
                             publish-time/freshness check. Stale oracle data can be exploited.",
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

impl Detector for PythDeprecatedFunction {
    fn id(&self) -> &'static str {
        "pyth_deprecated_function"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "Deprecated or unsafe Pyth access function detected. Prefer bounded modern APIs."
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

            for (local_idx, stmt) in program.statements[start..end.min(program.statements.len())]
                .iter()
                .enumerate()
            {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if !libfunc_name.contains("pyth") {
                    continue;
                }
                if !DEPRECATED_PYTH_KEYWORDS
                    .iter()
                    .any(|k| libfunc_name.contains(k))
                {
                    continue;
                }

                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Deprecated/unsafe Pyth function usage",
                    format!(
                        "Function '{}': '{}' at stmt {} matches deprecated/unsafe Pyth API \
                         patterns. Migrate to bounded/freshness-checked Pyth calls.",
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

        (findings, warnings)
    }
}

fn is_pyth_price_fetch(libfunc_name: &str) -> bool {
    libfunc_name.contains("pyth")
        && (libfunc_name.contains("get_price")
            || libfunc_name.contains("get_ema_price")
            || libfunc_name.contains("price_no_older_than"))
}

fn is_unbounded_pyth_fetch(libfunc_name: &str) -> bool {
    libfunc_name.contains("pyth")
        && (libfunc_name.contains("get_price") || libfunc_name.contains("get_ema_price"))
        && !libfunc_name.contains("no_older_than")
        && !libfunc_name.contains("unsafe")
}
