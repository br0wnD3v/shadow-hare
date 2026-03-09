use std::collections::HashSet;

use crate::analysis::sanitizers::all_general_sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Pyth oracle read without confidence interval validation.
pub struct PythUncheckedConfidence;

/// Pyth oracle read without publish-time / freshness validation.
pub struct PythUncheckedPublishtime;

/// Pyth deprecated/unsafe function usage.
pub struct PythDeprecatedFunction;

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

/// Check if unsanitized taint reaches any sink: Return, storage_write, or call_contract.
fn taint_reaches_any_sink(
    cfg: &crate::analysis::cfg::Cfg,
    block_taint: &std::collections::HashMap<crate::analysis::cfg::BlockIdx, HashSet<u64>>,
    program: &ProgramIR,
) -> bool {
    for block in &cfg.blocks {
        let Some(tainted) = block_taint.get(&block.id) else {
            continue;
        };
        if tainted.is_empty() {
            continue;
        }
        for &stmt_idx in &block.stmts {
            let Some(stmt) = program.statements.get(stmt_idx) else {
                continue;
            };
            match stmt {
                Statement::Return(vars) => {
                    if vars.iter().any(|v| tainted.contains(v)) {
                        return true;
                    }
                }
                Statement::Invocation(inv) => {
                    let name = program
                        .libfunc_registry
                        .generic_id(&inv.libfunc_id)
                        .or(inv.libfunc_id.debug_name.as_deref())
                        .unwrap_or("");

                    let is_sink = program.libfunc_registry.is_storage_write(&inv.libfunc_id)
                        || name.contains("call_contract");
                    if is_sink && inv.args.iter().any(|a| tainted.contains(a)) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

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

        // Build confidence sanitizers: general + confidence keywords
        let mut sanitizers = all_general_sanitizers();
        sanitizers.extend_from_slice(CONFIDENCE_KEYWORDS);

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Collect taint seeds: results of pyth price fetch calls
            let mut seeds: HashSet<u64> = HashSet::new();
            let mut first_fetch_site: Option<usize> = None;

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if is_pyth_price_fetch(libfunc_name) {
                    first_fetch_site.get_or_insert(start + local_idx);
                    for branch in &inv.branches {
                        for r in &branch.results {
                            seeds.insert(*r);
                        }
                    }
                }
            }

            if seeds.is_empty() {
                continue;
            }

            // Run CFG-based taint analysis
            let (cfg, block_taint) =
                run_taint_analysis(program, func.idx, seeds, &sanitizers, &["function_call"]);

            // Check if unsanitized taint reaches any sink (Return, storage_write, call_contract)
            if !taint_reaches_any_sink(&cfg, &block_taint, program) {
                continue;
            }

            if let Some(site) = first_fetch_site {
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

        // Build freshness sanitizers: general + freshness keywords
        let mut sanitizers = all_general_sanitizers();
        sanitizers.extend_from_slice(FRESHNESS_KEYWORDS);

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Collect taint seeds: results of unbounded pyth fetch calls
            let mut seeds: HashSet<u64> = HashSet::new();
            let mut first_unbounded_fetch_site: Option<usize> = None;

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if is_unbounded_pyth_fetch(libfunc_name) {
                    first_unbounded_fetch_site.get_or_insert(start + local_idx);
                    for branch in &inv.branches {
                        for r in &branch.results {
                            seeds.insert(*r);
                        }
                    }
                }
            }

            if seeds.is_empty() {
                continue;
            }

            // Run CFG-based taint analysis
            let (cfg, block_taint) =
                run_taint_analysis(program, func.idx, seeds, &sanitizers, &["function_call"]);

            // Check if unsanitized taint reaches any sink (Return, storage_write, call_contract)
            if !taint_reaches_any_sink(&cfg, &block_taint, program) {
                continue;
            }

            if let Some(site) = first_unbounded_fetch_site {
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
                    .or(inv.libfunc_id.debug_name.as_deref())
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
