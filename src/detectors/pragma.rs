use std::collections::HashSet;

use crate::analysis::cfg::Cfg;
use crate::analysis::reentrancy::{build_stmt_to_block_map, forward_reachable_blocks};
use crate::analysis::sanitizers::all_general_sanitizers;
use crate::analysis::taint::run_taint_analysis;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Pragma oracle price feed used without timestamp/staleness check.
pub struct PragmaUncheckedFreshness;

/// Pragma oracle single source price without aggregation verification.
pub struct PragmaMissingAggregation;

/// Pragma oracle missing source count validation.
pub struct PragmaUncheckedNumSources;

const PRAGMA_PRICE_KEYWORDS: &[&str] = &[
    "pragma",
    "get_data_median",
    "get_data",
    "get_spot_median",
    "get_twap",
];

const FRESHNESS_KEYWORDS: &[&str] = &[
    "last_updated_timestamp",
    "timestamp",
    "stale",
    "max_age",
    "freshness",
    "older_than",
];

const AGGREGATION_KEYWORDS: &[&str] = &[
    "aggregation",
    "aggregation_mode",
    "median",
    "twap",
    "num_sources",
];

const NUM_SOURCES_KEYWORDS: &[&str] = &[
    "num_sources",
    "num_sources_aggregated",
    "sources_count",
    "min_sources",
];

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

fn is_pragma_price_fetch(name: &str) -> bool {
    PRAGMA_PRICE_KEYWORDS.iter().any(|k| name.contains(k))
        && (name.contains("get_data")
            || name.contains("get_spot")
            || name.contains("get_twap")
            || name.contains("get_price")
            || name.contains("pragma"))
}

impl Detector for PragmaUncheckedFreshness {
    fn id(&self) -> &'static str {
        "pragma_unchecked_freshness"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Pragma price feed is consumed without an observable timestamp/freshness check. \
         Stale oracle data can be exploited for price manipulation."
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

        // Build freshness sanitizers: general sanitizers + freshness keywords
        let mut sanitizers = all_general_sanitizers();
        sanitizers.extend_from_slice(FRESHNESS_KEYWORDS);

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Collect taint seeds: results of pragma price fetch calls
            let mut seeds: HashSet<u64> = HashSet::new();
            let mut first_fetch_site: Option<usize> = None;

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if is_pragma_price_fetch(name) {
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
            let taint_reaches_sink =
                taint_reaches_any_sink(&cfg, &block_taint, program);

            if let Some(site) = first_fetch_site {
                if taint_reaches_sink {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Pragma price freshness not checked",
                        format!(
                            "Function '{}': Pragma price read at stmt {} has no observable \
                             timestamp/freshness check. Stale oracle data can be exploited.",
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

impl Detector for PragmaMissingAggregation {
    fn id(&self) -> &'static str {
        "pragma_missing_aggregation"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Pragma oracle price used without aggregation mode verification. \
         Single-source prices are easily manipulable."
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

            let mut first_fetch_site: Option<usize> = None;
            let mut fetch_block: Option<usize> = None;
            let mut has_builtin_aggregation = false;

            // Build CFG for reachability analysis
            let cfg = Cfg::build(&program.statements, start, end);
            let stmt_to_block = build_stmt_to_block_map(&cfg, start);

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if is_pragma_price_fetch(name) {
                    first_fetch_site.get_or_insert(start + local_idx);
                    fetch_block = fetch_block.or_else(|| stmt_to_block.get(&local_idx).copied());
                    // If the function name itself contains "median" or "twap",
                    // aggregation is built into the call.
                    if name.contains("median") || name.contains("twap") {
                        has_builtin_aggregation = true;
                    }
                }
            }

            if has_builtin_aggregation || first_fetch_site.is_none() {
                continue;
            }

            // Check if an aggregation keyword block is forward-reachable from fetch block
            let has_aggregation_check = if let Some(fb) = fetch_block {
                let reachable = forward_reachable_blocks(&cfg, fb);
                cfg.blocks.iter().any(|block| {
                    if !reachable.contains(&block.id) {
                        return false;
                    }
                    block.stmts.iter().any(|&stmt_idx| {
                        let Some(stmt) = program.statements.get(stmt_idx) else {
                            return false;
                        };
                        let Some(inv) = stmt.as_invocation() else {
                            return false;
                        };
                        let name = program
                            .libfunc_registry
                            .generic_id(&inv.libfunc_id)
                            .or(inv.libfunc_id.debug_name.as_deref())
                            .unwrap_or("");
                        AGGREGATION_KEYWORDS.iter().any(|k| name.contains(k))
                    })
                })
            } else {
                false
            };

            if let Some(site) = first_fetch_site {
                if !has_aggregation_check {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Pragma aggregation not verified",
                        format!(
                            "Function '{}': Pragma price read at stmt {} has no observable \
                             aggregation check. Single-source prices are manipulable.",
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

impl Detector for PragmaUncheckedNumSources {
    fn id(&self) -> &'static str {
        "pragma_unchecked_num_sources"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::Low
    }

    fn description(&self) -> &'static str {
        "Pragma oracle price used without checking the number of reporting sources. \
         Low source count makes price manipulation easier."
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

            let mut first_fetch_site: Option<usize> = None;
            let mut fetch_block: Option<usize> = None;

            // Build CFG for reachability analysis
            let cfg = Cfg::build(&program.statements, start, end);
            let stmt_to_block = build_stmt_to_block_map(&cfg, start);

            for (local_idx, stmt) in stmts.iter().enumerate() {
                let Some(inv) = stmt.as_invocation() else {
                    continue;
                };
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or(inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                if is_pragma_price_fetch(name) {
                    first_fetch_site.get_or_insert(start + local_idx);
                    fetch_block = fetch_block.or_else(|| stmt_to_block.get(&local_idx).copied());
                }
            }

            if first_fetch_site.is_none() {
                continue;
            }

            // Check if a num_sources keyword block is forward-reachable from fetch block
            let has_num_sources_check = if let Some(fb) = fetch_block {
                let reachable = forward_reachable_blocks(&cfg, fb);
                cfg.blocks.iter().any(|block| {
                    if !reachable.contains(&block.id) {
                        return false;
                    }
                    block.stmts.iter().any(|&stmt_idx| {
                        let Some(stmt) = program.statements.get(stmt_idx) else {
                            return false;
                        };
                        let Some(inv) = stmt.as_invocation() else {
                            return false;
                        };
                        let name = program
                            .libfunc_registry
                            .generic_id(&inv.libfunc_id)
                            .or(inv.libfunc_id.debug_name.as_deref())
                            .unwrap_or("");
                        NUM_SOURCES_KEYWORDS.iter().any(|k| name.contains(k))
                    })
                })
            } else {
                false
            };

            if let Some(site) = first_fetch_site {
                if !has_num_sources_check {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "Pragma source count not checked",
                        format!(
                            "Function '{}': Pragma price read at stmt {} has no observable \
                             num_sources check. Low source count enables manipulation.",
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
