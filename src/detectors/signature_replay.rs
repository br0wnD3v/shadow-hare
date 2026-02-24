use std::collections::{HashMap, HashSet};

use crate::analysis::callgraph::CallGraph;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects likely signature replay exposure in account validation paths.
///
/// The detector evaluates three replay-risk failure modes:
/// 1) validation path has signature/tx-info flow but no storage read (no nonce/state load)
/// 2) storage-read state exists but is never bound into signature/hash or tx-info checks
/// 3) account validate path appears bound, but no storage write is observed on `__execute__`
///
/// Analysis is inter-procedural over `function_call` edges:
/// helper reads/writes/binding logic is folded into entrypoint summaries.
pub struct SignatureReplay;

const SIGNATURE_FLOW_LIBFUNCS: &[&str] = &[
    "ecdsa",
    "secp256",
    "starknet_keccak",
    "sha256",
    "pedersen",
    "poseidon",
    "hades_permutation",
];

const TX_INFO_LIBFUNCS: &[&str] = &["get_tx_info", "get_execution_info"];
const NONCE_BIND_COMPARE_LIBFUNCS: &[&str] = &[
    "assert_eq",
    "assert_ne",
    "contract_address_eq",
    "u128_eq",
    "u256_eq",
];

const TAG_STORAGE: u8 = 0b01;
const TAG_TX_INFO: u8 = 0b10;

#[derive(Debug, Default, Clone)]
struct ReplaySummary {
    has_storage_read: bool,
    has_storage_write: bool,
    has_signature_flow: bool,
    has_tx_info: bool,
    has_nonce_binding: bool,
    returns_storage_derived: bool,
    returns_tx_info_derived: bool,
}

impl Detector for SignatureReplay {
    fn id(&self) -> &'static str {
        "signature_replay"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "Validation/signature entrypoint appears to verify transaction/signature data \
         without reading nonce-bearing storage, which can allow signature replay."
    }

    fn requirements(&self) -> DetectorRequirements {
        DetectorRequirements {
            min_tier: CompatibilityTier::Tier3,
            requires_debug_info: true,
            source_aware: false,
        }
    }

    fn run(&self, program: &ProgramIR) -> (Vec<Finding>, Vec<AnalyzerWarning>) {
        let mut findings = Vec::new();
        let warnings = Vec::new();
        let callgraph = CallGraph::build(program);
        let mut summary_cache: HashMap<usize, ReplaySummary> = HashMap::new();
        let execute_has_storage_write = program
            .all_functions()
            .filter(|f| is_execute_entrypoint(&f.name))
            .any(|f| {
                summarize_function(
                    f.idx,
                    program,
                    &callgraph,
                    &mut summary_cache,
                    &mut HashSet::new(),
                )
                .has_storage_write
            });

        for func in program.all_functions() {
            let is_account_validate =
                func.is_account_entrypoint() && is_validate_entrypoint(&func.name);
            let is_signature_entrypoint =
                func.is_entrypoint() && is_signature_entrypoint(&func.name);
            if !(is_account_validate || is_signature_entrypoint) {
                continue;
            }
            let summary = summarize_function(
                func.idx,
                program,
                &callgraph,
                &mut summary_cache,
                &mut HashSet::new(),
            );
            let likely_signature_path = summary.has_signature_flow || summary.has_tx_info;
            if !likely_signature_path {
                continue;
            }

            let reason = if !summary.has_storage_read {
                "signature/tx-info flow is present but no storage read is observed in the reachable validation path (nonce/state may never be loaded)."
                    .to_string()
            } else if !summary.has_nonce_binding {
                "storage-derived state is read but does not flow into a signature/hash operation or a storage-vs-tx-info comparison (nonce may be ignored in validation)."
                    .to_string()
            } else if is_account_validate && !execute_has_storage_write {
                "__execute__ path has no storage write in its reachable call tree, so nonce/state does not appear to be persisted after validation."
                    .to_string()
            } else {
                continue;
            };

            {
                let (start, _) = program.function_statement_range(func.idx);
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Potential signature replay exposure",
                    format!(
                        "Validation/signature entrypoint '{}': {}",
                        func.name, reason
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(start),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}

fn is_execute_entrypoint(name: &str) -> bool {
    name.contains("__execute__") || name.ends_with("__execute")
}

fn is_validate_entrypoint(name: &str) -> bool {
    name.contains("__validate__")
        || name.contains("__validate_declare__")
        || name.contains("__validate_deploy__")
}

fn is_signature_entrypoint(name: &str) -> bool {
    name.contains("is_valid_signature")
}

fn is_signature_flow_libfunc(name: &str) -> bool {
    SIGNATURE_FLOW_LIBFUNCS.iter().any(|p| name.contains(p))
}

fn is_tx_info_libfunc(name: &str) -> bool {
    TX_INFO_LIBFUNCS.iter().any(|p| name.contains(p))
}

fn is_nonce_bind_compare_libfunc(name: &str) -> bool {
    NONCE_BIND_COMPARE_LIBFUNCS.iter().any(|p| name.contains(p))
}

fn summarize_function(
    func_idx: usize,
    program: &ProgramIR,
    callgraph: &CallGraph,
    cache: &mut HashMap<usize, ReplaySummary>,
    visiting: &mut HashSet<usize>,
) -> ReplaySummary {
    if let Some(cached) = cache.get(&func_idx) {
        return cached.clone();
    }
    if !visiting.insert(func_idx) {
        return ReplaySummary::default();
    }

    let (start, end) = program.function_statement_range(func_idx);
    if start >= end {
        visiting.remove(&func_idx);
        let summary = ReplaySummary::default();
        cache.insert(func_idx, summary.clone());
        return summary;
    }

    let mut summary = ReplaySummary::default();
    let mut tags: HashMap<u64, u8> = HashMap::new();

    for stmt in &program.statements[start..end.min(program.statements.len())] {
        match stmt {
            Statement::Return(vars) => {
                if vars
                    .iter()
                    .any(|v| tags.get(v).copied().unwrap_or(0) & TAG_STORAGE != 0)
                {
                    summary.returns_storage_derived = true;
                }
                if vars
                    .iter()
                    .any(|v| tags.get(v).copied().unwrap_or(0) & TAG_TX_INFO != 0)
                {
                    summary.returns_tx_info_derived = true;
                }
            }
            Statement::Invocation(inv) => {
                let libfunc_name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("");

                let mut arg_union = 0u8;
                let mut has_storage_arg = false;
                let mut has_tx_info_arg = false;
                for arg in &inv.args {
                    let tag = tags.get(arg).copied().unwrap_or(0);
                    arg_union |= tag;
                    if tag & TAG_STORAGE != 0 {
                        has_storage_arg = true;
                    }
                    if tag & TAG_TX_INFO != 0 {
                        has_tx_info_arg = true;
                    }
                }

                if is_signature_flow_libfunc(libfunc_name) {
                    summary.has_signature_flow = true;
                    if has_storage_arg {
                        summary.has_nonce_binding = true;
                    }
                }
                if is_nonce_bind_compare_libfunc(libfunc_name) && has_storage_arg && has_tx_info_arg
                {
                    summary.has_nonce_binding = true;
                }

                let mut produced_tag = arg_union;
                if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
                    summary.has_storage_read = true;
                    produced_tag |= TAG_STORAGE;
                }
                if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                    summary.has_storage_write = true;
                }
                if is_tx_info_libfunc(libfunc_name) {
                    summary.has_tx_info = true;
                    produced_tag |= TAG_TX_INFO;
                }

                let is_function_call = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .map(|g| g == "function_call")
                    .unwrap_or(false);
                if is_function_call {
                    if let Some(callee_idx) =
                        callgraph.callee_of(&inv.libfunc_id, &program.libfunc_registry)
                    {
                        let callee_summary =
                            summarize_function(callee_idx, program, callgraph, cache, visiting);
                        summary.has_storage_read |= callee_summary.has_storage_read;
                        summary.has_storage_write |= callee_summary.has_storage_write;
                        summary.has_signature_flow |= callee_summary.has_signature_flow;
                        summary.has_tx_info |= callee_summary.has_tx_info;
                        summary.has_nonce_binding |= callee_summary.has_nonce_binding;
                        if callee_summary.returns_storage_derived {
                            produced_tag |= TAG_STORAGE;
                        }
                        if callee_summary.returns_tx_info_derived {
                            produced_tag |= TAG_TX_INFO;
                        }
                    }
                }

                if produced_tag != 0 {
                    for branch in &inv.branches {
                        for r in &branch.results {
                            let entry = tags.entry(*r).or_insert(0);
                            *entry |= produced_tag;
                        }
                    }
                }
            }
        }
    }

    visiting.remove(&func_idx);
    cache.insert(func_idx, summary.clone());
    summary
}
