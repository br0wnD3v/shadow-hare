use std::collections::{HashSet, VecDeque};

use crate::analysis::callgraph::CallGraph;
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects likely signature replay exposure in account validation paths.
///
/// Conservative heuristic:
/// - Target only account/signature validation entrypoints
///   (`__validate__`, `__validate_declare__`, `__validate_deploy__`, `is_valid_signature`)
/// - Require cryptographic/signature/tx-info activity in the reachable call path
/// - Flag when no storage read is observed in that path (nonce/state not loaded)
///
/// This catches common replay primitives where signature checks run but
/// validation never reads nonce-bearing state.
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
        let execute_has_storage_write = program
            .all_functions()
            .filter(|f| f.name.contains("__execute__"))
            .any(|f| {
                let flags = scan_reachable_flags(program, &callgraph, f.idx);
                flags.has_storage_write
            });

        for func in program.all_functions() {
            let is_account_validate = func.is_account_entrypoint()
                && (func.name.contains("__validate__")
                    || func.name.contains("__validate_declare__")
                    || func.name.contains("__validate_deploy__"));
            let is_signature_entrypoint =
                func.is_entrypoint() && func.name.contains("is_valid_signature");
            if !(is_account_validate || is_signature_entrypoint) {
                continue;
            }
            let flags = scan_reachable_flags(program, &callgraph, func.idx);
            let likely_signature_path = flags.has_signature_flow || flags.has_tx_info;
            // For validate entrypoints, require both:
            // 1) no nonce/state read in validate path, and
            // 2) no nonce/state write in execute path.
            //
            // This avoids flagging contracts like OZ account where validate itself
            // doesn't read storage but execute still persists nonce/state.
            let replay_exposed = if is_account_validate {
                !flags.has_storage_read && !execute_has_storage_write
            } else {
                // is_valid_signature-style paths remain strictly local.
                !flags.has_storage_read
            };

            if likely_signature_path && replay_exposed {
                let (start, _) = program.function_statement_range(func.idx);
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Potential signature replay exposure",
                    format!(
                        "Validation entrypoint '{}' performs signature/tx-info flow but \
                         no storage read is observed in its reachable call path. This may \
                         indicate nonce/state is not loaded before signature acceptance.",
                        func.name
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

fn reachable_functions(start: usize, callgraph: &CallGraph) -> HashSet<usize> {
    let mut seen = HashSet::new();
    let mut q = VecDeque::new();
    seen.insert(start);
    q.push_back(start);

    while let Some(node) = q.pop_front() {
        if let Some(callees) = callgraph.edges.get(&node) {
            for &callee in callees {
                if seen.insert(callee) {
                    q.push_back(callee);
                }
            }
        }
    }

    seen
}

#[derive(Default)]
struct PathFlags {
    has_storage_read: bool,
    has_storage_write: bool,
    has_signature_flow: bool,
    has_tx_info: bool,
}

fn scan_reachable_flags(
    program: &ProgramIR,
    callgraph: &CallGraph,
    start_func: usize,
) -> PathFlags {
    let mut flags = PathFlags::default();
    let reachable = reachable_functions(start_func, callgraph);
    for idx in reachable {
        let (start, end) = program.function_statement_range(idx);
        if start >= end {
            continue;
        }
        let stmts = &program.statements[start..end.min(program.statements.len())];
        for stmt in stmts {
            let inv = match stmt.as_invocation() {
                Some(inv) => inv,
                None => continue,
            };

            if program.libfunc_registry.is_storage_read(&inv.libfunc_id) {
                flags.has_storage_read = true;
            }
            if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                flags.has_storage_write = true;
            }

            let libfunc_name = program
                .libfunc_registry
                .generic_id(&inv.libfunc_id)
                .or_else(|| inv.libfunc_id.debug_name.as_deref())
                .unwrap_or("");

            if SIGNATURE_FLOW_LIBFUNCS
                .iter()
                .any(|p| libfunc_name.contains(p))
            {
                flags.has_signature_flow = true;
            }
            if TX_INFO_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                flags.has_tx_info = true;
            }
        }
    }
    flags
}
