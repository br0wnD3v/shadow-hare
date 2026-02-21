use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::{CompatibilityTier, Statement};

/// Detects L1 handler functions that do not validate the `from_address` parameter.
///
/// L1 handlers in Starknet receive messages from Ethereum. The first parameter
/// is always `from_address: felt252` — the Ethereum address that sent the message.
/// Failing to check this allows any Ethereum address to trigger the handler,
/// which is a critical access-control vulnerability.
///
/// Detection strategy (Sierra-only):
/// 1. Find functions classified as L1_HANDLER.
/// 2. Check whether the first parameter variable (from_address) is used in
///    any conditional branch or equality check.
/// 3. If not used in a check, report as unchecked.
pub struct UncheckedL1Handler;

/// Libfunc patterns that represent comparison / validation operations.
const COMPARISON_LIBFUNCS: &[&str] = &[
    "felt252_is_zero",
    "felt252_sub",
    "felt252_add",
    "u256_eq",
    "contract_address_to_felt252",
    "into_felt252",
    "assert_eq",
    "assert_ne",
    "bool_not",
    "branch_align",
    // equality checks on various integer types
    "u128_eq",
    "u64_eq",
    "u32_eq",
    "u16_eq",
    "u8_eq",
];

impl Detector for UncheckedL1Handler {
    fn id(&self) -> &'static str {
        "unchecked_l1_handler"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "L1 handler does not validate the from_address parameter. \
         Any Ethereum address can trigger this handler, bypassing access control."
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

        for func in program.l1_handler_functions() {
            // The first two params of an L1 handler are:
            //   param[0]: implicit System arg
            //   param[1]: from_address: felt252   ← this is what we track
            //
            // In Sierra, params are numbered starting from 0. The from_address
            // is param variable ID 0 or 1 depending on implicit args.
            // We track all param variables to be safe.
            let param_var_ids: Vec<u64> =
                func.raw.params.iter().map(|(id, _)| *id).collect();

            if param_var_ids.is_empty() {
                // No parameters — definitely can't validate from_address
                findings.push(make_finding(
                    self,
                    program,
                    func.idx,
                    &func.name,
                    None,
                    "L1 handler has no parameters — cannot validate from_address",
                ));
                continue;
            }

            // Identify the from_address variable. In Starknet ABI, after implicit
            // args (like System context), the first explicit param is from_address.
            // We heuristically pick the first felt252 param.
            let from_address_var = find_from_address_var(&func.raw.params, program);
            let from_address_var = match from_address_var {
                Some(v) => v,
                None => {
                    // Cannot identify — conservative: skip with warning
                    continue;
                }
            };

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Check if from_address_var is ever used in a comparison/branch
            let is_validated = is_variable_validated(from_address_var, stmts, program);

            if !is_validated {
                findings.push(make_finding(
                    self,
                    program,
                    func.idx,
                    &func.name,
                    Some(start),
                    &format!(
                        "L1 handler '{}': from_address (var {}) is never compared or validated. \
                         Any Ethereum address can call this handler.",
                        func.name, from_address_var
                    ),
                ));
            }
        }

        (findings, warnings)
    }
}

fn find_from_address_var(
    params: &[(u64, crate::loader::SierraId)],
    program: &ProgramIR,
) -> Option<u64> {
    // Look for the first felt252 param. In L1 handlers:
    //   - implicit: System (context pointer)
    //   - explicit[0]: from_address: felt252
    for (var_id, ty) in params {
        if program.type_registry.is_felt252(ty) {
            return Some(*var_id);
        }
    }
    // Fallback: second param if no type info
    params.get(1).map(|(id, _)| *id)
}

fn is_variable_validated(
    var: u64,
    stmts: &[Statement],
    program: &ProgramIR,
) -> bool {
    for stmt in stmts {
        let inv = match stmt.as_invocation() {
            Some(inv) => inv,
            None => continue,
        };

        // If var is used as an argument to a comparison libfunc, it's validated
        if inv.args.contains(&var) {
            let is_comparison = COMPARISON_LIBFUNCS
                .iter()
                .any(|p| program.libfunc_registry.matches(&inv.libfunc_id, p));

            if is_comparison {
                return true;
            }

            // Also: if the libfunc has 2+ branches and var is an arg,
            // it's likely being branched on (e.g. felt252_is_zero)
            if inv.branches.len() >= 2 {
                return true;
            }
        }

        // Track variable propagation: if var flows into a result that IS compared,
        // mark the results as derived from from_address.
        // (Simplified: we don't do full taint here — just direct usage.)
    }
    false
}

fn make_finding(
    detector: &UncheckedL1Handler,
    program: &ProgramIR,
    func_idx: usize,
    func_name: &str,
    stmt_idx: Option<usize>,
    description: &str,
) -> Finding {
    Finding::new(
        detector.id(),
        detector.severity(),
        detector.confidence(),
        "Unchecked L1 handler from_address",
        description.to_string(),
        Location {
            file: program.source.display().to_string(),
            function: func_name.to_string(),
            statement_idx: stmt_idx,
            line: None,
            col: None,
        },
    )
}
