use crate::detectors::{
    Confidence, Detector, DetectorRequirements, Finding, Location, Severity,
};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects L1 handler functions that use payload amounts (params[2+]) in
/// arithmetic operations or external calls without any prior bounds check.
///
/// When an L1 message carries a token amount (e.g. a deposit), the Cairo
/// handler MUST validate that the amount is within sane bounds before:
/// - Passing it to token.mint() or transfer()
/// - Writing it directly to storage as a balance
///
/// If no bounds check is performed:
/// - A compromised or buggy L1 contract can mint unbounded tokens on L2
/// - A replay of an old, large-deposit message could drain insurance funds
///
/// Vulnerable pattern:
///   @l1_handler fn deposit(from_address, amount) {
///     token.mint(recipient, amount);   // no check: amount > 0, amount <= cap
///   }
///
/// Safe pattern:
///   assert(amount > 0 && amount <= MAX_DEPOSIT);
///   token.mint(recipient, amount);
pub struct L1HandlerUncheckedAmount;

/// Libfuncs that represent arithmetic operations — using unchecked amounts here is risky.
const ARITHMETIC_LIBFUNCS: &[&str] = &[
    "u256_add",
    "u256_sub",
    "u256_mul",
    "u128_overflowing_add",
    "u128_overflowing_sub",
    "u128_mul_guarantee_verify",
    "felt252_add",
    "felt252_sub",
    "felt252_mul",
];

/// Libfuncs that represent comparison / bounds checks — these sanitize the amount.
const COMPARISON_LIBFUNCS: &[&str] = &[
    "felt252_is_zero",
    "u256_is_zero",
    "u128_is_zero",
    "u256_lt",
    "u256_le",
    "u128_lt",
    "felt252_lt",
    "assert_eq",
    "assert_ne",
    "assert_lt",
    "assert_le",
];

impl Detector for L1HandlerUncheckedAmount {
    fn id(&self) -> &'static str {
        "l1_handler_unchecked_amount"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn description(&self) -> &'static str {
        "L1 handler uses payload amount in arithmetic or external call without \
         a prior bounds check. A compromised L1 contract can mint unbounded \
         tokens or manipulate L2 accounting."
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
            // L1 handler param layout:
            //   param[0]: System (implicit)
            //   param[1]: from_address: felt252
            //   param[2+]: message payload (amounts, addresses, etc.)
            //
            // We are interested in params[2+] — the message payload values.
            if func.raw.params.len() < 3 {
                // No payload parameters at all — nothing to check
                continue;
            }

            // Collect payload param IDs (skip system + from_address)
            let payload_var_ids: Vec<u64> = func
                .raw
                .params
                .iter()
                .skip(2)
                .map(|(id, _)| *id)
                .collect();

            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let stmts = &program.statements[start..end.min(program.statements.len())];

            // Only comparisons that use a payload variable count as sanitizers.
            // Comparisons on from_address (param[1]) do NOT protect the amount.
            let mut has_payload_comparison = false;
            let mut arithmetic_site: Option<usize> = None;
            let mut call_site: Option<usize> = None;

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

                // Check for bounds/comparison operations on PAYLOAD vars
                if COMPARISON_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                    if inv.args.iter().any(|a| payload_var_ids.contains(a)) {
                        has_payload_comparison = true;
                    }
                    continue;
                }

                // Check for arithmetic using payload vars
                let uses_payload = inv.args.iter().any(|a| payload_var_ids.contains(a));

                if uses_payload {
                    if ARITHMETIC_LIBFUNCS.iter().any(|p| libfunc_name.contains(p)) {
                        if arithmetic_site.is_none() {
                            arithmetic_site = Some(start + local_idx);
                        }
                    }

                    // External call using payload as calldata (arg[3+], not the selector
                    // at arg[2]). Selector injection is a separate detector.
                    if libfunc_name.contains("call_contract") {
                        let in_calldata = inv
                            .args
                            .iter()
                            .skip(3)
                            .any(|a| payload_var_ids.contains(a));
                        if in_calldata && call_site.is_none() {
                            call_site = Some(start + local_idx);
                        }
                    }

                    // Direct storage write of payload value
                    if program.libfunc_registry.is_storage_write(&inv.libfunc_id) {
                        // Check arg[2] is a payload var (the value being stored)
                        let value_is_payload = inv
                            .args
                            .get(2)
                            .map(|v| payload_var_ids.contains(v))
                            .unwrap_or(false);
                        if value_is_payload && call_site.is_none() {
                            call_site = Some(start + local_idx);
                        }
                    }
                }
            }

            let risky_site = arithmetic_site.or(call_site);
            if let Some(site) = risky_site {
                if !has_payload_comparison {
                    findings.push(Finding::new(
                        self.id(),
                        self.severity(),
                        self.confidence(),
                        "L1 handler amount used without bounds check",
                        format!(
                            "Function '{}': L1 payload amount used at stmt {} \
                             (arithmetic or external call) with no prior bounds comparison. \
                             Validate: amount > 0 and amount <= MAX_DEPOSIT.",
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
