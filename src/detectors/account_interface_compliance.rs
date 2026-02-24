use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects account-like contracts that expose an incomplete SRC6-style account
/// external interface.
///
/// This is a structural interface check for account contracts:
/// - required core: __execute__, __validate__, is_valid_signature, supports_interface
/// - required protocol hooks: __validate_declare__, __validate_deploy__
///
/// The detector only runs when function debug names are available.
pub struct AccountInterfaceCompliance;

#[derive(Default)]
struct AccountMethods {
    execute: bool,
    validate: bool,
    validate_declare: bool,
    validate_deploy: bool,
    is_valid_signature: bool,
    supports_interface: bool,
}

impl AccountMethods {
    fn account_marker_count(&self) -> usize {
        [
            self.execute,
            self.validate,
            self.validate_declare,
            self.validate_deploy,
            self.is_valid_signature,
        ]
        .into_iter()
        .filter(|b| *b)
        .count()
    }
}

impl Detector for AccountInterfaceCompliance {
    fn id(&self) -> &'static str {
        "account_interface_compliance"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "Account-like contract appears to expose an incomplete SRC6 account interface \
         (missing core or protocol validation entrypoints)."
    }

    fn requirements(&self) -> DetectorRequirements {
        DetectorRequirements {
            min_tier: CompatibilityTier::Tier3,
            requires_debug_info: true,
            source_aware: false,
        }
    }

    fn run(&self, program: &ProgramIR) -> (Vec<Finding>, Vec<AnalyzerWarning>) {
        let warnings = Vec::new();
        let mut findings = Vec::new();

        let mut methods = AccountMethods::default();
        let mut first_site: Option<usize> = None;

        for func in program.all_functions() {
            let n = func.name.to_ascii_lowercase();
            let leaf = function_leaf(&n);
            let mut touched = false;

            if is_execute_name(&n) {
                methods.execute = true;
                touched = true;
            }
            if is_validate_name(&n) {
                methods.validate = true;
                touched = true;
            }
            if n.contains("__validate_declare__") {
                methods.validate_declare = true;
                touched = true;
            }
            if n.contains("__validate_deploy__") {
                methods.validate_deploy = true;
                touched = true;
            }
            if leaf == "is_valid_signature" || leaf == "isvalidsignature" {
                methods.is_valid_signature = true;
                touched = true;
            }
            if leaf == "supports_interface" || leaf == "supportsinterface" {
                methods.supports_interface = true;
                touched = true;
            }

            if touched && first_site.is_none() {
                first_site = Some(func.raw.entry_point);
            }
        }

        // Avoid firing on non-account contracts with incidental name collisions.
        if methods.account_marker_count() < 2 {
            return (findings, warnings);
        }

        let mut missing_core = Vec::new();
        let mut missing_protocol = Vec::new();

        if !methods.execute {
            missing_core.push("__execute__");
        }
        if !methods.validate {
            missing_core.push("__validate__");
        }
        if !methods.is_valid_signature {
            missing_core.push("is_valid_signature");
        }
        if !methods.supports_interface {
            missing_core.push("supports_interface");
        }
        if !methods.validate_declare {
            missing_protocol.push("__validate_declare__");
        }
        if !methods.validate_deploy {
            missing_protocol.push("__validate_deploy__");
        }

        if missing_core.is_empty() && missing_protocol.is_empty() {
            return (findings, warnings);
        }

        let mut detail = String::new();
        if !missing_core.is_empty() {
            detail.push_str(&format!(
                "missing core account methods: {}",
                missing_core.join(", ")
            ));
        }
        if !missing_protocol.is_empty() {
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail.push_str(&format!(
                "missing protocol validation hooks: {}",
                missing_protocol.join(", ")
            ));
        }

        findings.push(Finding::new(
            self.id(),
            self.severity(),
            self.confidence(),
            "Incomplete account interface surface",
            format!(
                "Account-like function set detected, but interface compliance check failed: {}.",
                detail
            ),
            Location {
                file: program.source.display().to_string(),
                function: "<program>".to_string(),
                statement_idx: first_site,
                line: None,
                col: None,
            },
        ));

        (findings, warnings)
    }
}

fn function_leaf(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

fn is_execute_name(name: &str) -> bool {
    name.contains("__execute__") || name.ends_with("__execute")
}

fn is_validate_name(name: &str) -> bool {
    name.contains("__validate__")
        && !name.contains("__validate_declare__")
        && !name.contains("__validate_deploy__")
}
