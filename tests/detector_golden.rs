use std::path::PathBuf;

use shadowhare::config::AnalyzerConfig;
use shadowhare::detectors::{DetectorRegistry, Severity};
use shadowhare::ir::program::ProgramIR;
use shadowhare::loader::{sierra_loader, CompatibilityMatrix};
use shadowhare::{analyse_paths, render_output, OutputFormat};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

fn load_program(path: PathBuf) -> ProgramIR {
    let matrix = CompatibilityMatrix::default();
    let artifact = sierra_loader::load_artifact(&path, &matrix)
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
    ProgramIR::from_artifact(artifact)
}

// ── u256_underflow ────────────────────────────────────────────────────────────

#[test]
fn u256_underflow_detects_unchecked_subtraction() {
    let program = load_program(fixture("vulnerable/u256_underflow.sierra.json"));
    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();
    let (findings, _warnings) = registry.run_all(&program, &config);

    let underflow_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.detector_id == "u256_underflow")
        .collect();

    assert!(
        !underflow_findings.is_empty(),
        "Expected u256_underflow to fire on vulnerable fixture"
    );
    assert_eq!(underflow_findings[0].severity, Severity::High);
}

#[test]
fn u256_underflow_clean_on_checked_subtraction() {
    let program = load_program(fixture("clean/safe_u256_checked.sierra.json"));
    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();
    let (findings, _warnings) = registry.run_all(&program, &config);

    let underflow_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.detector_id == "u256_underflow")
        .collect();

    assert!(
        underflow_findings.is_empty(),
        "u256_underflow should NOT fire on a checked subtraction. Got: {underflow_findings:?}"
    );
}

// ── unchecked_l1_handler ──────────────────────────────────────────────────────

#[test]
fn l1_handler_detects_unchecked_from_address() {
    let program = load_program(fixture("vulnerable/unchecked_l1_handler.sierra.json"));
    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();
    let (findings, _warnings) = registry.run_all(&program, &config);

    let l1_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.detector_id == "unchecked_l1_handler")
        .collect();

    assert!(
        !l1_findings.is_empty(),
        "Expected unchecked_l1_handler to fire on vulnerable fixture"
    );
    assert_eq!(l1_findings[0].severity, Severity::High);
    assert_eq!(
        l1_findings[0].confidence,
        shadowhare::detectors::Confidence::High
    );
}

// ── reentrancy ────────────────────────────────────────────────────────────────

#[test]
fn reentrancy_detects_read_call_write_pattern() {
    let program = load_program(fixture("vulnerable/reentrancy.sierra.json"));
    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();
    let (findings, _warnings) = registry.run_all(&program, &config);

    let reentrant: Vec<_> = findings
        .iter()
        .filter(|f| f.detector_id == "reentrancy")
        .collect();

    assert!(
        !reentrant.is_empty(),
        "Expected reentrancy to fire on vulnerable fixture"
    );
}

// ── unprotected_upgrade regression tests ─────────────────────────────────────

#[test]
fn unprotected_upgrade_not_masked_by_arithmetic_mixing() {
    let program = load_program(fixture(
        "vulnerable/unprotected_upgrade_arithmetic_only.sierra.json",
    ));
    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();
    let (findings, _warnings) = registry.run_all(&program, &config);

    let upgrade_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.detector_id == "unprotected_upgrade")
        .collect();

    assert!(
        !upgrade_findings.is_empty(),
        "Expected unprotected_upgrade to fire when caller+storage values are only used in arithmetic, not an auth guard"
    );
}

#[test]
fn unprotected_upgrade_recognizes_storage_owner_from_helper_return() {
    let program = load_program(fixture(
        "clean/protected_upgrade_helper_owner_read.sierra.json",
    ));
    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();
    let (findings, _warnings) = registry.run_all(&program, &config);

    let upgrade_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.detector_id == "unprotected_upgrade")
        .collect();

    assert!(
        upgrade_findings.is_empty(),
        "unprotected_upgrade should not fire when a helper reads owner from storage and caller performs the auth comparison"
    );
}

// ── Severity threshold filtering ──────────────────────────────────────────────

#[test]
fn severity_threshold_filters_low_findings() {
    let program = load_program(fixture("vulnerable/u256_underflow.sierra.json"));
    let registry = DetectorRegistry::all();
    let mut config = AnalyzerConfig::default();
    config.min_severity = Severity::Critical; // Only critical

    let (findings, _) = registry.run_all(&program, &config);

    for f in &findings {
        assert!(
            f.severity >= Severity::Critical,
            "Finding {:?} below threshold",
            f.detector_id
        );
    }
}

// ── Fingerprint stability ────────────────────────────────────────────────────

#[test]
fn findings_have_stable_fingerprints() {
    let path = fixture("vulnerable/u256_underflow.sierra.json");
    let config = AnalyzerConfig::default();
    let registry = DetectorRegistry::all();

    let result1 = analyse_paths(&[path.clone()], &config, &registry).unwrap();
    let result2 = analyse_paths(&[path], &config, &registry).unwrap();

    let fps1: Vec<_> = result1
        .findings
        .iter()
        .filter_map(|f| f.fingerprint.as_deref())
        .collect();
    let fps2: Vec<_> = result2
        .findings
        .iter()
        .filter_map(|f| f.fingerprint.as_deref())
        .collect();

    assert_eq!(fps1, fps2, "Fingerprints must be stable across runs");
}

// ── Output formats ────────────────────────────────────────────────────────────

#[test]
fn json_output_is_valid() {
    let path = fixture("vulnerable/u256_underflow.sierra.json");
    let config = AnalyzerConfig::default();
    let registry = DetectorRegistry::all();
    let result = analyse_paths(&[path], &config, &registry).unwrap();

    let json = render_output(&result, OutputFormat::Json).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON output must be valid");

    assert!(parsed.get("schema_version").is_some());
    assert!(parsed.get("findings").is_some());
    assert!(parsed.get("summary").is_some());
}

#[test]
fn sarif_output_is_valid() {
    let path = fixture("vulnerable/u256_underflow.sierra.json");
    let config = AnalyzerConfig::default();
    let registry = DetectorRegistry::all();
    let result = analyse_paths(&[path], &config, &registry).unwrap();

    let sarif = render_output(&result, OutputFormat::Sarif).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&sarif).expect("SARIF must be valid JSON");

    assert_eq!(parsed["version"].as_str(), Some("2.1.0"));
    assert!(parsed["runs"].is_array());
}

// ── Contract class loader integration ────────────────────────────────────────

/// Verifies that the contract class loader correctly decodes the binary-encoded
/// Sierra program from a real .contract_class.json file.
/// This catches the VarId serialization mismatch (struct vs u64) that the
/// old JSON round-trip approach would silently swallow.
#[test]
fn contract_class_loader_produces_nonempty_program() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target_contracts/cairo-compiler-testdata")
        .join("minimal_contract__minimal_contract.contract_class.json");

    if !path.exists() {
        eprintln!("Skipping: test fixture not found at {}", path.display());
        return;
    }

    let matrix = CompatibilityMatrix::default();
    let artifact = sierra_loader::load_artifact(&path, &matrix)
        .unwrap_or_else(|e| panic!("Failed to load contract class: {e}"));

    assert!(
        !artifact.program.functions.is_empty(),
        "Contract class loader produced 0 functions — likely a JSON round-trip bug. \
         Check convert_cairo_program in sierra_loader.rs. Warnings: {:?}",
        artifact.warnings
    );
    assert!(
        !artifact.program.statements.is_empty(),
        "Contract class loader produced 0 statements. \
         Functions: {:?}. Warnings: {:?}",
        artifact
            .program
            .functions
            .iter()
            .map(|f| f.id.canonical_name())
            .collect::<Vec<_>>(),
        artifact.warnings
    );

    // Verify function names are present (debug info decoded correctly)
    let func_names: Vec<String> = artifact
        .program
        .functions
        .iter()
        .map(|f| f.id.canonical_name())
        .collect();
    eprintln!("Contract class functions: {func_names:?}");
    eprintln!("Statements: {}", artifact.program.statements.len());
    eprintln!("Warnings: {:?}", artifact.warnings);
}

// ── No panics on malformed input ──────────────────────────────────────────────

#[test]
fn no_panic_on_empty_program() {
    let empty_program_json = r#"{
        "type_declarations": [],
        "libfunc_declarations": [],
        "statements": [],
        "funcs": []
    }"#;

    let tmp = tempfile::NamedTempFile::with_suffix(".sierra.json").unwrap();
    std::fs::write(tmp.path(), empty_program_json).unwrap();

    let matrix = CompatibilityMatrix::default();
    let result = sierra_loader::load_artifact(tmp.path(), &matrix);
    // Should not panic — may succeed or return a graceful error
    match result {
        Ok(artifact) => {
            let program = ProgramIR::from_artifact(artifact);
            let registry = DetectorRegistry::all();
            let config = AnalyzerConfig::default();
            let (findings, _) = registry.run_all(&program, &config);
            // No findings on empty program is expected
            assert!(findings.len() < 100, "Too many findings on empty program");
        }
        Err(e) => {
            // Graceful error is acceptable
            eprintln!("Graceful error on empty program: {e}");
        }
    }
}

// ── Seeded fixture helpers ────────────────────────────────────────────────────

fn seeded_fixture(subdir: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .join("target_contracts")
        .join("seeded")
        .join(subdir)
        .join(name)
}

/// Load a seeded fixture and return (detector_ids_that_fired, total_finding_count).
fn run_seeded(subdir: &str, name: &str) -> (Vec<String>, usize) {
    let path = seeded_fixture(subdir, name);
    let matrix = CompatibilityMatrix::default();
    let artifact = sierra_loader::load_artifact(&path, &matrix)
        .unwrap_or_else(|e| panic!("Failed to load seeded/{subdir}/{name}: {e}"));
    let program = ProgramIR::from_artifact(artifact);
    let registry = DetectorRegistry::all();
    let mut config = AnalyzerConfig::default();
    config.min_severity = Severity::Info; // capture Info-level (dead_code)
    if subdir == "pure" {
        let detector_id = name.trim_end_matches(".sierra.json").to_string();
        config.detectors =
            shadowhare::config::DetectorSelection::Include([detector_id].into_iter().collect());
    }
    let (findings, _warnings) = registry.run_all(&program, &config);
    let detector_ids: Vec<String> = findings.iter().map(|f| f.detector_id.clone()).collect();
    let count = findings.len();
    (detector_ids, count)
}

// ── Pure fixtures — exactly one detector each ─────────────────────────────────

#[test]
fn seeded_pure_felt252_overflow_fires() {
    let (ids, count) = run_seeded("pure", "felt252_overflow.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"felt252_overflow".to_string()),
        "felt252_overflow not in {ids:?}"
    );
}

#[test]
fn seeded_pure_controlled_library_call_fires() {
    let (ids, count) = run_seeded("pure", "controlled_library_call.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"controlled_library_call".to_string()),
        "controlled_library_call not in {ids:?}"
    );
}

#[test]
fn seeded_pure_tx_origin_auth_fires() {
    let (ids, count) = run_seeded("pure", "tx_origin_auth.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"tx_origin_auth".to_string()),
        "tx_origin_auth not in {ids:?}"
    );
}

#[test]
fn seeded_pure_unused_return_fires() {
    let (ids, count) = run_seeded("pure", "unused_return.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"unused_return".to_string()),
        "unused_return not in {ids:?}"
    );
}

#[test]
fn seeded_pure_dead_code_fires() {
    let (ids, count) = run_seeded("pure", "dead_code.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"dead_code".to_string()),
        "dead_code not in {ids:?}"
    );
}

// ── Compound fixtures — two detectors each ────────────────────────────────────

/// Lending-style flash loan: reentrancy + felt252 accumulator overflow
#[test]
fn seeded_compound_lending_flash_loan_fires() {
    let (ids, count) = run_seeded("compound", "lending_flash_loan_style.sierra.json");
    assert_eq!(
        count, 2,
        "Expected exactly 2 findings, got {count}: {ids:?}"
    );
    assert!(
        ids.contains(&"reentrancy".to_string()),
        "reentrancy not in {ids:?}"
    );
    assert!(
        ids.contains(&"felt252_overflow".to_string()),
        "felt252_overflow not in {ids:?}"
    );
}

/// Proxy upgrade attack: user-controlled class_hash + orphaned auth gate (dead code)
#[test]
fn seeded_compound_proxy_upgrade_fires() {
    let (ids, count) = run_seeded("compound", "proxy_upgrade_attack.sierra.json");
    assert_eq!(
        count, 2,
        "Expected exactly 2 findings, got {count}: {ids:?}"
    );
    assert!(
        ids.contains(&"controlled_library_call".to_string()),
        "controlled_library_call not in {ids:?}"
    );
    assert!(
        ids.contains(&"dead_code".to_string()),
        "dead_code not in {ids:?}"
    );
}

/// L1 bridge: missing from_address validation + silently dropped call result
#[test]
fn seeded_compound_l1_bridge_fires() {
    let (ids, count) = run_seeded("compound", "l1_bridge_vulnerable.sierra.json");
    assert_eq!(
        count, 2,
        "Expected exactly 2 findings, got {count}: {ids:?}"
    );
    assert!(
        ids.contains(&"unchecked_l1_handler".to_string()),
        "unchecked_l1_handler not in {ids:?}"
    );
    assert!(
        ids.contains(&"unused_return".to_string()),
        "unused_return not in {ids:?}"
    );
}

/// AMM swap: tx.origin authentication + CEI-violating reentrancy
#[test]
fn seeded_compound_amm_swap_fires() {
    let (ids, count) = run_seeded("compound", "amm_swap_vulnerable.sierra.json");
    assert_eq!(
        count, 2,
        "Expected exactly 2 findings, got {count}: {ids:?}"
    );
    assert!(
        ids.contains(&"reentrancy".to_string()),
        "reentrancy not in {ids:?}"
    );
    assert!(
        ids.contains(&"tx_origin_auth".to_string()),
        "tx_origin_auth not in {ids:?}"
    );
}

// ── New detector pure fixtures ─────────────────────────────────────────────

#[test]
fn seeded_pure_unprotected_upgrade_fires() {
    let (ids, count) = run_seeded("pure", "unprotected_upgrade.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"unprotected_upgrade".to_string()),
        "unprotected_upgrade not in {ids:?}"
    );
}

#[test]
fn seeded_pure_unchecked_integer_overflow_fires() {
    let (ids, count) = run_seeded("pure", "unchecked_integer_overflow.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"unchecked_integer_overflow".to_string()),
        "unchecked_integer_overflow not in {ids:?}"
    );
}

#[test]
fn seeded_pure_divide_before_multiply_fires() {
    let (ids, count) = run_seeded("pure", "divide_before_multiply.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"divide_before_multiply".to_string()),
        "divide_before_multiply not in {ids:?}"
    );
}

#[test]
fn seeded_pure_tainted_storage_key_fires() {
    let (ids, count) = run_seeded("pure", "tainted_storage_key.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"tainted_storage_key".to_string()),
        "tainted_storage_key not in {ids:?}"
    );
}

#[test]
fn seeded_pure_missing_event_emission_fires() {
    let (ids, count) = run_seeded("pure", "missing_event_emission.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"missing_event_emission".to_string()),
        "missing_event_emission not in {ids:?}"
    );
}

#[test]
fn seeded_pure_arbitrary_token_transfer_fires() {
    let (ids, count) = run_seeded("pure", "arbitrary_token_transfer.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"arbitrary_token_transfer".to_string()),
        "arbitrary_token_transfer not in {ids:?}"
    );
}

#[test]
fn seeded_pure_pyth_unchecked_confidence_fires() {
    let (ids, count) = run_seeded("pure", "pyth_unchecked_confidence.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"pyth_unchecked_confidence".to_string()),
        "pyth_unchecked_confidence not in {ids:?}"
    );
}

#[test]
fn seeded_pure_pyth_unchecked_publishtime_fires() {
    let (ids, count) = run_seeded("pure", "pyth_unchecked_publishtime.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"pyth_unchecked_publishtime".to_string()),
        "pyth_unchecked_publishtime not in {ids:?}"
    );
}

#[test]
fn seeded_pure_pyth_deprecated_function_fires() {
    let (ids, count) = run_seeded("pure", "pyth_deprecated_function.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"pyth_deprecated_function".to_string()),
        "pyth_deprecated_function not in {ids:?}"
    );
}

#[test]
fn seeded_pure_tautological_compare_fires() {
    let (ids, count) = run_seeded("pure", "tautological_compare.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"tautological_compare".to_string()),
        "tautological_compare not in {ids:?}"
    );
}

#[test]
fn seeded_pure_unchecked_transfer_fires() {
    let (ids, count) = run_seeded("pure", "unchecked_transfer.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"unchecked_transfer".to_string()),
        "unchecked_transfer not in {ids:?}"
    );
}

#[test]
fn seeded_pure_weak_prng_fires() {
    let (ids, count) = run_seeded("pure", "weak_prng.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"weak_prng".to_string()),
        "weak_prng not in {ids:?}"
    );
}

#[test]
fn seeded_pure_tautology_fires() {
    let (ids, count) = run_seeded("pure", "tautology.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"tautology".to_string()),
        "tautology not in {ids:?}"
    );
}

#[test]
fn seeded_pure_calls_loop_fires() {
    let (ids, count) = run_seeded("pure", "calls_loop.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"calls_loop".to_string()),
        "calls_loop not in {ids:?}"
    );
}

#[test]
fn seeded_pure_write_after_write_fires() {
    let (ids, count) = run_seeded("pure", "write_after_write.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"write_after_write".to_string()),
        "write_after_write not in {ids:?}"
    );
}

#[test]
fn seeded_pure_reentrancy_events_fires() {
    let (ids, count) = run_seeded("pure", "reentrancy_events.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"reentrancy_events".to_string()),
        "reentrancy_events not in {ids:?}"
    );
}

#[test]
fn seeded_pure_missing_events_access_control_fires() {
    let (ids, count) = run_seeded("pure", "missing_events_access_control.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"missing_events_access_control".to_string()),
        "missing_events_access_control not in {ids:?}"
    );
}

#[test]
fn seeded_pure_missing_events_arithmetic_fires() {
    let (ids, count) = run_seeded("pure", "missing_events_arithmetic.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"missing_events_arithmetic".to_string()),
        "missing_events_arithmetic not in {ids:?}"
    );
}

#[test]
fn seeded_pure_boolean_equality_fires() {
    let (ids, count) = run_seeded("pure", "boolean_equality.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"boolean_equality".to_string()),
        "boolean_equality not in {ids:?}"
    );
}

#[test]
fn seeded_pure_costly_loop_fires() {
    let (ids, count) = run_seeded("pure", "costly_loop.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"costly_loop".to_string()),
        "costly_loop not in {ids:?}"
    );
}

#[test]
fn seeded_pure_cache_array_length_fires() {
    let (ids, count) = run_seeded("pure", "cache_array_length.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"cache_array_length".to_string()),
        "cache_array_length not in {ids:?}"
    );
}

#[test]
fn seeded_pure_rtlo_fires() {
    let (ids, count) = run_seeded("pure", "rtlo.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(ids.contains(&"rtlo".to_string()), "rtlo not in {ids:?}");
}

#[test]
fn seeded_pure_shadowing_builtin_fires() {
    let (ids, count) = run_seeded("pure", "shadowing_builtin.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"shadowing_builtin".to_string()),
        "shadowing_builtin not in {ids:?}"
    );
}

#[test]
fn seeded_pure_shadowing_local_fires() {
    let (ids, count) = run_seeded("pure", "shadowing_local.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"shadowing_local".to_string()),
        "shadowing_local not in {ids:?}"
    );
}

#[test]
fn seeded_pure_shadowing_state_fires() {
    let (ids, count) = run_seeded("pure", "shadowing_state.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"shadowing_state".to_string()),
        "shadowing_state not in {ids:?}"
    );
}

#[test]
fn seeded_pure_incorrect_erc20_interface_fires() {
    let (ids, count) = run_seeded("pure", "incorrect_erc20_interface.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"incorrect_erc20_interface".to_string()),
        "incorrect_erc20_interface not in {ids:?}"
    );
}

#[test]
fn seeded_pure_incorrect_erc721_interface_fires() {
    let (ids, count) = run_seeded("pure", "incorrect_erc721_interface.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"incorrect_erc721_interface".to_string()),
        "incorrect_erc721_interface not in {ids:?}"
    );
}

#[test]
fn seeded_pure_unindexed_event_fires() {
    let (ids, count) = run_seeded("pure", "unindexed_event.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"unindexed_event".to_string()),
        "unindexed_event not in {ids:?}"
    );
}

#[test]
fn seeded_pure_unused_state_fires() {
    let (ids, count) = run_seeded("pure", "unused_state.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"unused_state".to_string()),
        "unused_state not in {ids:?}"
    );
}

// ── 10 new detector pure fixtures ─────────────────────────────────────────────

#[test]
fn seeded_pure_integer_truncation_fires() {
    let (ids, count) = run_seeded("pure", "integer_truncation.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"integer_truncation".to_string()),
        "integer_truncation not in {ids:?}"
    );
}

#[test]
fn seeded_pure_unchecked_address_cast_fires() {
    let (ids, count) = run_seeded("pure", "unchecked_address_cast.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"unchecked_address_cast".to_string()),
        "unchecked_address_cast not in {ids:?}"
    );
}

#[test]
fn seeded_pure_unchecked_array_access_fires() {
    let (ids, count) = run_seeded("pure", "unchecked_array_access.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"unchecked_array_access".to_string()),
        "unchecked_array_access not in {ids:?}"
    );
}

#[test]
fn seeded_pure_oracle_price_manipulation_fires() {
    let (ids, count) = run_seeded("pure", "oracle_price_manipulation.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"oracle_price_manipulation".to_string()),
        "oracle_price_manipulation not in {ids:?}"
    );
}

#[test]
fn seeded_pure_block_timestamp_dependence_fires() {
    let (ids, count) = run_seeded("pure", "block_timestamp_dependence.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"block_timestamp_dependence".to_string()),
        "block_timestamp_dependence not in {ids:?}"
    );
}

#[test]
fn seeded_pure_hardcoded_address_fires() {
    let (ids, count) = run_seeded("pure", "hardcoded_address.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"hardcoded_address".to_string()),
        "hardcoded_address not in {ids:?}"
    );
}

#[test]
fn seeded_pure_write_without_caller_check_fires() {
    let (ids, count) = run_seeded("pure", "write_without_caller_check.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"write_without_caller_check".to_string()),
        "write_without_caller_check not in {ids:?}"
    );
}

#[test]
fn seeded_pure_missing_nonce_validation_fires() {
    let (ids, count) = run_seeded("pure", "missing_nonce_validation.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"missing_nonce_validation".to_string()),
        "missing_nonce_validation not in {ids:?}"
    );
}

#[test]
fn seeded_pure_multiple_external_calls_fires() {
    let (ids, count) = run_seeded("pure", "multiple_external_calls.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"multiple_external_calls".to_string()),
        "multiple_external_calls not in {ids:?}"
    );
}

#[test]
fn seeded_pure_unchecked_l1_message_fires() {
    let (ids, count) = run_seeded("pure", "unchecked_l1_message.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"unchecked_l1_message".to_string()),
        "unchecked_l1_message not in {ids:?}"
    );
}

// ── L1<->L2 messaging detectors ───────────────────────────────────────────────

#[test]
fn seeded_pure_l2_to_l1_tainted_destination_fires() {
    let (ids, count) = run_seeded("pure", "l2_to_l1_tainted_destination.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"l2_to_l1_tainted_destination".to_string()),
        "l2_to_l1_tainted_destination not in {ids:?}"
    );
}

#[test]
fn seeded_pure_l1_handler_unchecked_amount_fires() {
    let (ids, count) = run_seeded("pure", "l1_handler_unchecked_amount.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"l1_handler_unchecked_amount".to_string()),
        "l1_handler_unchecked_amount not in {ids:?}"
    );
}

#[test]
fn seeded_pure_l1_handler_payload_to_storage_fires() {
    let (ids, count) = run_seeded("pure", "l1_handler_payload_to_storage.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"l1_handler_payload_to_storage".to_string()),
        "l1_handler_payload_to_storage not in {ids:?}"
    );
}

#[test]
fn seeded_pure_l2_to_l1_double_send_fires() {
    let (ids, count) = run_seeded("pure", "l2_to_l1_double_send.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"l2_to_l1_double_send".to_string()),
        "l2_to_l1_double_send not in {ids:?}"
    );
}

#[test]
fn seeded_pure_l1_handler_unchecked_selector_fires() {
    let (ids, count) = run_seeded("pure", "l1_handler_unchecked_selector.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"l1_handler_unchecked_selector".to_string()),
        "l1_handler_unchecked_selector not in {ids:?}"
    );
}

#[test]
fn seeded_pure_l2_to_l1_unverified_amount_fires() {
    let (ids, count) = run_seeded("pure", "l2_to_l1_unverified_amount.sierra.json");
    assert_eq!(count, 1, "Expected exactly 1 finding, got {count}: {ids:?}");
    assert!(
        ids.contains(&"l2_to_l1_unverified_amount".to_string()),
        "l2_to_l1_unverified_amount not in {ids:?}"
    );
}
