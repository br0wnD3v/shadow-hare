use std::path::PathBuf;

use shadowhare::config::AnalyzerConfig;
use shadowhare::detectors::{DetectorRegistry, Severity};
use shadowhare::loader::{sierra_loader, CompatibilityMatrix};
use shadowhare::ir::program::ProgramIR;
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
    assert_eq!(l1_findings[0].confidence, shadowhare::detectors::Confidence::High);
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
            "Finding {:?} below threshold", f.detector_id
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

    let fps1: Vec<_> = result1.findings.iter().filter_map(|f| f.fingerprint.as_deref()).collect();
    let fps2: Vec<_> = result2.findings.iter().filter_map(|f| f.fingerprint.as_deref()).collect();

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
        artifact.program.functions.iter().map(|f| f.id.canonical_name()).collect::<Vec<_>>(),
        artifact.warnings
    );

    // Verify function names are present (debug info decoded correctly)
    let func_names: Vec<String> = artifact.program.functions
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
