use std::path::PathBuf;

use shadowhare::analyse_paths;
use shadowhare::config::AnalyzerConfig;
use shadowhare::detectors::DetectorRegistry;
use shadowhare::error::WarningKind;
use shadowhare::ir::program::ProgramIR;
use shadowhare::loader::{sierra_loader, CompatibilityMatrix};

fn write_empty_raw_sierra() -> tempfile::NamedTempFile {
    let empty_program_json = r#"{
        "type_declarations": [],
        "libfunc_declarations": [],
        "statements": [],
        "funcs": []
    }"#;

    let tmp = tempfile::NamedTempFile::with_suffix(".sierra.json").expect("temp file");
    std::fs::write(tmp.path(), empty_program_json).expect("write temp sierra");
    tmp
}

#[test]
fn requires_debug_info_detectors_are_skipped_without_debug_info() {
    let tmp = write_empty_raw_sierra();
    let matrix = CompatibilityMatrix::default();
    let artifact = sierra_loader::load_artifact(tmp.path(), &matrix).expect("load artifact");
    let program = ProgramIR::from_artifact(artifact);
    assert!(!program.has_debug_info, "fixture should have no debug info");

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();
    let (_findings, warnings) = registry.run_all(&program, &config);

    assert!(
        warnings.iter().any(|w| {
            w.kind == WarningKind::MissingDebugInfo
                && w.message.contains("missing_nonce_validation")
        }),
        "expected missing_nonce_validation to be skipped for missing debug info; warnings={warnings:?}"
    );
    assert!(
        warnings.iter().any(|w| {
            w.kind == WarningKind::MissingDebugInfo && w.message.contains("signature_replay")
        }),
        "expected signature_replay to be skipped for missing debug info; warnings={warnings:?}"
    );
}

#[test]
fn strict_mode_fails_on_missing_debug_info_requirements() {
    let tmp = write_empty_raw_sierra();
    let registry = DetectorRegistry::all();
    let mut config = AnalyzerConfig::default();
    config.strict = true;

    let paths = vec![PathBuf::from(tmp.path())];
    let err = analyse_paths(&paths, &config, &registry).expect_err("strict mode should fail");
    let msg = err.to_string();
    assert!(
        msg.contains("Strict mode blocked analysis due to degraded guarantees"),
        "unexpected strict-mode error: {msg}"
    );
    assert!(
        msg.contains("missing_nonce_validation"),
        "strict-mode error should mention skipped detectors: {msg}"
    );
}
