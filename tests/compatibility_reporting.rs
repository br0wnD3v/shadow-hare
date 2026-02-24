use std::path::PathBuf;

use shadowhare::analyse_paths;
use shadowhare::config::AnalyzerConfig;
use shadowhare::detectors::DetectorRegistry;
use shadowhare::loader::{CompatibilityTier, VersionMetadataSource};
use shadowhare::{render_output, OutputFormat};

fn write_raw_sierra_with_versions(
    compiler_version: Option<&str>,
    sierra_version: Option<&str>,
) -> tempfile::NamedTempFile {
    let mut payload = serde_json::json!({
        "type_declarations": [],
        "libfunc_declarations": [],
        "statements": [],
        "funcs": [
            {
                "id": { "id": 0, "debug_name": "compat::entry" },
                "signature": {
                    "param_types": [],
                    "ret_types": []
                },
                "params": [],
                "entry_point": 0
            }
        ]
    });

    if let Some(v) = compiler_version {
        payload["compiler_version"] = serde_json::json!(v);
    }
    if let Some(v) = sierra_version {
        payload["sierra_version"] = serde_json::json!(v);
    }

    let tmp = tempfile::NamedTempFile::with_suffix(".sierra.json").expect("temp file");
    std::fs::write(
        tmp.path(),
        serde_json::to_string_pretty(&payload).expect("serialize payload"),
    )
    .expect("write temp artifact");
    tmp
}

#[test]
fn json_report_includes_compiler_version_compatibility_metadata() {
    let tmp = write_raw_sierra_with_versions(Some("2.16.1"), None);

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();
    let paths = vec![PathBuf::from(tmp.path())];
    let result = analyse_paths(&paths, &config, &registry).expect("analysis");

    assert_eq!(result.compatibility.len(), 1);
    assert_eq!(
        result.compatibility[0].compatibility_tier,
        CompatibilityTier::Tier1
    );
    assert_eq!(
        result.compatibility[0].metadata_source,
        VersionMetadataSource::CompilerVersion
    );
    assert!(result.compatibility[0].degraded_reason.is_none());

    let json = render_output(&result, OutputFormat::Json).expect("render json");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    let artifact = &parsed["artifacts"][0];
    assert_eq!(artifact["compatibility_tier"], "tier1");
    assert_eq!(artifact["metadata_source"], "compiler_version");
    assert!(artifact["degraded_reason"].is_null());
}

#[test]
fn missing_version_metadata_reports_tier3_best_effort() {
    let tmp = write_raw_sierra_with_versions(None, None);

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();
    let paths = vec![PathBuf::from(tmp.path())];
    let result = analyse_paths(&paths, &config, &registry).expect("analysis");

    assert_eq!(result.compatibility.len(), 1);
    assert_eq!(
        result.compatibility[0].compatibility_tier,
        CompatibilityTier::Tier3
    );
    assert_eq!(
        result.compatibility[0].metadata_source,
        VersionMetadataSource::Unavailable
    );
    let degraded = result.compatibility[0]
        .degraded_reason
        .as_deref()
        .unwrap_or("");
    assert!(
        degraded.contains("assuming Tier3 best-effort"),
        "expected best-effort degraded reason, got: {degraded}"
    );
}

#[test]
fn human_report_includes_compatibility_metadata_and_reason() {
    let tmp = write_raw_sierra_with_versions(None, None);

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();
    let paths = vec![PathBuf::from(tmp.path())];
    let result = analyse_paths(&paths, &config, &registry).expect("analysis");

    let human = render_output(&result, OutputFormat::Human).expect("render human");
    assert!(
        human.contains("Compatibility:"),
        "expected compatibility section in human output, got: {human}"
    );
    assert!(
        human.contains("source=unavailable"),
        "expected metadata source in human output, got: {human}"
    );
    assert!(
        human.contains("assuming Tier3 best-effort"),
        "expected degraded reason in human output, got: {human}"
    );
}

#[test]
fn strict_mode_fails_on_compatibility_degradation() {
    let tmp = write_raw_sierra_with_versions(None, None);

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
        msg.contains("assuming Tier3 best-effort"),
        "strict-mode error should include compatibility downgrade reason: {msg}"
    );
}
