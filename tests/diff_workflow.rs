use std::path::PathBuf;

use shadowhare::config::AnalyzerConfig;
use shadowhare::detectors::{DetectorRegistry, Severity};
use shadowhare::diff::{analyse_diff_paths, render_diff_output, DiffOutputFormat};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

#[test]
fn detect_diff_reports_resolved_when_issue_is_patched() {
    let left = fixture("vulnerable/u256_underflow.sierra.json");
    let right = fixture("clean/safe_u256_checked.sierra.json");

    let config = AnalyzerConfig::default();
    let registry = DetectorRegistry::all();

    let diff = analyse_diff_paths(&[left], &[right], &config, &registry).expect("diff analysis");

    assert!(
        diff.resolved_findings
            .iter()
            .any(|f| f.detector_id == "u256_underflow"),
        "expected u256_underflow to appear as resolved"
    );
}

#[test]
fn detect_diff_reports_new_when_issue_is_introduced() {
    let left = fixture("clean/safe_u256_checked.sierra.json");
    let right = fixture("vulnerable/u256_underflow.sierra.json");

    let config = AnalyzerConfig::default();
    let registry = DetectorRegistry::all();

    let diff = analyse_diff_paths(&[left], &[right], &config, &registry).expect("diff analysis");

    assert!(
        diff.new_findings
            .iter()
            .any(|f| f.detector_id == "u256_underflow"),
        "expected u256_underflow to appear as new"
    );
    assert_eq!(diff.exit_code(Some(Severity::High)), 1);
}

#[test]
fn detect_diff_reports_unchanged_fingerprints_on_identical_inputs() {
    let left = fixture("vulnerable/u256_underflow.sierra.json");
    let right = fixture("vulnerable/u256_underflow.sierra.json");

    let config = AnalyzerConfig::default();
    let registry = DetectorRegistry::all();

    let diff = analyse_diff_paths(&[left], &[right], &config, &registry).expect("diff analysis");

    assert!(diff.new_findings.is_empty());
    assert!(diff.resolved_findings.is_empty());
    assert!(
        !diff.unchanged_fingerprints.is_empty(),
        "expected unchanged fingerprints on identical inputs"
    );
}

#[test]
fn diff_json_output_contains_summary_and_finding_groups() {
    let left = fixture("clean/safe_u256_checked.sierra.json");
    let right = fixture("vulnerable/u256_underflow.sierra.json");

    let config = AnalyzerConfig::default();
    let registry = DetectorRegistry::all();

    let diff = analyse_diff_paths(&[left], &[right], &config, &registry).expect("diff analysis");
    let json = render_diff_output(&diff, DiffOutputFormat::Json).expect("diff json render");

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid diff json");
    assert!(parsed.get("summary").is_some());
    assert!(parsed.get("new_findings").is_some());
    assert!(parsed.get("resolved_findings").is_some());
    assert!(parsed.get("unchanged_fingerprints").is_some());
}
