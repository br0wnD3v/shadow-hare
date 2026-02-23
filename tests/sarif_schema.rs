use shadowhare::detectors::{Confidence, Finding, Location, Severity};
use shadowhare::output::sarif::{build_sarif, SARIF_SCHEMA, SARIF_VERSION};

fn sample_finding(detector_id: &str, severity: Severity) -> Finding {
    Finding::new(
        detector_id,
        severity,
        Confidence::High,
        "Test finding title",
        "Test description".to_string(),
        Location {
            file: "test.sierra.json".to_string(),
            function: "test_function".to_string(),
            statement_idx: Some(42),
            line: Some(10),
            col: Some(5),
        },
    )
}

#[test]
fn sarif_version_is_correct() {
    let sarif = build_sarif(&[], &[]);
    let json = serde_json::to_value(&sarif).unwrap();
    assert_eq!(json["version"].as_str(), Some(SARIF_VERSION));
    assert_eq!(json["$schema"].as_str(), Some(SARIF_SCHEMA));
}

#[test]
fn sarif_has_required_structure() {
    let findings = vec![
        sample_finding("u256_underflow", Severity::High),
        sample_finding("reentrancy", Severity::High),
    ];
    let sarif = build_sarif(&findings, &["test.sierra.json".to_string()]);
    let json = serde_json::to_value(&sarif).unwrap();

    assert!(json["runs"].is_array());
    let run = &json["runs"][0];
    assert!(run["tool"]["driver"]["name"].as_str().is_some());
    assert!(run["results"].is_array());
    assert!(run["artifacts"].is_array());
    assert_eq!(run["results"].as_array().unwrap().len(), 2);
}

#[test]
fn sarif_severity_mapping() {
    let findings = vec![
        sample_finding("critical_det", Severity::Critical),
        sample_finding("high_det", Severity::High),
        sample_finding("medium_det", Severity::Medium),
        sample_finding("low_det", Severity::Low),
        sample_finding("info_det", Severity::Info),
    ];

    let sarif = build_sarif(&findings, &[]);
    let json = serde_json::to_value(&sarif).unwrap();
    let results = json["runs"][0]["results"].as_array().unwrap();

    assert_eq!(results[0]["level"].as_str(), Some("error")); // critical
    assert_eq!(results[1]["level"].as_str(), Some("error")); // high
    assert_eq!(results[2]["level"].as_str(), Some("warning")); // medium
    assert_eq!(results[3]["level"].as_str(), Some("note")); // low
    assert_eq!(results[4]["level"].as_str(), Some("note")); // info
}

#[test]
fn sarif_fingerprints_are_present() {
    let findings = vec![sample_finding("u256_underflow", Severity::High)];
    let sarif = build_sarif(&findings, &[]);
    let json = serde_json::to_value(&sarif).unwrap();
    let result = &json["runs"][0]["results"][0];

    // fingerprints key should be present (even if empty object for findings without fp)
    assert!(result.get("fingerprints").is_some());
}

#[test]
fn sarif_rules_deduplicated() {
    // Two findings with the same detector_id — should produce only one rule.
    let findings = vec![
        sample_finding("u256_underflow", Severity::High),
        sample_finding("u256_underflow", Severity::High),
    ];
    let sarif = build_sarif(&findings, &[]);
    let json = serde_json::to_value(&sarif).unwrap();
    let rules = json["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 1, "Duplicate rules should be deduplicated");
}

#[test]
fn sarif_logical_locations_include_function() {
    let findings = vec![sample_finding("reentrancy", Severity::High)];
    let sarif = build_sarif(&findings, &[]);
    let json = serde_json::to_value(&sarif).unwrap();

    let logical_locs = &json["runs"][0]["results"][0]["locations"][0]["logicalLocations"];
    assert!(logical_locs.is_array());
    let loc = &logical_locs[0];
    assert_eq!(loc["name"].as_str(), Some("test_function"));
    assert_eq!(loc["kind"].as_str(), Some("function"));
}
