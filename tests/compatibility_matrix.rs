use semver::Version;
use shadowhare::loader::version::{parse_version_loose, CompatibilityMatrix, CompatibilityTier};

#[test]
fn tier1_is_current_stable() {
    let matrix = CompatibilityMatrix::default();
    assert_eq!(
        matrix.classify(&Version::parse("2.16.0").unwrap()),
        CompatibilityTier::Tier1
    );
    assert_eq!(
        matrix.classify(&Version::parse("2.16.5").unwrap()),
        CompatibilityTier::Tier1
    );
}

#[test]
fn tier2_is_n_minus_1() {
    let matrix = CompatibilityMatrix::default();
    assert_eq!(
        matrix.classify(&Version::parse("2.15.0").unwrap()),
        CompatibilityTier::Tier2
    );
}

#[test]
fn tier3_is_n_minus_2() {
    let matrix = CompatibilityMatrix::default();
    assert_eq!(
        matrix.classify(&Version::parse("2.14.0").unwrap()),
        CompatibilityTier::Tier3
    );
}

#[test]
fn old_2x_versions_are_tier3_best_effort() {
    let matrix = CompatibilityMatrix::default();
    for v in &["2.5.0", "2.10.0", "2.13.1"] {
        assert_eq!(
            matrix.classify(&Version::parse(v).unwrap()),
            CompatibilityTier::Tier3,
            "Expected Tier3 best-effort for {v}"
        );
    }
}

#[test]
fn major_1_is_unsupported() {
    let matrix = CompatibilityMatrix::default();
    assert_eq!(
        matrix.classify(&Version::parse("1.0.0").unwrap()),
        CompatibilityTier::Unsupported
    );
}

#[test]
fn version_parsing_handles_suffixes() {
    assert_eq!(
        parse_version_loose("2.16.0 (abc123)"),
        Some(Version::parse("2.16.0").unwrap())
    );
    assert_eq!(
        parse_version_loose("2.16.0-rc.0"),
        Some(Version::parse("2.16.0-rc.0").unwrap())
    );
    assert_eq!(parse_version_loose("not_a_version"), None);
}

#[test]
fn tier_ordering_is_correct() {
    // Higher tier = better support
    assert!(CompatibilityTier::Tier1 > CompatibilityTier::Tier2);
    assert!(CompatibilityTier::Tier2 > CompatibilityTier::Tier3);
    assert!(CompatibilityTier::Tier3 > CompatibilityTier::ParseOnly);
    assert!(CompatibilityTier::ParseOnly > CompatibilityTier::Unsupported);
}
