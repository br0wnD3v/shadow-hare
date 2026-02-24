use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

use crate::error::{AnalyzerError, AnalyzerWarning};

/// Tier defines how thoroughly we support a given Sierra/Cairo version.
///
/// Ordering: Tier1 > Tier2 > Tier3 > ParseOnly > Unsupported (higher = better support).
/// Derived `Ord` uses declaration order, so we declare worst-first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityTier {
    /// Completely unsupported — we refuse to continue.
    Unsupported,
    /// Parse-only — no detector guarantees, just schema validation.
    ParseOnly,
    /// Best-effort — some detectors may skip gracefully.
    Tier3,
    /// Full support — previous stable.
    Tier2,
    /// Full support — all detectors run, CI-quality guarantees.
    Tier1,
}

impl std::fmt::Display for CompatibilityTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tier1 => write!(f, "Tier1 (fully supported)"),
            Self::Tier2 => write!(f, "Tier2 (fully supported, N-1)"),
            Self::Tier3 => write!(f, "Tier3 (best-effort, N-2 and older 2.x)"),
            Self::ParseOnly => write!(f, "ParseOnly (no detector guarantees)"),
            Self::Unsupported => write!(f, "Unsupported"),
        }
    }
}

/// Which artifact field provided (or failed to provide) version metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionMetadataSource {
    CompilerVersion,
    SierraVersion,
    ContractClassVersion,
    Unavailable,
}

impl std::fmt::Display for VersionMetadataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CompilerVersion => write!(f, "compiler_version"),
            Self::SierraVersion => write!(f, "sierra_version"),
            Self::ContractClassVersion => write!(f, "contract_class_version"),
            Self::Unavailable => write!(f, "unavailable"),
        }
    }
}

/// Version information extracted from a Sierra artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactVersion {
    /// The contract_class_version field, if present (e.g. "0.1.0").
    pub contract_class_version: Option<String>,
    /// The compiler version in debug_info, if present.
    pub compiler_version: Option<String>,
    /// Sierra program encoding version.
    pub sierra_version: Option<String>,
}

/// Best-effort metadata source classification for reporting.
pub fn metadata_source(artifact: &ArtifactVersion) -> VersionMetadataSource {
    if artifact.compiler_version.is_some() {
        VersionMetadataSource::CompilerVersion
    } else if artifact.sierra_version.is_some() {
        VersionMetadataSource::SierraVersion
    } else if artifact.contract_class_version.is_some() {
        VersionMetadataSource::ContractClassVersion
    } else {
        VersionMetadataSource::Unavailable
    }
}

/// The current compatibility matrix (updated per release cadence).
///
/// As of 2026-02-21:
///   Tier 1: Cairo/Sierra 2.16.x
///   Tier 2: 2.15.x
///   Tier 3: 2.14.x and older 2.x (best-effort detector execution)
pub struct CompatibilityMatrix {
    pub tier1: VersionReq,
    pub tier2: VersionReq,
    pub tier3: VersionReq,
}

impl Default for CompatibilityMatrix {
    fn default() -> Self {
        Self {
            tier1: VersionReq::parse("~2.16").expect("valid semver req"),
            tier2: VersionReq::parse("~2.15").expect("valid semver req"),
            tier3: VersionReq::parse("~2.14").expect("valid semver req"),
        }
    }
}

impl CompatibilityMatrix {
    pub fn is_legacy_2x(&self, version: &Version) -> bool {
        version.major == 2
            && !self.tier1.matches(version)
            && !self.tier2.matches(version)
            && !self.tier3.matches(version)
    }

    pub fn classify(&self, version: &Version) -> CompatibilityTier {
        if self.tier1.matches(version) {
            CompatibilityTier::Tier1
        } else if self.tier2.matches(version) {
            CompatibilityTier::Tier2
        } else if self.tier3.matches(version) || self.is_legacy_2x(version) {
            CompatibilityTier::Tier3
        } else {
            CompatibilityTier::Unsupported
        }
    }
}

/// Negotiate compatibility from artifact version info.
/// Returns tier + any warnings.
pub fn negotiate(
    artifact: &ArtifactVersion,
    matrix: &CompatibilityMatrix,
) -> Result<(CompatibilityTier, Vec<AnalyzerWarning>), AnalyzerError> {
    let mut warnings = Vec::new();

    // Try compiler_version first, then sierra_version, then a conservative
    // contract_class_version mapping when it looks like a Cairo semver.
    let (version_str, source) = select_version_candidate(artifact);

    let version = match version_str {
        Some(s) => parse_version_loose(s),
        None => {
            warnings.push(AnalyzerWarning {
                kind: crate::error::WarningKind::IncompatibleVersion,
                message: match source {
                    VersionMetadataSource::ContractClassVersion => format!(
                        "contract_class_version='{}' is present but cannot be mapped to a Cairo/Sierra semver — assuming Tier3 best-effort",
                        artifact.contract_class_version.as_deref().unwrap_or("unknown")
                    ),
                    VersionMetadataSource::Unavailable => {
                        "No compiler/sierra version found in artifact — assuming Tier3 best-effort"
                            .to_string()
                    }
                    _ => {
                        "No usable compiler/sierra version found in artifact — assuming Tier3 best-effort"
                            .to_string()
                    }
                },
            });
            return Ok((CompatibilityTier::Tier3, warnings));
        }
    };

    let version = match version {
        Some(v) => v,
        None => {
            warnings.push(AnalyzerWarning {
                kind: crate::error::WarningKind::IncompatibleVersion,
                message: format!(
                    "Could not parse {}='{}' — assuming Tier3 best-effort",
                    source,
                    version_str.unwrap_or("unknown")
                ),
            });
            return Ok((CompatibilityTier::Tier3, warnings));
        }
    };

    let tier = matrix.classify(&version);
    let legacy_2x = matrix.is_legacy_2x(&version);

    match tier {
        CompatibilityTier::Unsupported => Err(AnalyzerError::UnsupportedVersion {
            version: version.to_string(),
            reason: "Version predates Sierra 2.x — no parsing guarantees".to_string(),
        }),
        CompatibilityTier::ParseOnly => {
            warnings.push(AnalyzerWarning {
                kind: crate::error::WarningKind::IncompatibleVersion,
                message: format!(
                    "Cairo {version} is older than N-2 — detectors disabled, parse-only mode"
                ),
            });
            Ok((tier, warnings))
        }
        CompatibilityTier::Tier3 => {
            warnings.push(AnalyzerWarning {
                kind: crate::error::WarningKind::IncompatibleVersion,
                message: if legacy_2x {
                    format!(
                        "Cairo {version} is older than tested window (N-2) — running detectors in best-effort compatibility mode"
                    )
                } else {
                    format!(
                        "Cairo {version} is Tier3 (N-2) — some detectors may skip gracefully"
                    )
                },
            });
            Ok((tier, warnings))
        }
        _ => Ok((tier, warnings)),
    }
}

fn select_version_candidate(artifact: &ArtifactVersion) -> (Option<&str>, VersionMetadataSource) {
    if let Some(v) = artifact.compiler_version.as_deref() {
        return (Some(v), VersionMetadataSource::CompilerVersion);
    }
    if let Some(v) = artifact.sierra_version.as_deref() {
        return (Some(v), VersionMetadataSource::SierraVersion);
    }
    if let Some(v) = artifact.contract_class_version.as_deref() {
        // contract_class_version can carry values like "0.1.0" that are not a
        // Cairo compiler semver. Only treat it as negotiable when it looks like
        // an actual Cairo major stream (2.x+).
        let parsed = parse_version_loose(v);
        if parsed.as_ref().is_some_and(|pv| pv.major >= 2) {
            return (Some(v), VersionMetadataSource::ContractClassVersion);
        }
        return (None, VersionMetadataSource::ContractClassVersion);
    }
    (None, VersionMetadataSource::Unavailable)
}

/// Parse a version string that might have extra suffixes like "2.16.0 (abc123)".
/// Preserves semver pre-release labels like "-rc.0".
pub fn parse_version_loose(s: &str) -> Option<Version> {
    // Strip build metadata marker (+) and anything after whitespace.
    let trimmed = s.split_whitespace().next().unwrap_or(s);
    let without_build = trimmed.split('+').next().unwrap_or(trimmed);

    // Try direct parse first (handles "2.16.0-rc.0" cleanly).
    if let Ok(v) = Version::parse(without_build) {
        return Some(v);
    }

    // Try appending ".0" for "major.minor" shorthand.
    let with_patch = format!("{without_build}.0");
    Version::parse(&with_patch).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_classification() {
        let matrix = CompatibilityMatrix::default();
        assert_eq!(
            matrix.classify(&Version::parse("2.16.0").unwrap()),
            CompatibilityTier::Tier1
        );
        assert_eq!(
            matrix.classify(&Version::parse("2.15.3").unwrap()),
            CompatibilityTier::Tier2
        );
        assert_eq!(
            matrix.classify(&Version::parse("2.14.0").unwrap()),
            CompatibilityTier::Tier3
        );
        assert_eq!(
            matrix.classify(&Version::parse("2.5.0").unwrap()),
            CompatibilityTier::Tier3
        );
        assert_eq!(
            matrix.classify(&Version::parse("1.0.0").unwrap()),
            CompatibilityTier::Unsupported
        );
    }

    #[test]
    fn test_parse_version_loose() {
        assert_eq!(
            parse_version_loose("2.16.0 (abc123)"),
            Some(Version::parse("2.16.0").unwrap())
        );
        assert_eq!(
            parse_version_loose("2.16"),
            Some(Version::parse("2.16.0").unwrap())
        );
        assert_eq!(parse_version_loose("invalid"), None);
    }

    #[test]
    fn metadata_source_priority() {
        let a = ArtifactVersion {
            contract_class_version: Some("0.1.0".to_string()),
            compiler_version: Some("2.16.0".to_string()),
            sierra_version: Some("2.15.0".to_string()),
        };
        assert_eq!(metadata_source(&a), VersionMetadataSource::CompilerVersion);

        let b = ArtifactVersion {
            contract_class_version: Some("0.1.0".to_string()),
            compiler_version: None,
            sierra_version: Some("2.15.0".to_string()),
        };
        assert_eq!(metadata_source(&b), VersionMetadataSource::SierraVersion);

        let c = ArtifactVersion {
            contract_class_version: Some("0.1.0".to_string()),
            compiler_version: None,
            sierra_version: None,
        };
        assert_eq!(
            metadata_source(&c),
            VersionMetadataSource::ContractClassVersion
        );
    }

    #[test]
    fn contract_class_version_hint_without_cairo_semver_degrades_to_tier3() {
        let matrix = CompatibilityMatrix::default();
        let artifact = ArtifactVersion {
            contract_class_version: Some("0.1.0".to_string()),
            compiler_version: None,
            sierra_version: None,
        };
        let (tier, warnings) = negotiate(&artifact, &matrix).expect("negotiate");
        assert_eq!(tier, CompatibilityTier::Tier3);
        assert!(
            warnings.iter().any(|w| {
                w.message.contains("contract_class_version='0.1.0'")
                    && w.message.contains("assuming Tier3 best-effort")
            }),
            "expected contract_class_version degradation warning, got {warnings:?}"
        );
    }

    #[test]
    fn contract_class_version_cairo_semver_can_negotiate_tier() {
        let matrix = CompatibilityMatrix::default();
        let artifact = ArtifactVersion {
            contract_class_version: Some("2.15.3".to_string()),
            compiler_version: None,
            sierra_version: None,
        };
        let (tier, warnings) = negotiate(&artifact, &matrix).expect("negotiate");
        assert_eq!(tier, CompatibilityTier::Tier2);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }
}
