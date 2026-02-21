use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::detectors::Severity;
use crate::error::AnalyzerError;

/// Top-level analyzer configuration, merged from Scarb.toml + CLI flags.
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Which detectors to run. Empty = all.
    pub detectors: DetectorSelection,
    /// Minimum severity to report.
    pub min_severity: Severity,
    /// Only fail on new findings compared to baseline.
    pub fail_on_new_only: bool,
    /// Path to baseline file.
    pub baseline_path: Option<PathBuf>,
    /// Suppress specific findings by (detector_id, location_hash).
    pub suppressions: Vec<Suppression>,
    /// Strict mode: no fallback downgrades for unknown types.
    pub strict: bool,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            detectors: DetectorSelection::All,
            min_severity: Severity::Low,
            fail_on_new_only: false,
            baseline_path: None,
            suppressions: Vec::new(),
            strict: false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum DetectorSelection {
    All,
    Include(HashSet<String>),
    Exclude(HashSet<String>),
}

impl DetectorSelection {
    pub fn should_run(&self, detector_id: &str) -> bool {
        match self {
            Self::All => true,
            Self::Include(ids) => ids.contains(detector_id),
            Self::Exclude(ids) => !ids.contains(detector_id),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    pub detector_id: String,
    /// SHA-256 of "function_name:line_col" or similar stable location fingerprint.
    pub location_hash: Option<String>,
}

/// The `[tool.shadowhare]` table from Scarb.toml.
/// `[tool.analyzer]` is still accepted for backward compatibility.
#[derive(Debug, Default, Deserialize)]
pub struct ScarbAnalyzerConfig {
    pub detectors: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
    pub severity_threshold: Option<String>,
    pub baseline: Option<String>,
    pub strict: Option<bool>,
    pub suppress: Option<Vec<ScarbSuppression>>,
}

#[derive(Debug, Deserialize)]
pub struct ScarbSuppression {
    pub id: String,
    pub location_hash: Option<String>,
}

/// Partial Scarb.toml structure — only the parts we need.
#[derive(Debug, Default, Deserialize)]
struct ScarbToml {
    #[serde(default)]
    tool: ScarbToolSection,
}

#[derive(Debug, Default, Deserialize)]
struct ScarbToolSection {
    #[serde(default)]
    shadowhare: Option<ScarbAnalyzerConfig>,
    #[serde(default)]
    analyzer: Option<ScarbAnalyzerConfig>,
}

pub fn load_scarb_config(manifest_path: &Path) -> Result<Option<ScarbAnalyzerConfig>, AnalyzerError> {
    if !manifest_path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(manifest_path).map_err(|e| AnalyzerError::Io {
        path: manifest_path.to_path_buf(),
        source: e,
    })?;

    let parsed: ScarbToml = toml::from_str(&content)
        .map_err(|e| AnalyzerError::Config(format!("Failed to parse Scarb.toml: {e}")))?;

    Ok(parsed.tool.shadowhare.or(parsed.tool.analyzer))
}

impl AnalyzerConfig {
    pub fn from_scarb(scarb: ScarbAnalyzerConfig) -> Result<Self, AnalyzerError> {
        let detectors = match (scarb.detectors, scarb.exclude) {
            (Some(include), _) if !include.iter().any(|d| d == "all") => {
                DetectorSelection::Include(include.into_iter().collect())
            }
            (_, Some(exclude)) => {
                DetectorSelection::Exclude(exclude.into_iter().collect())
            }
            _ => DetectorSelection::All,
        };

        let min_severity = match scarb.severity_threshold.as_deref() {
            Some("high") => Severity::High,
            Some("medium") => Severity::Medium,
            Some("low") | None => Severity::Low,
            Some("info") => Severity::Info,
            Some(other) => {
                return Err(AnalyzerError::Config(format!(
                    "Unknown severity threshold '{other}'"
                )))
            }
        };

        let suppressions = scarb
            .suppress
            .unwrap_or_default()
            .into_iter()
            .map(|s| Suppression {
                detector_id: s.id,
                location_hash: s.location_hash,
            })
            .collect();

        Ok(Self {
            detectors,
            min_severity,
            fail_on_new_only: false,
            baseline_path: scarb.baseline.map(PathBuf::from),
            suppressions,
            strict: scarb.strict.unwrap_or(false),
        })
    }
}
