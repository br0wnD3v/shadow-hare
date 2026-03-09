use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::detectors::Finding;
use crate::error::AnalyzerError;

/// Persisted baseline — the known set of findings at a point in time.
/// CI fails only on findings whose fingerprint is NOT in the baseline.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub schema_version: String,
    /// Set of finding fingerprints recorded at baseline time.
    pub fingerprints: HashSet<String>,
}

impl Baseline {
    pub fn load(path: &Path) -> Result<Self, AnalyzerError> {
        if !path.exists() {
            return Ok(Self::default_with_version());
        }

        let content = std::fs::read_to_string(path).map_err(|e| AnalyzerError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        let baseline: Self = serde_json::from_str(&content)
            .map_err(|e| AnalyzerError::Baseline(format!("Failed to parse baseline: {e}")))?;
        debug!(entries = baseline.fingerprints.len(), path = %path.display(), "Baseline loaded");
        Ok(baseline)
    }

    pub fn save(&self, path: &Path) -> Result<(), AnalyzerError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| AnalyzerError::Baseline(e.to_string()))?;

        std::fs::write(path, json).map_err(|e| AnalyzerError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    }

    pub fn update_from_findings(&mut self, findings: &[Finding]) {
        self.fingerprints = findings
            .iter()
            .filter_map(|f| f.fingerprint.clone())
            .collect();
    }

    /// Returns only findings whose fingerprint is NOT in the baseline.
    pub fn new_findings<'a>(&self, findings: &'a [Finding]) -> Vec<&'a Finding> {
        let result: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.fingerprint
                    .as_ref()
                    .map(|fp| !self.fingerprints.contains(fp))
                    .unwrap_or(true)
            })
            .collect();
        debug!(
            new = result.len(),
            total = findings.len(),
            "Baseline comparison"
        );
        result
    }

    pub fn is_new(&self, finding: &Finding) -> bool {
        finding
            .fingerprint
            .as_ref()
            .map(|fp| !self.fingerprints.contains(fp))
            .unwrap_or(true)
    }

    fn default_with_version() -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            fingerprints: HashSet::new(),
        }
    }
}
