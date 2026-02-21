use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error("IO error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON parse error in {path}: {source}")]
    JsonParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("Unsupported Sierra version {version}: {reason}")]
    UnsupportedVersion { version: String, reason: String },

    #[error("Unknown Sierra type id {id} — skipping detector")]
    UnknownType { id: String },

    #[error("Unknown libfunc id {id} — skipping analysis")]
    UnknownLibfunc { id: String },

    #[error("Config error: {0}")]
    Config(String),

    #[error("Baseline error: {0}")]
    Baseline(String),

    #[error("SARIF schema validation failed: {0}")]
    SarifValidation(String),
}

/// A non-fatal warning that doesn't stop analysis but should be surfaced.
#[derive(Debug, Clone)]
pub struct AnalyzerWarning {
    pub kind: WarningKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarningKind {
    UnknownType,
    UnknownLibfunc,
    MissingDebugInfo,
    IncompatibleVersion,
    DetectorSkipped,
}

impl AnalyzerWarning {
    pub fn unknown_type(id: &str) -> Self {
        Self {
            kind: WarningKind::UnknownType,
            message: format!("Unknown Sierra type '{id}' — type-dependent detectors may skip"),
        }
    }

    pub fn unknown_libfunc(id: &str) -> Self {
        Self {
            kind: WarningKind::UnknownLibfunc,
            message: format!("Unknown libfunc '{id}' — call-graph analysis may be incomplete"),
        }
    }

    pub fn missing_debug_info(detector: &str) -> Self {
        Self {
            kind: WarningKind::MissingDebugInfo,
            message: format!(
                "Detector '{detector}' requires cairo-annotations debug info — skipped"
            ),
        }
    }

    pub fn detector_skipped(detector: &str, reason: &str) -> Self {
        Self {
            kind: WarningKind::DetectorSkipped,
            message: format!("Detector '{detector}' skipped: {reason}"),
        }
    }
}
