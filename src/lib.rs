pub mod analysis;
pub mod baseline;
pub mod config;
pub mod detectors;
pub mod error;
pub mod ir;
pub mod loader;
pub mod output;

use std::path::{Path, PathBuf};

use crate::baseline::Baseline;
use crate::config::AnalyzerConfig;
use crate::detectors::{DetectorRegistry, Finding};
use crate::error::{AnalyzerError, AnalyzerWarning};
use crate::ir::program::ProgramIR;
use crate::loader::{sierra_loader, CompatibilityMatrix};
use crate::output::{build_sarif, JsonReport};

/// Output format for analysis results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

/// Result of analysing one or more Sierra artifacts.
#[derive(Debug)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub warnings: Vec<AnalyzerWarning>,
    pub sources: Vec<String>,
    /// Findings that are NEW relative to the baseline (if baseline is in use).
    pub new_findings: Vec<Finding>,
}

impl AnalysisResult {
    /// Exit code following the convention:
    ///   0 = no actionable findings
    ///   1 = findings at/above threshold
    ///   2 = execution error
    pub fn exit_code(&self, fail_on_new_only: bool) -> i32 {
        let relevant = if fail_on_new_only {
            &self.new_findings
        } else {
            &self.findings
        };

        if relevant.is_empty() {
            0
        } else {
            1
        }
    }
}

/// Top-level analysis entry point.
pub fn analyse_paths(
    paths: &[PathBuf],
    config: &AnalyzerConfig,
    registry: &DetectorRegistry,
) -> Result<AnalysisResult, AnalyzerError> {
    let matrix = CompatibilityMatrix::default();

    let mut all_findings: Vec<Finding> = Vec::new();
    let mut all_warnings: Vec<AnalyzerWarning> = Vec::new();
    let mut sources: Vec<String> = Vec::new();

    for path in paths {
        let artifact =
            sierra_loader::load_artifact(path, &matrix)?;

        sources.push(path.display().to_string());

        // Collect loader warnings before artifact is consumed by from_artifact.
        let loader_warnings = artifact.warnings.clone();
        let program = ProgramIR::from_artifact(artifact);
        all_warnings.extend(loader_warnings);

        // Skip detectors if compatibility is below Tier3 parse-only
        use crate::loader::CompatibilityTier;
        if program.compatibility <= CompatibilityTier::ParseOnly {
            all_warnings.push(AnalyzerWarning {
                kind: crate::error::WarningKind::IncompatibleVersion,
                message: format!(
                    "{}: parse-only mode — detectors skipped",
                    path.display()
                ),
            });
            continue;
        }

        let (findings, warnings) = registry.run_all(&program, config);
        all_findings.extend(findings);
        all_warnings.extend(warnings);
    }

    // Baseline comparison
    let baseline = if let Some(bp) = &config.baseline_path {
        Some(Baseline::load(bp)?)
    } else {
        None
    };

    let new_findings = if let Some(ref bl) = baseline {
        all_findings
            .iter()
            .filter(|f| bl.is_new(f))
            .cloned()
            .collect()
    } else {
        all_findings.clone()
    };

    Ok(AnalysisResult {
        findings: all_findings,
        warnings: all_warnings,
        sources,
        new_findings,
    })
}

/// Update the baseline file with the current set of findings.
pub fn update_baseline(
    baseline_path: &Path,
    findings: &[Finding],
) -> Result<(), AnalyzerError> {
    let mut baseline = Baseline::load(baseline_path)?;
    baseline.update_from_findings(findings);
    baseline.save(baseline_path)
}

/// Render analysis results in the requested format.
pub fn render_output(
    result: &AnalysisResult,
    format: OutputFormat,
) -> Result<String, AnalyzerError> {
    match format {
        OutputFormat::Human => {
            let mut buf = Vec::new();
            let source = result.sources.join(", ");
            output::human::print_report(
                &mut buf,
                &result.findings,
                &result.warnings,
                &source,
            )
            .map_err(|e| AnalyzerError::Io {
                path: PathBuf::from("<stdout>"),
                source: e,
            })?;
            Ok(String::from_utf8_lossy(&buf).into_owned())
        }
        OutputFormat::Json => {
            let report = JsonReport::build(
                &result.findings,
                &result.warnings,
                result.sources.clone(),
            );
            report.to_json_string().map_err(|e| {
                AnalyzerError::Config(format!("JSON serialisation failed: {e}"))
            })
        }
        OutputFormat::Sarif => {
            let sarif = build_sarif(&result.findings, &result.sources);
            serde_json::to_string_pretty(&sarif)
                .map_err(|e| AnalyzerError::Config(format!("SARIF serialisation failed: {e}")))
        }
    }
}
