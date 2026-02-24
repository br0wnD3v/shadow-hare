pub mod analysis;
pub mod baseline;
pub mod config;
pub mod detectors;
pub mod diff;
pub mod error;
pub mod ir;
pub mod loader;
pub mod output;
pub mod printers;

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::baseline::Baseline;
use crate::config::{AnalyzerConfig, Suppression};
use crate::detectors::{DetectorRegistry, Finding};
use crate::error::{AnalyzerError, AnalyzerWarning, WarningKind};
use crate::ir::program::ProgramIR;
use crate::loader::{sierra_loader, CompatibilityMatrix, CompatibilityTier, VersionMetadataSource};
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
    pub compatibility: Vec<SourceCompatibility>,
    /// Findings that are NEW relative to the baseline (if baseline is in use).
    pub new_findings: Vec<Finding>,
}

#[derive(Debug, Clone)]
pub struct SourceCompatibility {
    pub source: String,
    pub compatibility_tier: CompatibilityTier,
    pub metadata_source: VersionMetadataSource,
    pub degraded_reason: Option<String>,
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
    let mut compatibility: Vec<SourceCompatibility> = Vec::new();

    for path in paths {
        let artifact = sierra_loader::load_artifact(path, &matrix)?;

        sources.push(path.display().to_string());
        compatibility.push(SourceCompatibility {
            source: path.display().to_string(),
            compatibility_tier: artifact.compatibility,
            metadata_source: artifact.version_metadata_source,
            degraded_reason: artifact.compatibility_degraded_reason.clone(),
        });

        // Collect loader warnings before artifact is consumed by from_artifact.
        let loader_warnings = artifact.warnings.clone();
        let program = ProgramIR::from_artifact(artifact);
        all_warnings.extend(loader_warnings);

        // Skip detectors only in explicit parse-only mode.
        if program.compatibility <= CompatibilityTier::ParseOnly {
            all_warnings.push(AnalyzerWarning {
                kind: crate::error::WarningKind::IncompatibleVersion,
                message: format!("{}: parse-only mode — detectors skipped", path.display()),
            });
            continue;
        }

        let (mut findings, warnings) = registry.run_all(&program, config);
        enrich_findings_with_source_locations(&mut findings, &program);
        all_findings.extend(findings);
        all_warnings.extend(warnings);

        let (mut plugin_findings, plugin_warnings) = run_external_plugins(path, config);
        enrich_findings_with_source_locations(&mut plugin_findings, &program);
        all_findings.extend(plugin_findings);
        all_warnings.extend(plugin_warnings);
    }

    if config.strict {
        let strict_issues: Vec<String> = all_warnings
            .iter()
            .filter(|w| is_strict_blocking_warning(w))
            .map(|w| w.message.clone())
            .collect();
        if !strict_issues.is_empty() {
            return Err(AnalyzerError::Config(format!(
                "Strict mode blocked analysis due to degraded guarantees:\n- {}",
                strict_issues.join("\n- ")
            )));
        }
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
        compatibility,
        new_findings,
    })
}

fn is_strict_blocking_warning(warning: &AnalyzerWarning) -> bool {
    match warning.kind {
        WarningKind::UnknownType | WarningKind::UnknownLibfunc | WarningKind::MissingDebugInfo => {
            true
        }
        // Any compatibility downgrade is considered degraded guarantees in strict mode.
        WarningKind::IncompatibleVersion => true,
        WarningKind::DetectorSkipped => false,
    }
}

fn enrich_findings_with_source_locations(findings: &mut [Finding], program: &ProgramIR) {
    for finding in findings {
        if let Some(stmt_idx) = finding.location.statement_idx {
            if let Some(source_loc) = program.source_location_for_stmt(stmt_idx) {
                if finding.location.line.is_none() {
                    finding.location.line = Some(source_loc.line);
                }
                if finding.location.col.is_none() {
                    finding.location.col = Some(source_loc.col);
                }
            }
        }
    }
}

fn run_external_plugins(
    path: &Path,
    config: &AnalyzerConfig,
) -> (Vec<Finding>, Vec<AnalyzerWarning>) {
    if config.plugin_commands.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut findings = Vec::new();
    let mut warnings = Vec::new();

    for plugin_cmd in &config.plugin_commands {
        let output = Command::new(plugin_cmd).arg(path).output();
        let output = match output {
            Ok(out) => out,
            Err(err) => {
                warnings.push(AnalyzerWarning::detector_skipped(
                    plugin_cmd,
                    &format!("plugin execution failed: {err}"),
                ));
                continue;
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warnings.push(AnalyzerWarning::detector_skipped(
                plugin_cmd,
                &format!(
                    "plugin exited with status {}: {}",
                    output.status,
                    stderr.trim()
                ),
            ));
            continue;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        match parse_plugin_findings(&stdout) {
            Ok(mut plugin_findings) => {
                plugin_findings.retain(|f| !is_suppressed(f, &config.suppressions));
                plugin_findings.retain(|f| f.severity >= config.min_severity);
                findings.extend(plugin_findings);
            }
            Err(err) => {
                warnings.push(AnalyzerWarning::detector_skipped(
                    plugin_cmd,
                    &format!("invalid plugin JSON output: {err}"),
                ));
            }
        }
    }

    (findings, warnings)
}

fn parse_plugin_findings(stdout: &str) -> Result<Vec<Finding>, String> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let value: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|e| format!("JSON parse error: {e}"))?;

    if value.is_array() {
        return serde_json::from_value(value).map_err(|e| format!("findings parse error: {e}"));
    }

    if let Some(findings_value) = value.get("findings") {
        return serde_json::from_value(findings_value.clone())
            .map_err(|e| format!("findings parse error: {e}"));
    }

    Err("expected JSON array or object with findings[]".to_string())
}

fn is_suppressed(finding: &Finding, suppressions: &[Suppression]) -> bool {
    suppressions.iter().any(|s| {
        s.detector_id == finding.detector_id
            && match &s.location_hash {
                None => true,
                Some(h) => finding.fingerprint.as_deref() == Some(h.as_str()),
            }
    })
}

/// Update the baseline file with the current set of findings.
pub fn update_baseline(baseline_path: &Path, findings: &[Finding]) -> Result<(), AnalyzerError> {
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
                &result.compatibility,
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
                result.compatibility.clone(),
            );
            report
                .to_json_string()
                .map_err(|e| AnalyzerError::Config(format!("JSON serialisation failed: {e}")))
        }
        OutputFormat::Sarif => {
            let sarif = build_sarif(&result.findings, &result.sources);
            serde_json::to_string_pretty(&sarif)
                .map_err(|e| AnalyzerError::Config(format!("SARIF serialisation failed: {e}")))
        }
    }
}
