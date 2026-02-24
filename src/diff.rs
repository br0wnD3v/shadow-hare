use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::config::AnalyzerConfig;
use crate::detectors::{DetectorRegistry, Finding, Severity};
use crate::error::{AnalyzerError, AnalyzerWarning, WarningKind};
use crate::{analyse_paths, AnalysisResult};

const DIFF_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffOutputFormat {
    Human,
    Json,
}

#[derive(Debug)]
pub struct DiffResult {
    pub left: AnalysisResult,
    pub right: AnalysisResult,
    pub new_findings: Vec<Finding>,
    pub resolved_findings: Vec<Finding>,
    pub unchanged_fingerprints: Vec<String>,
}

impl DiffResult {
    pub fn exit_code(&self, fail_on_new_severity: Option<Severity>) -> i32 {
        match fail_on_new_severity {
            Some(min) => {
                if self.new_findings.iter().any(|f| f.severity >= min) {
                    1
                } else {
                    0
                }
            }
            None => {
                if self.new_findings.is_empty() {
                    0
                } else {
                    1
                }
            }
        }
    }
}

pub fn analyse_diff_paths(
    left_paths: &[std::path::PathBuf],
    right_paths: &[std::path::PathBuf],
    config: &AnalyzerConfig,
    registry: &DetectorRegistry,
) -> Result<DiffResult, AnalyzerError> {
    let left = analyse_paths(left_paths, config, registry)?;
    let right = analyse_paths(right_paths, config, registry)?;

    let left_map = keyed_findings(&left.findings);
    let right_map = keyed_findings(&right.findings);

    let mut new_findings = Vec::new();
    for (key, finding) in &right_map {
        if !left_map.contains_key(key) {
            new_findings.push(finding.clone());
        }
    }

    let mut resolved_findings = Vec::new();
    for (key, finding) in &left_map {
        if !right_map.contains_key(key) {
            resolved_findings.push(finding.clone());
        }
    }

    let left_keys: BTreeSet<String> = left_map.keys().cloned().collect();
    let right_keys: BTreeSet<String> = right_map.keys().cloned().collect();
    let unchanged_fingerprints = left_keys
        .intersection(&right_keys)
        .cloned()
        .collect::<Vec<_>>();

    Ok(DiffResult {
        left,
        right,
        new_findings,
        resolved_findings,
        unchanged_fingerprints,
    })
}

pub fn render_diff_output(
    result: &DiffResult,
    format: DiffOutputFormat,
) -> Result<String, AnalyzerError> {
    match format {
        DiffOutputFormat::Human => Ok(render_human(result)),
        DiffOutputFormat::Json => render_json(result),
    }
}

fn keyed_findings(findings: &[Finding]) -> BTreeMap<String, Finding> {
    let mut map = BTreeMap::new();
    for f in findings {
        let key = finding_key(f);
        map.entry(key).or_insert_with(|| f.clone());
    }
    map
}

fn finding_key(f: &Finding) -> String {
    if let Some(fp) = &f.fingerprint {
        return fp.clone();
    }

    format!(
        "{}:{}:{}:{}",
        f.detector_id,
        f.location.function,
        f.location.statement_idx.unwrap_or(0),
        f.location.file
    )
}

#[derive(Debug, Serialize)]
struct DiffJsonReport {
    schema_version: &'static str,
    left_sources: Vec<String>,
    right_sources: Vec<String>,
    summary: DiffSummary,
    new_findings: Vec<Finding>,
    resolved_findings: Vec<Finding>,
    unchanged_fingerprints: Vec<String>,
    left_warnings: Vec<String>,
    right_warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DiffSummary {
    new: usize,
    resolved: usize,
    unchanged: usize,
    new_by_severity: SeverityBreakdown,
    resolved_by_severity: SeverityBreakdown,
}

#[derive(Debug, Default, Serialize)]
struct SeverityBreakdown {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

fn render_json(result: &DiffResult) -> Result<String, AnalyzerError> {
    let report = DiffJsonReport {
        schema_version: DIFF_SCHEMA_VERSION,
        left_sources: result.left.sources.clone(),
        right_sources: result.right.sources.clone(),
        summary: build_summary(result),
        new_findings: result.new_findings.clone(),
        resolved_findings: result.resolved_findings.clone(),
        unchanged_fingerprints: result.unchanged_fingerprints.clone(),
        left_warnings: format_warnings(&result.left.warnings),
        right_warnings: format_warnings(&result.right.warnings),
    };

    serde_json::to_string_pretty(&report)
        .map_err(|e| AnalyzerError::Config(format!("JSON serialisation failed: {e}")))
}

fn render_human(result: &DiffResult) -> String {
    let summary = build_summary(result);

    let mut out = String::new();
    out.push_str("Shadowhare Diff Report\n\n");

    out.push_str("Left sources:\n");
    if result.left.sources.is_empty() {
        out.push_str("  - (none)\n");
    } else {
        for s in &result.left.sources {
            out.push_str(&format!("  - {s}\n"));
        }
    }

    out.push_str("Right sources:\n");
    if result.right.sources.is_empty() {
        out.push_str("  - (none)\n");
    } else {
        for s in &result.right.sources {
            out.push_str(&format!("  - {s}\n"));
        }
    }

    out.push('\n');
    out.push_str(&format!(
        "Summary: new={} resolved={} unchanged={}\n",
        summary.new, summary.resolved, summary.unchanged
    ));
    out.push_str(&format!(
        "  New by severity: critical={} high={} medium={} low={} info={}\n",
        summary.new_by_severity.critical,
        summary.new_by_severity.high,
        summary.new_by_severity.medium,
        summary.new_by_severity.low,
        summary.new_by_severity.info
    ));
    out.push_str(&format!(
        "  Resolved by severity: critical={} high={} medium={} low={} info={}\n",
        summary.resolved_by_severity.critical,
        summary.resolved_by_severity.high,
        summary.resolved_by_severity.medium,
        summary.resolved_by_severity.low,
        summary.resolved_by_severity.info
    ));

    out.push_str("\nNew findings:\n");
    if result.new_findings.is_empty() {
        out.push_str("  - (none)\n");
    } else {
        for f in &result.new_findings {
            out.push_str(&format!(
                "  - [{}] {} ({})\n",
                f.severity, f.detector_id, f.title
            ));
            out.push_str(&format!(
                "    at {} :: {} :: stmt {:?}\n",
                f.location.file, f.location.function, f.location.statement_idx
            ));
            out.push_str(&format!(
                "    fp={}\n",
                f.fingerprint.as_deref().unwrap_or("<none>")
            ));
        }
    }

    out.push_str("\nResolved findings:\n");
    if result.resolved_findings.is_empty() {
        out.push_str("  - (none)\n");
    } else {
        for f in &result.resolved_findings {
            out.push_str(&format!(
                "  - [{}] {} ({})\n",
                f.severity, f.detector_id, f.title
            ));
            out.push_str(&format!(
                "    at {} :: {} :: stmt {:?}\n",
                f.location.file, f.location.function, f.location.statement_idx
            ));
            out.push_str(&format!(
                "    fp={}\n",
                f.fingerprint.as_deref().unwrap_or("<none>")
            ));
        }
    }

    out.push_str("\nUnchanged fingerprints:\n");
    if result.unchanged_fingerprints.is_empty() {
        out.push_str("  - (none)\n");
    } else {
        for fp in &result.unchanged_fingerprints {
            out.push_str(&format!("  - {fp}\n"));
        }
    }

    if !result.left.warnings.is_empty() || !result.right.warnings.is_empty() {
        out.push_str("\nWarnings:\n");
        for w in format_warnings(&result.left.warnings) {
            out.push_str(&format!("  - left: {w}\n"));
        }
        for w in format_warnings(&result.right.warnings) {
            out.push_str(&format!("  - right: {w}\n"));
        }
    }

    out
}

fn build_summary(result: &DiffResult) -> DiffSummary {
    DiffSummary {
        new: result.new_findings.len(),
        resolved: result.resolved_findings.len(),
        unchanged: result.unchanged_fingerprints.len(),
        new_by_severity: severity_breakdown(&result.new_findings),
        resolved_by_severity: severity_breakdown(&result.resolved_findings),
    }
}

fn severity_breakdown(findings: &[Finding]) -> SeverityBreakdown {
    let mut counts = SeverityBreakdown::default();
    for f in findings {
        match f.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
    }
    counts
}

fn format_warnings(warnings: &[AnalyzerWarning]) -> Vec<String> {
    warnings
        .iter()
        .map(|w| {
            let kind = match w.kind {
                WarningKind::UnknownType => "unknown_type",
                WarningKind::UnknownLibfunc => "unknown_libfunc",
                WarningKind::MissingDebugInfo => "missing_debug_info",
                WarningKind::IncompatibleVersion => "incompatible_version",
                WarningKind::DetectorSkipped => "detector_skipped",
            };
            format!("{kind}: {}", w.message)
        })
        .collect()
}
