use std::io::Write;

use owo_colors::OwoColorize;
use tracing::debug;

use crate::detectors::{Finding, Severity};
use crate::error::AnalyzerWarning;
use crate::SourceCompatibility;

/// Print a human-readable report to the given writer.
pub fn print_report<W: Write>(
    writer: &mut W,
    findings: &[Finding],
    warnings: &[AnalyzerWarning],
    compatibility: &[SourceCompatibility],
    source: &str,
) -> std::io::Result<()> {
    debug!(
        findings = findings.len(),
        warnings = warnings.len(),
        "Rendering human report"
    );
    // Header
    writeln!(writer, "\n{} — {source}\n", "shadowhare".bold())?;
    writeln!(writer, "{}", "─".repeat(60).dimmed())?;

    if findings.is_empty() {
        writeln!(writer, "  No findings.")?;
    } else {
        for finding in findings {
            print_finding(writer, finding)?;
        }
    }

    writeln!(writer, "{}", "─".repeat(60).dimmed())?;

    // Summary
    let counts = finding_counts(findings);
    writeln!(
        writer,
        "  {}: {} critical, {} high, {} medium, {} low, {} info",
        "Summary".bold(),
        if counts.critical > 0 {
            format!("{}", counts.critical.red().bold())
        } else {
            format!("{}", counts.critical)
        },
        if counts.high > 0 {
            format!("{}", counts.high.red())
        } else {
            format!("{}", counts.high)
        },
        if counts.medium > 0 {
            format!("{}", counts.medium.yellow())
        } else {
            format!("{}", counts.medium)
        },
        if counts.low > 0 {
            format!("{}", counts.low.cyan())
        } else {
            format!("{}", counts.low)
        },
        counts.info.dimmed()
    )?;

    if !compatibility.is_empty() {
        writeln!(writer, "\n  Compatibility:")?;
        for c in compatibility {
            if let Some(reason) = &c.degraded_reason {
                writeln!(
                    writer,
                    "    - {}: tier={} source={} (degraded: {})",
                    c.source, c.compatibility_tier, c.metadata_source, reason
                )?;
            } else {
                writeln!(
                    writer,
                    "    - {}: tier={} source={}",
                    c.source, c.compatibility_tier, c.metadata_source
                )?;
            }
        }
    }

    // Warnings
    if !warnings.is_empty() {
        writeln!(writer, "\n  Warnings:")?;
        for w in warnings {
            writeln!(writer, "    ⚠  {}", w.message)?;
        }
    }

    writeln!(writer)?;
    Ok(())
}

fn print_finding<W: Write>(writer: &mut W, f: &Finding) -> std::io::Result<()> {
    let icon = severity_icon_colored(f.severity);
    writeln!(writer, "\n{icon} {title}", title = f.title)?;
    writeln!(writer, "   Detector:   {}", f.detector_id)?;
    writeln!(writer, "   Confidence: {}", f.confidence)?;
    writeln!(writer, "   Function:   {}", f.location.function)?;
    writeln!(writer, "   File:       {}", f.location.file)?;
    if let Some(idx) = f.location.statement_idx {
        writeln!(writer, "   Sierra stmt: {idx}")?;
    }
    if let Some(line) = f.location.line {
        writeln!(
            writer,
            "   Source:     line {line}{}",
            f.location.col.map(|c| format!(":{c}")).unwrap_or_default()
        )?;
    }
    writeln!(writer, "\n   {}", f.description)?;
    if let Some(fp) = &f.fingerprint {
        writeln!(writer, "\n   Fingerprint: {fp}")?;
    }
    Ok(())
}

fn severity_icon_colored(s: Severity) -> String {
    match s {
        Severity::Critical => format!("{}", "[CRITICAL]".red().bold()),
        Severity::High => format!("{}", "[HIGH]    ".red()),
        Severity::Medium => format!("{}", "[MEDIUM]  ".yellow()),
        Severity::Low => format!("{}", "[LOW]     ".cyan()),
        Severity::Info => format!("{}", "[INFO]    ".dimmed()),
    }
}

struct FindingCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

fn finding_counts(findings: &[Finding]) -> FindingCounts {
    FindingCounts {
        critical: findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count(),
        high: findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count(),
        medium: findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count(),
        low: findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count(),
        info: findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count(),
    }
}
