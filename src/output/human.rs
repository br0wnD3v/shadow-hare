use std::io::Write;

use crate::detectors::{Finding, Severity};
use crate::error::AnalyzerWarning;

/// Print a human-readable report to the given writer.
pub fn print_report<W: Write>(
    writer: &mut W,
    findings: &[Finding],
    warnings: &[AnalyzerWarning],
    source: &str,
) -> std::io::Result<()> {
    // Header
    writeln!(writer, "\nshadowhare — {source}\n")?;
    writeln!(writer, "{}", "─".repeat(60))?;

    if findings.is_empty() {
        writeln!(writer, "  No findings.")?;
    } else {
        for finding in findings {
            print_finding(writer, finding)?;
        }
    }

    writeln!(writer, "{}", "─".repeat(60))?;

    // Summary
    let counts = finding_counts(findings);
    writeln!(
        writer,
        "  Summary: {} critical, {} high, {} medium, {} low, {} info",
        counts.critical, counts.high, counts.medium, counts.low, counts.info
    )?;

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
    let icon = severity_icon(f.severity);
    writeln!(writer, "\n{icon} [{severity}] {title}", severity = f.severity, title = f.title)?;
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

fn severity_icon(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "[CRITICAL]",
        Severity::High => "[HIGH]    ",
        Severity::Medium => "[MEDIUM]  ",
        Severity::Low => "[LOW]     ",
        Severity::Info => "[INFO]    ",
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
        critical: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
        high: findings.iter().filter(|f| f.severity == Severity::High).count(),
        medium: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
        low: findings.iter().filter(|f| f.severity == Severity::Low).count(),
        info: findings.iter().filter(|f| f.severity == Severity::Info).count(),
    }
}
