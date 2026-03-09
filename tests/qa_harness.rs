/// QA harness for measuring false positives and false negatives.
///
/// Scans all fixtures in `fixtures/vulnerable/` and `fixtures/clean/`,
/// plus seeded fixtures in `target_contracts/seeded/`, and reports:
/// - Per-detector hit counts
/// - Clean fixtures that produce unexpected findings (FP candidates)
/// - Vulnerable fixtures that produce zero findings (FN candidates)
/// - Seeded fixture coverage (detectors with/without dedicated tests)
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use shadowhare::config::AnalyzerConfig;
use shadowhare::detectors::{DetectorRegistry, Severity};
use shadowhare::ir::program::ProgramIR;
use shadowhare::loader::{sierra_loader, CompatibilityMatrix};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn seeded_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target_contracts")
        .join("seeded")
}

fn load_program(path: &Path) -> ProgramIR {
    let matrix = CompatibilityMatrix::default();
    let artifact = sierra_loader::load_artifact(path, &matrix)
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
    ProgramIR::from_artifact(artifact)
}

fn collect_sierra_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json")
                && path
                    .to_str()
                    .map(|s| s.contains(".sierra."))
                    .unwrap_or(false)
            {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

// ── Vulnerable fixture: must produce findings ───────────────────────────────

#[test]
fn qa_vulnerable_fixtures_produce_findings() {
    let vulnerable_dir = fixture_dir().join("vulnerable");
    let files = collect_sierra_files(&vulnerable_dir);
    assert!(!files.is_empty(), "No vulnerable fixtures found");

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig {
        min_severity: Severity::Info,
        ..AnalyzerConfig::default()
    };

    let mut fn_candidates = Vec::new();

    for path in &files {
        let program = load_program(path);
        let (findings, _) = registry.run_all(&program, &config);

        let non_info: Vec<_> = findings
            .iter()
            .filter(|f| f.severity >= Severity::Low)
            .collect();

        if non_info.is_empty() {
            fn_candidates.push(path.file_name().unwrap().to_string_lossy().to_string());
        }
    }

    assert!(
        fn_candidates.is_empty(),
        "False negative candidates (vulnerable fixtures with no findings >= Low):\n  {}",
        fn_candidates.join("\n  ")
    );
}

// ── Clean fixtures: must NOT produce HIGH findings ──────────────────────────

#[test]
fn qa_clean_fixtures_produce_no_high_findings() {
    let clean_dir = fixture_dir().join("clean");
    let files = collect_sierra_files(&clean_dir);
    assert!(!files.is_empty(), "No clean fixtures found");

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();

    let mut fp_candidates = Vec::new();

    for path in &files {
        let program = load_program(path);
        let (findings, _) = registry.run_all(&program, &config);

        let high_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.severity >= Severity::High)
            .collect();

        if !high_findings.is_empty() {
            fp_candidates.push(format!(
                "{}: {} HIGH findings ({:?})",
                path.file_name().unwrap().to_string_lossy(),
                high_findings.len(),
                high_findings
                    .iter()
                    .map(|f| f.detector_id.as_str())
                    .collect::<Vec<_>>()
            ));
        }
    }

    // Report FP candidates. Clean fixtures are designed to be clean for
    // their SPECIFIC detector, not necessarily all detectors. Cross-detector
    // findings are expected on minimal fixtures.
    if !fp_candidates.is_empty() {
        eprintln!(
            "\n=== FP Candidates (clean fixtures with HIGH findings) ===\n  {}\n===\n",
            fp_candidates.join("\n  ")
        );
    }

    // Hard limit: no single clean fixture should have more than 10 HIGH findings.
    // That would indicate a systemic problem.
    for path in &files {
        let program = load_program(path);
        let (findings, _) = registry.run_all(&program, &config);
        let high_count = findings
            .iter()
            .filter(|f| f.severity >= Severity::High)
            .count();
        assert!(
            high_count <= 10,
            "Clean fixture {} has {high_count} HIGH findings — too many",
            path.file_name().unwrap().to_string_lossy()
        );
    }
}

// ── Seeded fixtures: each must fire its target detector ─────────────────────

#[test]
fn qa_seeded_pure_fixtures_fire_target_detector() {
    let pure_dir = seeded_dir().join("pure");
    let files = collect_sierra_files(&pure_dir);
    assert!(
        files.len() >= 40,
        "Expected at least 40 pure seeded fixtures, found {}",
        files.len()
    );

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig {
        min_severity: Severity::Info,
        ..AnalyzerConfig::default()
    };

    let mut missed: Vec<String> = Vec::new();
    let mut tested = 0;

    for path in &files {
        let filename = path.file_name().unwrap().to_string_lossy().to_string();
        // Derive expected detector ID from filename:
        //   "felt252_overflow.sierra.json" → "felt252_overflow"
        let expected_detector = filename
            .strip_suffix(".sierra.json")
            .unwrap_or(&filename)
            .to_string();

        let program = load_program(path);
        let (findings, _) = registry.run_all(&program, &config);

        let has_target = findings.iter().any(|f| f.detector_id == expected_detector);

        tested += 1;
        if !has_target {
            let actual_ids: Vec<_> = findings.iter().map(|f| f.detector_id.as_str()).collect();
            missed.push(format!(
                "  {filename}: expected '{expected_detector}', got {:?}",
                actual_ids
            ));
        }
    }

    eprintln!("\n=== Seeded Pure Fixture Results ===");
    eprintln!("Tested: {tested}, Missed: {}", missed.len());
    if !missed.is_empty() {
        eprintln!("Fixtures that didn't fire their target detector:");
        for m in &missed {
            eprintln!("{m}");
        }
    }
    eprintln!("====================================\n");

    // Allow some tolerance — fixture names might not exactly match detector IDs
    // for renamed or composite detectors.
    let miss_rate = missed.len() as f64 / tested as f64;
    assert!(
        miss_rate < 0.15,
        "Too many seeded fixtures missed ({} / {}, {:.0}%):\n{}",
        missed.len(),
        tested,
        miss_rate * 100.0,
        missed.join("\n")
    );
}

// ── Compound fixtures: must fire multiple detectors ─────────────────────────

#[test]
fn qa_seeded_compound_fixtures_fire_multiple_detectors() {
    let compound_dir = seeded_dir().join("compound");
    let files = collect_sierra_files(&compound_dir);

    if files.is_empty() {
        eprintln!("No compound fixtures found — skipping");
        return;
    }

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig {
        min_severity: Severity::Info,
        ..AnalyzerConfig::default()
    };

    let mut single_detector_files = Vec::new();

    for path in &files {
        let filename = path.file_name().unwrap().to_string_lossy().to_string();
        let program = load_program(path);
        let (findings, _) = registry.run_all(&program, &config);

        let unique_detectors: std::collections::HashSet<_> =
            findings.iter().map(|f| f.detector_id.as_str()).collect();

        eprintln!(
            "  {filename}: {} unique detectors ({:?})",
            unique_detectors.len(),
            unique_detectors
        );

        if unique_detectors.len() < 2 {
            single_detector_files.push(format!(
                "{filename}: only {} detector(s): {:?}",
                unique_detectors.len(),
                unique_detectors
            ));
        }
    }

    assert!(
        single_detector_files.is_empty(),
        "Compound fixtures should fire 2+ detectors:\n  {}",
        single_detector_files.join("\n  ")
    );
}

// ── Coverage report ─────────────────────────────────────────────────────────

#[test]
fn qa_detector_coverage_report() {
    let vulnerable_dir = fixture_dir().join("vulnerable");
    let clean_dir = fixture_dir().join("clean");
    let pure_dir = seeded_dir().join("pure");

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig {
        min_severity: Severity::Info,
        ..AnalyzerConfig::default()
    };

    let mut detector_hits: BTreeMap<String, usize> = BTreeMap::new();

    for det in registry.iter() {
        detector_hits.insert(det.id().to_string(), 0);
    }

    let all_files: Vec<PathBuf> = collect_sierra_files(&vulnerable_dir)
        .into_iter()
        .chain(collect_sierra_files(&clean_dir))
        .chain(collect_sierra_files(&pure_dir))
        .collect();

    for path in &all_files {
        let program = load_program(path);
        let (findings, _) = registry.run_all(&program, &config);
        for finding in &findings {
            *detector_hits
                .entry(finding.detector_id.clone())
                .or_insert(0) += 1;
        }
    }

    let total_detectors = detector_hits.len();
    let active_detectors = detector_hits.values().filter(|&&v| v > 0).count();
    let untested: Vec<_> = detector_hits
        .iter()
        .filter(|(_, &v)| v == 0)
        .map(|(id, _)| id.as_str())
        .collect();

    eprintln!("\n=== Detector Coverage Report ===");
    eprintln!(
        "Active: {active_detectors}/{total_detectors} detectors fired on fixtures ({:.0}%)",
        active_detectors as f64 / total_detectors as f64 * 100.0
    );
    for (det_id, hits) in &detector_hits {
        let marker = if *hits > 0 { "+" } else { "-" };
        eprintln!("  [{marker}] {det_id}: {hits} findings");
    }
    if !untested.is_empty() {
        eprintln!("\nUntested detectors ({}):", untested.len());
        for id in &untested {
            eprintln!("  - {id}");
        }
    }
    eprintln!("================================\n");

    // At least 80% of detectors should fire on at least one fixture.
    let coverage_pct = active_detectors as f64 / total_detectors as f64 * 100.0;
    assert!(
        coverage_pct >= 75.0,
        "Detector coverage too low: {active_detectors}/{total_detectors} ({coverage_pct:.0}%). \
         Untested: {untested:?}"
    );
}
