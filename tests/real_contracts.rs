/// Regression tests against real-world production contracts.
///
/// These tests validate that Shadowhare:
///   1. Does not panic on any real contract
///   2. Loads and analyses all contracts within reasonable time
///   3. Produces sensible finding counts (no false-positive explosions)
///   4. Handles both raw Sierra and contract_class.json formats
///
/// Contracts under test:
///   - 28 Cairo compiler test data contracts (starkware-libs/cairo)
///   - 6 Argent production contracts (accounts + multisig)
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use shadowhare::config::AnalyzerConfig;
use shadowhare::detectors::{DetectorRegistry, Severity};
use shadowhare::ir::program::ProgramIR;
use shadowhare::loader::{sierra_loader, CompatibilityMatrix};

fn target_contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target_contracts")
}

fn load_program(path: &Path) -> ProgramIR {
    let matrix = CompatibilityMatrix::default();
    let artifact = sierra_loader::load_artifact(path, &matrix)
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
    ProgramIR::from_artifact(artifact)
}

fn collect_contract_class_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "json")
            {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// Contracts that are compiler test harnesses, not production code.
/// These contain deliberately unsafe patterns for testing.
fn is_test_contract(name: &str) -> bool {
    name.contains("test_contract")
        || name.contains("libfuncs_coverage")
        || name.contains("circuit_contract")
}

// ── Cairo compiler testdata ─────────────────────────────────────────────────

#[test]
fn testdata_contracts_no_panics() {
    let dir = target_contracts_dir().join("cairo-compiler-testdata");
    let files = collect_contract_class_files(&dir);
    assert!(
        files.len() >= 20,
        "Expected at least 20 testdata contracts, found {}",
        files.len()
    );

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig {
        min_severity: Severity::Info,
        ..AnalyzerConfig::default()
    };

    let mut total_findings = 0;
    let mut per_contract: BTreeMap<String, usize> = BTreeMap::new();

    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let program = load_program(path);
        let (findings, _warnings) = registry.run_all(&program, &config);
        per_contract.insert(name, findings.len());
        total_findings += findings.len();
    }

    eprintln!("\n=== Cairo testdata contracts (all severities) ===");
    for (name, count) in &per_contract {
        eprintln!("  {name}: {count} findings");
    }
    eprintln!(
        "  TOTAL: {total_findings} findings across {} contracts",
        files.len()
    );
    eprintln!("==================================================\n");

    // No single contract should produce a ridiculous number of findings.
    // Test/coverage contracts get a higher threshold.
    for (name, count) in &per_contract {
        let limit = if is_test_contract(name) { 200 } else { 80 };
        assert!(
            *count < limit,
            "Contract {name} produced {count} findings (limit {limit}) — likely FP explosion"
        );
    }
}

#[test]
fn testdata_contracts_medium_plus_bounded() {
    let dir = target_contracts_dir().join("cairo-compiler-testdata");
    let files = collect_contract_class_files(&dir);

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default(); // Medium+

    let mut per_contract: BTreeMap<String, usize> = BTreeMap::new();

    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let program = load_program(path);
        let (findings, _) = registry.run_all(&program, &config);
        per_contract.insert(name, findings.len());
    }

    eprintln!("\n=== Cairo testdata contracts (Medium+) ===");
    for (name, count) in &per_contract {
        eprintln!("  {name}: {count} findings");
    }
    eprintln!("============================================\n");

    // At Medium+ severity, well-written contracts should have very few findings.
    for (name, count) in &per_contract {
        if is_test_contract(name) {
            continue;
        }
        assert!(
            *count <= 15,
            "Contract {name} has {count} Medium+ findings — investigate FPs"
        );
    }
}

#[test]
fn testdata_contracts_high_findings_are_bounded() {
    let dir = target_contracts_dir().join("cairo-compiler-testdata");
    let files = collect_contract_class_files(&dir);

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();

    let mut high_details: Vec<String> = Vec::new();

    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        // Skip known test/coverage contracts.
        if is_test_contract(&name) {
            continue;
        }
        let program = load_program(path);
        let (findings, _) = registry.run_all(&program, &config);

        for h in findings.iter().filter(|f| f.severity >= Severity::High) {
            high_details.push(format!("  {name}: [{:?}] {}", h.severity, h.detector_id));
        }
    }

    eprintln!("\n=== HIGH+ findings on non-test testdata ===");
    if high_details.is_empty() {
        eprintln!("  None — all clean");
    } else {
        for d in &high_details {
            eprintln!("{d}");
        }
    }
    eprintln!("=============================================\n");

    // account_ contracts have known account-specific findings (missing v0 block, etc.)
    // token_bridge has known l1_handler findings.
    // These are expected: they are simplified demo contracts, not production.
    // But the count should still be bounded.
    assert!(
        high_details.len() <= 15,
        "Too many HIGH findings on non-test contracts ({}):\n{}",
        high_details.len(),
        high_details.join("\n")
    );
}

// ── Argent production contracts ─────────────────────────────────────────────

#[test]
fn argent_contracts_no_panics() {
    let dir = target_contracts_dir().join("argent");
    let files = collect_contract_class_files(&dir);
    assert!(
        files.len() >= 4,
        "Expected at least 4 Argent contracts, found {}",
        files.len()
    );

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig {
        min_severity: Severity::Info,
        ..AnalyzerConfig::default()
    };

    let mut per_contract: BTreeMap<String, usize> = BTreeMap::new();

    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let program = load_program(path);
        let (findings, _) = registry.run_all(&program, &config);
        per_contract.insert(name, findings.len());
    }

    eprintln!("\n=== Argent production contracts (all severities) ===");
    for (name, count) in &per_contract {
        eprintln!("  {name}: {count} findings");
    }
    eprintln!("======================================================\n");

    // Argent contracts are well-audited. With Info included, some informational
    // findings are expected (dead_code, costly_loop). But not hundreds.
    for (name, count) in &per_contract {
        assert!(
            *count < 100,
            "Argent contract {name} produced {count} findings — likely FP explosion"
        );
    }
}

#[test]
fn argent_contracts_zero_high_findings() {
    let dir = target_contracts_dir().join("argent");
    let files = collect_contract_class_files(&dir);

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();

    let mut high_findings: Vec<String> = Vec::new();

    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let program = load_program(path);
        let (findings, _) = registry.run_all(&program, &config);

        for f in &findings {
            if f.severity >= Severity::High {
                high_findings.push(format!(
                    "  {name}: [{:?}/{:?}] {} — {}",
                    f.severity, f.confidence, f.detector_id, f.title
                ));
            }
        }
    }

    // Argent contracts are professionally audited — any HIGH finding is
    // almost certainly a false positive in our tool.
    assert!(
        high_findings.is_empty(),
        "Argent production contracts should have ZERO HIGH findings (FP indicator):\n{}",
        high_findings.join("\n")
    );
}

// ── Performance regression ──────────────────────────────────────────────────

#[test]
fn analysis_completes_within_timeout() {
    let testdata_dir = target_contracts_dir().join("cairo-compiler-testdata");
    let argent_dir = target_contracts_dir().join("argent");

    let mut all_files = collect_contract_class_files(&testdata_dir);
    all_files.extend(collect_contract_class_files(&argent_dir));

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();

    let start = Instant::now();

    for path in &all_files {
        let program = load_program(path);
        let _results = registry.run_all(&program, &config);
    }

    let elapsed = start.elapsed();
    eprintln!(
        "\n=== Performance: {} contracts in {:.2}s ({:.0}ms/contract) ===\n",
        all_files.len(),
        elapsed.as_secs_f64(),
        elapsed.as_millis() as f64 / all_files.len() as f64
    );

    // 60s is generous — should normally complete in <10s.
    assert!(
        elapsed.as_secs() < 60,
        "Analysis took {elapsed:?} — performance regression"
    );
}

// ── Per-detector FP rate tracking ───────────────────────────────────────────

#[test]
fn detector_fp_report_on_real_contracts() {
    let testdata_dir = target_contracts_dir().join("cairo-compiler-testdata");
    let argent_dir = target_contracts_dir().join("argent");

    let mut all_files = collect_contract_class_files(&testdata_dir);
    all_files.extend(collect_contract_class_files(&argent_dir));

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig {
        min_severity: Severity::Info,
        ..AnalyzerConfig::default()
    };

    let mut detector_hits: BTreeMap<String, usize> = BTreeMap::new();
    let mut detector_contracts: BTreeMap<String, usize> = BTreeMap::new();

    for det in registry.iter() {
        detector_hits.insert(det.id().to_string(), 0);
        detector_contracts.insert(det.id().to_string(), 0);
    }

    for path in &all_files {
        let program = load_program(path);
        let (findings, _) = registry.run_all(&program, &config);

        let mut seen_detectors = std::collections::HashSet::new();
        for f in &findings {
            *detector_hits.entry(f.detector_id.clone()).or_insert(0) += 1;
            if seen_detectors.insert(f.detector_id.clone()) {
                *detector_contracts.entry(f.detector_id.clone()).or_insert(0) += 1;
            }
        }
    }

    let total = all_files.len();
    eprintln!("\n=== Detector Activity on {total} Real Contracts ===");
    eprintln!("{:<40} {:>6} {:>10}", "Detector", "Hits", "Contracts");
    eprintln!("{}", "-".repeat(60));

    for (det_id, hits) in &detector_hits {
        let contracts = detector_contracts.get(det_id).copied().unwrap_or(0);
        let marker = if *hits > 0 { "!" } else { " " };
        eprintln!("{marker} {det_id:<39} {hits:>6} {contracts:>6}/{total}");
    }
    eprintln!("=============================================\n");

    // Any detector firing on >60% of real contracts is suspicious (likely FP).
    let threshold = (total as f64 * 0.6) as usize;
    let noisy: Vec<_> = detector_contracts
        .iter()
        .filter(|(_, &count)| count > threshold)
        .collect();

    assert!(
        noisy.is_empty(),
        "Noisy detectors (>60% hit rate) indicate FP problems:\n{}",
        noisy
            .iter()
            .map(|(id, count)| format!("  {id}: fires on {count}/{total} contracts"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
