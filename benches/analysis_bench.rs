use criterion::{criterion_group, criterion_main, Criterion};
use std::path::PathBuf;

use shadowhare::config::AnalyzerConfig;
use shadowhare::detectors::DetectorRegistry;
use shadowhare::ir::program::ProgramIR;
use shadowhare::loader::{sierra_loader, CompatibilityMatrix};

fn load_fixture(name: &str) -> ProgramIR {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name);
    let matrix = CompatibilityMatrix::default();
    let artifact = sierra_loader::load_artifact(&path, &matrix).unwrap();
    ProgramIR::from_artifact(artifact)
}

fn bench_loader(c: &mut Criterion) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/vulnerable/reentrancy.sierra.json");
    let matrix = CompatibilityMatrix::default();

    c.bench_function("loader::load_artifact", |b| {
        b.iter(|| {
            sierra_loader::load_artifact(&path, &matrix).unwrap();
        });
    });
}

fn bench_ir_construction(c: &mut Criterion) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/vulnerable/reentrancy.sierra.json");
    let matrix = CompatibilityMatrix::default();
    let artifact = sierra_loader::load_artifact(&path, &matrix).unwrap();

    c.bench_function("ProgramIR::from_artifact", |b| {
        b.iter_with_setup(|| artifact.clone(), ProgramIR::from_artifact);
    });
}

fn bench_all_detectors(c: &mut Criterion) {
    let program = load_fixture("vulnerable/reentrancy.sierra.json");
    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();

    c.bench_function("detectors::run_all (reentrancy fixture)", |b| {
        b.iter(|| {
            registry.run_all(&program, &config);
        });
    });
}

fn bench_clean_fixture(c: &mut Criterion) {
    let program = load_fixture("clean/protected_upgrade_helper_owner_read.sierra.json");
    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();

    c.bench_function("detectors::run_all (clean upgrade fixture)", |b| {
        b.iter(|| {
            registry.run_all(&program, &config);
        });
    });
}

fn bench_cfg_construction(c: &mut Criterion) {
    use shadowhare::analysis::cfg::Cfg;

    let program = load_fixture("vulnerable/reentrancy.sierra.json");

    c.bench_function("Cfg::build (all functions)", |b| {
        b.iter(|| {
            for func in &program.functions {
                let (start, end) = program.function_statement_range(func.idx);
                if start < end {
                    let end = end.min(program.statements.len());
                    Cfg::build(&program.statements, start, end);
                }
            }
        });
    });
}

fn bench_callgraph(c: &mut Criterion) {
    use shadowhare::analysis::CallGraph;

    let program = load_fixture("vulnerable/reentrancy.sierra.json");

    c.bench_function("CallGraph::build", |b| {
        b.iter(|| {
            CallGraph::build(&program);
        });
    });
}

fn bench_full_pipeline(c: &mut Criterion) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/vulnerable/reentrancy.sierra.json");
    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();

    c.bench_function("full_pipeline (load + analyse)", |b| {
        b.iter(|| {
            let paths = vec![path.clone()];
            shadowhare::analyse_paths(&paths, &config, &registry).unwrap();
        });
    });
}

fn target_contracts_dir() -> std::path::PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target_contracts")
}

fn collect_json_files(dir: &std::path::Path) -> Vec<PathBuf> {
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

fn bench_real_contracts_pipeline(c: &mut Criterion) {
    let testdata_dir = target_contracts_dir().join("cairo-compiler-testdata");
    let argent_dir = target_contracts_dir().join("argent");

    let mut all_files = collect_json_files(&testdata_dir);
    all_files.extend(collect_json_files(&argent_dir));

    if all_files.is_empty() {
        eprintln!("No target contracts found — skipping real contract bench");
        return;
    }

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();
    let matrix = CompatibilityMatrix::default();

    c.bench_function(&format!("real_contracts_{}_files", all_files.len()), |b| {
        b.iter(|| {
            for path in &all_files {
                let artifact = sierra_loader::load_artifact(path, &matrix).unwrap();
                let program = ProgramIR::from_artifact(artifact);
                let _ = registry.run_all(&program, &config);
            }
        });
    });
}

fn bench_argent_detectors(c: &mut Criterion) {
    let argent_dir = target_contracts_dir().join("argent");
    let files = collect_json_files(&argent_dir);

    if files.is_empty() {
        return;
    }

    let matrix = CompatibilityMatrix::default();
    let programs: Vec<ProgramIR> = files
        .iter()
        .map(|p| {
            let artifact = sierra_loader::load_artifact(p, &matrix).unwrap();
            ProgramIR::from_artifact(artifact)
        })
        .collect();

    let registry = DetectorRegistry::all();
    let config = AnalyzerConfig::default();

    c.bench_function("argent_detectors_only", |b| {
        b.iter(|| {
            for program in &programs {
                let _ = registry.run_all(program, &config);
            }
        });
    });
}

criterion_group!(
    benches,
    bench_loader,
    bench_ir_construction,
    bench_cfg_construction,
    bench_callgraph,
    bench_all_detectors,
    bench_clean_fixture,
    bench_full_pipeline,
    bench_real_contracts_pipeline,
    bench_argent_detectors,
);
criterion_main!(benches);
