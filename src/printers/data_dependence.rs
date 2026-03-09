use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

use crate::error::AnalyzerError;
use crate::ir::ProgramIR;
use crate::loader::Statement;

use super::{LoadedProgram, PrinterFormat, PRINTER_SCHEMA_VERSION};

#[derive(Debug, Serialize)]
struct DataDepReport {
    schema_version: &'static str,
    printer: &'static str,
    artifacts: Vec<DataDepArtifact>,
}

#[derive(Debug, Serialize)]
struct DataDepArtifact {
    source: String,
    functions: Vec<FuncDataDep>,
}

#[derive(Debug, Serialize)]
struct FuncDataDep {
    function: String,
    kind: String,
    /// Map from variable ID → list of variable IDs it depends on (inputs).
    def_use_chains: BTreeMap<u64, Vec<u64>>,
}

pub fn render(loaded: &[LoadedProgram], format: PrinterFormat) -> Result<String, AnalyzerError> {
    let artifacts: Vec<DataDepArtifact> = loaded.iter().map(build_artifact).collect();

    match format {
        PrinterFormat::Json => {
            let report = DataDepReport {
                schema_version: PRINTER_SCHEMA_VERSION,
                printer: "data_dependence",
                artifacts,
            };
            serde_json::to_string_pretty(&report)
                .map_err(|e| AnalyzerError::Config(format!("JSON serialisation failed: {e}")))
        }
        PrinterFormat::Human => {
            let mut out = String::new();
            out.push_str("Shadowhare Printer Report\n");
            out.push_str("Printer: data-dependence\n\n");

            for artifact in &artifacts {
                let _ = writeln!(&mut out, "Source: {}", artifact.source);
                for func in &artifact.functions {
                    let _ = writeln!(&mut out, "  {} [{}]:", func.function, func.kind);
                    if func.def_use_chains.is_empty() {
                        out.push_str("    (no data flow)\n");
                        continue;
                    }
                    for (var, deps) in &func.def_use_chains {
                        let dep_str: Vec<String> = deps.iter().map(|d| d.to_string()).collect();
                        let _ = writeln!(&mut out, "    v{var} <- [{}]", dep_str.join(", "));
                    }
                }
                out.push('\n');
            }

            Ok(out)
        }
        PrinterFormat::Dot => Err(AnalyzerError::Config(
            "data-dependence printer does not support dot format".to_string(),
        )),
    }
}

fn build_artifact(loaded: &LoadedProgram) -> DataDepArtifact {
    let program = &loaded.program;
    let mut functions = Vec::new();

    for func in &program.functions {
        if !func.is_entrypoint() {
            continue;
        }

        let chains = build_def_use_chains(program, func.idx);
        functions.push(FuncDataDep {
            function: func.name.clone(),
            kind: func.kind.to_string(),
            def_use_chains: chains,
        });
    }

    DataDepArtifact {
        source: loaded.source.clone(),
        functions,
    }
}

fn build_def_use_chains(program: &ProgramIR, func_idx: usize) -> BTreeMap<u64, Vec<u64>> {
    let mut chains: BTreeMap<u64, Vec<u64>> = BTreeMap::new();

    for (_stmt_idx, stmt) in program.function_statements(func_idx) {
        if let Statement::Invocation(inv) = stmt {
            for branch in &inv.branches {
                for &result in &branch.results {
                    chains.insert(result, inv.args.clone());
                }
            }
        }
    }

    chains
}
