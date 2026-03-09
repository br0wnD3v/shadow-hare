use std::fmt::Write as _;

use serde::Serialize;

use crate::error::AnalyzerError;
use crate::ir::ProgramIR;

use super::{LoadedProgram, PrinterFormat, PRINTER_SCHEMA_VERSION};

#[derive(Debug, Serialize)]
struct FunctionSigReport {
    schema_version: &'static str,
    printer: &'static str,
    artifacts: Vec<FunctionSigArtifact>,
}

#[derive(Debug, Serialize)]
struct FunctionSigArtifact {
    source: String,
    functions: Vec<FunctionSig>,
}

#[derive(Debug, Serialize)]
struct FunctionSig {
    name: String,
    kind: String,
    index: usize,
    entry_point: usize,
    n_params: usize,
    param_types: Vec<String>,
    return_types: Vec<String>,
}

pub fn render(loaded: &[LoadedProgram], format: PrinterFormat) -> Result<String, AnalyzerError> {
    let artifacts: Vec<FunctionSigArtifact> = loaded.iter().map(build_artifact).collect();

    match format {
        PrinterFormat::Json => {
            let report = FunctionSigReport {
                schema_version: PRINTER_SCHEMA_VERSION,
                printer: "function_signatures",
                artifacts,
            };
            serde_json::to_string_pretty(&report)
                .map_err(|e| AnalyzerError::Config(format!("JSON serialisation failed: {e}")))
        }
        PrinterFormat::Human => {
            let mut out = String::new();
            out.push_str("Shadowhare Printer Report\n");
            out.push_str("Printer: function-signatures\n\n");

            for artifact in &artifacts {
                let _ = writeln!(&mut out, "Source: {}", artifact.source);
                for sig in &artifact.functions {
                    let params = sig.param_types.join(", ");
                    let returns = sig.return_types.join(", ");
                    let _ = writeln!(
                        &mut out,
                        "  [{kind}] {name}({params}) -> ({returns})",
                        kind = sig.kind,
                        name = sig.name,
                    );
                }
                out.push('\n');
            }

            Ok(out)
        }
        PrinterFormat::Dot => Err(AnalyzerError::Config(
            "function-signatures printer does not support dot format".to_string(),
        )),
    }
}

fn build_artifact(loaded: &LoadedProgram) -> FunctionSigArtifact {
    let program = &loaded.program;

    let functions: Vec<FunctionSig> = program
        .functions
        .iter()
        .filter(|f| f.is_entrypoint())
        .map(|f| build_sig(program, f))
        .collect();

    FunctionSigArtifact {
        source: loaded.source.clone(),
        functions,
    }
}

fn build_sig(program: &ProgramIR, func: &crate::ir::FunctionInfo) -> FunctionSig {
    let param_types: Vec<String> = func
        .raw
        .params
        .iter()
        .map(|(_, ty)| resolve_type_name(program, ty))
        .collect();

    let return_types: Vec<String> = func
        .raw
        .ret_types
        .iter()
        .map(|t| resolve_type_name(program, t))
        .collect();

    FunctionSig {
        name: func.name.clone(),
        kind: func.kind.to_string(),
        index: func.idx,
        entry_point: func.raw.entry_point,
        n_params: param_types.len(),
        param_types,
        return_types,
    }
}

fn resolve_type_name(program: &ProgramIR, type_id: &crate::loader::SierraId) -> String {
    type_id
        .debug_name
        .clone()
        .or_else(|| {
            program
                .type_registry
                .lookup(type_id)
                .map(|td| td.generic_id.clone())
        })
        .unwrap_or_else(|| format!("type_{}", type_id.id.unwrap_or(0)))
}
