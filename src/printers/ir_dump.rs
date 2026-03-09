use std::fmt::Write as _;

use serde::Serialize;

use crate::error::AnalyzerError;
use crate::ir::ProgramIR;
use crate::loader::Statement;

use super::{LoadedProgram, PrinterFormat, PRINTER_SCHEMA_VERSION};

#[derive(Debug, Serialize)]
struct IrDumpReport {
    schema_version: &'static str,
    printer: &'static str,
    artifacts: Vec<IrDumpArtifact>,
}

#[derive(Debug, Serialize)]
struct IrDumpArtifact {
    source: String,
    type_count: usize,
    libfunc_count: usize,
    function_count: usize,
    statement_count: usize,
    functions: Vec<IrFunction>,
}

#[derive(Debug, Serialize)]
struct IrFunction {
    name: String,
    kind: String,
    index: usize,
    entry_point: usize,
    statement_count: usize,
    statements: Vec<IrStatement>,
}

#[derive(Debug, Serialize)]
struct IrStatement {
    index: usize,
    kind: String,
    text: String,
}

pub fn render(loaded: &[LoadedProgram], format: PrinterFormat) -> Result<String, AnalyzerError> {
    let artifacts: Vec<IrDumpArtifact> = loaded.iter().map(build_artifact).collect();

    match format {
        PrinterFormat::Json => {
            let report = IrDumpReport {
                schema_version: PRINTER_SCHEMA_VERSION,
                printer: "ir_dump",
                artifacts,
            };
            serde_json::to_string_pretty(&report)
                .map_err(|e| AnalyzerError::Config(format!("JSON serialisation failed: {e}")))
        }
        PrinterFormat::Human => {
            let mut out = String::new();
            out.push_str("Shadowhare Printer Report\n");
            out.push_str("Printer: ir-dump\n\n");

            for artifact in &artifacts {
                let _ = writeln!(&mut out, "Source: {}", artifact.source);
                let _ = writeln!(
                    &mut out,
                    "  types={} libfuncs={} functions={} statements={}",
                    artifact.type_count,
                    artifact.libfunc_count,
                    artifact.function_count,
                    artifact.statement_count,
                );

                for func in &artifact.functions {
                    let _ = writeln!(
                        &mut out,
                        "\n  --- {} [{}] (entry={}, {} stmts) ---",
                        func.name, func.kind, func.entry_point, func.statement_count,
                    );
                    for stmt in &func.statements {
                        let _ = writeln!(
                            &mut out,
                            "    [{:>4}] {} {}",
                            stmt.index, stmt.kind, stmt.text
                        );
                    }
                }
                out.push('\n');
            }

            Ok(out)
        }
        PrinterFormat::Dot => Err(AnalyzerError::Config(
            "ir-dump printer does not support dot format".to_string(),
        )),
    }
}

fn build_artifact(loaded: &LoadedProgram) -> IrDumpArtifact {
    let program = &loaded.program;

    let functions: Vec<IrFunction> = program
        .functions
        .iter()
        .filter(|f| f.is_entrypoint())
        .map(|f| build_function_dump(program, f))
        .collect();

    IrDumpArtifact {
        source: loaded.source.clone(),
        type_count: program.type_registry.declarations.len(),
        libfunc_count: program.libfunc_registry.declarations.len(),
        function_count: program.functions.len(),
        statement_count: program.statements.len(),
        functions,
    }
}

fn build_function_dump(program: &ProgramIR, func: &crate::ir::FunctionInfo) -> IrFunction {
    let mut statements = Vec::new();

    for (stmt_idx, stmt) in program.function_statements(func.idx) {
        let (kind, text) = format_statement(program, stmt);
        statements.push(IrStatement {
            index: stmt_idx,
            kind,
            text,
        });
    }

    IrFunction {
        name: func.name.clone(),
        kind: func.kind.to_string(),
        index: func.idx,
        entry_point: func.raw.entry_point,
        statement_count: statements.len(),
        statements,
    }
}

fn format_statement(program: &ProgramIR, stmt: &Statement) -> (String, String) {
    match stmt {
        Statement::Return(vars) => {
            let var_str: Vec<String> = vars.iter().map(|v| format!("v{v}")).collect();
            ("return".to_string(), format!("({})", var_str.join(", ")))
        }
        Statement::Invocation(inv) => {
            let libfunc = program
                .libfunc_registry
                .generic_id(&inv.libfunc_id)
                .or(inv.libfunc_id.debug_name.as_deref())
                .unwrap_or("?");
            let args: Vec<String> = inv.args.iter().map(|a| format!("v{a}")).collect();
            let results: Vec<String> = inv
                .branches
                .iter()
                .map(|b| {
                    let r: Vec<String> = b.results.iter().map(|r| format!("v{r}")).collect();
                    format!("({})", r.join(", "))
                })
                .collect();

            (
                "invoke".to_string(),
                format!(
                    "{}({}) -> [{}]",
                    libfunc,
                    args.join(", "),
                    results.join(", ")
                ),
            )
        }
    }
}
