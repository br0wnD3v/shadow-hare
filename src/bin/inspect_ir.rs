use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use shadowhare::ir::program::ProgramIR;
use shadowhare::loader::{sierra_loader, CompatibilityMatrix, Statement};

#[derive(Parser, Debug)]
#[command(name = "inspect-ir", about = "Inspect normalized Sierra IR statements")]
struct Cli {
    /// Path to .sierra.json or .contract_class.json artifact
    artifact: PathBuf,
    /// Absolute statement index in ProgramIR
    #[arg(long)]
    stmt: usize,
    /// Number of statements before/after to print
    #[arg(long, default_value_t = 8)]
    context: usize,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let matrix = CompatibilityMatrix::default();
    let artifact = sierra_loader::load_artifact(&cli.artifact, &matrix)
        .with_context(|| format!("Failed to load {}", cli.artifact.display()))?;
    let program = ProgramIR::from_artifact(artifact);

    if cli.stmt >= program.statements.len() {
        anyhow::bail!(
            "Statement index {} out of range (len={})",
            cli.stmt,
            program.statements.len()
        );
    }

    let mut owner_func = None;
    for f in &program.functions {
        let (start, end) = program.function_statement_range(f.idx);
        if cli.stmt >= start && cli.stmt < end {
            owner_func = Some((f.idx, f.name.clone(), start, end));
            break;
        }
    }

    if let Some((idx, name, start, end)) = owner_func {
        println!("Function idx={idx} name={name} range=[{start}, {end})");
    } else {
        println!("Function: <not resolved>");
    }

    let lo = cli.stmt.saturating_sub(cli.context);
    let hi = (cli.stmt + cli.context + 1).min(program.statements.len());
    for i in lo..hi {
        match &program.statements[i] {
            Statement::Return(vars) => {
                println!(
                    "{} {:>6}: Return {:?}",
                    if i == cli.stmt { ">>" } else { "  " },
                    i,
                    vars
                );
            }
            Statement::Invocation(inv) => {
                let name = program
                    .libfunc_registry
                    .generic_id(&inv.libfunc_id)
                    .or_else(|| inv.libfunc_id.debug_name.as_deref())
                    .unwrap_or("<unknown>");
                println!(
                    "{} {:>6}: {} args={:?} branches={}",
                    if i == cli.stmt { ">>" } else { "  " },
                    i,
                    name,
                    inv.args,
                    inv.branches.len()
                );
            }
        }
    }

    Ok(())
}
