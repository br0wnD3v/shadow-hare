use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use shadowhare::config::{load_scarb_config, AnalyzerConfig, DetectorSelection};
use shadowhare::detectors::{DetectorRegistry, Severity};
use shadowhare::{analyse_paths, render_output, update_baseline, OutputFormat};

// ── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "shadowhare",
    version = env!("CARGO_PKG_VERSION"),
    about = "Production-grade static analyzer for Cairo/Starknet smart contracts",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run detectors on Sierra artifacts.
    Detect(DetectArgs),
    /// Update the baseline file with the current set of findings.
    UpdateBaseline(UpdateBaselineArgs),
    /// List all available detectors.
    ListDetectors,
}

#[derive(Args)]
struct DetectArgs {
    /// Path(s) to .sierra.json or .contract_class.json files.
    /// If a directory is provided, it is searched recursively.
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Output format.
    #[arg(long, default_value = "human")]
    format: FormatArg,

    /// Minimum severity to report (info, low, medium, high, critical).
    #[arg(long, default_value = "low")]
    min_severity: SeverityArg,

    /// Only exit with code 1 for findings new since the baseline.
    #[arg(long)]
    fail_on_new_only: bool,

    /// Path to the baseline file.
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Comma-separated list of detector IDs to run (default: all).
    #[arg(long)]
    detectors: Option<String>,

    /// Comma-separated list of detector IDs to exclude.
    #[arg(long)]
    exclude: Option<String>,

    /// Read config from Scarb.toml at this path.
    #[arg(long)]
    manifest: Option<PathBuf>,

    /// Strict mode: no fallback downgrades for unknown types.
    #[arg(long)]
    strict: bool,

    /// External detector plugin executable (repeatable).
    /// Plugin protocol: `<plugin> <artifact_path>` and stdout JSON (findings[] or full report).
    #[arg(long = "plugin")]
    plugins: Vec<String>,
}

#[derive(Args)]
struct UpdateBaselineArgs {
    /// Path(s) to .sierra.json or .contract_class.json files.
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Path to the baseline file to update.
    #[arg(long, default_value = ".shadowhare-baseline.json")]
    baseline: PathBuf,
}

#[derive(Clone, clap::ValueEnum)]
enum FormatArg {
    Human,
    Json,
    Sarif,
}

#[derive(Clone, clap::ValueEnum)]
enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

impl From<FormatArg> for OutputFormat {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Human => OutputFormat::Human,
            FormatArg::Json => OutputFormat::Json,
            FormatArg::Sarif => OutputFormat::Sarif,
        }
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Detect(args) => run_detect(args),
        Command::UpdateBaseline(args) => run_update_baseline(args),
        Command::ListDetectors => run_list_detectors(),
    };

    match result {
        Ok(code) => process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            process::exit(2);
        }
    }
}

fn run_detect(args: DetectArgs) -> Result<i32> {
    // Build config, merging Scarb.toml → CLI flags (CLI takes precedence)
    let mut config = if let Some(manifest) = &args.manifest {
        match load_scarb_config(manifest)? {
            Some(scarb_cfg) => shadowhare::config::AnalyzerConfig::from_scarb(scarb_cfg)
                .context("Invalid Scarb.toml [tool.shadowhare] config")?,
            None => AnalyzerConfig::default(),
        }
    } else {
        // Auto-discover Scarb.toml in CWD
        let cwd_manifest = std::env::current_dir()
            .ok()
            .map(|d| d.join("Scarb.toml"))
            .filter(|p| p.exists());

        if let Some(manifest) = cwd_manifest {
            match load_scarb_config(&manifest)? {
                Some(scarb_cfg) => shadowhare::config::AnalyzerConfig::from_scarb(scarb_cfg)
                    .context("Invalid Scarb.toml [tool.shadowhare] config")?,
                None => AnalyzerConfig::default(),
            }
        } else {
            AnalyzerConfig::default()
        }
    };

    // CLI overrides
    if let Some(d) = &args.detectors {
        config.detectors =
            DetectorSelection::Include(d.split(',').map(|s| s.trim().to_string()).collect());
    }
    if let Some(e) = &args.exclude {
        config.detectors =
            DetectorSelection::Exclude(e.split(',').map(|s| s.trim().to_string()).collect());
    }
    config.min_severity = args.min_severity.into();
    config.fail_on_new_only = args.fail_on_new_only;
    config.strict = args.strict;
    if !args.plugins.is_empty() {
        config.plugin_commands.extend(args.plugins.clone());
    }
    if let Some(bp) = args.baseline {
        config.baseline_path = Some(bp);
    }

    // Resolve input paths
    let paths = resolve_paths(&args.paths);
    if paths.is_empty() {
        anyhow::bail!("No Sierra artifacts found at the provided paths");
    }

    let registry = DetectorRegistry::all();
    let result = analyse_paths(&paths, &config, &registry).context("Analysis failed")?;

    let output = render_output(&result, args.format.into()).context("Render failed")?;
    print!("{output}");

    Ok(result.exit_code(config.fail_on_new_only))
}

fn run_update_baseline(args: UpdateBaselineArgs) -> Result<i32> {
    let paths = resolve_paths(&args.paths);
    if paths.is_empty() {
        anyhow::bail!("No Sierra artifacts found");
    }

    let config = AnalyzerConfig::default();
    let registry = DetectorRegistry::all();
    let result = analyse_paths(&paths, &config, &registry).context("Analysis failed")?;

    update_baseline(&args.baseline, &result.findings).context("Failed to update baseline")?;

    eprintln!(
        "Baseline updated: {} findings written to {}",
        result.findings.len(),
        args.baseline.display()
    );
    Ok(0)
}

fn run_list_detectors() -> Result<i32> {
    println!(
        "{:<30} {:<10} {:<10} Description",
        "ID", "SEVERITY", "CONFIDENCE"
    );
    println!("{}", "-".repeat(80));

    let registry = DetectorRegistry::all();
    for detector in registry.iter() {
        println!(
            "{:<30} {:<10} {:<10} {}",
            detector.id(),
            detector.severity(),
            detector.confidence(),
            detector.description()
        );
    }
    Ok(0)
}

fn resolve_paths(inputs: &[PathBuf]) -> Vec<PathBuf> {
    use shadowhare::loader::sierra_loader::resolve_artifacts;

    let mut paths = Vec::new();
    for input in inputs {
        if input.is_dir() {
            paths.extend(resolve_artifacts(input));
        } else if input.exists() {
            paths.push(input.clone());
        } else {
            eprintln!("warning: path not found: {}", input.display());
        }
    }
    paths
}
