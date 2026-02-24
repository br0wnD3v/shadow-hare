use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::analysis::CallGraph;
use crate::error::{AnalyzerError, AnalyzerWarning, WarningKind};
use crate::ir::{FunctionKind, ProgramIR};
use crate::loader::{sierra_loader, CompatibilityMatrix, CompatibilityTier, VersionMetadataSource};

const PRINTER_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrinterKind {
    Summary,
    Callgraph,
    AttackSurface,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrinterFormat {
    Human,
    Json,
    Dot,
}

pub fn render_paths(
    paths: &[PathBuf],
    printer: PrinterKind,
    format: PrinterFormat,
) -> Result<String, AnalyzerError> {
    let mut loaded = load_programs(paths)?;
    loaded.sort_by(|a, b| a.source.cmp(&b.source));

    match printer {
        PrinterKind::Summary => render_summary(&loaded, format),
        PrinterKind::Callgraph => render_callgraph(&loaded, format),
        PrinterKind::AttackSurface => render_attack_surface(&loaded, format),
    }
}

#[derive(Debug)]
struct LoadedProgram {
    source: String,
    compatibility_tier: CompatibilityTier,
    metadata_source: VersionMetadataSource,
    degraded_reason: Option<String>,
    warnings: Vec<AnalyzerWarning>,
    program: ProgramIR,
}

fn load_programs(paths: &[PathBuf]) -> Result<Vec<LoadedProgram>, AnalyzerError> {
    let matrix = CompatibilityMatrix::default();
    paths
        .iter()
        .map(|p| load_single_program(p, &matrix))
        .collect()
}

fn load_single_program(
    path: &Path,
    matrix: &CompatibilityMatrix,
) -> Result<LoadedProgram, AnalyzerError> {
    let artifact = sierra_loader::load_artifact(path, matrix)?;

    let compatibility_tier = artifact.compatibility;
    let metadata_source = artifact.version_metadata_source;
    let degraded_reason = artifact.compatibility_degraded_reason.clone();
    let warnings = artifact.warnings.clone();
    let program = ProgramIR::from_artifact(artifact);

    Ok(LoadedProgram {
        source: path.display().to_string(),
        compatibility_tier,
        metadata_source,
        degraded_reason,
        warnings,
        program,
    })
}

// =============================================================================
// Summary printer
// =============================================================================

#[derive(Debug, Serialize)]
struct SummaryReport {
    schema_version: &'static str,
    printer: &'static str,
    artifacts: Vec<SummaryArtifact>,
}

#[derive(Debug, Serialize)]
struct SummaryArtifact {
    source: String,
    compatibility_tier: CompatibilityTier,
    metadata_source: VersionMetadataSource,
    degraded_reason: Option<String>,
    warnings: Vec<String>,
    functions: FunctionCounts,
    statements: usize,
    callgraph_edges: usize,
}

#[derive(Debug, Serialize)]
struct FunctionCounts {
    total: usize,
    external: usize,
    view: usize,
    l1_handler: usize,
    constructor: usize,
    internal: usize,
    entrypoints: usize,
}

fn build_summary_artifact(loaded: &LoadedProgram) -> SummaryArtifact {
    let functions = function_counts(&loaded.program);
    let callgraph = CallGraph::build(&loaded.program);
    let callgraph_edges = callgraph.edges.values().map(std::vec::Vec::len).sum();
    let warnings = loaded
        .warnings
        .iter()
        .map(|w| format_warning(w))
        .collect::<Vec<_>>();

    SummaryArtifact {
        source: loaded.source.clone(),
        compatibility_tier: loaded.compatibility_tier,
        metadata_source: loaded.metadata_source,
        degraded_reason: loaded.degraded_reason.clone(),
        warnings,
        functions,
        statements: loaded.program.statements.len(),
        callgraph_edges,
    }
}

fn render_summary(
    loaded: &[LoadedProgram],
    format: PrinterFormat,
) -> Result<String, AnalyzerError> {
    let artifacts = loaded
        .iter()
        .map(build_summary_artifact)
        .collect::<Vec<_>>();

    match format {
        PrinterFormat::Json => {
            let report = SummaryReport {
                schema_version: PRINTER_SCHEMA_VERSION,
                printer: "summary",
                artifacts,
            };
            serde_json::to_string_pretty(&report)
                .map_err(|e| AnalyzerError::Config(format!("JSON serialisation failed: {e}")))
        }
        PrinterFormat::Human => {
            let mut out = String::new();
            out.push_str("Shadowhare Printer Report\n");
            out.push_str("Printer: summary\n\n");

            for artifact in artifacts {
                let _ = writeln!(&mut out, "Source: {}", artifact.source);
                let _ = writeln!(
                    &mut out,
                    "  compatibility: tier={} source={}",
                    artifact.compatibility_tier, artifact.metadata_source
                );
                if let Some(reason) = artifact.degraded_reason {
                    let _ = writeln!(&mut out, "  degraded_reason: {reason}");
                }
                if !artifact.warnings.is_empty() {
                    out.push_str("  warnings:\n");
                    for w in artifact.warnings {
                        let _ = writeln!(&mut out, "    - {w}");
                    }
                }
                let f = artifact.functions;
                let _ = writeln!(&mut out, "  functions: total={} entrypoints={} external={} view={} l1_handler={} constructor={} internal={}",
                    f.total, f.entrypoints, f.external, f.view, f.l1_handler, f.constructor, f.internal);
                let _ = writeln!(&mut out, "  statements: {}", artifact.statements);
                let _ = writeln!(&mut out, "  callgraph_edges: {}", artifact.callgraph_edges);
                out.push('\n');
            }

            Ok(out)
        }
        PrinterFormat::Dot => Err(AnalyzerError::Config(
            "summary printer does not support dot format".to_string(),
        )),
    }
}

fn function_counts(program: &ProgramIR) -> FunctionCounts {
    let mut counts = FunctionCounts {
        total: program.functions.len(),
        external: 0,
        view: 0,
        l1_handler: 0,
        constructor: 0,
        internal: 0,
        entrypoints: 0,
    };

    for f in &program.functions {
        if f.is_entrypoint() {
            counts.entrypoints += 1;
        }

        match f.kind {
            FunctionKind::External => counts.external += 1,
            FunctionKind::View => counts.view += 1,
            FunctionKind::L1Handler => counts.l1_handler += 1,
            FunctionKind::Constructor => counts.constructor += 1,
            FunctionKind::Internal => counts.internal += 1,
        }
    }

    counts
}

fn format_warning(warning: &AnalyzerWarning) -> String {
    let kind = match warning.kind {
        WarningKind::UnknownType => "unknown_type",
        WarningKind::UnknownLibfunc => "unknown_libfunc",
        WarningKind::MissingDebugInfo => "missing_debug_info",
        WarningKind::IncompatibleVersion => "incompatible_version",
        WarningKind::DetectorSkipped => "detector_skipped",
    };
    format!("{kind}: {}", warning.message)
}

// =============================================================================
// Callgraph printer
// =============================================================================

#[derive(Debug, Serialize)]
struct CallgraphReport {
    schema_version: &'static str,
    printer: &'static str,
    artifacts: Vec<CallgraphArtifact>,
}

#[derive(Debug, Serialize)]
struct CallgraphArtifact {
    source: String,
    nodes: Vec<CallgraphNode>,
    edges: Vec<CallgraphEdge>,
}

#[derive(Debug, Serialize)]
struct CallgraphNode {
    id: usize,
    name: String,
    kind: String,
    is_entrypoint: bool,
}

#[derive(Debug, Serialize)]
struct CallgraphEdge {
    from: usize,
    to: usize,
    from_name: String,
    to_name: String,
}

fn build_callgraph_artifact(loaded: &LoadedProgram) -> CallgraphArtifact {
    let program = &loaded.program;
    let graph = CallGraph::build(program);

    let nodes = program
        .functions
        .iter()
        .map(|f| CallgraphNode {
            id: f.idx,
            name: f.name.clone(),
            kind: f.kind.to_string(),
            is_entrypoint: f.is_entrypoint(),
        })
        .collect::<Vec<_>>();

    let mut edges = Vec::new();
    let mut callers = graph.edges.keys().copied().collect::<Vec<_>>();
    callers.sort_unstable();

    for from in callers {
        let Some(callees) = graph.edges.get(&from) else {
            continue;
        };

        let mut sorted_callees = callees.clone();
        sorted_callees.sort_unstable();

        for to in sorted_callees {
            let from_name = program
                .functions
                .get(from)
                .map(|f| f.name.clone())
                .unwrap_or_else(|| format!("func_{from}"));
            let to_name = program
                .functions
                .get(to)
                .map(|f| f.name.clone())
                .unwrap_or_else(|| format!("func_{to}"));

            edges.push(CallgraphEdge {
                from,
                to,
                from_name,
                to_name,
            });
        }
    }

    CallgraphArtifact {
        source: loaded.source.clone(),
        nodes,
        edges,
    }
}

fn render_callgraph(
    loaded: &[LoadedProgram],
    format: PrinterFormat,
) -> Result<String, AnalyzerError> {
    let artifacts = loaded
        .iter()
        .map(build_callgraph_artifact)
        .collect::<Vec<_>>();

    match format {
        PrinterFormat::Json => {
            let report = CallgraphReport {
                schema_version: PRINTER_SCHEMA_VERSION,
                printer: "callgraph",
                artifacts,
            };
            serde_json::to_string_pretty(&report)
                .map_err(|e| AnalyzerError::Config(format!("JSON serialisation failed: {e}")))
        }
        PrinterFormat::Human => {
            let mut out = String::new();
            out.push_str("Shadowhare Printer Report\n");
            out.push_str("Printer: callgraph\n\n");

            for artifact in artifacts {
                let _ = writeln!(&mut out, "Source: {}", artifact.source);
                let _ = writeln!(
                    &mut out,
                    "  nodes: {}  edges: {}",
                    artifact.nodes.len(),
                    artifact.edges.len()
                );

                if artifact.edges.is_empty() {
                    out.push_str("  edges:\n    - (none)\n\n");
                    continue;
                }

                out.push_str("  edges:\n");
                for e in artifact.edges {
                    let _ = writeln!(&mut out, "    - {} -> {}", e.from_name, e.to_name);
                }
                out.push('\n');
            }

            Ok(out)
        }
        PrinterFormat::Dot => Ok(render_callgraph_dot(&artifacts)),
    }
}

fn render_callgraph_dot(artifacts: &[CallgraphArtifact]) -> String {
    let mut out = String::new();
    out.push_str("digraph shadowhare_callgraph {\n");
    out.push_str("  rankdir=LR;\n");

    for (artifact_idx, artifact) in artifacts.iter().enumerate() {
        let _ = writeln!(&mut out, "  subgraph cluster_{artifact_idx} {{");
        let _ = writeln!(&mut out, "    label=\"{}\";", dot_escape(&artifact.source));
        out.push_str("    color=\"gray70\";\n");

        for node in &artifact.nodes {
            let shape = if node.is_entrypoint { "box" } else { "ellipse" };
            let _ = writeln!(
                &mut out,
                "    a{artifact_idx}_f{} [label=\"{}\\n({})\", shape={}];",
                node.id,
                dot_escape(&node.name),
                dot_escape(&node.kind),
                shape
            );
        }

        for edge in &artifact.edges {
            let _ = writeln!(
                &mut out,
                "    a{artifact_idx}_f{} -> a{artifact_idx}_f{};",
                edge.from, edge.to
            );
        }

        out.push_str("  }\n");
    }

    out.push_str("}\n");
    out
}

fn dot_escape(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

// =============================================================================
// Attack-surface printer
// =============================================================================

#[derive(Debug, Serialize)]
struct AttackSurfaceReport {
    schema_version: &'static str,
    printer: &'static str,
    artifacts: Vec<AttackSurfaceArtifact>,
}

#[derive(Debug, Serialize)]
struct AttackSurfaceArtifact {
    source: String,
    entrypoints: Vec<EntryPointSurface>,
    sink_reach_counts: BTreeMap<String, usize>,
    direct_sink_functions: Vec<FunctionSurface>,
}

#[derive(Debug, Serialize)]
struct EntryPointSurface {
    function: String,
    kind: String,
    reachable_sinks: Vec<SinkKind>,
}

#[derive(Debug, Serialize)]
struct FunctionSurface {
    function: String,
    kind: String,
    direct_sinks: Vec<SinkKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum SinkKind {
    StorageWrite,
    ExternalCall,
    LibraryCall,
    L2ToL1Message,
    Upgrade,
    Deploy,
}

impl SinkKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::StorageWrite => "storage_write",
            Self::ExternalCall => "external_call",
            Self::LibraryCall => "library_call",
            Self::L2ToL1Message => "l2_to_l1_message",
            Self::Upgrade => "upgrade",
            Self::Deploy => "deploy",
        }
    }
}

fn render_attack_surface(
    loaded: &[LoadedProgram],
    format: PrinterFormat,
) -> Result<String, AnalyzerError> {
    let artifacts = loaded
        .iter()
        .map(build_attack_surface_artifact)
        .collect::<Vec<_>>();

    match format {
        PrinterFormat::Json => {
            let report = AttackSurfaceReport {
                schema_version: PRINTER_SCHEMA_VERSION,
                printer: "attack_surface",
                artifacts,
            };
            serde_json::to_string_pretty(&report)
                .map_err(|e| AnalyzerError::Config(format!("JSON serialisation failed: {e}")))
        }
        PrinterFormat::Human => {
            let mut out = String::new();
            out.push_str("Shadowhare Printer Report\n");
            out.push_str("Printer: attack-surface\n\n");

            for artifact in artifacts {
                let _ = writeln!(&mut out, "Source: {}", artifact.source);

                out.push_str("  sink_reach_counts:\n");
                if artifact.sink_reach_counts.is_empty() {
                    out.push_str("    - (none)\n");
                } else {
                    for (sink, count) in artifact.sink_reach_counts {
                        let _ = writeln!(&mut out, "    - {}: {}", sink, count);
                    }
                }

                out.push_str("  entrypoints:\n");
                if artifact.entrypoints.is_empty() {
                    out.push_str("    - (none)\n");
                } else {
                    for ep in artifact.entrypoints {
                        if ep.reachable_sinks.is_empty() {
                            let _ =
                                writeln!(&mut out, "    - {} [{}] => (none)", ep.function, ep.kind);
                        } else {
                            let sinks = ep
                                .reachable_sinks
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(", ");
                            let _ = writeln!(
                                &mut out,
                                "    - {} [{}] => {}",
                                ep.function, ep.kind, sinks
                            );
                        }
                    }
                }

                out.push_str("  direct_sink_functions:\n");
                if artifact.direct_sink_functions.is_empty() {
                    out.push_str("    - (none)\n\n");
                    continue;
                }

                for f in artifact.direct_sink_functions {
                    let sinks = f
                        .direct_sinks
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let _ = writeln!(&mut out, "    - {} [{}] => {}", f.function, f.kind, sinks);
                }
                out.push('\n');
            }

            Ok(out)
        }
        PrinterFormat::Dot => Err(AnalyzerError::Config(
            "attack-surface printer does not support dot format".to_string(),
        )),
    }
}

fn build_attack_surface_artifact(loaded: &LoadedProgram) -> AttackSurfaceArtifact {
    let program = &loaded.program;
    let callgraph = CallGraph::build(program);

    let direct_sinks = compute_direct_sinks(program);
    let reachable_sinks = compute_reachable_sinks(&callgraph, &direct_sinks);

    let mut entrypoints = Vec::new();
    let mut sink_reach_counts: BTreeMap<String, usize> = BTreeMap::new();

    for f in &program.functions {
        if !f.is_entrypoint() {
            continue;
        }

        let sinks = reachable_sinks
            .get(f.idx)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();

        for sink in &sinks {
            *sink_reach_counts
                .entry(sink.as_str().to_string())
                .or_insert(0) += 1;
        }

        entrypoints.push(EntryPointSurface {
            function: f.name.clone(),
            kind: f.kind.to_string(),
            reachable_sinks: sinks,
        });
    }

    let mut direct_sink_functions = Vec::new();
    for f in &program.functions {
        let sinks = direct_sinks
            .get(f.idx)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();

        if sinks.is_empty() {
            continue;
        }

        direct_sink_functions.push(FunctionSurface {
            function: f.name.clone(),
            kind: f.kind.to_string(),
            direct_sinks: sinks,
        });
    }

    AttackSurfaceArtifact {
        source: loaded.source.clone(),
        entrypoints,
        sink_reach_counts,
        direct_sink_functions,
    }
}

fn compute_direct_sinks(program: &ProgramIR) -> Vec<BTreeSet<SinkKind>> {
    let mut direct = vec![BTreeSet::new(); program.functions.len()];

    for f in &program.functions {
        let sinks = &mut direct[f.idx];

        for (_stmt_idx, stmt) in program.function_statements(f.idx) {
            let Some(inv) = stmt.as_invocation() else {
                continue;
            };
            let name = program
                .get_libfunc_name(&inv.libfunc_id)
                .or_else(|| inv.libfunc_id.debug_name.as_deref())
                .unwrap_or("");

            if name.contains("storage_write") {
                sinks.insert(SinkKind::StorageWrite);
            }
            if name.contains("call_contract") {
                sinks.insert(SinkKind::ExternalCall);
            }
            if name.contains("library_call") {
                sinks.insert(SinkKind::LibraryCall);
            }
            if name.contains("send_message_to_l1") {
                sinks.insert(SinkKind::L2ToL1Message);
            }
            if name.contains("replace_class") {
                sinks.insert(SinkKind::Upgrade);
            }
            if name.contains("deploy") {
                sinks.insert(SinkKind::Deploy);
            }
        }
    }

    direct
}

fn compute_reachable_sinks(
    callgraph: &CallGraph,
    direct: &[BTreeSet<SinkKind>],
) -> Vec<BTreeSet<SinkKind>> {
    let n = direct.len();
    let mut memo: Vec<Option<BTreeSet<SinkKind>>> = vec![None; n];
    let mut visiting = vec![false; n];

    for idx in 0..n {
        let _ = reachable_sinks_dfs(idx, callgraph, direct, &mut memo, &mut visiting);
    }

    memo.into_iter().map(|m| m.unwrap_or_default()).collect()
}

fn reachable_sinks_dfs(
    idx: usize,
    callgraph: &CallGraph,
    direct: &[BTreeSet<SinkKind>],
    memo: &mut [Option<BTreeSet<SinkKind>>],
    visiting: &mut [bool],
) -> BTreeSet<SinkKind> {
    if let Some(cached) = &memo[idx] {
        return cached.clone();
    }

    if visiting[idx] {
        return direct[idx].clone();
    }

    visiting[idx] = true;

    let mut sinks = direct[idx].clone();
    if let Some(callees) = callgraph.edges.get(&idx) {
        let mut sorted = callees.clone();
        sorted.sort_unstable();
        for callee in sorted {
            if callee >= direct.len() {
                continue;
            }
            let child = reachable_sinks_dfs(callee, callgraph, direct, memo, visiting);
            sinks.extend(child);
        }
    }

    visiting[idx] = false;
    memo[idx] = Some(sinks.clone());
    sinks
}
