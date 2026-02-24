use std::path::PathBuf;

use shadowhare::printers::{render_paths, PrinterFormat, PrinterKind};

fn seeded_pure_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target_contracts")
        .join("seeded")
        .join("pure")
        .join(name)
}

#[test]
fn summary_printer_json_is_deterministic() {
    let path = seeded_pure_fixture("deploy_syscall_tainted_class_hash.sierra.json");

    let out1 = render_paths(&[path.clone()], PrinterKind::Summary, PrinterFormat::Json)
        .expect("summary render #1");
    let out2 = render_paths(&[path], PrinterKind::Summary, PrinterFormat::Json)
        .expect("summary render #2");

    assert_eq!(out1, out2, "summary printer output should be deterministic");

    let parsed: serde_json::Value = serde_json::from_str(&out1).expect("valid summary json");
    assert_eq!(parsed["printer"], "summary");
    assert!(
        parsed["artifacts"][0]["functions"]["total"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "expected at least one function in summary output"
    );
}

#[test]
fn callgraph_printer_json_contains_expected_edge() {
    let path = seeded_pure_fixture("view_state_modification.sierra.json");
    let out =
        render_paths(&[path], PrinterKind::Callgraph, PrinterFormat::Json).expect("callgraph json");

    let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid callgraph json");
    let edges = parsed["artifacts"][0]["edges"]
        .as_array()
        .expect("edges array");

    let has_expected = edges.iter().any(|e| {
        e["from_name"].as_str() == Some("oracle::__view::peek")
            && e["to_name"].as_str() == Some("oracle::helper_write")
    });

    assert!(
        has_expected,
        "expected callgraph edge oracle::__view::peek -> oracle::helper_write, got {edges:?}"
    );
}

#[test]
fn callgraph_printer_dot_contains_graph_header_and_labels() {
    let path = seeded_pure_fixture("view_state_modification.sierra.json");
    let out = render_paths(&[path], PrinterKind::Callgraph, PrinterFormat::Dot)
        .expect("callgraph dot render");

    assert!(out.contains("digraph shadowhare_callgraph"));
    assert!(out.contains("oracle::__view::peek"));
    assert!(out.contains("oracle::helper_write"));
}

#[test]
fn attack_surface_printer_reports_transitive_storage_write_for_view_entrypoint() {
    let path = seeded_pure_fixture("view_state_modification.sierra.json");
    let out = render_paths(&[path], PrinterKind::AttackSurface, PrinterFormat::Json)
        .expect("attack json");

    let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid attack json");
    let entrypoints = parsed["artifacts"][0]["entrypoints"]
        .as_array()
        .expect("entrypoints array");

    let mut found = false;
    for ep in entrypoints {
        if ep["function"].as_str() != Some("oracle::__view::peek") {
            continue;
        }
        let sinks = ep["reachable_sinks"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if sinks.iter().any(|s| s.as_str() == Some("storage_write")) {
            found = true;
            break;
        }
    }

    assert!(
        found,
        "expected oracle::__view::peek to reach storage_write sink in attack-surface output"
    );
}
