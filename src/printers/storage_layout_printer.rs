use std::fmt::Write as _;

use serde::Serialize;

use crate::analysis::StorageLayout;
use crate::error::AnalyzerError;

use super::{LoadedProgram, PrinterFormat, PRINTER_SCHEMA_VERSION};

#[derive(Debug, Serialize)]
struct StorageLayoutReport {
    schema_version: &'static str,
    printer: &'static str,
    artifacts: Vec<StorageLayoutArtifact>,
}

#[derive(Debug, Serialize)]
struct StorageLayoutArtifact {
    source: String,
    slots: Vec<SlotEntry>,
    unique_addresses: usize,
}

#[derive(Debug, Serialize)]
struct SlotEntry {
    address_const: String,
    name: Option<String>,
    defined_at: usize,
}

pub fn render(loaded: &[LoadedProgram], format: PrinterFormat) -> Result<String, AnalyzerError> {
    let artifacts: Vec<StorageLayoutArtifact> = loaded.iter().map(build_artifact).collect();

    match format {
        PrinterFormat::Json => {
            let report = StorageLayoutReport {
                schema_version: PRINTER_SCHEMA_VERSION,
                printer: "storage_layout",
                artifacts,
            };
            serde_json::to_string_pretty(&report)
                .map_err(|e| AnalyzerError::Config(format!("JSON serialisation failed: {e}")))
        }
        PrinterFormat::Human => {
            let mut out = String::new();
            out.push_str("Shadowhare Printer Report\n");
            out.push_str("Printer: storage-layout\n\n");

            for artifact in &artifacts {
                let _ = writeln!(&mut out, "Source: {}", artifact.source);
                let _ = writeln!(
                    &mut out,
                    "  unique addresses: {}",
                    artifact.unique_addresses
                );
                out.push_str("  slots:\n");
                if artifact.slots.is_empty() {
                    out.push_str("    (none)\n");
                } else {
                    for slot in &artifact.slots {
                        let name = slot.name.as_deref().unwrap_or("(unknown)");
                        let _ = writeln!(
                            &mut out,
                            "    - 0x{} => {} (stmt {})",
                            slot.address_const, name, slot.defined_at
                        );
                    }
                }
                out.push('\n');
            }

            Ok(out)
        }
        PrinterFormat::Dot => Err(AnalyzerError::Config(
            "storage-layout printer does not support dot format".to_string(),
        )),
    }
}

fn build_artifact(loaded: &LoadedProgram) -> StorageLayoutArtifact {
    let layout = StorageLayout::extract(&loaded.program);

    let slots: Vec<SlotEntry> = layout
        .slots
        .iter()
        .map(|s| SlotEntry {
            address_const: s.address_const.clone(),
            name: s.name.clone(),
            defined_at: s.defined_at,
        })
        .collect();

    let unique_addresses = layout.unique_slot_addresses().len();

    StorageLayoutArtifact {
        source: loaded.source.clone(),
        slots,
        unique_addresses,
    }
}
