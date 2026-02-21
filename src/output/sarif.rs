use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::detectors::{Finding, Severity};

/// SARIF 2.1.0 output for GitHub code scanning and CI integration.
/// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
pub const SARIF_VERSION: &str = "2.1.0";
pub const SARIF_SCHEMA: &str =
    "https://json.schemastore.org/sarif-2.1.0.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
    pub artifacts: Vec<SarifArtifact>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfiguration,
    pub properties: SarifRuleProperties,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifConfiguration {
    pub level: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRuleProperties {
    pub tags: Vec<String>,
    pub precision: String,
    #[serde(rename = "security-severity")]
    pub security_severity: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(rename = "fingerprints")]
    pub fingerprints: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
    #[serde(rename = "logicalLocations")]
    pub logical_locations: Vec<SarifLogicalLocation>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(rename = "uriBaseId")]
    pub uri_base_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine", skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLogicalLocation {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifact {
    pub location: SarifArtifactLocation,
}

/// Build a SARIF 2.1.0 log from analyzer findings.
pub fn build_sarif(findings: &[Finding], sources: &[String]) -> SarifLog {
    // Collect unique rules from findings
    let mut seen_rules: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut rules: Vec<SarifRule> = Vec::new();

    for finding in findings {
        if seen_rules.insert(finding.detector_id.clone()) {
            rules.push(SarifRule {
                id: finding.detector_id.clone(),
                name: to_camel_case(&finding.detector_id),
                short_description: SarifMessage {
                    text: finding.title.clone(),
                },
                full_description: SarifMessage {
                    text: finding.description.clone(),
                },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(finding.severity),
                },
                properties: SarifRuleProperties {
                    tags: vec!["security".to_string(), "cairo".to_string()],
                    precision: confidence_to_precision(&finding.confidence.to_string()),
                    security_severity: severity_to_cvss_score(finding.severity),
                },
            });
        }
    }

    let sarif_results: Vec<SarifResult> = findings
        .iter()
        .map(|f| {
            let fingerprint_val = f
                .fingerprint
                .as_deref()
                .map(|fp| serde_json::json!({ "primaryLocationLineHash/v1": fp }))
                .unwrap_or(serde_json::json!({}));

            SarifResult {
                rule_id: f.detector_id.clone(),
                level: severity_to_sarif_level(f.severity),
                message: SarifMessage {
                    text: f.description.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.location.file.clone(),
                            uri_base_id: "%SRCROOT%".to_string(),
                        },
                        region: f.location.line.map(|line| SarifRegion {
                            start_line: Some(line),
                            start_column: f.location.col,
                        }),
                    },
                    logical_locations: vec![SarifLogicalLocation {
                        name: f.location.function.clone(),
                        kind: "function".to_string(),
                    }],
                }],
                fingerprints: fingerprint_val,
            }
        })
        .collect();

    let artifacts: Vec<SarifArtifact> = sources
        .iter()
        .map(|s| SarifArtifact {
            location: SarifArtifactLocation {
                uri: s.clone(),
                uri_base_id: "%SRCROOT%".to_string(),
            },
        })
        .collect();

    SarifLog {
        schema: SARIF_SCHEMA.to_string(),
        version: SARIF_VERSION.to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "shadowhare".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/shadowhare/shadowhare".to_string(),
                    rules,
                },
            },
            results: sarif_results,
            artifacts,
        }],
    }
}

fn severity_to_sarif_level(s: Severity) -> String {
    match s {
        Severity::Critical | Severity::High => "error".to_string(),
        Severity::Medium => "warning".to_string(),
        Severity::Low | Severity::Info => "note".to_string(),
    }
}

fn severity_to_cvss_score(s: Severity) -> String {
    match s {
        Severity::Critical => "9.8".to_string(),
        Severity::High => "7.5".to_string(),
        Severity::Medium => "5.0".to_string(),
        Severity::Low => "2.5".to_string(),
        Severity::Info => "0.0".to_string(),
    }
}

fn confidence_to_precision(confidence: &str) -> String {
    match confidence {
        "high" => "high".to_string(),
        "medium" => "medium".to_string(),
        _ => "low".to_string(),
    }
}

fn to_camel_case(s: &str) -> String {
    s.split('_')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect()
}
