use std::collections::HashMap;
use std::path::{Path, PathBuf};

use cairo_annotations::annotations::coverage::VersionedCoverageAnnotations;
use cairo_annotations::annotations::TryFromDebugInfo;
use serde::{Deserialize, Serialize};

use crate::error::{AnalyzerError, AnalyzerWarning};
use crate::loader::version::{ArtifactVersion, CompatibilityMatrix, CompatibilityTier};

/// Unified artifact type that we can produce from either format.
#[derive(Debug, Clone)]
pub struct LoadedArtifact {
    pub source_path: PathBuf,
    pub format: ArtifactFormat,
    pub version: ArtifactVersion,
    pub compatibility: CompatibilityTier,
    pub program: SierraProgram,
    pub entry_points: EntryPoints,
    pub statement_locations: HashMap<usize, SourceLocation>,
    pub warnings: Vec<AnalyzerWarning>,
}

#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file: Option<String>,
    pub line: u32,
    pub col: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactFormat {
    RawSierraJson,
    StarknetContractClass,
}

// ── Raw Sierra Program (cairo-lang-sierra JSON format) ─────────────────────

/// Mirrors `cairo_lang_sierra::program::Program` serde output.
#[derive(Debug, Clone, Deserialize)]
pub struct RawSierraProgram {
    #[serde(default)]
    pub type_declarations: Vec<RawTypeDeclaration>,
    #[serde(default)]
    pub libfunc_declarations: Vec<RawLibfuncDeclaration>,
    #[serde(default)]
    pub statements: Vec<RawStatement>,
    #[serde(default)]
    pub funcs: Vec<RawFunction>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawTypeDeclaration {
    pub id: SierraId,
    pub long_id: RawConcreteTypeLongId,
    #[serde(default)]
    pub declared_type_info: Option<RawDeclaredTypeInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawConcreteTypeLongId {
    pub generic_id: String,
    #[serde(default)]
    pub generic_args: Vec<RawGenericArg>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RawGenericArg {
    Type { ty: SierraId },
    Value { value: serde_json::Value },
    UserType { user_type: serde_json::Value },
    Unknown(serde_json::Value),
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawDeclaredTypeInfo {
    #[serde(default)]
    pub storable: bool,
    #[serde(default)]
    pub droppable: bool,
    #[serde(default)]
    pub duplicatable: bool,
    #[serde(default)]
    pub zero_sized: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawLibfuncDeclaration {
    pub id: SierraId,
    pub long_id: RawConcreteLibfuncLongId,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawConcreteLibfuncLongId {
    pub generic_id: String,
    #[serde(default)]
    pub generic_args: Vec<RawGenericArg>,
}

/// A Sierra statement is either an Invocation or a Return.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RawStatement {
    Invocation(RawInvocation),
    Return {
        #[serde(rename = "Return")]
        ret: Vec<RawVarId>,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawInvocation {
    #[serde(rename = "Invocation")]
    pub inner: RawInvocationInner,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawInvocationInner {
    pub libfunc_id: SierraId,
    #[serde(default)]
    pub args: Vec<RawVarId>,
    #[serde(default)]
    pub branches: Vec<RawBranchInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawBranchInfo {
    pub target: RawBranchTarget,
    #[serde(default)]
    pub results: Vec<RawVarId>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RawBranchTarget {
    Fallthrough(serde_json::Value), // "Fallthrough" string
    Statement {
        #[serde(rename = "Statement")]
        idx: u64,
    },
}

impl RawBranchTarget {
    pub fn statement_idx(&self) -> Option<u64> {
        match self {
            Self::Statement { idx } => Some(*idx),
            Self::Fallthrough(_) => None,
        }
    }

    pub fn is_fallthrough(&self) -> bool {
        matches!(self, Self::Fallthrough(_))
    }
}

/// Variable ID — deserializes from either a plain integer (contract class / old format)
/// or an object `{"id": N, "debug_name": ...}` (raw Sierra JSON from Scarb).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RawVarId(pub u64);

impl<'de> serde::Deserialize<'de> for RawVarId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        match &v {
            serde_json::Value::Number(n) => n
                .as_u64()
                .map(RawVarId)
                .ok_or_else(|| serde::de::Error::custom("VarId number out of u64 range")),
            serde_json::Value::Object(obj) => obj
                .get("id")
                .and_then(|v| v.as_u64())
                .map(RawVarId)
                .ok_or_else(|| serde::de::Error::custom("VarId object missing numeric id")),
            _ => Err(serde::de::Error::custom(
                "Expected VarId (integer or {id: N})",
            )),
        }
    }
}

/// Sierra ID — can be numeric, named, or both.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct SierraId {
    pub id: Option<u64>,
    pub debug_name: Option<String>,
}

impl SierraId {
    pub fn canonical_name(&self) -> String {
        if let Some(name) = &self.debug_name {
            name.clone()
        } else if let Some(id) = self.id {
            id.to_string()
        } else {
            "<unknown>".to_string()
        }
    }

    pub fn matches_name(&self, pattern: &str) -> bool {
        self.debug_name
            .as_deref()
            .map(|n| n.contains(pattern))
            .unwrap_or(false)
    }
}

impl<'de> serde::Deserialize<'de> for SierraId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        match v {
            serde_json::Value::Number(n) => Ok(SierraId {
                id: n.as_u64(),
                debug_name: None,
            }),
            serde_json::Value::String(s) => Ok(SierraId {
                id: None,
                debug_name: Some(s),
            }),
            serde_json::Value::Object(obj) => {
                let id = obj.get("id").and_then(|v| v.as_u64());
                let debug_name = obj
                    .get("debug_name")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                Ok(SierraId { id, debug_name })
            }
            _ => Err(serde::de::Error::custom("Expected Sierra ID")),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawFunction {
    pub id: SierraId,
    pub signature: RawFunctionSignature,
    #[serde(default)]
    pub params: Vec<RawParam>,
    pub entry_point: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawFunctionSignature {
    #[serde(default)]
    pub param_types: Vec<SierraId>,
    #[serde(default)]
    pub ret_types: Vec<SierraId>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawParam {
    pub id: RawVarId,
    pub ty: SierraId,
}

// ── Starknet Contract Class format ─────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct RawContractClass {
    /// Hex-encoded Felt252 array representing the Sierra program.
    #[serde(default)]
    pub sierra_program: Vec<String>,
    #[serde(default)]
    pub sierra_program_debug_info: Option<RawContractDebugInfo>,
    pub contract_class_version: Option<String>,
    pub entry_points_by_type: Option<RawEntryPointsByType>,
    #[serde(default)]
    pub abi: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawContractDebugInfo {
    #[serde(default)]
    pub type_names: Vec<(u64, String)>,
    #[serde(default)]
    pub libfunc_names: Vec<(u64, String)>,
    #[serde(default)]
    pub user_func_names: Vec<(u64, String)>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RawEntryPointsByType {
    #[serde(rename = "EXTERNAL", default)]
    pub external: Vec<RawEntryPoint>,
    #[serde(rename = "L1_HANDLER", default)]
    pub l1_handler: Vec<RawEntryPoint>,
    #[serde(rename = "CONSTRUCTOR", default)]
    pub constructor: Vec<RawEntryPoint>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawEntryPoint {
    pub selector: String,
    pub function_idx: u64,
}

// ── Normalised types our IR uses ────────────────────────────────────────────

/// Normalised Sierra program used by the rest of the analyzer.
#[derive(Debug, Clone)]
pub struct SierraProgram {
    pub type_declarations: Vec<TypeDeclaration>,
    pub libfunc_declarations: Vec<LibfuncDeclaration>,
    pub statements: Vec<Statement>,
    pub functions: Vec<Function>,
}

#[derive(Debug, Clone)]
pub struct TypeDeclaration {
    pub id: SierraId,
    pub generic_id: String,
    pub generic_args: Vec<RawGenericArg>,
    pub info: Option<RawDeclaredTypeInfo>,
}

#[derive(Debug, Clone)]
pub struct LibfuncDeclaration {
    pub id: SierraId,
    pub generic_id: String,
    pub generic_args: Vec<RawGenericArg>,
}

#[derive(Debug, Clone)]
pub enum Statement {
    Invocation(Invocation),
    Return(Vec<u64>),
}

impl Statement {
    pub fn as_invocation(&self) -> Option<&Invocation> {
        match self {
            Self::Invocation(inv) => Some(inv),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Invocation {
    pub libfunc_id: SierraId,
    pub args: Vec<u64>,
    pub branches: Vec<BranchInfo>,
}

#[derive(Debug, Clone)]
pub struct BranchInfo {
    pub target: BranchTarget,
    pub results: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchTarget {
    Fallthrough,
    Statement(usize),
}

#[derive(Debug, Clone)]
pub struct Function {
    pub id: SierraId,
    pub param_types: Vec<SierraId>,
    pub ret_types: Vec<SierraId>,
    pub params: Vec<(u64, SierraId)>,
    pub entry_point: usize,
}

#[derive(Debug, Clone, Default)]
pub struct EntryPoints {
    pub external: Vec<EntryPoint>,
    pub l1_handler: Vec<EntryPoint>,
    pub constructor: Vec<EntryPoint>,
}

#[derive(Debug, Clone)]
pub struct EntryPoint {
    pub selector: String,
    pub function_idx: usize,
}

// ── Loader ──────────────────────────────────────────────────────────────────

/// Load and normalise a Sierra artifact from a file path.
pub fn load_artifact(
    path: &Path,
    matrix: &CompatibilityMatrix,
) -> Result<LoadedArtifact, AnalyzerError> {
    let content = std::fs::read_to_string(path).map_err(|e| AnalyzerError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let value: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| AnalyzerError::JsonParse {
            path: path.to_path_buf(),
            source: e,
        })?;

    // Detect format: contract class has "sierra_program" as array of hex strings,
    // raw Sierra has "type_declarations".
    let format = if value.get("sierra_program").is_some() {
        ArtifactFormat::StarknetContractClass
    } else {
        ArtifactFormat::RawSierraJson
    };

    match format {
        ArtifactFormat::RawSierraJson => load_raw_sierra(path, &value, matrix),
        ArtifactFormat::StarknetContractClass => load_contract_class(path, &value, matrix),
    }
}

fn load_raw_sierra(
    path: &Path,
    value: &serde_json::Value,
    matrix: &CompatibilityMatrix,
) -> Result<LoadedArtifact, AnalyzerError> {
    let raw: RawSierraProgram =
        serde_json::from_value(value.clone()).map_err(|e| AnalyzerError::JsonParse {
            path: path.to_path_buf(),
            source: e,
        })?;

    let artifact_version = ArtifactVersion {
        contract_class_version: None,
        compiler_version: None,
        sierra_version: None,
    };

    let (compat, mut warnings) = crate::loader::version::negotiate(&artifact_version, matrix)?;
    let program = normalise_raw_program(raw, &mut warnings);

    Ok(LoadedArtifact {
        source_path: path.to_path_buf(),
        format: ArtifactFormat::RawSierraJson,
        version: artifact_version,
        compatibility: compat,
        program,
        entry_points: EntryPoints::default(),
        statement_locations: HashMap::new(),
        warnings,
    })
}

fn load_contract_class(
    path: &Path,
    value: &serde_json::Value,
    matrix: &CompatibilityMatrix,
) -> Result<LoadedArtifact, AnalyzerError> {
    let raw: RawContractClass =
        serde_json::from_value(value.clone()).map_err(|e| AnalyzerError::JsonParse {
            path: path.to_path_buf(),
            source: e,
        })?;

    let artifact_version = ArtifactVersion {
        contract_class_version: raw.contract_class_version.clone(),
        compiler_version: None,
        sierra_version: None,
    };

    let (compat, mut warnings) = crate::loader::version::negotiate(&artifact_version, matrix)?;

    // Decode the encoded Sierra program from the contract class.
    let (program, statement_locations) = decode_contract_class_program(&raw, path, &mut warnings)?;

    let entry_points = normalise_entry_points(raw.entry_points_by_type.as_ref());

    Ok(LoadedArtifact {
        source_path: path.to_path_buf(),
        format: ArtifactFormat::StarknetContractClass,
        version: artifact_version,
        compatibility: compat,
        program,
        entry_points,
        statement_locations,
        warnings,
    })
}

/// Decode the Starknet contract class Sierra program encoding.
///
/// The contract class stores the Sierra program as a flat array of Felt252 hex values.
/// We use cairo-lang-starknet-classes for proper decoding.
fn decode_contract_class_program(
    raw: &RawContractClass,
    path: &Path,
    warnings: &mut Vec<AnalyzerWarning>,
) -> Result<(SierraProgram, HashMap<usize, SourceLocation>), AnalyzerError> {
    // Re-read the original file and deserialize into cairo-lang-starknet-classes' ContractClass.
    let raw_json = std::fs::read_to_string(path).map_err(|e| AnalyzerError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let cc: Result<cairo_lang_starknet_classes::contract_class::ContractClass, AnalyzerError> =
        serde_json::from_str(&raw_json).map_err(|_| {
            AnalyzerError::Config(format!(
                "Could not deserialize {} as ContractClass",
                path.display()
            ))
        });

    match cc {
        Ok(cc) => {
            let extracted = cc.extract_sierra_program(false).map_err(|e| {
                AnalyzerError::Config(format!("Failed to decode Sierra program: {e}"))
            })?;
            let statement_locations = cc
                .sierra_program_debug_info
                .as_ref()
                .map(extract_statement_locations)
                .unwrap_or_default();

            let mut w = Vec::new();
            let mut program = convert_cairo_program(extracted.program, &mut w);
            warnings.extend(w);

            // Enrich function/libfunc/type debug names from sierra_program_debug_info.
            // extract_sierra_program(false) strips debug names; we restore them here.
            if let Some(debug_info) = &raw.sierra_program_debug_info {
                let func_names: std::collections::HashMap<u64, &str> = debug_info
                    .user_func_names
                    .iter()
                    .map(|(id, name)| (*id, name.as_str()))
                    .collect();
                for func in &mut program.functions {
                    if let (Some(id), None) = (func.id.id, func.id.debug_name.as_deref()) {
                        if let Some(name) = func_names.get(&id) {
                            func.id.debug_name = Some((*name).to_string());
                        }
                    }
                }

                let libfunc_names: std::collections::HashMap<u64, &str> = debug_info
                    .libfunc_names
                    .iter()
                    .map(|(id, name)| (*id, name.as_str()))
                    .collect();
                for decl in &mut program.libfunc_declarations {
                    if let (Some(id), None) = (decl.id.id, decl.id.debug_name.as_deref()) {
                        if let Some(name) = libfunc_names.get(&id) {
                            decl.id.debug_name = Some((*name).to_string());
                            decl.generic_id =
                                name.split('<').next().unwrap_or(name).trim().to_string();
                        }
                    }
                }

                let type_names: std::collections::HashMap<u64, &str> = debug_info
                    .type_names
                    .iter()
                    .map(|(id, name)| (*id, name.as_str()))
                    .collect();
                for decl in &mut program.type_declarations {
                    if let (Some(id), None) = (decl.id.id, decl.id.debug_name.as_deref()) {
                        if let Some(name) = type_names.get(&id) {
                            decl.id.debug_name = Some((*name).to_string());
                            decl.generic_id =
                                name.split('<').next().unwrap_or(name).trim().to_string();
                        }
                    }
                }
            }

            Ok((program, statement_locations))
        }
        Err(err) => {
            // Fallback: create empty program with warning
            warnings.push(AnalyzerWarning {
                kind: crate::error::WarningKind::IncompatibleVersion,
                message: format!(
                    "Could not decode sierra_program in {} — only entry point metadata available: {err}",
                    path.display()
                ),
            });
            Ok((
                SierraProgram {
                    type_declarations: Vec::new(),
                    libfunc_declarations: Vec::new(),
                    statements: Vec::new(),
                    functions: extract_functions_from_debug_info(raw),
                },
                HashMap::new(),
            ))
        }
    }
}

fn extract_statement_locations(
    debug_info: &cairo_lang_sierra::debug_info::DebugInfo,
) -> HashMap<usize, SourceLocation> {
    let mut out = HashMap::new();
    let Ok(VersionedCoverageAnnotations::V1(coverage)) =
        VersionedCoverageAnnotations::try_from_debug_info(debug_info)
    else {
        return out;
    };

    for (stmt_idx, code_locations) in coverage.statements_code_locations {
        let Some(first) = code_locations.first() else {
            continue;
        };
        let (clean_path, _) = first.0.remove_virtual_file_markings();
        out.insert(
            stmt_idx.0,
            SourceLocation {
                file: Some(clean_path.to_string()),
                line: (first.1.start.line.0 as u32).saturating_add(1),
                col: (first.1.start.col.0 as u32).saturating_add(1),
            },
        );
    }

    out
}

fn extract_functions_from_debug_info(raw: &RawContractClass) -> Vec<Function> {
    let debug = match &raw.sierra_program_debug_info {
        Some(d) => d,
        None => return Vec::new(),
    };

    debug
        .user_func_names
        .iter()
        .enumerate()
        .map(|(_idx, (id, name))| Function {
            id: SierraId {
                id: Some(*id),
                debug_name: Some(name.clone()),
            },
            param_types: Vec::new(),
            ret_types: Vec::new(),
            params: Vec::new(),
            entry_point: 0,
        })
        .collect()
}

fn normalise_entry_points(raw: Option<&RawEntryPointsByType>) -> EntryPoints {
    let raw = match raw {
        Some(r) => r,
        None => return EntryPoints::default(),
    };

    EntryPoints {
        external: raw
            .external
            .iter()
            .map(|e| EntryPoint {
                selector: e.selector.clone(),
                function_idx: e.function_idx as usize,
            })
            .collect(),
        l1_handler: raw
            .l1_handler
            .iter()
            .map(|e| EntryPoint {
                selector: e.selector.clone(),
                function_idx: e.function_idx as usize,
            })
            .collect(),
        constructor: raw
            .constructor
            .iter()
            .map(|e| EntryPoint {
                selector: e.selector.clone(),
                function_idx: e.function_idx as usize,
            })
            .collect(),
    }
}

fn normalise_raw_program(
    raw: RawSierraProgram,
    warnings: &mut Vec<AnalyzerWarning>,
) -> SierraProgram {
    let type_declarations = raw
        .type_declarations
        .into_iter()
        .map(|t| TypeDeclaration {
            id: t.id,
            generic_id: t.long_id.generic_id,
            generic_args: t.long_id.generic_args,
            info: t.declared_type_info,
        })
        .collect();

    let libfunc_declarations = raw
        .libfunc_declarations
        .into_iter()
        .map(|l| LibfuncDeclaration {
            id: l.id,
            generic_id: l.long_id.generic_id,
            generic_args: l.long_id.generic_args,
        })
        .collect();

    let statements = raw
        .statements
        .into_iter()
        .map(|s| normalise_statement(s, warnings))
        .collect();

    let functions = raw
        .funcs
        .into_iter()
        .map(|f| Function {
            id: f.id,
            param_types: f.signature.param_types,
            ret_types: f.signature.ret_types,
            params: f.params.into_iter().map(|p| (p.id.0, p.ty)).collect(),
            entry_point: f.entry_point as usize,
        })
        .collect();

    SierraProgram {
        type_declarations,
        libfunc_declarations,
        statements,
        functions,
    }
}

fn normalise_statement(raw: RawStatement, _warnings: &mut Vec<AnalyzerWarning>) -> Statement {
    match raw {
        RawStatement::Return { ret } => Statement::Return(ret.into_iter().map(|v| v.0).collect()),
        RawStatement::Invocation(inv) => {
            let branches = inv
                .inner
                .branches
                .into_iter()
                .map(|b| BranchInfo {
                    target: match &b.target {
                        RawBranchTarget::Fallthrough(_) => BranchTarget::Fallthrough,
                        RawBranchTarget::Statement { idx } => {
                            BranchTarget::Statement(*idx as usize)
                        }
                    },
                    results: b.results.into_iter().map(|v| v.0).collect(),
                })
                .collect();

            Statement::Invocation(Invocation {
                libfunc_id: inv.inner.libfunc_id,
                args: inv.inner.args.into_iter().map(|v| v.0).collect(),
                branches,
            })
        }
    }
}

/// Convert cairo-lang-sierra's Program type to our SierraProgram.
///
/// Direct field-by-field conversion to avoid JSON round-trip issues:
/// cairo-lang-sierra serializes `VarId` as `{"id": N, "debug_name": ...}` (a struct),
/// but our `RawVarId` expects plain integers. Direct conversion bypasses that mismatch.
fn convert_cairo_program(
    program: cairo_lang_sierra::program::Program,
    _warnings: &mut Vec<AnalyzerWarning>,
) -> SierraProgram {
    use cairo_lang_sierra::program::{GenBranchTarget, GenStatement};

    let type_declarations = program
        .type_declarations
        .into_iter()
        .map(|t| TypeDeclaration {
            id: SierraId {
                id: Some(t.id.id),
                debug_name: t.id.debug_name.as_ref().map(|s| s.to_string()),
            },
            generic_id: t.long_id.generic_id.0.to_string(),
            generic_args: Vec::new(),
            info: t.declared_type_info.map(|dti| RawDeclaredTypeInfo {
                storable: dti.storable,
                droppable: dti.droppable,
                duplicatable: dti.duplicatable,
                zero_sized: dti.zero_sized,
            }),
        })
        .collect();

    let libfunc_declarations = program
        .libfunc_declarations
        .into_iter()
        .map(|l| LibfuncDeclaration {
            id: SierraId {
                id: Some(l.id.id),
                debug_name: l.id.debug_name.as_ref().map(|s| s.to_string()),
            },
            generic_id: l.long_id.generic_id.0.to_string(),
            generic_args: Vec::new(),
        })
        .collect();

    let statements = program
        .statements
        .into_iter()
        .map(|s| match s {
            GenStatement::Return(vars) => {
                Statement::Return(vars.into_iter().map(|v| v.id).collect())
            }
            GenStatement::Invocation(inv) => Statement::Invocation(Invocation {
                libfunc_id: SierraId {
                    id: Some(inv.libfunc_id.id),
                    debug_name: inv.libfunc_id.debug_name.as_ref().map(|s| s.to_string()),
                },
                args: inv.args.into_iter().map(|v| v.id).collect(),
                branches: inv
                    .branches
                    .into_iter()
                    .map(|b| BranchInfo {
                        target: match b.target {
                            GenBranchTarget::Fallthrough => BranchTarget::Fallthrough,
                            GenBranchTarget::Statement(idx) => BranchTarget::Statement(idx.0),
                        },
                        results: b.results.into_iter().map(|v| v.id).collect(),
                    })
                    .collect(),
            }),
        })
        .collect();

    let functions = program
        .funcs
        .into_iter()
        .map(|f| Function {
            id: SierraId {
                id: Some(f.id.id),
                debug_name: f.id.debug_name.as_ref().map(|s| s.to_string()),
            },
            param_types: f
                .signature
                .param_types
                .iter()
                .map(|ty| SierraId {
                    id: Some(ty.id),
                    debug_name: ty.debug_name.as_ref().map(|s| s.to_string()),
                })
                .collect(),
            ret_types: f
                .signature
                .ret_types
                .iter()
                .map(|ty| SierraId {
                    id: Some(ty.id),
                    debug_name: ty.debug_name.as_ref().map(|s| s.to_string()),
                })
                .collect(),
            params: f
                .params
                .into_iter()
                .map(|p| {
                    (
                        p.id.id,
                        SierraId {
                            id: Some(p.ty.id),
                            debug_name: p.ty.debug_name.as_ref().map(|s| s.to_string()),
                        },
                    )
                })
                .collect(),
            entry_point: f.entry_point.0,
        })
        .collect();

    SierraProgram {
        type_declarations,
        libfunc_declarations,
        statements,
        functions,
    }
}

impl Default for RawSierraProgram {
    fn default() -> Self {
        Self {
            type_declarations: Vec::new(),
            libfunc_declarations: Vec::new(),
            statements: Vec::new(),
            funcs: Vec::new(),
        }
    }
}

/// Resolve all .sierra.json and .contract_class.json files under a directory.
pub fn resolve_artifacts(dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    fn walk(dir: &Path, paths: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(&p, paths);
            } else if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".sierra.json") || name.ends_with(".contract_class.json") {
                    paths.push(p);
                }
            }
        }
    }

    walk(dir, &mut paths);
    paths.sort();
    paths
}
