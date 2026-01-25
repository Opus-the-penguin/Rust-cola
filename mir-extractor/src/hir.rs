#![cfg(feature = "hir-driver")]

use super::{build_cargo_command, detect_crate_name, discover_rustc_targets, RustcTarget};
use crate::SourceSpan;
use anyhow::{anyhow, Context, Result};
use hir::def::{CtorKind, DefKind};
use hir::def_id::{DefId, LocalDefId};
use hir::definitions::DisambiguatedDefPathData;
use hir::Node;
use rustc_hir as hir;
use rustc_middle::ty::{self, print::with_no_trimmed_paths, ImplPolarity, TyCtxt};
use rustc_span::def_id::CRATE_DEF_INDEX;
use rustc_span::{symbol::kw, Span, Symbol};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirItem {
    pub def_path: String,
    #[serde(default)]
    pub def_path_hash: String,
    pub def_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpan>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<HirVisibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<HirSymbol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<HirItemKind>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum HirVisibility {
    Public,
    Crate { crate_name: String },
    Restricted { parent: String },
    Private,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirSymbol {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disambiguator: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum HirItemKind {
    Module(HirNamedItem),
    Struct(HirStruct),
    Enum(HirEnum),
    Union(HirStruct),
    Trait(HirTrait),
    Impl(HirImpl),
    TypeAlias(HirTypeAlias),
    Const(HirConst),
    Static(HirStatic),
    Use(HirUse),
    ExternCrate(HirExternCrate),
    ForeignMod(HirForeignMod),
    Function(HirFunction),
    Macro(HirNamedItem),
    Other(HirNamedItem),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirNamedItem {
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirStruct {
    pub name: String,
    pub kind: HirStructKind,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HirStructKind {
    Record,
    Tuple,
    Unit,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirEnum {
    pub name: String,
    pub variants: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirTrait {
    pub name: String,
    pub is_auto: bool,
    pub is_unsafe: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirImpl {
    pub self_ty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trait_ref: Option<String>,
    pub polarity: HirImplPolarity,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HirImplPolarity {
    Positive,
    Negative,
    Reservation,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirTypeAlias {
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirConst {
    pub name: String,
    pub ty: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirStatic {
    pub name: String,
    pub mutable: bool,
    pub ty: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirUse {
    pub path: String,
    pub is_glob: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirExternCrate {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirForeignMod {
    pub abi: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirFunction {
    pub name: String,
    pub asyncness: bool,
    pub constness: bool,
    pub unsafety: bool,
    pub abi: String,
    pub has_body: bool,
    pub owner: HirFunctionOwner,
    #[serde(default)]
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "owner", content = "data", rename_all = "snake_case")]
pub enum HirFunctionOwner {
    Free,
    Impl {
        self_ty: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trait_ref: Option<String>,
    },
    Trait {
        trait_name: String,
        provided: bool,
    },
    Foreign {
        abi: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirFunctionBody {
    pub def_path: String,
    #[serde(default)]
    pub def_path_hash: String,
    #[serde(default)]
    pub signature: String,
    pub mir_local_count: usize,
    pub mir_basic_block_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirTargetSpec {
    pub kind: String,
    pub crate_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirPackage {
    pub crate_name: String,
    pub crate_root: String,
    pub target: HirTargetSpec,
    pub items: Vec<HirItem>,
    #[serde(default)]
    pub functions: Vec<HirFunctionBody>,
    #[serde(default)]
    pub type_metadata: Vec<HirTypeMetadata>,
}

/// Type metadata for semantic analysis
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirTypeMetadata {
    /// Type name (def_path)
    pub type_name: String,
    /// Size in bytes (None for unsized types)
    pub size_bytes: Option<usize>,
    /// Whether the type implements Send
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_send: Option<bool>,
    /// Whether the type implements Sync
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_sync: Option<bool>,
    /// Whether the type is zero-sized (computed from size_bytes == Some(0))
    #[serde(default)]
    pub is_zst: bool,
}

#[derive(Clone, Debug, Default)]
pub struct HirIndex {
    by_path: HashMap<String, usize>,
    by_hash: HashMap<String, usize>,
    function_by_path: HashMap<String, usize>,
    function_by_hash: HashMap<String, usize>,
}

const WRAPPER_ENV: &str = "MIR_COLA_HIR_WRAPPER";
const TARGET_SPEC_ENV: &str = "MIR_COLA_HIR_TARGET_SPEC";
const CAPTURE_OUT_ENV: &str = "MIR_COLA_HIR_CAPTURE_OUT";
const CAPTURE_ROOT_ENV: &str = "MIR_COLA_HIR_CAPTURE_ROOT";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HirCaptureErrorKind {
    RustcIce,
    CommandFailed,
}

#[derive(Debug)]
pub struct HirCaptureError {
    command: String,
    status: Option<i32>,
    stdout: String,
    stderr: String,
    kind: HirCaptureErrorKind,
}

impl HirCaptureError {
    pub fn rustc_ice(command: String, status: Option<i32>, stdout: String, stderr: String) -> Self {
        Self {
            command,
            status,
            stdout,
            stderr,
            kind: HirCaptureErrorKind::RustcIce,
        }
    }

    pub fn command_failed(
        command: String,
        status: Option<i32>,
        stdout: String,
        stderr: String,
    ) -> Self {
        Self {
            command,
            status,
            stdout,
            stderr,
            kind: HirCaptureErrorKind::CommandFailed,
        }
    }

    pub fn kind(&self) -> HirCaptureErrorKind {
        self.kind
    }

    pub fn status(&self) -> Option<i32> {
        self.status
    }

    pub fn stderr(&self) -> &str {
        &self.stderr
    }

    pub fn primary_diagnostic(&self) -> String {
        self.stderr
            .lines()
            .map(|line| line.trim())
            .find(|line| !line.is_empty())
            .map(str::to_string)
            .or_else(|| {
                if self.stdout.trim().is_empty() {
                    None
                } else {
                    Some(self.stdout.trim().to_string())
                }
            })
            .unwrap_or_else(|| "no compiler diagnostics captured".to_string())
    }
}

impl fmt::Display for HirCaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status_text = self
            .status
            .map(|code| code.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        match self.kind {
            HirCaptureErrorKind::RustcIce => write!(
                f,
                "{} exited with a rustc ICE (status {}): {}",
                self.command,
                status_text,
                self.primary_diagnostic()
            ),
            HirCaptureErrorKind::CommandFailed => write!(
                f,
                "{} failed with status {}: {}",
                self.command,
                status_text,
                self.primary_diagnostic()
            ),
        }
    }
}

impl std::error::Error for HirCaptureError {}

fn format_def_path_hash(hash: rustc_span::def_id::DefPathHash) -> String {
    hash.0.to_hex()
}

fn format_full_fn_signature(tcx: TyCtxt<'_>, def_id: DefId) -> String {
    let _guard = with_no_trimmed_paths();
    let sig = tcx.fn_sig(def_id).instantiate_identity();
    let safety = sig.safety();
    let abi_name = sig.abi().as_str();
    let inputs = sig.inputs().skip_binder();
    let c_variadic = sig.c_variadic();
    let output = sig.output().skip_binder();
    let mut parts = String::new();

    if safety.is_unsafe() {
        parts.push_str("unsafe ");
    }

    if abi_name != "Rust" {
        parts.push_str("extern \"");
        parts.push_str(abi_name);
        parts.push_str("\" ");
    }

    parts.push_str("fn ");
    parts.push_str(&tcx.def_path_str(def_id));
    parts.push('(');

    for (idx, ty) in inputs.iter().enumerate() {
        if idx > 0 {
            parts.push_str(", ");
        }
        parts.push_str(&ty.to_string());
    }

    if c_variadic {
        if !inputs.is_empty() {
            parts.push_str(", ");
        }
        parts.push_str("...");
    }

    parts.push(')');

    if !output.is_unit() {
        parts.push_str(" -> ");
        parts.push_str(&output.to_string());
    }

    parts
}

pub fn capture_hir(crate_path: &Path) -> Result<HirPackage> {
    let canonical =
        fs::canonicalize(crate_path).context("canonicalize crate path for HIR capture")?;
    let targets = discover_rustc_targets(&canonical)?;

    if targets.is_empty() {
        return Err(anyhow!(
            "crate {} has no targets to compile for HIR capture",
            canonical.display()
        ));
    }

    let detected_name = detect_crate_name(&canonical).unwrap_or_else(|| {
        canonical
            .file_name()
            .and_then(|os| os.to_str())
            .unwrap_or("unknown")
            .to_string()
    });
    let sanitized_detected = sanitize_crate_name(&detected_name);

    let primary = targets
        .iter()
        .find(|target| matches!(target, RustcTarget::Lib))
        .cloned()
        .unwrap_or_else(|| targets[0].clone());

    let target_spec = HirTargetSpec::from_target(&primary, &sanitized_detected);
    let wrapper_path = locate_wrapper_executable()?;
    let output_path = unique_output_path()?;

    if output_path.exists() {
        fs::remove_file(&output_path).ok();
    }

    let mut cmd = build_cargo_command();
    cmd.current_dir(&canonical);
    cmd.env_remove("RUSTC");
    cmd.env_remove("RUSTFLAGS");

    // Use a dedicated target directory for HIR capture to avoid cache issues
    let hir_target_dir = env::temp_dir().join("rust-cola-hir-builds");
    fs::create_dir_all(&hir_target_dir).ok();
    cmd.env("CARGO_TARGET_DIR", &hir_target_dir);

    cmd.arg("rustc");

    match &primary {
        RustcTarget::Lib => {
            cmd.arg("--lib");
        }
        RustcTarget::Bin(name) => {
            cmd.arg("--bin");
            cmd.arg(name);
        }
    }

    cmd.arg("--quiet");

    cmd.env("RUSTC_WRAPPER", &wrapper_path);
    cmd.env(CAPTURE_OUT_ENV, &output_path);
    cmd.env(
        CAPTURE_ROOT_ENV,
        canonical
            .to_str()
            .ok_or_else(|| anyhow!("crate path is not valid UTF-8"))?,
    );
    cmd.env(
        TARGET_SPEC_ENV,
        serde_json::to_string(&target_spec).expect("serialize target spec"),
    );

    cmd.arg("--");
    cmd.args(["--emit", "metadata"]);

    // Add a unique metadata string to force cargo to treat each HIR capture as a fresh build
    // This prevents cargo from reusing cached builds with stale environment variables
    let unique_metadata = format!(
        "hir_capture_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    cmd.args(["-C", &format!("metadata={}", unique_metadata)]);

    let command_display = describe_command(&cmd);
    let output = cmd
        .output()
        .with_context(|| format!("run cargo rustc with wrapper in {}", canonical.display()))?;

    if output.status.success() {
        let data = fs::read(&output_path)
            .with_context(|| format!("read HIR capture output from {}", output_path.display()))?;
        fs::remove_file(&output_path).ok();

        let mut package: HirPackage =
            serde_json::from_slice(&data).context("parse captured HIR JSON")?;
        package.target = target_spec;
        package.crate_root = canonical
            .to_str()
            .ok_or_else(|| anyhow!("crate root is not valid UTF-8"))?
            .to_string();
        return Ok(package);
    }

    if output_path.exists() {
        fs::remove_file(&output_path).ok();
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let status_code = output.status.code();

    if is_rustc_ice(&stdout, &stderr) {
        return Err(
            HirCaptureError::rustc_ice(command_display, status_code, stdout, stderr).into(),
        );
    }

    Err(HirCaptureError::command_failed(command_display, status_code, stdout, stderr).into())
}

fn describe_command(cmd: &Command) -> String {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let args: Vec<String> = cmd
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    if args.is_empty() {
        program
    } else {
        format!("{} {}", program, args.join(" "))
    }
}

fn is_rustc_ice(stdout: &str, stderr: &str) -> bool {
    let mut combined = String::with_capacity(stdout.len() + stderr.len() + 1);
    combined.push_str(stdout);
    if !stdout.is_empty() && !stderr.is_empty() {
        combined.push('\n');
    }
    combined.push_str(stderr);
    let lower = combined.to_lowercase();

    lower.contains("internal compiler error")
        || lower.contains("thread 'rustc' panicked")
        || lower.contains("the compiler unexpectedly panicked")
        || lower.contains("query stack during panic")
}

pub fn locate_wrapper_executable() -> Result<PathBuf> {
    if let Ok(path) = env::var(WRAPPER_ENV) {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    if let Some(path) = option_env!("CARGO_BIN_EXE_hir-driver-wrapper") {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    let current = env::current_exe().context("determine current executable path")?;
    let wrapper_name = if cfg!(windows) {
        "hir-driver-wrapper.exe"
    } else {
        "hir-driver-wrapper"
    };
    let candidate = current.with_file_name(wrapper_name);
    if candidate.exists() {
        return Ok(candidate);
    }

    Err(anyhow!(
        "unable to locate hir-driver-wrapper executable; set {} to override",
        WRAPPER_ENV
    ))
}

fn unique_output_path() -> Result<PathBuf> {
    // Use PID to make path unique per process, not timestamp
    // This avoids issues with cargo caching stale timestamps
    let mut path = env::temp_dir();
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("rust-cola-hir-{pid}-{nanos}.json"));
    Ok(path)
}

fn sanitize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

impl HirTargetSpec {
    fn from_target(target: &RustcTarget, detected_crate_name: &str) -> Self {
        match target {
            RustcTarget::Lib => HirTargetSpec {
                kind: "lib".to_string(),
                crate_name: detected_crate_name.to_string(),
                target_name: None,
            },
            RustcTarget::Bin(name) => HirTargetSpec {
                kind: "bin".to_string(),
                crate_name: sanitize_crate_name(name),
                target_name: Some(name.clone()),
            },
        }
    }
}

impl HirIndex {
    pub fn build(package: &HirPackage) -> Self {
        let mut by_path = HashMap::with_capacity(package.items.len());
        let mut by_hash = HashMap::with_capacity(package.items.len());
        for (idx, item) in package.items.iter().enumerate() {
            by_path.insert(item.def_path.clone(), idx);
            if !item.def_path_hash.is_empty() {
                by_hash.insert(item.def_path_hash.clone(), idx);
            }
        }

        let mut function_by_path = HashMap::with_capacity(package.functions.len());
        let mut function_by_hash = HashMap::with_capacity(package.functions.len());
        for (idx, body) in package.functions.iter().enumerate() {
            function_by_path.insert(body.def_path.clone(), idx);
            if !body.def_path_hash.is_empty() {
                function_by_hash.insert(body.def_path_hash.clone(), idx);
            }
        }

        HirIndex {
            by_path,
            by_hash,
            function_by_path,
            function_by_hash,
        }
    }

    pub fn lookup<'a>(&'a self, package: &'a HirPackage, def_path: &str) -> Option<&'a HirItem> {
        self.by_path
            .get(def_path)
            .and_then(|idx| package.items.get(*idx))
    }

    pub fn contains(&self, def_path: &str) -> bool {
        self.by_path.contains_key(def_path)
    }

    pub fn lookup_hash<'a>(
        &'a self,
        package: &'a HirPackage,
        def_path_hash: &str,
    ) -> Option<&'a HirItem> {
        self.by_hash
            .get(def_path_hash)
            .and_then(|idx| package.items.get(*idx))
    }

    pub fn lookup_function<'a>(
        &'a self,
        package: &'a HirPackage,
        def_path: &str,
    ) -> Option<&'a HirFunctionBody> {
        self.function_by_path
            .get(def_path)
            .and_then(|idx| package.functions.get(*idx))
    }

    pub fn lookup_function_by_hash<'a>(
        &'a self,
        package: &'a HirPackage,
        def_path_hash: &str,
    ) -> Option<&'a HirFunctionBody> {
        self.function_by_hash
            .get(def_path_hash)
            .and_then(|idx| package.functions.get(*idx))
    }
}

pub fn collect_crate_snapshot<'tcx>(
    tcx: TyCtxt<'tcx>,
    target: &HirTargetSpec,
    crate_root: &str,
) -> HirPackage {
    let crate_name = tcx
        .crate_name(rustc_span::def_id::LOCAL_CRATE)
        .as_str()
        .to_string();
    let mut items = Vec::new();
    let mut functions = Vec::new();

    let hir_items = tcx.hir_crate_items(());

    for local_def_id in hir_items.definitions() {
        let def_id: DefId = local_def_id.to_def_id();
        let def_path = tcx.def_path_str(def_id);
        let def_path_hash = format_def_path_hash(tcx.def_path_hash(def_id));
        let def_kind = format!("{:?}", tcx.def_kind(def_id));
        let span = span_to_source_span(tcx, tcx.def_span(def_id));
        let attributes = collect_attributes(tcx, def_id);
        let visibility = to_hir_visibility(tcx, def_id);
        let symbol = build_symbol(tcx, def_id);
        let kind = classify_item(tcx, def_id, local_def_id);

        if matches!(
            tcx.def_kind(def_id),
            DefKind::Fn | DefKind::AssocFn | DefKind::Ctor(..)
        ) {
            let mir = tcx.optimized_mir(local_def_id);
            functions.push(HirFunctionBody {
                def_path: def_path.clone(),
                def_path_hash: def_path_hash.clone(),
                signature: format_full_fn_signature(tcx, def_id),
                mir_local_count: mir.local_decls.len(),
                mir_basic_block_count: mir.basic_blocks.len(),
            });
        }

        items.push(HirItem {
            def_path,
            def_path_hash,
            def_kind,
            span,
            attributes,
            visibility,
            symbol,
            kind,
        });
    }

    // Collect type metadata for structs and enums
    let mut type_metadata = Vec::new();
    for local_def_id in hir_items.definitions() {
        let def_id: DefId = local_def_id.to_def_id();
        let def_kind = tcx.def_kind(def_id);

        // Only collect metadata for types that can have instances
        if matches!(def_kind, DefKind::Struct | DefKind::Enum | DefKind::Union) {
            let def_path = tcx.def_path_str(def_id);

            // Try to get type size
            let size_bytes = extract_type_size(tcx, def_id);

            // Compute is_zst from size
            let is_zst = size_bytes == Some(0);

            // Extract Send/Sync trait implementation status
            let is_send = extract_type_is_send(tcx, def_id);
            let is_sync = extract_type_is_sync(tcx, def_id);

            type_metadata.push(HirTypeMetadata {
                type_name: def_path,
                size_bytes,
                is_send,
                is_sync,
                is_zst,
            });
        }
    }

    HirPackage {
        crate_name,
        crate_root: crate_root.to_string(),
        target: target.clone(),
        items,
        functions,
        type_metadata,
    }
}

fn collect_attributes(tcx: TyCtxt<'_>, def_id: DefId) -> Vec<String> {
    tcx.get_all_attrs(def_id)
        .iter()
        .map(attribute_name)
        .collect()
}

/// Extract the size of a type in bytes
/// Returns None for unsized types or if size cannot be determined
fn extract_type_size<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> Option<usize> {
    // Get the type
    let ty = tcx.type_of(def_id).instantiate_identity();

    // Create TypingEnv from def_id - the API takes a def_id, not a param_env
    let typing_env = rustc_middle::ty::TypingEnv::non_body_analysis(tcx, def_id);

    // Create the query input
    let query_input = rustc_middle::ty::PseudoCanonicalInput {
        typing_env,
        value: ty,
    };

    match tcx.layout_of(query_input) {
        Ok(layout) => Some(layout.size.bytes() as usize),
        Err(_) => None,
    }
}

/// Check if a type implements a given trait
/// Uses the trait solver to properly evaluate trait bounds including auto traits
fn type_implements_trait<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
    trait_def_id: DefId,
) -> Option<bool> {
    use rustc_infer::infer::TyCtxtInferExt;
    use rustc_infer::traits::{Obligation, ObligationCause};
    use rustc_middle::ty::{TypeVisitableExt, Upcast};
    use rustc_trait_selection::traits::query::evaluate_obligation::InferCtxtExt;

    // Get the type
    let ty = tcx.type_of(def_id).instantiate_identity();

    // Skip types with unsubstituted generics - we can't evaluate trait bounds for them
    if ty.has_param() {
        return None;
    }

    // Create TypingEnv for non-body analysis
    let typing_env = ty::TypingEnv::non_body_analysis(tcx, def_id);

    // Build inference context
    let (infcx, param_env) = tcx.infer_ctxt().build_with_typing_env(typing_env);

    // Create the trait reference: ty: Trait
    let trait_ref = ty::TraitRef::new(tcx, trait_def_id, [ty]);

    // Create the obligation
    let obligation = Obligation {
        cause: ObligationCause::dummy(),
        param_env,
        recursion_depth: 0,
        predicate: trait_ref.upcast(tcx),
    };

    // Evaluate the obligation
    // EvaluatedToOk or EvaluatedToOkModuloRegions means it definitely implements
    // EvaluatedToErr means it definitely does not implement
    // Other results (ambiguous) mean we can't determine
    let result = infcx.evaluate_obligation(&obligation);
    match result {
        Ok(eval_result) => {
            use rustc_middle::traits::EvaluationResult::*;
            match eval_result {
                EvaluatedToOk | EvaluatedToOkModuloRegions | EvaluatedToOkModuloOpaqueTypes => {
                    Some(true)
                }
                EvaluatedToErr => Some(false),
                // Ambiguous results - can't determine
                _ => None,
            }
        }
        Err(_) => None,
    }
}

/// Extract whether a type implements Send
fn extract_type_is_send<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> Option<bool> {
    use rustc_span::sym;
    let send_trait = tcx.get_diagnostic_item(sym::Send)?;
    type_implements_trait(tcx, def_id, send_trait)
}

/// Extract whether a type implements Sync
fn extract_type_is_sync<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> Option<bool> {
    use rustc_span::sym;
    let sync_trait = tcx.get_diagnostic_item(sym::Sync)?;
    type_implements_trait(tcx, def_id, sync_trait)
}

fn attribute_name(attr: &hir::Attribute) -> String {
    if attr.is_doc_comment() {
        return "doc".to_string();
    }

    attr.path()
        .iter()
        .map(|symbol| symbol.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn to_hir_visibility(tcx: TyCtxt<'_>, def_id: DefId) -> Option<HirVisibility> {
    match tcx.visibility(def_id) {
        ty::Visibility::Public => Some(HirVisibility::Public),
        ty::Visibility::Restricted(scope) => {
            let parent = tcx.opt_parent(def_id);
            if parent == Some(scope) {
                Some(HirVisibility::Private)
            } else if scope.index == CRATE_DEF_INDEX {
                let crate_name = tcx.crate_name(scope.krate).to_string();
                Some(HirVisibility::Crate { crate_name })
            } else {
                let parent = tcx.def_path_str(scope);
                Some(HirVisibility::Restricted { parent })
            }
        }
    }
}

fn build_symbol(tcx: TyCtxt<'_>, def_id: DefId) -> Option<HirSymbol> {
    let name = tcx.opt_item_name(def_id)?;
    let disambiguator = tcx
        .def_path(def_id)
        .data
        .last()
        .map(|DisambiguatedDefPathData { disambiguator, .. }| *disambiguator);
    Some(HirSymbol {
        name: name.to_string(),
        disambiguator,
    })
}

fn classify_item<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
    local_def_id: LocalDefId,
) -> Option<HirItemKind> {
    Some(match tcx.hir_node_by_def_id(local_def_id) {
        Node::Item(item) => classify_crate_item(tcx, def_id, item),
        Node::ImplItem(item) => classify_impl_item(tcx, def_id, item),
        Node::TraitItem(item) => classify_trait_item(tcx, def_id, item),
        Node::ForeignItem(item) => classify_foreign_item(tcx, def_id, item),
        _ => return None,
    })
}

fn classify_crate_item<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
    item: &'tcx hir::Item<'tcx>,
) -> HirItemKind {
    // Use opt_item_name because some items (like Use statements) don't have names
    let name = tcx
        .opt_item_name(def_id)
        .map(|sym| sym.to_string())
        .unwrap_or_else(|| String::from(""));
    match &item.kind {
        hir::ItemKind::Mod(..) => HirItemKind::Module(HirNamedItem { name }),
        hir::ItemKind::Struct(_, _, data) => HirItemKind::Struct(HirStruct {
            name,
            kind: struct_kind_from_variant(data),
        }),
        hir::ItemKind::Union(_, _, data) => HirItemKind::Union(HirStruct {
            name,
            kind: struct_kind_from_variant(data),
        }),
        hir::ItemKind::Enum(_, _, enum_def) => HirItemKind::Enum(HirEnum {
            name,
            variants: enum_def.variants.len(),
        }),
        hir::ItemKind::Trait(_, is_auto, safety, ..) => HirItemKind::Trait(HirTrait {
            name,
            is_auto: matches!(is_auto, hir::IsAuto::Yes),
            is_unsafe: safety.is_unsafe(),
        }),
        hir::ItemKind::Impl(..) => HirItemKind::Impl(build_impl_info(tcx, def_id)),
        hir::ItemKind::Fn { sig, has_body, .. } => HirItemKind::Function(build_function(
            tcx,
            def_id,
            sig,
            *has_body,
            HirFunctionOwner::Free,
            name,
        )),
        hir::ItemKind::Const(..) => HirItemKind::Const(HirConst {
            name,
            ty: format_type_of(tcx, def_id),
        }),
        hir::ItemKind::Static(mutability, ..) => HirItemKind::Static(HirStatic {
            name,
            mutable: matches!(mutability, hir::Mutability::Mut),
            ty: format_type_of(tcx, def_id),
        }),
        hir::ItemKind::TyAlias(..) | hir::ItemKind::TraitAlias(..) => {
            HirItemKind::TypeAlias(HirTypeAlias { name })
        }
        hir::ItemKind::Use(path, kind) => HirItemKind::Use(HirUse {
            path: use_path_to_string(path),
            is_glob: matches!(kind, hir::UseKind::Glob),
        }),
        hir::ItemKind::ExternCrate(original, _) => HirItemKind::ExternCrate(HirExternCrate {
            name,
            original: original.map(|sym: Symbol| sym.to_string()),
        }),
        hir::ItemKind::ForeignMod { abi, .. } => HirItemKind::ForeignMod(HirForeignMod {
            abi: abi.as_str().to_string(),
        }),
        hir::ItemKind::Macro(..) => HirItemKind::Macro(HirNamedItem { name }),
        _ => HirItemKind::Other(HirNamedItem { name }),
    }
}

fn classify_impl_item(tcx: TyCtxt<'_>, def_id: DefId, item: &hir::ImplItem<'_>) -> HirItemKind {
    let name = tcx
        .opt_item_name(def_id)
        .map(|sym| sym.to_string())
        .unwrap_or_else(|| String::from(""));
    match item.kind {
        hir::ImplItemKind::Fn(ref sig, _) => {
            let parent_impl = tcx
                .opt_parent(def_id)
                .expect("impl item without parent impl");
            let owner = impl_owner_info(tcx, parent_impl);
            HirItemKind::Function(build_function(tcx, def_id, sig, true, owner, name))
        }
        hir::ImplItemKind::Const(..) => HirItemKind::Const(HirConst {
            name,
            ty: format_type_of(tcx, def_id),
        }),
        hir::ImplItemKind::Type(..) => HirItemKind::TypeAlias(HirTypeAlias { name }),
    }
}

fn classify_trait_item(tcx: TyCtxt<'_>, def_id: DefId, item: &hir::TraitItem<'_>) -> HirItemKind {
    let name = tcx
        .opt_item_name(def_id)
        .map(|sym| sym.to_string())
        .unwrap_or_else(|| String::from(""));
    match item.kind {
        hir::TraitItemKind::Fn(ref sig, ref trait_fn) => {
            let provided = matches!(trait_fn, hir::TraitFn::Provided(_));
            let owner = trait_owner_info(tcx, def_id, provided);
            HirItemKind::Function(build_function(tcx, def_id, sig, provided, owner, name))
        }
        hir::TraitItemKind::Const(..) => HirItemKind::Const(HirConst {
            name,
            ty: format_type_of(tcx, def_id),
        }),
        hir::TraitItemKind::Type(..) => HirItemKind::TypeAlias(HirTypeAlias { name }),
    }
}

fn classify_foreign_item(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    item: &hir::ForeignItem<'_>,
) -> HirItemKind {
    let name = tcx
        .opt_item_name(def_id)
        .map(|sym| sym.to_string())
        .unwrap_or_else(|| String::from(""));
    match item.kind {
        hir::ForeignItemKind::Fn(ref sig, ..) => {
            let abi = sig.header.abi.as_str().to_string();
            HirItemKind::Function(build_function(
                tcx,
                def_id,
                sig,
                false,
                HirFunctionOwner::Foreign { abi },
                name,
            ))
        }
        hir::ForeignItemKind::Static(_, mutability, _) => HirItemKind::Static(HirStatic {
            name,
            mutable: matches!(mutability, hir::Mutability::Mut),
            ty: format_type_of(tcx, def_id),
        }),
        hir::ForeignItemKind::Type => HirItemKind::TypeAlias(HirTypeAlias { name }),
    }
}

fn build_impl_info(tcx: TyCtxt<'_>, def_id: DefId) -> HirImpl {
    let self_ty = format_type_of(tcx, def_id);
    let trait_ref = tcx
        .impl_trait_ref(def_id)
        .map(|trait_ref| format_trait_ref(trait_ref.instantiate_identity()));
    let polarity = map_impl_polarity(tcx.impl_polarity(def_id));
    HirImpl {
        self_ty,
        trait_ref,
        polarity,
    }
}

fn impl_owner_info(tcx: TyCtxt<'_>, impl_def_id: DefId) -> HirFunctionOwner {
    let self_ty = format_type_of(tcx, impl_def_id);
    let trait_ref = tcx
        .impl_trait_ref(impl_def_id)
        .map(|trait_ref| format_trait_ref(trait_ref.instantiate_identity()));
    HirFunctionOwner::Impl { self_ty, trait_ref }
}

fn map_impl_polarity(polarity: ImplPolarity) -> HirImplPolarity {
    match polarity {
        ImplPolarity::Positive => HirImplPolarity::Positive,
        ImplPolarity::Negative => HirImplPolarity::Negative,
        ImplPolarity::Reservation => HirImplPolarity::Reservation,
    }
}

fn build_function(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    sig: &hir::FnSig<'_>,
    has_body: bool,
    owner: HirFunctionOwner,
    name: String,
) -> HirFunction {
    let header = &sig.header;
    HirFunction {
        name,
        asyncness: header.is_async(),
        constness: header.is_const(),
        unsafety: header.is_unsafe(),
        abi: header.abi.as_str().to_string(),
        has_body,
        owner,
        signature: format_full_fn_signature(tcx, def_id),
    }
}

fn trait_owner_info(tcx: TyCtxt<'_>, def_id: DefId, provided: bool) -> HirFunctionOwner {
    let trait_def_id = tcx
        .opt_parent(def_id)
        .expect("trait item without parent trait");
    let trait_name = tcx
        .opt_item_name(trait_def_id)
        .map(|sym| sym.to_string())
        .unwrap_or_else(|| String::from(""));
    HirFunctionOwner::Trait {
        trait_name,
        provided,
    }
}

fn format_type_of(tcx: TyCtxt<'_>, def_id: DefId) -> String {
    let _guard = with_no_trimmed_paths();
    tcx.type_of(def_id).instantiate_identity().to_string()
}

fn format_trait_ref(trait_ref: ty::TraitRef<'_>) -> String {
    let _guard = with_no_trimmed_paths();
    trait_ref.to_string()
}

fn struct_kind_from_variant(data: &hir::VariantData<'_>) -> HirStructKind {
    match data.ctor_kind() {
        Some(CtorKind::Const) => HirStructKind::Unit,
        Some(CtorKind::Fn) => HirStructKind::Tuple,
        None => {
            if data.fields().is_empty() {
                HirStructKind::Unit
            } else {
                HirStructKind::Record
            }
        }
    }
}

fn use_path_to_string(path: &hir::UsePath<'_>) -> String {
    let is_global = path
        .segments
        .first()
        .is_some_and(|segment| segment.ident.name == kw::PathRoot);
    let mut segments = Vec::with_capacity(path.segments.len());
    for segment in path.segments.iter() {
        let name = segment.ident.name;
        if name == kw::PathRoot {
            continue;
        }
        segments.push(name.to_string());
    }
    let joined = segments.join("::");
    if is_global {
        format!("::{joined}")
    } else {
        joined
    }
}

fn span_to_source_span(tcx: TyCtxt<'_>, span: Span) -> Option<SourceSpan> {
    let sm = tcx.sess.source_map();
    let lo = sm.lookup_char_pos(span.lo());
    let hi = sm.lookup_char_pos(span.hi());

    let file = lo.file.name.prefer_local().to_string();

    Some(SourceSpan {
        file,
        start_line: lo.line as u32,
        start_column: lo.col_display as u32 + 1,
        end_line: hi.line as u32,
        end_column: hi.col_display as u32 + 1,
    })
}

pub fn target_spec_from_env() -> Result<HirTargetSpec> {
    let spec_json = env::var(TARGET_SPEC_ENV).context("missing HIR target spec in environment")?;
    let value: Value = serde_json::from_str(&spec_json).context("parse HIR target spec JSON")?;
    serde_json::from_value(value).context("deserialize HIR target spec")
}

pub fn capture_root_from_env() -> Result<String> {
    env::var(CAPTURE_ROOT_ENV).context("missing HIR capture root in environment")
}
