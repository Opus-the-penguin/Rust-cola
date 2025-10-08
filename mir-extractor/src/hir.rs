#![cfg(feature = "hir-driver")]

use super::{detect_crate_name, discover_rustc_targets, RustcTarget};
use crate::SourceSpan;
use anyhow::{anyhow, Context, Result};
use rustc_ast::{AttrKind, Attribute};
use rustc_hir::definitions::{DisambiguatedDefPathData, CRATE_DEF_INDEX};
use rustc_hir::{
    self,
    def::{CtorKind, DefKind},
    def_id::DefId,
    def_id::LocalDefId,
    Node,
};
use rustc_middle::ty::{self, print::with_no_trimmed_paths, ImplPolarity, TyCtxt};
use rustc_span::{symbol::kw, Span, Symbol};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HirItem {
    pub def_path: String,
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
}

#[derive(Clone, Debug, Default)]
pub struct HirIndex {
    by_path: HashMap<String, usize>,
}

const WRAPPER_ENV: &str = "MIR_COLA_HIR_WRAPPER";
const TARGET_SPEC_ENV: &str = "MIR_COLA_HIR_TARGET_SPEC";
const CAPTURE_OUT_ENV: &str = "MIR_COLA_HIR_CAPTURE_OUT";
const CAPTURE_ROOT_ENV: &str = "MIR_COLA_HIR_CAPTURE_ROOT";

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

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&canonical);
    cmd.env_remove("RUSTC");
    cmd.env_remove("RUSTFLAGS");
    cmd.arg("+nightly");
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

    let status = cmd
        .status()
        .with_context(|| format!("run cargo rustc with wrapper in {}", canonical.display()))?;

    if !status.success() {
        return Err(anyhow!(
            "cargo rustc failed while capturing HIR for {}",
            canonical.display()
        ));
    }

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
    Ok(package)
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
    let mut path = env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("rust-cola-hir-{nanos}.json"));
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
        for (idx, item) in package.items.iter().enumerate() {
            by_path.insert(item.def_path.clone(), idx);
        }
        HirIndex { by_path }
    }

    pub fn lookup<'a>(&'a self, package: &'a HirPackage, def_path: &str) -> Option<&'a HirItem> {
        self.by_path
            .get(def_path)
            .and_then(|idx| package.items.get(*idx))
    }

    pub fn contains(&self, def_path: &str) -> bool {
        self.by_path.contains_key(def_path)
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
                mir_local_count: mir.local_decls.len(),
                mir_basic_block_count: mir.basic_blocks.len(),
            });
        }

        items.push(HirItem {
            def_path,
            def_kind,
            span,
            attributes,
            visibility,
            symbol,
            kind,
        });
    }

    HirPackage {
        crate_name,
        crate_root: crate_root.to_string(),
        target: target.clone(),
        items,
        functions,
    }
}

fn collect_attributes(tcx: TyCtxt<'_>, def_id: DefId) -> Vec<String> {
    tcx.get_attrs(def_id).iter().map(attribute_name).collect()
}

fn attribute_name(attr: &Attribute) -> String {
    match &attr.kind {
        AttrKind::Normal(normal) => normal
            .item
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.name.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        AttrKind::DocComment(..) => "doc".to_string(),
    }
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
    let hir = tcx.hir();
    let hir_id = hir.local_def_id_to_hir_id(local_def_id);
    Some(match hir.get(hir_id) {
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
    let name = item.ident.name.to_string();
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
            is_unsafe: matches!(safety, hir::Safety::Unsafe),
        }),
        hir::ItemKind::Impl(..) => HirItemKind::Impl(build_impl_info(tcx, def_id)),
        hir::ItemKind::Fn { sig, has_body, .. } => {
            HirItemKind::Function(build_function(sig, *has_body, HirFunctionOwner::Free, name))
        }
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
            abi: abi.name().to_string(),
        }),
        hir::ItemKind::Macro(..) => HirItemKind::Macro(HirNamedItem { name }),
        _ => HirItemKind::Other(HirNamedItem { name }),
    }
}

fn classify_impl_item(tcx: TyCtxt<'_>, def_id: DefId, item: &hir::ImplItem<'_>) -> HirItemKind {
    let name = item.ident.name.to_string();
    match item.kind {
        hir::ImplItemKind::Fn(ref sig, _) => {
            let parent_impl = tcx.parent(def_id).expect("impl item without parent impl");
            let owner = impl_owner_info(tcx, parent_impl);
            HirItemKind::Function(build_function(sig, true, owner, name))
        }
        hir::ImplItemKind::Const(..) => HirItemKind::Const(HirConst {
            name,
            ty: format_type_of(tcx, def_id),
        }),
        hir::ImplItemKind::Type(..) => HirItemKind::TypeAlias(HirTypeAlias { name }),
    }
}

fn classify_trait_item(tcx: TyCtxt<'_>, def_id: DefId, item: &hir::TraitItem<'_>) -> HirItemKind {
    let name = item.ident.name.to_string();
    match item.kind {
        hir::TraitItemKind::Fn(ref sig, ref trait_fn) => {
            let provided = matches!(trait_fn, hir::TraitFn::Provided(_));
            let owner = trait_owner_info(tcx, def_id, provided);
            HirItemKind::Function(build_function(sig, provided, owner, name))
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
    let name = item.ident.name.to_string();
    match item.kind {
        hir::ForeignItemKind::Fn(ref sig, ..) => {
            let abi = sig.header.abi.name().to_string();
            HirItemKind::Function(build_function(
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
        .map(|trait_ref| format_trait_ref(tcx, trait_ref));
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
        .map(|trait_ref| format_trait_ref(tcx, trait_ref));
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
        abi: header.abi.name().to_string(),
        has_body,
        owner,
    }
}

fn trait_owner_info(tcx: TyCtxt<'_>, def_id: DefId, provided: bool) -> HirFunctionOwner {
    let trait_def_id = tcx.parent(def_id).expect("trait item without parent trait");
    let trait_name = tcx.item_name(trait_def_id).to_string();
    HirFunctionOwner::Trait {
        trait_name,
        provided,
    }
}

fn format_type_of(tcx: TyCtxt<'_>, def_id: DefId) -> String {
    with_no_trimmed_paths(|| tcx.type_of(def_id).skip_binder().to_string())
}

fn format_trait_ref<'tcx>(tcx: TyCtxt<'tcx>, trait_ref: ty::TraitRef<'tcx>) -> String {
    with_no_trimmed_paths(|| trait_ref.to_string())
}

fn struct_kind_from_variant(data: &hir::VariantData<'_>) -> HirStructKind {
    match data.ctor_kind() {
        Some(CtorKind::Const) => HirStructKind::Unit,
        Some(CtorKind::Fn) => HirStructKind::Tuple,
        Some(CtorKind::Fictive) | None => {
            if data.fields().is_empty() {
                HirStructKind::Unit
            } else {
                HirStructKind::Record
            }
        }
    }
}

fn use_path_to_string(path: &hir::UsePath<'_>) -> String {
    let mut segments = Vec::with_capacity(path.segments.len());
    for segment in path.segments {
        let name = segment.ident.name;
        if name == kw::PathRoot {
            continue;
        }
        segments.push(name.to_string());
    }
    let joined = segments.join("::");
    if path.is_global() {
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
