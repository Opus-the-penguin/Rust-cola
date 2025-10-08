#![cfg(feature = "hir-driver")]

use super::{detect_crate_name, discover_rustc_targets, RustcTarget};
use crate::SourceSpan;
use anyhow::{anyhow, Context, Result};
use rustc_hir::def::DefKind;
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;
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
        let attributes = Vec::new();

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
