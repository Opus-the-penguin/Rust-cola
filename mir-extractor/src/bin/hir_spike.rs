#![cfg(feature = "hir-driver")]
#![feature(rustc_private)]

use anyhow::{Context, Result};
use rustc_driver::{run_compiler, Callbacks, Compilation};
use rustc_hir::def::DefKind;
use rustc_interface::interface::Compiler;
use rustc_middle::ty::TyCtxt;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use toml::Value;

extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

fn main() {
    if let Err(err) = run() {
        eprintln!("hir-spike failed: {err:?}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let crate_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("examples/simple"));

    let manifest_path = if crate_dir.is_file() {
        crate_dir.clone()
    } else {
        crate_dir.join("Cargo.toml")
    };

    let manifest_dir = manifest_path
        .parent()
        .context("manifest path should have a parent directory")?
        .to_path_buf();

    let manifest = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read manifest at {}", manifest_path.display()))?;
    let manifest_toml: Value = toml::from_str(&manifest).context("parse Cargo.toml")?;

    let package_name = manifest_toml
        .get("package")
        .and_then(|pkg| pkg.get("name"))
        .and_then(Value::as_str)
        .context("package.name missing from manifest")?
        .to_string();

    let crate_name = package_name.replace('-', "_");

    let source_path = manifest_toml
        .get("lib")
        .and_then(|lib| lib.get("path"))
        .and_then(Value::as_str)
        .map(|relative| manifest_dir.join(relative))
        .unwrap_or_else(|| manifest_dir.join("src/lib.rs"));

    if !source_path.exists() {
        anyhow::bail!("lib source path {} does not exist", source_path.display());
    }

    let sysroot = detect_sysroot()?;

    let out_dir = manifest_dir.join("target/hir-spike");
    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let rustc_args = vec![
        "rustc".to_string(),
        source_path.to_string_lossy().to_string(),
        "--crate-type".to_string(),
        "lib".to_string(),
        "--crate-name".to_string(),
        crate_name.clone(),
        "--edition".to_string(),
        "2021".to_string(),
        "--emit".to_string(),
        "metadata".to_string(),
        "--out-dir".to_string(),
        out_dir.to_string_lossy().to_string(),
        "--sysroot".to_string(),
        sysroot,
    ];

    let mut callbacks = HirDumpCallbacks::default();
    run_compiler(&rustc_args, &mut callbacks);
    Ok(())
}

fn detect_sysroot() -> Result<String> {
    if let Ok(path) = env::var("SYSROOT") {
        if !path.trim().is_empty() {
            return Ok(path);
        }
    }

    let output = Command::new(env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string()))
        .args(["--print", "sysroot"])
        .output()
        .context("invoke rustc to determine sysroot")?;

    if !output.status.success() {
        anyhow::bail!("failed to detect sysroot (status {})", output.status);
    }

    let sysroot = String::from_utf8(output.stdout).context("sysroot output not utf-8")?;
    Ok(sysroot.trim().to_string())
}

#[derive(Default)]
struct HirDumpCallbacks {
    seen_items: usize,
    seen_functions: usize,
}

impl Callbacks for HirDumpCallbacks {
    fn after_analysis<'tcx>(&mut self, _compiler: &Compiler, tcx: TyCtxt<'tcx>) -> Compilation {
        self.dump_hir_and_mir(tcx);

        Compilation::Stop
    }
}

impl HirDumpCallbacks {
    fn dump_hir_and_mir(&mut self, tcx: TyCtxt<'_>) {
        let crate_items = tcx.hir_crate_items(());
        self.seen_items = crate_items.definitions().count();
        println!("[hir-spike] total HIR items: {}", self.seen_items);

        self.seen_functions = 0;

        for local_def_id in crate_items.definitions() {
            let def_id = local_def_id.to_def_id();
            let def_kind = tcx.def_kind(def_id);

            if matches!(def_kind, DefKind::Fn | DefKind::AssocFn | DefKind::Ctor(..)) {
                self.seen_functions += 1;
                let name = tcx.def_path_str(def_id);
                let mir = tcx.optimized_mir(local_def_id);
                println!(
                    "[hir-spike] fn {name} -> locals: {}, basic blocks: {}",
                    mir.local_decls.len(),
                    mir.basic_blocks.len()
                );
            }
        }

        println!(
            "[hir-spike] total function-like bodies with MIR: {}",
            self.seen_functions
        );
    }
}
