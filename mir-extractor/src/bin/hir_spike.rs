#![cfg(feature = "hir-driver")]
#![feature(rustc_private)]

use anyhow::{anyhow, Context, Result};
use cargo_metadata::{Metadata, MetadataCommand, Package, Target};
use rustc_driver::{run_compiler, Callbacks, Compilation};
use rustc_hir::def::DefKind;
use rustc_interface::interface::Compiler;
use rustc_middle::ty::TyCtxt;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{SystemTime, UNIX_EPOCH};

extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

const WRAPPER_ENV: &str = "HIR_SPIKE_WRAPPER_MODE";
const CAPTURE_ENV: &str = "HIR_SPIKE_CAPTURE_FILE";
const TARGET_ENV: &str = "HIR_SPIKE_TARGET_CRATE";

fn main() {
    if env::var(WRAPPER_ENV).as_deref() == Ok("1") {
        let code = match wrapper::run() {
            Ok(status) => status,
            Err(err) => {
                eprintln!("hir-spike wrapper error: {err:?}");
                1
            }
        };
        std::process::exit(code);
    }

    if let Err(err) = run() {
        eprintln!("hir-spike failed: {err:?}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let crate_arg = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("examples/simple"));

    let manifest_path = resolve_manifest_path(&crate_arg)?;
    let manifest_dir = manifest_path
        .parent()
        .context("manifest path should have a parent directory")?
        .to_path_buf();

    let metadata = load_metadata(&manifest_path)?;
    let package = find_package(&metadata, &manifest_path)?;
    let selection = select_target(&package)?;

    let capture_path = unique_capture_file()?;
    if capture_path.exists() {
        fs::remove_file(&capture_path).ok();
    }

    let wrapper_path = env::current_exe().context("locate hir-spike executable")?;
    run_cargo_rustc(&manifest_dir, &selection, &wrapper_path, &capture_path)?;

    let args = read_captured_args(&capture_path).with_context(|| {
        format!(
            "read captured rustc invocation from {}",
            capture_path.display()
        )
    })?;
    if args.len() < 2 {
        return Err(anyhow!(
            "captured rustc invocation missing arguments; expected at least path and one flag"
        ));
    }

    let rustc_args: Vec<String> = std::iter::once("rustc".to_string())
        .chain(args.into_iter().skip(1))
        .collect();

    env::remove_var(WRAPPER_ENV);
    env::remove_var(CAPTURE_ENV);
    env::remove_var(TARGET_ENV);
    env::remove_var("RUSTC_WRAPPER");

    let mut callbacks = HirDumpCallbacks::default();
    println!(
        "[hir-spike] analyzing crate `{}` (target {})",
        selection.human_name, selection.description
    );
    run_compiler(&rustc_args, &mut callbacks);

    println!("[hir-spike] total HIR items: {}", callbacks.seen_items);
    println!(
        "[hir-spike] total function-like bodies with MIR: {}",
        callbacks.seen_functions
    );

    Ok(())
}

fn resolve_manifest_path(arg: &Path) -> Result<PathBuf> {
    let canonical =
        fs::canonicalize(arg).with_context(|| format!("canonicalize path {}", arg.display()))?;
    if canonical.is_file() {
        Ok(canonical)
    } else {
        let manifest = canonical.join("Cargo.toml");
        if manifest.exists() {
            Ok(manifest)
        } else {
            Err(anyhow!(
                "expected Cargo.toml under {} (resolved from {})",
                canonical.display(),
                arg.display()
            ))
        }
    }
}

fn load_metadata(manifest_path: &Path) -> Result<Metadata> {
    let mut cmd = MetadataCommand::new();
    cmd.no_deps();
    cmd.manifest_path(manifest_path);
    cmd.exec().context("invoke cargo metadata")
}

fn find_package<'a>(metadata: &'a Metadata, manifest_path: &Path) -> Result<&'a Package> {
    let manifest_canonical = fs::canonicalize(manifest_path)
        .with_context(|| format!("canonicalize manifest {}", manifest_path.display()))?;

    metadata
        .packages
        .iter()
        .find(|pkg| {
            fs::canonicalize(pkg.manifest_path.clone().into_std_path_buf())
                .map(|path| path == manifest_canonical)
                .unwrap_or(false)
        })
        .or_else(|| metadata.root_package())
        .ok_or_else(|| {
            anyhow!(
                "could not locate package for manifest {} in cargo metadata",
                manifest_path.display()
            )
        })
}

fn select_target(package: &Package) -> Result<TargetSelection> {
    let mut preferred: Option<&Target> = None;
    let mut fallback: Option<&Target> = None;
    let mut skipped: Vec<String> = Vec::new();

    for target in &package.targets {
        if !target.required_features.is_empty() {
            skipped.push(target.name.clone());
            continue;
        }

        if target
            .kind
            .iter()
            .any(|kind| kind == "lib" || kind == "proc-macro")
        {
            preferred = Some(target);
            break;
        }

        if fallback.is_none() && target.kind.iter().any(|kind| kind == "bin") {
            fallback = Some(target);
        }
    }

    let chosen = preferred.or(fallback).ok_or_else(|| {
        if skipped.is_empty() {
            anyhow!(
                "package {} has no lib or bin targets available without extra features",
                package.name
            )
        } else {
            anyhow!(
                "package {} has no runnable targets; skipped due to required features: {}",
                package.name,
                skipped.join(", ")
            )
        }
    })?;

    let (cargo_args, crate_name, description) = if chosen
        .kind
        .iter()
        .any(|kind| kind == "lib" || kind == "proc-macro")
    {
        (
            vec!["--lib".to_string()],
            package.name.replace('-', "_"),
            "lib".to_string(),
        )
    } else {
        (
            vec!["--bin".to_string(), chosen.name.clone()],
            chosen.name.replace('-', "_"),
            format!("bin {}", chosen.name),
        )
    };

    Ok(TargetSelection {
        cargo_args,
        crate_name,
        human_name: package.name.clone(),
        description,
    })
}

fn unique_capture_file() -> Result<PathBuf> {
    let mut path = env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("hir-spike-capture-{nanos}.json"));
    Ok(path)
}

fn run_cargo_rustc(
    manifest_dir: &Path,
    selection: &TargetSelection,
    wrapper_path: &Path,
    capture_path: &Path,
) -> Result<()> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut cmd = Command::new(cargo);
    cmd.current_dir(manifest_dir);
    cmd.arg("rustc");
    cmd.arg("--quiet");
    for arg in &selection.cargo_args {
        cmd.arg(arg);
    }
    cmd.env(WRAPPER_ENV, "1");
    cmd.env(CAPTURE_ENV, capture_path);
    cmd.env(TARGET_ENV, &selection.crate_name);
    cmd.env("RUSTC_WRAPPER", wrapper_path);
    cmd.arg("--");
    cmd.args(["--emit", "metadata"]);

    let status = cmd
        .status()
        .context("invoke cargo rustc to capture rustc arguments")?;

    if !status.success() {
        return Err(anyhow!(
            "cargo rustc failed for target {}; status {}",
            selection.description,
            format_exit_status(status)
        ));
    }

    Ok(())
}

fn read_captured_args(path: &Path) -> Result<Vec<String>> {
    let data = fs::read(path).with_context(|| format!("read capture file {}", path.display()))?;
    if data.is_empty() {
        return Err(anyhow!(
            "rustc invocation was not captured; ensure the target crate compiled"
        ));
    }

    serde_json::from_slice(&data).context("decode captured rustc arguments")
}

fn format_exit_status(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => code.to_string(),
        None => "terminated by signal".to_string(),
    }
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
    }
}

struct TargetSelection {
    cargo_args: Vec<String>,
    crate_name: String,
    human_name: String,
    description: String,
}

mod wrapper {
    use super::{CAPTURE_ENV, TARGET_ENV, WRAPPER_ENV};
    use anyhow::{Context, Result};
    use serde_json::to_vec;
    use std::env;
    use std::ffi::OsString;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, ExitStatus};

    pub fn run() -> Result<i32> {
        let capture_path = env::var_os(CAPTURE_ENV)
            .map(PathBuf::from)
            .context("wrapper missing capture file env")?;
        let target_crate = env::var(TARGET_ENV).context("wrapper missing target crate env")?;

        let mut args = env::args_os();
        let _self = args.next();
        let rustc_path = args
            .next()
            .map(PathBuf::from)
            .context("wrapper expected rustc path argument")?;
        let rustc_args: Vec<OsString> = args.collect();

        if should_capture(&rustc_args, &target_crate) {
            write_capture(&capture_path, &rustc_path, &rustc_args)
                .context("persist captured rustc arguments")?;
        }

        let status =
            invoke_rustc(&rustc_path, &rustc_args).context("invoke real rustc from wrapper")?;
        Ok(status.code().unwrap_or(1))
    }

    fn should_capture(args: &[OsString], target: &str) -> bool {
        find_crate_name(args)
            .map(|name| name == target)
            .unwrap_or(false)
    }

    fn find_crate_name(args: &[OsString]) -> Option<String> {
        for (idx, arg) in args.iter().enumerate() {
            if let Some(value) = arg.to_str() {
                if let Some(name) = value.strip_prefix("--crate-name=") {
                    return Some(name.to_string());
                }
                if value == "--crate-name" {
                    return args
                        .get(idx + 1)
                        .and_then(|next| next.to_str())
                        .map(|s| s.to_string());
                }
            }
        }
        None
    }

    fn write_capture(path: &PathBuf, rustc_path: &PathBuf, args: &[OsString]) -> Result<()> {
        let arguments: Vec<String> = std::iter::once(rustc_path.to_string_lossy().into_owned())
            .chain(args.iter().map(|arg| arg.to_string_lossy().into_owned()))
            .collect();

        let data = to_vec(&arguments).context("serialize rustc argument capture")?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .with_context(|| format!("open capture file {}", path.display()))?;
        file.write_all(&data)
            .with_context(|| format!("write capture file {}", path.display()))?;
        Ok(())
    }

    fn invoke_rustc(path: &PathBuf, args: &[OsString]) -> Result<ExitStatus> {
        let mut cmd = Command::new(path);
        cmd.args(args);
        cmd.env_remove("RUSTC_WRAPPER");
        cmd.env_remove(WRAPPER_ENV);
        cmd.env_remove(CAPTURE_ENV);
        cmd.env_remove(TARGET_ENV);
        cmd.status()
            .with_context(|| format!("invoke rustc {}", path.display()))
    }
}
