#![cfg_attr(feature = "hir-driver", feature(rustc_private))]

#[cfg(feature = "hir-driver")]
mod capture {
    use anyhow::{anyhow, Context, Result};
    use mir_extractor::{
        capture_root_from_env, collect_crate_snapshot, target_spec_from_env, HirPackage,
        HirTargetSpec,
    };
    use rustc_driver::{run_compiler, Callbacks, Compilation};
    use rustc_interface::interface::Compiler;
    use rustc_middle::ty::TyCtxt;
    use rustc_span::def_id::LOCAL_CRATE;
    use std::env;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::Command;

    extern crate rustc_driver;
    extern crate rustc_hir;
    extern crate rustc_interface;
    extern crate rustc_middle;
    extern crate rustc_session;
    extern crate rustc_span;

    pub fn run() -> Result<()> {
        // Parse args first to check if we should passthrough
        let raw_args: Vec<String> = env::args().collect();

        if raw_args.len() < 2 {
            return Err(anyhow!(
                "hir-driver-wrapper requires the rustc path as the first argument"
            ));
        }

        let rustc_path = PathBuf::from(&raw_args[1]);
        let mut args = Vec::with_capacity(raw_args.len() - 1);
        args.push("rustc".to_string());
        args.extend(raw_args.iter().skip(2).cloned());

        // Check passthrough BEFORE reading env vars
        if should_passthrough(&args[1..]) {
            let status = Command::new(&rustc_path)
                .args(&args[1..])
                .status()
                .context("invoke real rustc for passthrough")?;
            if !status.success() {
                return Err(anyhow!(
                    "passthrough rustc invocation failed with status {}",
                    status
                ));
            }
            return Ok(());
        }

        // Now read env vars (only needed for non-passthrough)
        let output_path = env::var("MIR_COLA_HIR_CAPTURE_OUT")
            .context("missing MIR_COLA_HIR_CAPTURE_OUT for HIR capture")?;

        let output_path = PathBuf::from(output_path);
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).ok();
        }

        let target_spec = target_spec_from_env()?;

        let crate_root = capture_root_from_env()?;

        let mut callbacks = HirCaptureCallbacks {
            output: output_path,
            target_spec,
            crate_root,
            recorded: false,
        };

        run_compiler(&args, &mut callbacks);

        if !callbacks.recorded {
            return Err(anyhow!(
                "HIR capture did not observe target crate {}",
                callbacks.target_spec.crate_name
            ));
        }

        Ok(())
    }

    struct HirCaptureCallbacks {
        output: PathBuf,
        target_spec: HirTargetSpec,
        crate_root: String,
        recorded: bool,
    }

    impl Callbacks for HirCaptureCallbacks {
        fn after_analysis<'tcx>(&mut self, _compiler: &Compiler, tcx: TyCtxt<'tcx>) -> Compilation {
            let actual_crate_name = tcx.crate_name(LOCAL_CRATE).as_str().to_string();

            if actual_crate_name != self.target_spec.crate_name {
                return Compilation::Continue;
            }

            let package = collect_crate_snapshot(tcx, &self.target_spec, &self.crate_root);

            if let Err(err) = write_package(&self.output, &package) {
                eprintln!(
                    "hir-driver-wrapper: failed to persist HIR package to {}: {err:?}",
                    self.output.display()
                );
                return Compilation::Stop;
            }

            self.recorded = true;
            Compilation::Continue
        }
    }

    fn write_package(path: &PathBuf, package: &HirPackage) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create parent directory {}", parent.display()))?;
        }
        let mut file = File::create(path)
            .with_context(|| format!("create HIR capture file at {}", path.display()))?;
        serde_json::to_writer_pretty(&mut file, package)
            .with_context(|| format!("serialize HIR package to {}", path.display()))?;
        file.write_all(b"\n").ok();
        Ok(())
    }

    fn should_passthrough(args: &[String]) -> bool {
        if args.iter().any(|arg| arg == "-vV" || arg == "--version") {
            return true;
        }

        let has_emit = args
            .iter()
            .any(|arg| arg == "--emit" || arg.starts_with("--emit="));
        !has_emit
    }
}

#[cfg(not(feature = "hir-driver"))]
fn main() {
    eprintln!("hir-driver-wrapper requires the hir-driver feature to be enabled");
    std::process::exit(1);
}

#[cfg(feature = "hir-driver")]
fn main() {
    std::process::exit(match capture::run() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("hir-driver-wrapper: {err:?}");
            1
        }
    });
}
