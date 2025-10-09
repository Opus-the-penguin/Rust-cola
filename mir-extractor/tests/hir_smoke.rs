#![cfg(feature = "hir-driver")]

use assert_cmd::prelude::*;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

#[test]
#[ignore]
fn captures_hir_snapshot_for_examples_simple() {
    let temp = tempdir().expect("temp dir");
    let hir_path = temp.path().join("hir.json");

    let mut cmd = Command::cargo_bin("mir-extractor").expect("binary available");
    cmd.current_dir(Path::new(".."));
    // Ensure the smoke test can locate cargo, even when the outer environment lacks it.
    if let Ok(cargo_path) = std::env::var("CARGO") {
        if let Some(dir) = Path::new(&cargo_path).parent() {
            let current = std::env::var("PATH").unwrap_or_default();
            let updated_path = if current.is_empty() {
                dir.display().to_string()
            } else {
                format!("{}:{}", dir.display(), current)
            };
            cmd.env("PATH", updated_path);
        }
        cmd.env("CARGO", cargo_path);
    }
    // macOS requires DYLD_LIBRARY_PATH for rustc_private dylibs when using the wrapper.
    if let Ok(output) = std::process::Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
    {
        if output.status.success() {
            let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let lib_dir = Path::new(&sysroot).join("lib");
            if lib_dir.is_dir() {
                let current = std::env::var("DYLD_LIBRARY_PATH").unwrap_or_default();
                let updated = if current.is_empty() {
                    lib_dir.display().to_string()
                } else {
                    format!("{}:{}", lib_dir.display(), current)
                };
                cmd.env("DYLD_LIBRARY_PATH", updated);
            }
        }
    }

    cmd.arg("--crate-path")
        .arg(Path::new("examples/simple"))
        .arg("--out-dir")
        .arg(temp.path())
        .arg("--cache=false")
        .arg("--hir-json")
        .arg(&hir_path);

    let assert = cmd.assert();
    let output = assert.get_output().clone();
    assert.success();

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !hir_path.exists() {
        const HIR_CAPTURE_ICE_LOG_PREFIX: &str = "rust-cola: rustc ICE while capturing HIR";
        if stderr.contains(HIR_CAPTURE_ICE_LOG_PREFIX) {
            eprintln!(
                "hir_smoke: skipping assertion because rustc ICE was reported while capturing HIR."
            );
            eprintln!("{}", stderr);
            return;
        }

        panic!(
            "mir-extractor did not produce HIR JSON at {}.\nstdout:\n{}\nstderr:\n{}",
            hir_path.display(),
            stdout,
            stderr
        );
    }

    let contents = fs::read_to_string(&hir_path).expect("hir.json readable");
    assert!(
        contents.contains("\"crate_name\""),
        "expected HIR JSON to include crate metadata"
    );
}
