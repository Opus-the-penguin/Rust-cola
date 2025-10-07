use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn cli_outputs_span_locations_for_findings() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempdir()?;
    let crate_dir = temp.path().join("fixture");
    fs::create_dir(&crate_dir)?;
    fs::create_dir(crate_dir.join("src"))?;

    fs::write(
        crate_dir.join("Cargo.toml"),
        r#"[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"#,
    )?;

    fs::write(
        crate_dir.join("src/lib.rs"),
        r#"pub extern "C" fn ffi_create(x: i32) -> *mut i32 {
    let b = Box::new(x);
    Box::into_raw(b)
}

pub struct Holder;

impl Holder {
    pub unsafe fn set_len_unsound(&mut self, v: &mut Vec<u8>) {
        v.set_len(16);
    }
}
"#,
    )?;

    let out_dir = temp.path().join("out");
    let mut cmd = Command::cargo_bin("cargo-cola")?;
    cmd.arg("--crate-path")
        .arg(&crate_dir)
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--fail-on-findings=false")
        .arg("--cache=false");

    let assert = cmd.assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();

    assert!(
        stdout.contains("location: src/lib.rs:"),
        "expected stdout to contain span location for fixture, got:\n{}",
        stdout
    );

    Ok(())
}
