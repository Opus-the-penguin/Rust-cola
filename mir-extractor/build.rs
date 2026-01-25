use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let feature_hir_driver = env::var("CARGO_FEATURE_HIR_DRIVER").is_ok();

    if feature_hir_driver && target_os == "macos" {
        println!("cargo:warning=hir-driver: enabling dynamic stdlib linkage on macOS");
        println!("cargo:rustc-link-arg=-Wl,-undefined,dynamic_lookup");

        if let Some(search_dir) = stdlib_search_dir() {
            println!("cargo:rustc-link-search=native={}", search_dir.display());
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", search_dir.display());
        }
        println!("cargo:rustc-flag=-Cprefer-dynamic");
    }
}

fn stdlib_search_dir() -> Option<PathBuf> {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let sysroot_output = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .ok()?;

    if !sysroot_output.status.success() {
        return None;
    }

    let sysroot = String::from_utf8(sysroot_output.stdout)
        .ok()?
        .trim()
        .to_string();
    let target = env::var("TARGET").unwrap_or_default();
    let lib_path = PathBuf::from(sysroot)
        .join("lib")
        .join("rustlib")
        .join(target)
        .join("lib");

    if lib_path.exists() {
        Some(lib_path)
    } else {
        None
    }
}
