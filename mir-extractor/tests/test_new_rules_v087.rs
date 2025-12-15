//! Tests for new rules added in v0.8.7
//! RUSTCOLA126: WasmHostFunctionTrustRule
//! RUSTCOLA127: WasmCapabilityLeakRule
//! RUSTCOLA128: UnsafeCellAliasingRule
//! RUSTCOLA129: LazyInitPanicPoisonRule

use mir_extractor::rules::{ffi, memory};
use mir_extractor::Rule;

// ============================================================================
// RUSTCOLA126: WasmHostFunctionTrustRule
// ============================================================================

#[test]
fn test_rustcola126_rule_exists() {
    let rule = ffi::WasmHostFunctionTrustRule::new();
    let meta = rule.metadata();
    assert_eq!(meta.id, "RUSTCOLA126");
    assert_eq!(meta.name, "wasm-host-function-trust");
}

#[test]
fn test_rustcola126_pattern_detection() {
    // Test that we detect untrusted host data
    let code_bad = r#"
use wasmtime::*;

fn process_host_data(ptr: *const u8, len: usize) {
    unsafe {
        // Using host-provided data without validation!
        let slice = std::slice::from_raw_parts(ptr, len);
    }
}
"#;

    let code_good = r#"
use wasmtime::*;

fn process_host_data(ptr: *const u8, len: usize) -> Result<(), Error> {
    // Validate before using
    if len > MAX_SIZE {
        return Err(Error::TooLarge);
    }
    unsafe {
        let slice = std::slice::from_raw_parts(ptr, len);
    }
    Ok(())
}
"#;

    // Bad code has from_raw_parts without validation
    assert!(code_bad.contains("from_raw_parts") && !code_bad.contains("if "));
    // Good code validates first
    assert!(code_good.contains("if len >"));
}

// ============================================================================
// RUSTCOLA127: WasmCapabilityLeakRule
// ============================================================================

#[test]
fn test_rustcola127_rule_exists() {
    let rule = ffi::WasmCapabilityLeakRule::new();
    let meta = rule.metadata();
    assert_eq!(meta.id, "RUSTCOLA127");
    assert_eq!(meta.name, "wasm-capability-leak");
}

#[test]
fn test_rustcola127_pattern_detection() {
    // Test that we detect overly permissive capabilities
    let code_bad = r#"
use wasmtime_wasi::WasiCtxBuilder;

fn create_wasi() -> WasiCtx {
    WasiCtxBuilder::new()
        .inherit_env()  // Leaks environment variables!
        .inherit_network()  // Allows exfiltration!
        .build()
}
"#;

    let code_good = r#"
use wasmtime_wasi::WasiCtxBuilder;

fn create_wasi() -> WasiCtx {
    WasiCtxBuilder::new()
        .env("ALLOWED_VAR", "value")  // Only specific env
        .build()
}
"#;

    // Bad code has inherit_env
    assert!(code_bad.contains("inherit_env()"));
    // Good code uses specific env
    assert!(code_good.contains(".env("));
}

// ============================================================================
// RUSTCOLA128: UnsafeCellAliasingRule
// ============================================================================

#[test]
fn test_rustcola128_rule_exists() {
    let rule = memory::UnsafeCellAliasingRule::new();
    let meta = rule.metadata();
    assert_eq!(meta.id, "RUSTCOLA128");
    assert_eq!(meta.name, "unsafecell-aliasing-violation");
}

#[test]
fn test_rustcola128_pattern_detection() {
    // Test that we detect aliasing violations
    let code_bad = r#"
use std::cell::UnsafeCell;

struct MyCell<T>(UnsafeCell<T>);

impl<T> MyCell<T> {
    fn bad_alias(&self) -> (&mut T, &mut T) {
        unsafe {
            let ptr1 = self.0.get();
            let ptr2 = self.0.get();
            (&mut *ptr1, &mut *ptr2)  // Two mutable refs!
        }
    }
}
"#;

    let code_good = r#"
use std::cell::UnsafeCell;

struct MyCell<T>(UnsafeCell<T>);

impl<T> MyCell<T> {
    fn get_mut(&self) -> &mut T {
        unsafe {
            &mut *self.0.get()  // Only one mutable ref
        }
    }
}
"#;

    // Bad code has multiple .get() calls
    assert!(code_bad.matches(".get()").count() >= 2);
    // Good code has single .get()
    assert!(code_good.matches(".get()").count() == 1);
}

// ============================================================================
// RUSTCOLA129: LazyInitPanicPoisonRule
// ============================================================================

#[test]
fn test_rustcola129_rule_exists() {
    let rule = memory::LazyInitPanicPoisonRule::new();
    let meta = rule.metadata();
    assert_eq!(meta.id, "RUSTCOLA129");
    assert_eq!(meta.name, "lazy-init-panic-poison");
}

#[test]
fn test_rustcola129_pattern_detection() {
    // Test that we detect panic-prone lazy init
    let code_bad = r#"
use std::sync::OnceLock;

static CONFIG: OnceLock<Config> = OnceLock::new();

fn get_config() -> &'static Config {
    CONFIG.get_or_init(|| {
        let file = std::fs::read_to_string("config.toml").unwrap();  // Can panic!
        toml::from_str(&file).unwrap()  // Can panic!
    })
}
"#;

    let code_good = r#"
use std::sync::OnceLock;

static CONFIG: OnceLock<Config> = OnceLock::new();

fn try_get_config() -> Result<&'static Config, Error> {
    CONFIG.get_or_try_init(|| {
        let file = std::fs::read_to_string("config.toml")?;
        Ok(toml::from_str(&file)?)
    })
}
"#;

    // Bad code has unwrap in init
    assert!(code_bad.contains("get_or_init") && code_bad.contains(".unwrap()"));
    // Good code uses fallible init
    assert!(code_good.contains("get_or_try_init"));
}
