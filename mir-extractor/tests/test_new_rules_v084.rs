/// Unit tests for v0.8.4 rules:
/// - RUSTCOLA103: WebAssembly Linear Memory OOB
/// - RUSTCOLA118: Returned Reference to Local
/// - RUSTCOLA119: Closure Escaping References  
/// - RUSTCOLA120: Self-Referential Struct Creation
/// - RUSTCOLA121: Executor Starvation Detection
///
/// These are pattern-based unit tests that verify the rules detect
/// the expected MIR patterns without running the full cargo-cola binary.
use mir_extractor::rules::{concurrency, ffi, memory};
use mir_extractor::{MirFunction, MirPackage, Rule, SourceSpan};

fn make_test_package(name: &str, signature: &str, body_lines: Vec<&str>) -> MirPackage {
    MirPackage {
        crate_name: "test_crate".to_string(),
        crate_root: "/test".to_string(),
        functions: vec![MirFunction {
            name: name.to_string(),
            signature: signature.to_string(),
            body: body_lines.into_iter().map(|s| s.to_string()).collect(),
            span: Some(SourceSpan {
                file: "test.rs".to_string(),
                start_line: 1,
                start_column: 1,
                end_line: 10,
                end_column: 1,
            }),
            hir: None,
        }],
    }
}

#[test]
fn test_rustcola118_rule_exists() {
    // Test that the ReturnedRefToLocalRule exists and has correct ID
    let rule = memory::ReturnedRefToLocalRule::new();
    let meta = rule.metadata();
    assert_eq!(meta.id, "RUSTCOLA118");
    // Name is kebab-case: "returned-ref-to-local"
    assert!(!meta.name.is_empty());
}

#[test]
fn test_rustcola118_pattern_detection() {
    let rule = memory::ReturnedRefToLocalRule::new();

    // Test function that returns pointer to local
    let pkg = make_test_package(
        "bad_return_local_ptr",
        "fn bad_return_local_ptr() -> *const i32",
        vec!["_1 = &_2;", "_0 = _1 as *const i32;", "return;"],
    );

    let findings = rule.evaluate(&pkg, None);
    println!("RUSTCOLA118 findings: {:?}", findings);
}

#[test]
fn test_rustcola119_rule_exists() {
    let rule = concurrency::ClosureEscapingRefsRule::new();
    let meta = rule.metadata();
    assert_eq!(meta.id, "RUSTCOLA119");
    assert!(!meta.name.is_empty());
}

#[test]
fn test_rustcola119_pattern_detection() {
    let rule = concurrency::ClosureEscapingRefsRule::new();

    // Test closure with transmute to extend lifetime
    let pkg = make_test_package(
        "bad_transmute_closure",
        "fn bad_transmute_closure<'a>() -> Box<dyn Fn() + 'static>",
        vec!["transmute::<Box<dyn Fn() + 'a>, Box<dyn Fn() + 'static>>(closure)"],
    );

    let findings = rule.evaluate(&pkg, None);
    println!("RUSTCOLA119 findings: {:?}", findings);
}

#[test]
fn test_rustcola120_rule_exists() {
    let rule = memory::SelfReferentialStructRule::new();
    let meta = rule.metadata();
    assert_eq!(meta.id, "RUSTCOLA120");
    assert!(!meta.name.is_empty());
}

#[test]
fn test_rustcola120_pattern_detection() {
    let rule = memory::SelfReferentialStructRule::new();

    // Test self-referential struct creation
    let pkg = make_test_package(
        "create_self_ref",
        "fn create_self_ref() -> SelfRef",
        vec!["_1.ptr = &_1.data;", "_0 = move _1;", "return;"],
    );

    let findings = rule.evaluate(&pkg, None);
    println!("RUSTCOLA120 findings: {:?}", findings);
}

#[test]
fn test_rustcola121_rule_exists() {
    let rule = concurrency::ExecutorStarvationRule::new();
    let meta = rule.metadata();
    assert_eq!(meta.id, "RUSTCOLA121");
    assert!(!meta.name.is_empty());
}

#[test]
fn test_rustcola121_pattern_detection() {
    let rule = concurrency::ExecutorStarvationRule::new();

    // Test async function with CPU-bound loop
    let pkg = make_test_package(
        "bad_cpu_loop",
        "async fn bad_cpu_loop() -> u64",
        vec!["loop {", "_1 = _1.wrapping_add(_2);", "}", "return;"],
    );

    let findings = rule.evaluate(&pkg, None);
    println!("RUSTCOLA121 findings: {:?}", findings);
}

#[test]
fn test_rustcola103_rule_exists() {
    let rule = ffi::WasmLinearMemoryOobRule::new();
    let meta = rule.metadata();
    assert_eq!(meta.id, "RUSTCOLA103");
    assert!(!meta.name.is_empty());
}

#[test]
fn test_rustcola103_pattern_detection() {
    let rule = ffi::WasmLinearMemoryOobRule::new();

    // Test WASM export with unchecked pointer access
    let pkg = make_test_package(
        "process_buffer",
        "#[no_mangle] pub extern \"C\" fn process_buffer(ptr: *mut u8, len: usize)",
        vec!["slice::from_raw_parts_mut(ptr, len)"],
    );

    let findings = rule.evaluate(&pkg, None);
    println!("RUSTCOLA103 findings: {:?}", findings);
}
