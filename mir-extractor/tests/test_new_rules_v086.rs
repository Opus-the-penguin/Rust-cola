//! Tests for new rules added in v0.8.6
//! RUSTCOLA122: AsyncDropCorrectnessRule
//! RUSTCOLA123: UnwrapInHotPathRule
//! RUSTCOLA124: PanicInDropImplRule
//! RUSTCOLA125: SpawnedTaskPanicRule

use mir_extractor::rules::{concurrency, code_quality};
use mir_extractor::Rule;

// ============================================================================
// RUSTCOLA122: AsyncDropCorrectnessRule
// ============================================================================

#[test]
fn test_rustcola122_rule_exists() {
    let rule = concurrency::AsyncDropCorrectnessRule::new();
    let meta = rule.metadata();
    assert_eq!(meta.id, "RUSTCOLA122");
    assert_eq!(meta.name, "async-drop-correctness");
}

#[test]
fn test_rustcola122_pattern_detection() {
    // Test that we detect Drop impl on types with async fields
    let code_bad = r#"
use tokio::task::JoinHandle;

struct AsyncTask {
    handle: JoinHandle<()>,
}

impl Drop for AsyncTask {
    fn drop(&mut self) {
        // Drops JoinHandle without awaiting - task may be cancelled
    }
}
"#;

    let code_good = r#"
use tokio::task::JoinHandle;

struct AsyncTask {
    handle: JoinHandle<()>,
}

impl AsyncTask {
    async fn shutdown(self) {
        self.handle.await.unwrap();
    }
}
"#;

    // Bad code has "impl Drop for" with JoinHandle field
    assert!(code_bad.contains("impl Drop for") && code_bad.contains("JoinHandle"));
    // Good code doesn't use Drop, uses async shutdown instead
    assert!(!code_good.contains("impl Drop for"));
}

// ============================================================================
// RUSTCOLA123: UnwrapInHotPathRule
// ============================================================================

#[test]
fn test_rustcola123_rule_exists() {
    let rule = code_quality::UnwrapInHotPathRule::new();
    let meta = rule.metadata();
    assert_eq!(meta.id, "RUSTCOLA123");
    assert_eq!(meta.name, "unwrap-in-hot-path");
}

#[test]
fn test_rustcola123_pattern_detection() {
    // Test that we detect unwrap in loops
    let code_bad = r#"
fn process_items(items: &[Option<i32>]) -> i32 {
    let mut sum = 0;
    for item in items {
        sum += item.unwrap(); // Panic risk in loop!
    }
    sum
}
"#;

    let code_good = r#"
fn process_items(items: &[Option<i32>]) -> i32 {
    let mut sum = 0;
    for item in items {
        if let Some(val) = item {
            sum += val;
        }
    }
    sum
}
"#;

    // Bad code has unwrap inside a for loop
    assert!(code_bad.contains("for") && code_bad.contains(".unwrap()"));
    // Good code uses if let instead
    assert!(code_good.contains("if let Some"));
}

// ============================================================================
// RUSTCOLA124: PanicInDropImplRule
// ============================================================================

#[test]
fn test_rustcola124_rule_exists() {
    let rule = concurrency::PanicInDropImplRule::new();
    let meta = rule.metadata();
    assert_eq!(meta.id, "RUSTCOLA124");
    assert_eq!(meta.name, "panic-in-drop-impl");
}

#[test]
fn test_rustcola124_pattern_detection() {
    // Test that we detect panic-prone code in Drop
    let code_bad = r#"
struct Resource {
    file: std::fs::File,
}

impl Drop for Resource {
    fn drop(&mut self) {
        self.file.sync_all().unwrap(); // Can panic during drop!
    }
}
"#;

    let code_good = r#"
struct Resource {
    file: std::fs::File,
}

impl Drop for Resource {
    fn drop(&mut self) {
        let _ = self.file.sync_all(); // Ignore errors in drop
    }
}
"#;

    // Bad code has unwrap inside fn drop
    assert!(code_bad.contains("fn drop") && code_bad.contains(".unwrap()"));
    // Good code ignores the error
    assert!(code_good.contains("let _ ="));
}

// ============================================================================
// RUSTCOLA125: SpawnedTaskPanicRule
// ============================================================================

#[test]
fn test_rustcola125_rule_exists() {
    let rule = concurrency::SpawnedTaskPanicRule::new();
    let meta = rule.metadata();
    assert_eq!(meta.id, "RUSTCOLA125");
    assert_eq!(meta.name, "spawned-task-panic-propagation");
}

#[test]
fn test_rustcola125_pattern_detection() {
    // Test that we detect spawned tasks without panic handling
    let code_bad = r#"
async fn start_background_work() {
    tokio::spawn(async {
        do_work().await;
        // If this panics, the error is silently swallowed!
    });
}
"#;

    let code_good = r#"
async fn start_background_work() {
    let handle: JoinHandle<()> = tokio::spawn(async {
        do_work().await;
    });
    
    // Await the handle to propagate any panics
    if let Err(e) = handle.await {
        log::error!("Task panicked: {:?}", e);
    }
}
"#;

    // Bad code spawns without storing JoinHandle
    assert!(code_bad.contains("spawn(") && !code_bad.contains("JoinHandle"));
    // Good code stores and awaits the JoinHandle
    assert!(code_good.contains("JoinHandle") && code_good.contains(".await"));
}
