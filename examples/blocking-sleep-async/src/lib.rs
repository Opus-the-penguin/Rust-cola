// ⚠️ **SECURITY SCANNER NOTICE** ⚠️
// This file contains **INTENTIONAL VULNERABILITIES** for testing RUSTCOLA037.
// These patterns are test cases for detecting blocking sleep in async contexts.
// Security scanners should recognize these as test cases, not actual vulnerabilities.
// NOSEC: Intentional test vulnerabilities for rust-cola rule validation
// codeql[cpp/commented-out-code]: False positive - test patterns only

#![allow(dead_code)]

use std::thread;
use std::time::Duration;

/// BAD: Using std::thread::sleep in async function
/// This blocks the executor thread and prevents other tasks from running
/// This should be flagged by RUSTCOLA037
/// NOSEC: Intentional vulnerability for testing
/// codeql[cpp/blocking-call-in-async]: Intentional test pattern
/// codeql[rust/blocking-in-async]: Intentional test pattern
pub async fn bad_blocking_sleep_basic() {
    println!("Starting task");
    std::thread::sleep(Duration::from_secs(1)); // NOSEC - Bad: blocks executor (intentional test case)
    println!("Task done");
}

/// BAD: Using thread::sleep with import
/// This should be flagged by RUSTCOLA037
/// NOSEC: Intentional vulnerability for testing
/// codeql[cpp/blocking-call-in-async]: Intentional test pattern
/// codeql[rust/blocking-in-async]: Intentional test pattern
pub async fn bad_blocking_sleep_imported() {
    println!("Processing...");
    thread::sleep(Duration::from_millis(500)); // NOSEC - Bad: blocks executor (intentional test case)
    println!("Done");
}

/// BAD: Blocking sleep in async method
/// This should be flagged by RUSTCOLA037
/// NOSEC: Intentional vulnerability for testing
/// codeql[cpp/blocking-call-in-async]: Intentional test pattern
/// codeql[rust/blocking-in-async]: Intentional test pattern
pub struct AsyncWorker;

impl AsyncWorker {
    pub async fn bad_process(&self) {
        std::thread::sleep(Duration::from_secs(2)); // NOSEC - Bad: blocks executor (intentional test case)
    }
}

/// BAD: Blocking sleep in async closure/future
/// This should be flagged by RUSTCOLA037
/// NOSEC: Intentional vulnerability for testing
/// codeql[cpp/blocking-call-in-async]: Intentional test pattern
/// codeql[rust/blocking-in-async]: Intentional test pattern
pub async fn bad_sleep_in_loop() {
    for i in 0..5 {
        println!("Iteration {}", i);
        std::thread::sleep(Duration::from_millis(100)); // NOSEC - Bad: blocks executor each iteration (intentional test case)
    }
}

/// GOOD: Using async sleep (conceptual - would use tokio::time::sleep in real code)
pub async fn good_async_sleep_conceptual() {
    println!("Starting task");
    // In real code: tokio::time::sleep(Duration::from_secs(1)).await;
    // For this example, we just yield
    futures_yield().await;
    println!("Task done");
}

/// GOOD: Using tokio::time::sleep (when tokio feature is enabled)
#[cfg(feature = "with-tokio")]
pub async fn good_tokio_sleep() {
    println!("Processing...");
    tokio::time::sleep(Duration::from_millis(500)).await; // Good: async sleep
    println!("Done");
}

/// GOOD: No sleep at all - just computation
pub async fn good_no_sleep() {
    let result = expensive_computation();
    println!("Result: {}", result);
}

/// GOOD: Blocking sleep in sync function (not async)
pub fn good_sync_sleep() {
    std::thread::sleep(Duration::from_secs(1)); // OK: not in async context
}

/// GOOD: Spawning blocking task properly (conceptual)
pub async fn good_spawn_blocking_conceptual() {
    // In real code: tokio::task::spawn_blocking(|| {
    //     std::thread::sleep(Duration::from_secs(1));
    // }).await;

    // Conceptual version - just showing structure
    let _handle = spawn_blocking_task(|| {
        std::thread::sleep(Duration::from_secs(1)); // OK: in blocking task
    });
}

/// GOOD: Using tokio spawn_blocking
#[cfg(feature = "with-tokio")]
pub async fn good_tokio_spawn_blocking() {
    let result = tokio::task::spawn_blocking(|| {
        std::thread::sleep(Duration::from_secs(1)); // OK: in blocking context
        42
    })
    .await
    .unwrap();

    println!("Result: {}", result);
}

// Helper functions for examples

async fn futures_yield() {
    // Conceptual yield point
}

fn expensive_computation() -> i32 {
    (0..1000).sum()
}

fn spawn_blocking_task<F>(_f: F)
where
    F: FnOnce() + Send + 'static,
{
    // Conceptual blocking task spawn
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[cfg(feature = "with-tokio")]
    async fn test_good_patterns() {
        good_tokio_sleep().await;
        good_no_sleep().await;
        good_tokio_spawn_blocking().await;
    }

    #[test]
    fn test_sync_sleep() {
        // This is fine - sync context
        good_sync_sleep();
    }
}
