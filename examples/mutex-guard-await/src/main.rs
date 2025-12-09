//! Test cases for RUSTCOLA094: MutexGuard held across .await points
//!
//! Holding a std::sync::MutexGuard across an .await point can cause deadlocks
//! because the guard is held while the async task is suspended. When the task
//! resumes on a different executor thread, it may try to acquire the same lock.
//!
//! Expected: 8 PROBLEMATIC patterns detected, 8 SAFE patterns not flagged

use std::sync::{Mutex, RwLock};
use std::sync::Arc;

// ============================================================================
// PROBLEMATIC PATTERNS - MutexGuard held across .await
// ============================================================================

/// PROBLEMATIC: MutexGuard held across .await
pub async fn bad_mutex_guard_held_across_await() {
    let mutex = Mutex::new(42);
    let guard = mutex.lock().unwrap();  // Guard acquired here
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;  // Held across .await!
    println!("Value: {}", *guard);
}

/// PROBLEMATIC: MutexGuard in block held across .await
pub async fn bad_mutex_guard_in_scope_across_await() {
    let mutex = Mutex::new(42);
    {
        let guard = mutex.lock().unwrap();
        some_async_operation().await;  // Held across .await!
        println!("Value: {}", *guard);
    }
}

/// PROBLEMATIC: RwLockReadGuard held across .await
pub async fn bad_rwlock_read_guard_across_await() {
    let rwlock = RwLock::new(42);
    let guard = rwlock.read().unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;  // Held across .await!
    println!("Value: {}", *guard);
}

/// PROBLEMATIC: RwLockWriteGuard held across .await
pub async fn bad_rwlock_write_guard_across_await() {
    let rwlock = RwLock::new(42);
    let guard = rwlock.write().unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;  // Held across .await!
    println!("Value: {}", *guard);
}

/// PROBLEMATIC: Multiple awaits with guard held
pub async fn bad_guard_held_across_multiple_awaits() {
    let mutex = Mutex::new(42);
    let guard = mutex.lock().unwrap();
    first_async_op().await;  // Held across .await!
    second_async_op().await;  // Still held!
    println!("Value: {}", *guard);
}

/// PROBLEMATIC: Guard from Arc<Mutex> held across await
pub async fn bad_arc_mutex_guard_across_await(data: Arc<Mutex<i32>>) {
    let guard = data.lock().unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    println!("Value: {}", *guard);
}

/// PROBLEMATIC: Guard assigned to _ still creates a temporary
pub async fn bad_underscore_guard_across_await() {
    let mutex = Mutex::new(42);
    let _guard = mutex.lock().unwrap();  // _ prefix doesn't help!
    some_async_operation().await;
}

/// PROBLEMATIC: Guard used in match across await
pub async fn bad_guard_in_match_across_await() {
    let mutex = Mutex::new(Some(42));
    let guard = mutex.lock().unwrap();
    match &*guard {
        Some(v) => {
            some_async_operation().await;  // Guard held in match arm!
            println!("Value: {}", v);
        }
        None => {}
    }
}

// ============================================================================
// SAFE PATTERNS - Guard dropped before .await
// ============================================================================

/// SAFE: Guard explicitly dropped before .await
pub async fn safe_guard_dropped_before_await() {
    let mutex = Mutex::new(42);
    let value = {
        let guard = mutex.lock().unwrap();
        *guard  // Copy the value
    };  // Guard dropped here
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    println!("Value: {}", value);
}

/// SAFE: Guard in separate scope before await
pub async fn safe_guard_scoped_before_await() {
    let mutex = Mutex::new(42);
    {
        let guard = mutex.lock().unwrap();
        println!("Value: {}", *guard);
    }  // Guard dropped here
    some_async_operation().await;  // No guard held
}

/// SAFE: Using tokio::sync::Mutex (async-aware)
pub async fn safe_tokio_mutex() {
    let mutex = tokio::sync::Mutex::new(42);
    let guard = mutex.lock().await;  // This is the async version
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    println!("Value: {}", *guard);
}

/// SAFE: Using tokio::sync::RwLock (async-aware)
pub async fn safe_tokio_rwlock() {
    let rwlock = tokio::sync::RwLock::new(42);
    let guard = rwlock.read().await;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    println!("Value: {}", *guard);
}

/// SAFE: Guard used and dropped in sync context
pub async fn safe_sync_only_usage() {
    let mutex = Mutex::new(42);
    let value = {
        let guard = mutex.lock().unwrap();
        *guard + 1
    };
    println!("Value: {}", value);
    some_async_operation().await;  // No guard here
}

/// SAFE: Using explicit drop()
pub async fn safe_explicit_drop() {
    let mutex = Mutex::new(42);
    let guard = mutex.lock().unwrap();
    let value = *guard;
    drop(guard);  // Explicitly dropped
    some_async_operation().await;
    println!("Value: {}", value);
}

/// SAFE: Guard created after await
pub async fn safe_guard_after_await() {
    some_async_operation().await;
    let mutex = Mutex::new(42);
    let guard = mutex.lock().unwrap();
    println!("Value: {}", *guard);
    // Guard dropped at end, no more awaits
}

/// SAFE: Non-async function (no await points possible)
pub fn safe_sync_function() {
    let mutex = Mutex::new(42);
    let guard = mutex.lock().unwrap();
    println!("Value: {}", *guard);
}

// Helper async functions
async fn some_async_operation() {
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
}

async fn first_async_op() {
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
}

async fn second_async_op() {
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
}

fn main() {
    println!("RUSTCOLA094 test cases - MutexGuard across await");
}
