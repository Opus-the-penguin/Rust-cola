//! Demonstrates RUSTSEC-2025-0023: Tokio broadcast with !Sync payloads
//!
//! This example shows how tokio::sync::broadcast can cause unsoundness when
//! used with types that are Send but not Sync (like Rc, RefCell).

use std::cell::RefCell;
use std::rc::Rc;
use tokio::sync::broadcast;

// ============================================================================
// VULNERABLE PATTERNS - Should trigger RUSTCOLA023
// ============================================================================

/// VULNERABLE: Broadcasting Rc<T> (Send but not Sync)
/// Rc can be cloned across threads unsoundly through broadcast
pub fn vulnerable_broadcast_rc() {
    // RUSTCOLA023 should flag this - Rc is !Sync
    let (tx, _rx) = broadcast::channel::<Rc<String>>(10);

    let value = Rc::new("shared data".to_string());
    let _ = tx.send(value);
}

/// VULNERABLE: Broadcasting RefCell<T> (Send but not Sync on some types)
pub fn vulnerable_broadcast_refcell() {
    // RUSTCOLA023 should flag this - RefCell is !Sync
    let (tx, _rx) = broadcast::channel::<RefCell<Vec<u8>>>(10);

    let cell = RefCell::new(vec![1, 2, 3]);
    let _ = tx.send(cell);
}

/// VULNERABLE: Broadcasting Rc<RefCell<T>> (doubly unsafe)
pub fn vulnerable_broadcast_rc_refcell() {
    // RUSTCOLA023 should flag this - Rc<RefCell<T>> is !Sync
    let (tx, _rx) = broadcast::channel::<Rc<RefCell<i32>>>(10);

    let data = Rc::new(RefCell::new(42));
    let _ = tx.send(data);
}

/// VULNERABLE: Type alias hiding !Sync type
pub type UnsafeData = Rc<Vec<u8>>;

pub fn vulnerable_broadcast_type_alias() {
    // RUSTCOLA023 should flag this - UnsafeData = Rc<Vec<u8>>
    let (tx, _rx) = broadcast::channel::<UnsafeData>(10);

    let data = Rc::new(vec![1, 2, 3]);
    let _ = tx.send(data);
}

/// VULNERABLE: Struct wrapping !Sync type
#[derive(Clone)]
pub struct UnsafeWrapper {
    inner: Rc<String>,
}

// Manually implementing Send (but not Sync) - dangerous!
unsafe impl Send for UnsafeWrapper {}

pub fn vulnerable_broadcast_wrapper() {
    // RUSTCOLA023 should flag this - UnsafeWrapper contains Rc
    let (tx, _rx) = broadcast::channel::<UnsafeWrapper>(10);

    let wrapper = UnsafeWrapper {
        inner: Rc::new("data".to_string()),
    };
    let _ = tx.send(wrapper);
}

/// VULNERABLE: Creating sender/receiver separately
pub fn vulnerable_separate_creation() {
    // RUSTCOLA023 should flag this
    let (tx, mut rx) = broadcast::channel::<Rc<i32>>(10);

    let value = Rc::new(100);
    let _ = tx.send(value.clone());
    let _ = rx.recv();
}

/// VULNERABLE: Storing sender for later use
pub fn vulnerable_stored_sender() -> broadcast::Sender<Rc<String>> {
    // RUSTCOLA023 should flag this - returning sender with !Sync payload
    let (tx, _rx) = broadcast::channel(10);
    tx
}

/// VULNERABLE: Using subscribe() on unsync channel
pub fn vulnerable_subscribe() {
    let (tx, rx) = broadcast::channel::<Rc<Vec<u8>>>(10);

    // RUSTCOLA023 should flag this
    let _rx2 = rx.resubscribe();
    let _rx3 = tx.subscribe();

    let data = Rc::new(vec![1, 2, 3]);
    let _ = tx.send(data);
}

// ============================================================================
// SAFE PATTERNS - Should NOT trigger RUSTCOLA023
// ============================================================================

/// SAFE: Broadcasting Arc<T> (both Send and Sync)
pub fn safe_broadcast_arc() {
    use std::sync::Arc;

    // Safe: Arc is both Send and Sync
    let (tx, _rx) = broadcast::channel::<Arc<String>>(10);

    let value = Arc::new("shared data".to_string());
    let _ = tx.send(value);
}

/// SAFE: Broadcasting owned types
pub fn safe_broadcast_owned() {
    // Safe: String is Send + Sync
    let (tx, _rx) = broadcast::channel::<String>(10);

    let value = "owned data".to_string();
    let _ = tx.send(value);
}

/// SAFE: Broadcasting Copy types
pub fn safe_broadcast_copy() {
    // Safe: i32 is Copy + Send + Sync
    let (tx, _rx) = broadcast::channel::<i32>(10);

    let value = 42;
    let _ = tx.send(value);
}

/// SAFE: Broadcasting Mutex-wrapped types
pub fn safe_broadcast_mutex() {
    use std::sync::{Arc, Mutex};

    // Safe: Arc<Mutex<T>> is Sync when T is Send
    let (tx, _rx) = broadcast::channel::<Arc<Mutex<Vec<u8>>>>(10);

    let data = Arc::new(Mutex::new(vec![1, 2, 3]));
    let _ = tx.send(data);
}

/// SAFE: Broadcasting Arc<Mutex<T>>
pub fn safe_broadcast_arc_mutex() {
    use std::sync::{Arc, Mutex};

    // Safe: Arc<Mutex<T>> is Send + Sync
    let (tx, _rx) = broadcast::channel::<Arc<Mutex<i32>>>(10);

    let data = Arc::new(Mutex::new(42));
    let _ = tx.send(data);
}

/// SAFE: Broadcasting RwLock-wrapped types
pub fn safe_broadcast_rwlock() {
    use std::sync::{Arc, RwLock};

    // Safe: Arc<RwLock<T>> is Sync when T is Send + Sync
    let (tx, _rx) = broadcast::channel::<Arc<RwLock<String>>>(10);

    let data = Arc::new(RwLock::new("shared".to_string()));
    let _ = tx.send(data);
}

/// SAFE: Custom Sync type
#[derive(Clone)]
pub struct SafeWrapper {
    data: String,
}

unsafe impl Send for SafeWrapper {}
unsafe impl Sync for SafeWrapper {}

pub fn safe_broadcast_sync_wrapper() {
    // Safe: SafeWrapper implements both Send and Sync
    let (tx, _rx) = broadcast::channel::<SafeWrapper>(10);

    let wrapper = SafeWrapper {
        data: "safe data".to_string(),
    };
    let _ = tx.send(wrapper);
}

// ============================================================================
// EDGE CASES
// ============================================================================

/// EDGE: Generic function - might be called with !Sync types
pub fn edge_case_generic<T: Clone + Send>(value: T) {
    // Might be flagged if called with !Sync type
    let (tx, _rx) = broadcast::channel::<T>(10);
    let _ = tx.send(value);
}

/// EDGE: Conditional compilation
/// Note: This would require adding "unsafe_mode" feature to Cargo.toml
pub fn edge_case_conditional() {
    // This pattern might be used in libraries with feature flags
    // Uncomment to test: let (tx, _rx) = broadcast::channel::<Rc<i32>>(10);
}

/// EDGE: Type determined at runtime (trait objects)
pub fn edge_case_trait_object() {
    use std::sync::Arc;

    // Trait objects are typically Send + Sync if the trait requires it
    let (tx, _rx) = broadcast::channel::<Arc<dyn Send + Sync>>(10);

    let value: Arc<dyn Send + Sync> = Arc::new(42i32);
    let _ = tx.send(value);
}

// ============================================================================
// DEMONSTRATION OF THE BUG
// ============================================================================

/// This demonstrates the actual unsoundness in RUSTSEC-2025-0023
/// DO NOT RUN IN PRODUCTION - for educational purposes only
#[cfg(test)]
mod unsoundness_demo {
    use super::*;

    #[test]
    #[ignore] // Ignore by default as it demonstrates UB
    fn demonstrate_unsoundness() {
        // Create a broadcast channel with Rc<RefCell<i32>>
        let (tx, mut rx1) = broadcast::channel::<Rc<RefCell<i32>>>(10);
        let mut rx2 = tx.subscribe();

        // Send a value
        let value = Rc::new(RefCell::new(0));
        tx.send(value).unwrap();

        // In theory, both receivers could clone the Rc concurrently
        // from different threads, causing race conditions on Rc's
        // reference count (which is not atomic)

        // This is UB because Rc is !Sync
        let _v1 = rx1.try_recv().unwrap();
        let _v2 = rx2.try_recv().unwrap();

        // If these clones happened on different threads,
        // we'd have a data race on Rc's internal counter
    }
}
