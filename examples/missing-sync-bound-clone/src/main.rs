//! Test cases for RUSTCOLA111: Missing Sync Bound on Clone
//!
//! This example demonstrates dangerous patterns where concurrent data structures
//! clone values without requiring the Sync trait bound, which can cause data races.
//! Based on RUSTSEC-2025-0023 (tokio broadcast channel vulnerability).

use std::sync::Arc;

// ============================================================================
// PROBLEMATIC: Clone + Send without Sync bound
// ============================================================================

/// PROBLEMATIC: Receiver that clones without Sync bound
/// This pattern was the root cause of RUSTSEC-2025-0023
pub struct UnsafeReceiver<T: Clone + Send> {
    inner: Arc<SharedState<T>>,
}

struct SharedState<T> {
    value: T,
}

impl<T: Clone + Send> UnsafeReceiver<T> {
    /// PROBLEMATIC: Cloning value without Sync bound
    /// If two threads call recv() simultaneously, they may both try to
    /// clone the same inner value, causing a data race.
    pub fn recv(&self) -> T {
        // This clone can race if T is not Sync!
        self.inner.value.clone()
    }
}

// PROBLEMATIC: unsafe impl Sync for Sender without Sync bound on T
// This is exactly the pattern that caused the tokio vulnerability
unsafe impl<T: Clone + Send> Sync for UnsafeReceiver<T> {}

/// PROBLEMATIC: Broadcast channel without Sync bound
pub struct UnsafeBroadcastSender<T: Clone + Send> {
    shared: Arc<BroadcastShared<T>>,
}

struct BroadcastShared<T> {
    buffer: Vec<T>,
}

impl<T: Clone + Send> UnsafeBroadcastSender<T> {
    pub fn send(&self, _value: T) {
        // Sending is fine, the problem is receiving/cloning
    }
}

// PROBLEMATIC: Another unsafe impl Sync for a Channel type
unsafe impl<T: Clone + Send> Sync for UnsafeBroadcastSender<T> {}

// ============================================================================
// SAFE: Clone + Send + Sync bound
// ============================================================================

/// SAFE: Receiver that properly requires Sync bound
pub struct SafeReceiver<T: Clone + Send + Sync> {
    inner: Arc<SafeSharedState<T>>,
}

struct SafeSharedState<T> {
    value: T,
}

impl<T: Clone + Send + Sync> SafeReceiver<T> {
    /// SAFE: With Sync bound, concurrent cloning is safe
    pub fn recv(&self) -> T {
        self.inner.value.clone()
    }
}

// SAFE: impl Sync is fine because T: Sync
unsafe impl<T: Clone + Send + Sync> Sync for SafeReceiver<T> {}

/// SAFE: Channel with proper Sync bound
pub struct SafeChannel<T: Clone + Send + Sync> {
    shared: Arc<ChannelShared<T>>,
}

struct ChannelShared<T> {
    buffer: Vec<T>,
}

impl<T: Clone + Send + Sync> SafeChannel<T> {
    pub fn recv(&self) -> Option<T> {
        self.shared.buffer.first().cloned()
    }
}

// SAFE: Sync bound on T makes this safe
unsafe impl<T: Clone + Send + Sync> Sync for SafeChannel<T> {}

// ============================================================================
// ALSO SAFE: Using Mutex for synchronization
// ============================================================================

use std::sync::Mutex;

/// SAFE: Using Mutex instead of requiring Sync
pub struct MutexChannel<T: Clone + Send> {
    shared: Arc<Mutex<MutexShared<T>>>,
}

struct MutexShared<T> {
    value: Option<T>,
}

impl<T: Clone + Send> MutexChannel<T> {
    /// SAFE: Mutex provides synchronization
    pub fn recv(&self) -> Option<T> {
        let guard = self.shared.lock().unwrap();
        guard.value.clone()
    }
}

// SAFE: Mutex provides the synchronization, no Sync bound needed
// (This doesn't need unsafe impl Sync at all - Mutex<T> is Sync if T: Send)

fn main() {
    println!("RUSTCOLA111: Missing Sync Bound on Clone");
    println!("=========================================");
    println!();
    println!("PROBLEMATIC patterns (should trigger warnings):");
    println!("  - impl<T: Clone + Send> for channel types (missing Sync)");
    println!("  - unsafe impl Sync for Sender/Receiver/Channel without T: Sync");
    println!();
    println!("SAFE patterns:");
    println!("  - impl<T: Clone + Send + Sync> for channel types");
    println!("  - Using Mutex for synchronization instead");
    println!();
    println!("Reference: RUSTSEC-2025-0023 (tokio broadcast channel)");
}
