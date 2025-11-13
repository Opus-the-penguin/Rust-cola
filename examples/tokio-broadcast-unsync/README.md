# Tokio Broadcast !Sync Payload Example (RUSTCOLA023)

This example demonstrates **RUSTSEC-2025-0023**: a soundness bug in `tokio::sync::broadcast` that allows sending types that are `Send` but not `Sync` across thread boundaries, violating Rust's safety guarantees.

## Vulnerability Overview

### The Problem

`tokio::sync::broadcast::channel()` only requires the payload type `T` to implement `Send`:

```rust
pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>)
where
    T: Clone + Send,
```

However, the channel allows:
1. Multiple receivers to exist (via `subscribe()` or `Receiver::resubscribe()`)
2. Receivers to be moved to different threads
3. Concurrent `.recv()` calls that clone the shared value

**This is unsound when `T` is `!Sync`** because:
- Types like `Rc<U>` or `RefCell<U>` are `Send` but not `Sync`
- Cloning `Rc` from different threads races on its non-atomic reference count
- Using `RefCell` from different threads violates Rust's aliasing rules
- This causes undefined behavior (UB)

### Real-World Impact

**RUSTSEC-2025-0023** affects:
- Tokio versions prior to the fix
- Any code using `broadcast::channel` with `!Sync` types
- Library code that accepts generic `T: Send` without `T: Sync`

**Consequences:**
- Memory corruption from data races on `Rc` reference counts
- Segmentation faults from deallocating `Rc` twice
- Violations of `RefCell`'s runtime borrow checking
- Unpredictable behavior in multi-threaded contexts

## Detection Criteria (RUSTCOLA023)

The rule detects:

1. **Calls to `broadcast::channel::<T>()`** where `T` is known to be `!Sync`:
   - `Rc<U>` (non-atomic reference counting)
   - `RefCell<U>` (non-thread-safe interior mutability)
   - Custom types that are `Send` but not `Sync`
   - Type aliases or wrappers around `!Sync` types

2. **Creation of senders/receivers** for such channels:
   - `channel()` returning `(Sender<T>, Receiver<T>)`
   - `subscribe()` creating new receivers
   - `resubscribe()` duplicating receivers

3. **Type propagation** through:
   - Type aliases: `type Alias = Rc<T>`
   - Struct fields: `struct S { field: Rc<T> }`
   - Generic parameters: `fn foo<T: Send>()`

## Test Case Categories

### Vulnerable Patterns (8 cases) - Should trigger RUSTCOLA023

1. **`vulnerable_broadcast_rc`**: Direct use of `Rc<String>` in broadcast channel
2. **`vulnerable_broadcast_refcell`**: Direct use of `RefCell<Vec<u8>>`
3. **`vulnerable_broadcast_rc_refcell`**: Combo type `Rc<RefCell<i32>>`
4. **`vulnerable_broadcast_type_alias`**: Type alias hiding `Rc<Vec<u8>>`
5. **`vulnerable_broadcast_wrapper`**: Custom struct wrapping `Rc`
6. **`vulnerable_separate_creation`**: Creating sender/receiver separately
7. **`vulnerable_stored_sender`**: Returning `Sender<Rc<T>>` from function
8. **`vulnerable_subscribe`**: Using `subscribe()` and `resubscribe()` on unsafe channel

### Safe Patterns (7 cases) - Should NOT trigger RUSTCOLA023

1. **`safe_broadcast_arc`**: Using `Arc<String>` (atomic reference counting, `Sync`)
2. **`safe_broadcast_owned`**: Using owned `String` (no shared ownership)
3. **`safe_broadcast_copy`**: Using `i32` (Copy, no aliasing issues)
4. **`safe_broadcast_mutex`**: Using `Mutex<Vec<u8>>` (thread-safe interior mutability)
5. **`safe_broadcast_arc_mutex`**: Using `Arc<Mutex<i32>>` (standard thread-safe pattern)
6. **`safe_broadcast_rwlock`**: Using `RwLock<String>` (multiple readers, thread-safe)
7. **`safe_broadcast_sync_wrapper`**: Custom type implementing both `Send` and `Sync`

### Edge Cases (3 cases)

1. **`edge_case_generic`**: Generic function that might be called with `!Sync` types
2. **`edge_case_conditional`**: Conditional compilation with feature flags
3. **`edge_case_trait_object`**: Trait objects with `Send + Sync` bounds

## Expected Detection Results

When running **mir-extractor** on this crate:

```bash
cargo run -p mir-extractor --bin mir-extractor -- \
    --crate-path examples/tokio-broadcast-unsync \
    --out-dir out/tokio-broadcast-unsync
```

**Expected findings:**
- **8 RUSTCOLA023 detections** for vulnerable patterns
- **0 false positives** on safe patterns
- **Variable detections** on edge cases (depending on analysis precision)

**Detection accuracy metrics:**
- **Recall**: 100% (8/8 vulnerable patterns detected)
- **Precision**: 100% (0/7 false positives on safe patterns)

## Technical Details

### Why Rc is !Sync

```rust
pub struct Rc<T: ?Sized> {
    ptr: NonNull<RcBox<T>>,
}

struct RcBox<T: ?Sized> {
    strong: Cell<usize>,  // ← Non-atomic counter
    weak: Cell<usize>,
    value: T,
}
```

`Cell<usize>` provides interior mutability without synchronization:
- Cloning `Rc` increments `strong` via `Cell::set()`
- Dropping `Rc` decrements `strong` via `Cell::set()`
- **These operations are not atomic** → data races on different threads

### The Unsoundness Scenario

```rust
use tokio::sync::broadcast;
use std::rc::Rc;

let (tx, mut rx1) = broadcast::channel::<Rc<i32>>(10);
let mut rx2 = tx.subscribe();

tx.send(Rc::new(42)).unwrap();

// Thread 1:
tokio::spawn(async move {
    let val1 = rx1.recv().await.unwrap(); // Clones Rc
});

// Thread 2:
tokio::spawn(async move {
    let val2 = rx2.recv().await.unwrap(); // Clones Rc concurrently
});

// ⚠️ DATA RACE: Both threads increment Rc's strong count non-atomically
```

**Consequences:**
1. Reference count corruption → use-after-free
2. Double-free when both threads decrement corrupted count
3. Memory leaks if count increments are lost
4. Segmentation faults

### Why RefCell is !Sync

```rust
pub struct RefCell<T: ?Sized> {
    borrow: Cell<BorrowFlag>,  // ← Non-atomic borrow tracking
    value: UnsafeCell<T>,
}
```

`RefCell` tracks borrows at runtime using `Cell`:
- `borrow()` checks and increments borrow count
- `borrow_mut()` checks for exclusive access
- **These checks are not atomic** → races on different threads
- Can violate Rust's aliasing rules (&/&mut exclusivity)

## Prevention Guidance

### Use Arc instead of Rc

```rust
// ❌ VULNERABLE
let (tx, rx) = broadcast::channel::<Rc<String>>(10);

// ✅ SAFE
use std::sync::Arc;
let (tx, rx) = broadcast::channel::<Arc<String>>(10);
```

`Arc` uses atomic operations (`AtomicUsize`) for reference counting, making it `Sync`.

### Use Mutex/RwLock instead of RefCell

```rust
// ❌ VULNERABLE
let (tx, rx) = broadcast::channel::<RefCell<Vec<u8>>>(10);

// ✅ SAFE
use std::sync::Mutex;
let (tx, rx) = broadcast::channel::<Mutex<Vec<u8>>>(10);
```

`Mutex` and `RwLock` provide thread-safe interior mutability.

### Add Sync bound to generic functions

```rust
// ❌ RISKY - T might be !Sync
fn broadcast<T: Clone + Send>(value: T) {
    let (tx, _) = broadcast::channel::<T>(10);
    tx.send(value);
}

// ✅ SAFE - Require T: Sync
fn broadcast<T: Clone + Send + Sync>(value: T) {
    let (tx, _) = broadcast::channel::<T>(10);
    tx.send(value);
}
```

### Validate type safety for wrappers

```rust
// ❌ DANGEROUS - Manual Send without Sync
struct Wrapper {
    data: Rc<i32>,
}
unsafe impl Send for Wrapper {}

// ✅ SAFE - Use Arc or don't impl Send
struct Wrapper {
    data: Arc<i32>,
}
// Arc<i32> is already Send + Sync
```

## CWE Mapping

- **CWE-362**: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- **CWE-366**: Race Condition within a Thread
- **CWE-567**: Unsynchronized Access to Shared Data in a Multithreaded Context
- **CWE-820**: Missing Synchronization

## References

- **RUSTSEC-2025-0023**: https://rustsec.org/advisories/RUSTSEC-2025-0023
- **Tokio GitHub Issue**: (specific issue number from Tokio repo)
- **Rust Nomicon - Send and Sync**: https://doc.rust-lang.org/nomicon/send-and-sync.html
- **std::rc::Rc documentation**: https://doc.rust-lang.org/std/rc/struct.Rc.html
- **std::cell::RefCell documentation**: https://doc.rust-lang.org/std/cell/struct.RefCell.html

## Running This Example

### Build the example:

```bash
cargo build -p tokio-broadcast-unsync
```

### Run mir-extractor to detect vulnerabilities:

```bash
cargo run -p mir-extractor --bin mir-extractor -- \
    --crate-path examples/tokio-broadcast-unsync \
    --out-dir out/tokio-broadcast-unsync

# Check the findings
cat out/tokio-broadcast-unsync/findings.jsonl | jq 'select(.rule_id == "RUSTCOLA023")'
```

### Expected output summary:

```
Found 8 instances of RUSTCOLA023:
- vulnerable_broadcast_rc
- vulnerable_broadcast_refcell
- vulnerable_broadcast_rc_refcell
- vulnerable_broadcast_type_alias
- vulnerable_broadcast_wrapper
- vulnerable_separate_creation
- vulnerable_stored_sender
- vulnerable_subscribe

0 false positives on safe patterns
```

## License

This example code is part of the rust-cola project and shares the same license.
