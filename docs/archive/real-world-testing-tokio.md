# Real-World Testing: Tokio Async Runtime Analysis

## Overview

This document captures findings from analyzing the **tokio-rs/tokio** async runtime and its ecosystem for additional Rust-specific vulnerability patterns. Tokio is the most widely-used async runtime in the Rust ecosystem with millions of downloads.

**Date**: December 2025  
**Version Analyzed**: Latest main branch  
**Purpose**: Identify vulnerability patterns for rust-cola security rules

---

## RUSTSEC Advisory Analysis

### Direct Tokio Vulnerabilities

| Advisory ID | CVE | Severity | Description |
|-------------|-----|----------|-------------|
| RUSTSEC-2025-0023 | N/A | UNSOUND | Broadcast channel calls `clone` in parallel without requiring `Sync` bound |
| RUSTSEC-2023-0005 | N/A | UNSOUND | `ReadHalf<T>::unsplit` violates `Pin` contract |
| RUSTSEC-2023-0001 | N/A | VULN | `reject_remote_clients` configuration corruption |
| RUSTSEC-2021-0124 | CVE-2021-45710 | HIGH | Data race in oneshot channel after `close()` |
| RUSTSEC-2021-0072 | CVE-2021-38191 | HIGH | Task dropped in wrong thread when aborting `LocalSet` task |

### Tokio Ecosystem Vulnerabilities (TARmageddon)

| Advisory ID | CVE | Severity | Description |
|-------------|-----|----------|-------------|
| RUSTSEC-2025-0111 | CVE-2025-62518 | HIGH | `tokio-tar` PAX header parsing allows file smuggling |
| RUSTSEC-2025-0110 | CVE-2025-62518 | HIGH | `astral-tokio-tar` PAX header desynchronization |

### Related Ecosystem Vulnerabilities

| Advisory ID | Crate | Description |
|-------------|-------|-------------|
| RUSTSEC-2024-0019 | mio | Token delivery after deregistration |

---

## Vulnerability Pattern Analysis

### 1. Send/Sync Trait Bound Violations (RUSTSEC-2025-0023)

**Pattern**: Types that are `Send` but not `Sync` being used in contexts that assume `Sync`

**Technical Details**:
- The broadcast channel internally calls `clone` on stored values when receiving
- Channel only requires `T: Send`, not `T: Send + Sync`
- If `clone` implementation relies on the value being `!Sync`, unsoundness occurs

**Detection Strategy**:
```rust
// VULNERABLE: Clone called in parallel on Send + !Sync type
impl<T: Clone + Send> Receiver<T> {
    fn recv(&self) -> T {
        // clone() called from multiple threads simultaneously
        value.clone()  // If T is !Sync, this is unsound
    }
}

// SAFE: Requires T: Clone + Send + Sync
impl<T: Clone + Send + Sync> Receiver<T> {
    fn recv(&self) -> T {
        value.clone()
    }
}
```

**Rule Candidate**: `RUSTCOLA111` - MissingSyncBoundOnClone
- Detect channel/concurrent data structures that clone values without `Sync` bound
- Flag `unsafe impl Sync` without corresponding bounds validation

---

### 2. Pin Contract Violations (RUSTSEC-2023-0005)

**Pattern**: `unsplit` operations that move pinned values incorrectly

**Technical Details**:
- `ReadHalf<T>::unsplit` can violate Pin contract for `!Unpin` types
- Requires specific conditions: `!Unpin` type in `ReadHalf`
- Can lead to use-after-free in extreme cases

**Detection Strategy**:
```rust
// VULNERABLE: Moving pinned data through unsplit
let (read, write) = io.split();
let combined = read.unsplit(write);  // May move !Unpin data incorrectly

// Pattern to detect:
// - Split/unsplit pairs on potentially !Unpin types
// - Pin::new_unchecked followed by moves
```

**Rule Candidate**: `RUSTCOLA112` - PinContractViolation
- Detect `unsplit` patterns on generic IO types
- Flag potential Pin moves through reconstruction operations

---

### 3. Data Race on Channel Close (RUSTSEC-2021-0124)

**Pattern**: Race condition when `close()` is called concurrently with `send()`/`recv()`

**Technical Details**:
- If `oneshot::Receiver::close()` is called, then both `send()` and `await`/`try_recv()` are called concurrently
- The two halves can concurrently access shared memory
- Results in memory corruption

**Detection Strategy**:
```rust
// VULNERABLE PATTERN:
let (tx, mut rx) = oneshot::channel();

// Thread 1
rx.close();

// Thread 2 (concurrent)
let _ = tx.send(value);  // Race!

// Thread 3 (concurrent)  
let _ = rx.await;  // Race!
```

**Rule Candidate**: `RUSTCOLA113` - OneshotRaceAfterClose
- Detect `close()` followed by concurrent channel operations
- Flag patterns where sender/receiver are used after `close()`

---

### 4. LocalSet Task Thread Affinity (RUSTSEC-2021-0072)

**Pattern**: `JoinHandle::abort()` dropping `!Send` task on wrong thread

**Technical Details**:
- When aborting a `LocalSet` task via `JoinHandle::abort()`
- If task is not currently executing, future is dropped in the calling thread
- This violates thread-locality for `!Send` types (`Rc`, `RefCell`, etc.)

**Detection Strategy**:
```rust
// VULNERABLE PATTERN:
let local = LocalSet::new();
local.spawn_local(async {
    let rc = Rc::new(42);  // !Send type
    some_async_op().await;
    drop(rc);  // May be dropped on wrong thread if aborted!
});

// Called from another thread:
handle.abort();  // Drops Rc on wrong thread!
```

**Rule Candidate**: Already covered by `RUSTCOLA094` (MutexGuardAcrossAwait) pattern
- Extend to detect `!Send` types in `LocalSet` contexts with external abort handles

---

### 5. TARmageddon - Archive Parser Desynchronization (CVE-2025-62518)

**Pattern**: Parser boundary misalignment allowing file smuggling

**Technical Details**:
- PAX header specifies one size, ustar header specifies zero
- Parser uses wrong size for stream advancement
- Inner archive entries interpreted as outer archive entries
- Leads to file overwriting attacks, supply chain attacks, BOM bypass

**Attack Scenarios**:
1. **Python Build Backend Hijacking**: Malicious `pyproject.toml` smuggled into packages
2. **Container Image Poisoning**: Hidden files in container layers
3. **BOM/Manifest Bypass**: Security scanners see different files than extraction

**Detection Strategy**:
```rust
// VULNERABLE PATTERN:
// Using unmaintained tokio-tar for archive extraction
use tokio_tar::Archive;

let archive = Archive::new(tarball);
for entry in archive.entries()? {
    entry?.unpack_in(dest)?;  // May extract smuggled files!
}
```

**Rule Candidate**: `RUSTCOLA114` - UnmaintainedArchiveCrate
- Detect use of `tokio-tar` (unmaintained/vulnerable)
- Flag archive extraction to filesystem without validation
- Recommend `astral-tokio-tar` or synchronous `tar` crate wrapped in `spawn_blocking`

---

### 6. Blocking IO in Async Context

**Pattern**: Calling `std::fs::*` or blocking IO directly in async contexts

**Technical Details**:
- Tokio provides `tokio::fs::*` wrappers that use `spawn_blocking` internally
- Directly calling `std::fs::*` blocks the async runtime
- Can cause entire runtime to stall

**Existing Rule**: Already covered by `RUSTCOLA015` (BlockingInAsync)

**Validation**: Tokio codebase shows the correct pattern:
```rust
// Tokio's fs module wraps std::fs in spawn_blocking
pub async fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    asyncify(move || std::fs::read(path)).await
}

async fn asyncify<F, T>(f: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    spawn_blocking(f).await.map_err(/* ... */)?
}
```

---

### 7. Cancellation Safety Issues

**Pattern**: Futures that are not cancellation-safe being used in `select!`

**Technical Details**:
- Tokio's `select!` macro drops incomplete futures
- If a future is not cancellation-safe, data may be lost
- Tokio documents cancellation safety extensively

**Key Insight from Tokio Docs**:
```rust
/// # Cancellation safety
/// 
/// This method is only cancel safe if `fut` is cancel safe.
pub async fn run_until_cancelled<F>(&self, fut: F) -> Option<F::Output>
```

**Detection Strategy**:
- Already partially covered by `RUSTCOLA094`
- Could extend with `RUSTCOLA115` - NonCancellationSafeSelect

---

### 8. Panic Handling in Async Contexts

**Pattern**: Panics in async task destructors causing issues

**Technical Details from Tests**:
```rust
// tokio/tests/task_abort.rs
#[test]
#[cfg(panic = "unwind")]
fn test_abort_task_that_panics_on_drop_contained() {
    // Tokio catches panics in task destructors to prevent escape
}
```

**Key Finding**: Tokio actively catches panics from task destructors during abort

**Detection Strategy**:
- Detect `impl Drop` that may panic in async task contexts
- Already partially covered by existing panic rules

---

## Summary: New Rule Candidates from Tokio Research

| Rule ID | Name | Severity | Category |
|---------|------|----------|----------|
| RUSTCOLA111 | MissingSyncBoundOnClone | HIGH | Concurrency/Unsoundness |
| RUSTCOLA112 | PinContractViolation | HIGH | Memory Safety |
| RUSTCOLA113 | OneshotRaceAfterClose | HIGH | Concurrency/Race |
| RUSTCOLA114 | UnmaintainedArchiveCrate | HIGH | Supply Chain/Ecosystem |
| RUSTCOLA115 | NonCancellationSafeSelect | MEDIUM | Async/Data Loss |

---

## Patterns Validated (Existing Rules)

| Existing Rule | Tokio Validation |
|---------------|------------------|
| RUSTCOLA015 | Blocking in async - Tokio's fs module shows correct pattern |
| RUSTCOLA094 | MutexGuardAcrossAwait - LocalSet abort issues validate this pattern |

---

## Key Takeaways

### 1. Async Runtime Complexity Creates New Attack Surface
- Channel implementations have subtle Send/Sync requirements
- Task scheduling across threads creates opportunities for race conditions
- Cancellation and abort introduce non-obvious drop timing issues

### 2. Fork Lineage and Maintenance Risk
- TARmageddon affected multiple crates due to shared ancestry
- Unmaintained crates (`tokio-tar`) remain vulnerable indefinitely
- Need rules to detect use of known-vulnerable unmaintained crates

### 3. Logic Bugs vs Memory Safety
- Rust prevents memory corruption but not logic errors
- Parser desynchronization (TARmageddon) is a pure logic bug
- Send/Sync violations require correct trait bound specification

### 4. Defense in Depth Required
- Tokio's extensive testing for edge cases (panic in drop, abort races)
- But still has had multiple vulnerabilities discovered
- Static analysis can catch patterns before production

---

## References

1. [RUSTSEC-2025-0023](https://rustsec.org/advisories/RUSTSEC-2025-0023.html) - Broadcast channel Sync bound
2. [RUSTSEC-2023-0005](https://rustsec.org/advisories/RUSTSEC-2023-0005.html) - ReadHalf::unsplit unsound
3. [RUSTSEC-2021-0124](https://rustsec.org/advisories/RUSTSEC-2021-0124.html) - Oneshot data race
4. [RUSTSEC-2021-0072](https://rustsec.org/advisories/RUSTSEC-2021-0072.html) - LocalSet abort
5. [TARmageddon Blog Post](https://edera.dev/stories/tarmageddon) - CVE-2025-62518 details
6. [Tokio Cancellation Safety Docs](https://docs.rs/tokio/latest/tokio/sync/index.html#cancellation-safety)
