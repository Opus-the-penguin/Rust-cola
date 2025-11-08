# Blocking Sleep in Async Test Cases

⚠️ **SECURITY SCANNER NOTICE** ⚠️

This directory contains **INTENTIONAL VULNERABILITIES** for testing purposes.

## Purpose

Test cases for **RUSTCOLA037** (blocking-sleep-in-async) rule detection. These functions deliberately use `std::thread::sleep` inside async functions to verify the security scanner correctly identifies blocking calls that can stall async executors.

## Test Functions

### Bad Examples (Should be flagged)
- `bad_blocking_sleep_basic()` - Uses `std::thread::sleep()` in async function
- `bad_blocking_sleep_imported()` - Uses `thread::sleep()` with import
- `AsyncWorker::bad_process()` - Blocking sleep in async method
- `bad_sleep_in_loop()` - Repeated blocking sleeps in async loop

### Good Examples (Should NOT be flagged)
- `good_async_sleep_conceptual()` - Uses async sleep (conceptual)
- `good_tokio_sleep()` - Uses `tokio::time::sleep().await` (with feature)
- `good_no_sleep()` - No sleep, just computation
- `good_sync_sleep()` - Blocking sleep in sync function (OK)
- `good_spawn_blocking_conceptual()` - Spawns blocking task properly
- `good_tokio_spawn_blocking()` - Uses `tokio::task::spawn_blocking`

## Security Issue

Using `std::thread::sleep` or similar blocking sleep calls inside async functions blocks the executor thread, preventing other async tasks from running. This can lead to:
- Denial of service (executor thread stalled)
- Poor performance (tasks can't make progress)
- Deadlocks (if tasks wait for each other)
- Timeouts and failures

The async runtime expects tasks to yield control frequently via `.await` points. Blocking sleep prevents yielding and monopolizes the executor thread.

## Safe Alternatives

Instead of blocking sleep:
- Use async sleep: `tokio::time::sleep(duration).await`
- Use async-std sleep: `async_std::task::sleep(duration).await`
- For truly blocking operations, use `spawn_blocking`:
  ```rust
  tokio::task::spawn_blocking(|| {
      std::thread::sleep(duration);
  }).await
  ```
- Avoid sleep entirely if possible - use async event waiting

## DO NOT USE THIS CODE IN PRODUCTION

These patterns can cause denial of service and poor performance. They are for testing only.

## Suppression Comments

All vulnerable functions are marked with:
- `NOSEC` tags for general security scanners
- `CodeQL` suppression comments (`cpp/blocking-call-in-async`, `rust/blocking-in-async`)
- Inline comments explaining the intentional vulnerability

Security scanners should recognize these as test cases and not report them as actual vulnerabilities in the rust-cola codebase.
