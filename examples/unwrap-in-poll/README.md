# unwrap-in-poll

⚠️ **SECURITY SCANNER NOTICE** ⚠️

This directory contains **INTENTIONAL VULNERABILITIES** for testing RUSTCOLA041.

## Purpose

This test crate validates that Rust-cola correctly detects `unwrap()`, `expect()`, and `panic!()` calls inside `Future::poll` implementations.

## Why This Matters

Panicking in `Future::poll` can:
- **Stall async executors** - The executor may hang waiting for a future that will never complete
- **Cause runtime hangs** - Application becomes unresponsive
- **Make debugging difficult** - Stack traces don't show where the future was originally spawned
- **Break task cancellation** - Cleanup code may not run

## Bad Patterns (Should be detected)

1. **`unwrap()` in poll** - Panics if Option/Result contains None/Err
2. **`expect()` in poll** - Panics with custom message
3. **`panic!()` in poll** - Direct panic macro

## Good Patterns (Should NOT be detected)

1. **Match expressions** - Properly handle None/Err cases
2. **Error propagation** - Return `Poll::Ready(Err(...))` instead of panicking

## Expected Detection

Running `cargo-cola` on this crate should detect:
- ✅ 3 findings: unwrap, expect, panic in poll implementations
- ❌ 0 false positives in good patterns

## References

- [Rust Async Book: Wakeups](https://rust-lang.github.io/async-book/02_execution/03_wakeups.html)
- [Tokio: Best Practices](https://tokio.rs/tokio/topics/best-practices)
- Rule: RUSTCOLA041 (unwrap-in-poll)
- Severity: Medium
