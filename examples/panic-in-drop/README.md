# Panic in Drop Test Examples

⚠️ **WARNING: This crate contains INTENTIONAL security vulnerabilities** ⚠️

This crate is part of the Rust-cola SAST tool's test suite for **RUSTCOLA040: Panic in Drop implementation detection**.

## About the Vulnerability

Panicking inside a `Drop` implementation is dangerous because:

- **Double panic = abort**: If a panic occurs while already unwinding from another panic, the process immediately aborts
- **Masks original errors**: The original panic message is lost when Drop panics
- **Difficult debugging**: Stack traces become confusing and incomplete
- **Resource leaks**: Other destructors may not run if the process aborts

This violates Rust's exception safety principles and is explicitly warned against in the Nomicon.

## Test Patterns

### Bad Patterns (Should be detected)

1. **BadPanicDrop**: Uses `panic!()` macro directly in Drop
2. **BadUnwrapDrop**: Uses `.unwrap()` which can panic on error
3. **BadExpectDrop**: Uses `.expect()` which panics with a custom message
4. **BadUnreachableDrop**: Uses `unreachable!()` which panics
5. **BadTodoDrop**: Uses `todo!()` which panics (incomplete code)

### Good Patterns (Should NOT be detected)

1. **GoodDrop**: Proper error handling with `if let Err`
2. **GoodLogDrop**: Logs errors to stderr instead of panicking
3. **GoodSilentDrop**: Silently ignores errors with `let _`
4. **GoodCatchUnwindDrop**: Uses `catch_unwind` to prevent panic propagation
5. **GoodSimpleDrop**: Simple infallible cleanup operations

## Safe Alternatives

Instead of panicking in Drop, use these patterns:

```rust
impl Drop for MyType {
    fn drop(&mut self) {
        // ✅ GOOD: Handle errors gracefully
        if let Err(e) = self.cleanup() {
            eprintln!("Cleanup failed: {}", e);
        }
        
        // ✅ GOOD: Explicitly ignore non-critical errors
        let _ = std::fs::remove_file("temp.txt");
        
        // ✅ GOOD: Use catch_unwind for risky operations
        let _ = std::panic::catch_unwind(|| {
            self.potentially_panicking_cleanup();
        });
        
        // ❌ BAD: Don't do this
        // self.cleanup().unwrap();
        // panic!("cleanup failed");
    }
}
```

## Rust Best Practices

From the [Rust Nomicon on Exception Safety](https://doc.rust-lang.org/nomicon/exception-safety.html):

> "Panicking in a destructor is fine if you're not already panicking. If you are already panicking, though, the process will simply abort."

Guidelines:
1. **Never use `unwrap()`, `expect()`, or `panic!()` in Drop**
2. **Log errors** to stderr or logging framework
3. **Silently ignore** non-critical errors
4. **Use `catch_unwind`** if you must call risky code
5. **Keep Drop implementations simple** and infallible when possible

## When Double-Panic Occurs

```rust
struct Outer;
impl Drop for Outer {
    fn drop(&mut self) {
        panic!("outer"); // ← This panics first
    }
}

struct Inner;
impl Drop for Inner {
    fn drop(&mut self) {
        panic!("inner"); // ← This causes abort!
    }
}

fn main() {
    let _outer = Outer;
    let _inner = Inner;
    panic!("main"); // Process aborts when Inner drops during unwinding
}
```

## References

- [Rust Nomicon: Exception Safety](https://doc.rust-lang.org/nomicon/exception-safety.html)
- [Rust RFC 1236: Stabilize catch_panic](https://rust-lang.github.io/rfcs/1236-stabilize-catch-panic.html)
- [Drop trait documentation](https://doc.rust-lang.org/std/ops/trait.Drop.html)

## Scanner Configuration

This crate should be **excluded** from security scans or marked as a false positive. The vulnerabilities are intentional test cases.
