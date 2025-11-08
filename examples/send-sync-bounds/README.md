# Send/Sync Bounds Test Cases

⚠️ **SECURITY SCANNER NOTICE** ⚠️

This directory contains **INTENTIONAL VULNERABILITIES** for testing purposes.

## Purpose

Test cases for **RUSTCOLA015** (missing-send-sync-bounds) rule detection. These types deliberately implement `Send` and `Sync` unsafely without proper trait bounds on generic parameters to verify the security scanner correctly identifies potential thread-safety violations.

## Test Types

### Bad Examples (Should be flagged)
- `WrapperBad<T>` - unsafe impl Send/Sync without `T: Send`/`T: Sync` bounds (2 violations)
- `MultiWrapper<T, U>` - unsafe impl Send without `T: Send`, `U: Send` bounds
- `PhantomWrapper<T>` - unsafe impl Send without `T: Send` bound (PhantomData doesn't automatically convey bounds)

### Good Examples (Should NOT be flagged)
- `WrapperGood<T: Send>` - Properly requires T: Send for impl Send
- `WrapperFullBounds<T: Send + Sync>` - Properly requires both traits
- `PtrWrapper<T>` - No Send/Sync impls (correctly restricts to single thread)
- `GenericWrapper<T: MyTrait>` - Trait bound doesn't imply Send/Sync (correctly not implementing them)
- `WrapperConditional<T>` - Manual Send impl requires T: Send bound (correct)
- `SendOnly<T: Send>` - Correctly only impl Send with Send bound (not also implementing Sync incorrectly)

## Security Issue

Implementing `Send` or `Sync` for generic types without proper trait bounds can lead to:
- Data races (multiple threads accessing non-thread-safe data)
- Memory corruption (concurrent mutation of shared state)
- Undefined behavior (violating Rust's thread-safety guarantees)

The issue is particularly subtle with `PhantomData<T>` - even though the data is phantom (zero-size), the type still logically "owns" a `T` and must respect its thread-safety characteristics.

## DO NOT USE THIS CODE IN PRODUCTION

These patterns are dangerous and violate Rust's thread-safety guarantees. They are for testing only.

## Suppression Comments

All vulnerable implementations are marked with:
- `NOSEC` tags for general security scanners
- `CodeQL` suppression comments  
- Inline comments explaining the intentional vulnerability

Security scanners should recognize these as test cases and not report them as actual vulnerabilities in the rust-cola codebase.
