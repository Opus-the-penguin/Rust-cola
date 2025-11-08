# Unsafe CString Pointer Test Cases

⚠️ **SECURITY SCANNER NOTICE** ⚠️

This directory contains **INTENTIONAL VULNERABILITIES** for testing purposes.

## Purpose

Test cases for **RUSTCOLA036** (unsafe-cstring-pointer) rule detection. These functions deliberately use CString temporaries with `.as_ptr()` to verify the security scanner correctly identifies dangling pointer creation.

## Test Functions

### Bad Examples (Should be flagged)
- `bad_cstring_unwrap_as_ptr()` - `CString::new(s).unwrap().as_ptr()` creates dangling pointer
- `bad_cstring_expect_as_ptr()` - `CString::new(s).expect("...").as_ptr()` creates dangling pointer
- `bad_cstring_try_as_ptr()` - `CString::new(s)?.as_ptr()` creates dangling pointer
- `bad_direct_chain()` - `CString::new(s).ok().unwrap().as_ptr()` creates dangling pointer

### Good Examples (Should NOT be flagged)
- `good_stored_cstring()` - Stores CString in variable before calling `as_ptr()`
- `good_into_raw()` - Uses `into_raw()` to transfer ownership
- `good_return_cstring()` - Returns the CString itself
- `good_immediate_use()` - Uses pointer within CString's lifetime
- `good_as_c_str()` - Converts to `&CStr` which properly borrows

## Security Issue

Calling `.as_ptr()` on a CString temporary creates a dangling pointer because the CString is dropped at the end of the statement. Dereferencing this pointer is undefined behavior and can lead to:
- Use-after-free vulnerabilities
- Memory corruption
- Crashes or unpredictable behavior
- Security exploits

The issue occurs because:
1. `CString::new(...)` creates a temporary
2. `.unwrap()` / `.expect()` / `?` pass through the temporary
3. `.as_ptr()` returns a raw pointer
4. The temporary CString is immediately dropped
5. The pointer now points to freed memory

## Safe Alternatives

Instead of using temporaries:
- Store the CString in a variable: `let c_str = CString::new(...)?; c_str.as_ptr()`
- Use `into_raw()` to transfer ownership (caller must free with `from_raw`)
- Return the CString itself and let the caller extract the pointer
- Use `as_c_str()` to get a `&CStr` borrow

## DO NOT USE THIS CODE IN PRODUCTION

These patterns create dangling pointers and cause undefined behavior. They are for testing only.

## Suppression Comments

All vulnerable functions are marked with:
- `NOSEC` tags for general security scanners
- `CodeQL` suppression comments (`cpp/use-after-free`, `rust/dangling-pointer`)
- Inline comments explaining the intentional vulnerability

Security scanners should recognize these as test cases and not report them as actual vulnerabilities in the rust-cola codebase.
