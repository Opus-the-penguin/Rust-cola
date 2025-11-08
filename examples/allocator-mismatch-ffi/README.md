# Allocator Mismatch FFI Test Cases

⚠️ **SECURITY SCANNER NOTICE** ⚠️

This directory contains **INTENTIONAL VULNERABILITIES** for testing purposes.

## Purpose

Test cases for **RUSTCOLA017** (allocator-mismatch) rule detection. These functions deliberately mix Rust and C allocators to verify the security scanner correctly identifies allocator mismatches.

## Test Functions

### Bad Examples (Should be flagged)
- `box_freed_with_libc()` - Box::into_raw freed with libc::free
- `cstring_freed_with_libc()` - CString::into_raw freed with libc::free
- `malloc_to_box()` - malloc pointer converted to Box::from_raw
- `calloc_to_box()` - calloc pointer converted to Box::from_raw

### Good Examples (Should NOT be flagged)
- `box_freed_correctly()` - Box::into_raw freed with Box::from_raw
- `cstring_freed_correctly()` - CString::into_raw freed with CString::from_raw
- `malloc_freed_correctly()` - malloc freed with libc::free
- `system_alloc_consistent()` - Consistent C allocator usage

## DO NOT USE THIS CODE IN PRODUCTION

These patterns cause undefined behavior and memory corruption. They are for testing only.

## Suppression Comments

All vulnerable functions are marked with:
- `NOSEC` tags for general security scanners
- `CodeQL` suppression comments
- Inline comments explaining the intentional vulnerability

Security scanners should recognize these as test cases and not report them as actual vulnerabilities in the rust-cola codebase.
