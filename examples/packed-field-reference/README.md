# Packed Field Reference Test Cases

⚠️ **SECURITY SCANNER NOTICE** ⚠️

This directory contains **INTENTIONAL VULNERABILITIES** for testing purposes.

## Purpose

Test cases for **RUSTCOLA035** (repr-packed-field-reference) rule detection. These functions deliberately take references to fields of `#[repr(packed)]` structs to verify the security scanner correctly identifies unaligned reference creation (undefined behavior).

## Test Functions

### Bad Examples (Should be flagged)
- `bad_reference_to_packed_field()` - Takes `&data.y` reference to packed field
- `bad_mut_reference_to_packed_field()` - Takes `&mut data.z` reference to packed field  
- `bad_borrow_in_call()` - Passes `&data.y` to function call
- `bad_pattern_match()` - Uses `&data.y` in pattern matching

### Good Examples (Should NOT be flagged)
- `good_addr_of_packed_field()` - Uses `ptr::addr_of!` safely
- `good_addr_of_mut_packed_field()` - Uses `ptr::addr_of_mut!` for mutable access
- `good_copy_value()` - Copies value without taking reference
- `good_normal_struct_reference()` - Reference to non-packed struct (safe)
- `good_read_unaligned()` - Uses raw pointer with `read_unaligned`

## Security Issue

Taking references to fields of `#[repr(packed)]` structs creates unaligned references, which is undefined behavior in Rust. This can lead to:
- Memory corruption (misaligned access crashes on some architectures)
- Undefined behavior (compiler assumes all references are aligned)
- Performance degradation (unaligned access penalties)
- Security vulnerabilities (exploitable UB)

## Safe Alternatives

Instead of taking references, use:
- `ptr::addr_of!(data.field)` for immutable access
- `ptr::addr_of_mut!(data.field)` for mutable access  
- `read_unaligned()` / `write_unaligned()` with raw pointers
- Copy the value directly (no reference needed)

## DO NOT USE THIS CODE IN PRODUCTION

These patterns cause undefined behavior and are extremely dangerous. They are for testing only.

## Suppression Comments

All vulnerable functions are marked with:
- `NOSEC` tags for general security scanners
- `CodeQL` suppression comments (`cpp/unaligned-pointer`, `rust/unaligned-reference`)
- Inline comments explaining the intentional vulnerability

Security scanners should recognize these as test cases and not report them as actual vulnerabilities in the rust-cola codebase.
