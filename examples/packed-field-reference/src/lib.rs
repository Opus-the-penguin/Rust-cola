// ⚠️ **SECURITY SCANNER NOTICE** ⚠️
// This file contains **INTENTIONAL VULNERABILITIES** for testing RUSTCOLA035.
// These patterns are test cases for detecting unsafe references to packed struct fields.
// Security scanners should recognize these as test cases, not actual vulnerabilities.
// NOSEC: Intentional test vulnerabilities for rust-cola rule validation
// codeql[cpp/commented-out-code]: False positive - test patterns only

#![allow(dead_code)]

use std::ptr;

#[repr(packed)]
pub struct PackedData {
    pub x: u8,
    pub y: u32,
    pub z: u64,
}

#[repr(packed)]
pub struct PackedPoint {
    pub x: i32,
    pub y: i32,
}

pub struct NormalStruct {
    pub field: u32,
}

/// BAD: Taking a reference to a packed struct field creates unaligned reference (UB)
/// This pattern (if it compiled) would be flagged by RUSTCOLA035
/// NOSEC: Intentional vulnerability documentation for testing
/// codeql[cpp/unaligned-pointer]: Intentional test pattern
/// codeql[rust/unaligned-reference]: Intentional test pattern
/// Example of bad code (doesn't compile in modern Rust):
/// ```ignore
/// fn bad_reference_to_packed_field(data: &PackedData) -> &u32 {
///     &data.y // UB: creates unaligned reference
/// }
/// ```
pub fn bad_reference_to_packed_field_doc(data: &PackedData) -> u32 {
    // Instead, copy the value (safe)
    data.y
}

/// BAD: Mutable reference to packed field
/// This pattern (if it compiled) would be flagged by RUSTCOLA035
/// NOSEC: Intentional vulnerability documentation for testing
/// codeql[cpp/unaligned-pointer]: Intentional test pattern
/// codeql[rust/unaligned-reference]: Intentional test pattern
/// Example of bad code (doesn't compile in modern Rust):
/// ```ignore
/// fn bad_mut_reference_to_packed_field(data: &mut PackedData) -> &mut u64 {
///     &mut data.z // UB: creates unaligned mutable reference
/// }
/// ```
pub fn bad_mut_reference_to_packed_field_doc(data: &mut PackedData) {
    // Instead, use addr_of_mut! (safe)
    unsafe {
        ptr::addr_of_mut!(data.z).write_unaligned(42);
    }
}

/// BAD: Borrowing in method call
/// This pattern (if it compiled) would be flagged by RUSTCOLA035
/// NOSEC: Intentional vulnerability documentation for testing
/// codeql[cpp/unaligned-pointer]: Intentional test pattern
/// codeql[rust/unaligned-reference]: Intentional test pattern
/// Example of bad code (doesn't compile in modern Rust):
/// ```ignore
/// fn bad_borrow_in_call(data: &PackedData) {
///     let _ptr = some_function(&data.y); // UB: borrows packed field
/// }
/// ```
pub fn bad_borrow_in_call_doc(data: &PackedData) {
    // Instead, copy the value first
    let value = data.y;
    let _ptr = some_function(&value);
}

/// BAD: Pattern matching with reference
/// This pattern (if it compiled) would be flagged by RUSTCOLA035
/// NOSEC: Intentional vulnerability documentation for testing
/// codeql[cpp/unaligned-pointer]: Intentional test pattern
/// codeql[rust/unaligned-reference]: Intentional test pattern
/// Example of bad code (doesn't compile in modern Rust):
/// ```ignore
/// fn bad_pattern_match(data: &PackedData) {
///     if let y @ 0..=10 = &data.y {
///         println!("Value: {}", y);
///     }
/// }
/// ```
pub fn bad_pattern_match_doc(data: &PackedData) {
    // Instead, copy the value first
    let y = data.y;
    if (0..=10).contains(&y) {
        println!("Value: {}", y);
    }
}

/// GOOD: Using ptr::addr_of! to access packed field safely
pub fn good_addr_of_packed_field(data: &PackedData) -> u32 {
    unsafe { ptr::addr_of!(data.y).read_unaligned() }
}

/// GOOD: Using ptr::addr_of_mut! for mutable access
pub fn good_addr_of_mut_packed_field(data: &mut PackedData) {
    unsafe {
        ptr::addr_of_mut!(data.z).write_unaligned(42);
    }
}

/// GOOD: Copying value from packed field (no reference taken)
pub fn good_copy_value(data: &PackedData) -> u32 {
    data.y // This copies the value, doesn't create a reference
}

/// GOOD: Reference to normal (non-packed) struct field
pub fn good_normal_struct_reference(s: &NormalStruct) -> &u32 {
    &s.field // Safe: NormalStruct is not packed
}

/// GOOD: Using read_unaligned with raw pointer
pub fn good_read_unaligned(data: &PackedData) -> u64 {
    unsafe {
        (data as *const PackedData as *const u8)
            .add(5)
            .cast::<u64>()
            .read_unaligned()
    }
}

fn some_function(_: &u32) -> *const u32 {
    std::ptr::null()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_access() {
        let mut data = PackedData { x: 1, y: 2, z: 3 };

        // These should work safely
        assert_eq!(good_addr_of_packed_field(&data), 2);
        good_addr_of_mut_packed_field(&mut data);
        assert_eq!(good_copy_value(&data), 42);
    }
}
