//! Test cases for RUSTCOLA095: Transmute changing lifetimes
//!
//! Using transmute to change lifetime parameters is undefined behavior because
//! it can create references that outlive the data they point to.
//!
//! Expected: 6 PROBLEMATIC patterns detected, 6 SAFE patterns not flagged

use std::mem::transmute;

// ============================================================================
// PROBLEMATIC PATTERNS - Transmute changing lifetimes
// ============================================================================

/// PROBLEMATIC: Transmute extending lifetime of reference
pub fn bad_extend_lifetime<'a>(s: &'a str) -> &'static str {
    // DANGER: This creates a 'static reference from a shorter-lived one
    unsafe { transmute::<&'a str, &'static str>(s) }
}

/// PROBLEMATIC: Transmute to extend mutable reference lifetime
pub fn bad_extend_mut_lifetime<'a>(s: &'a mut String) -> &'static mut String {
    unsafe { transmute::<&'a mut String, &'static mut String>(s) }
}

/// PROBLEMATIC: Transmute slice with lifetime change
pub fn bad_extend_slice_lifetime<'a>(slice: &'a [u8]) -> &'static [u8] {
    unsafe { transmute::<&'a [u8], &'static [u8]>(slice) }
}

/// PROBLEMATIC: Transmute to shorten lifetime (still UB)
pub fn bad_shorten_lifetime<'a, 'b>(s: &'static str) -> &'a str 
where 
    'b: 'a
{
    // While this seems safer, it can still cause issues with lifetime inference
    unsafe { transmute::<&'static str, &'a str>(s) }
}

/// PROBLEMATIC: Transmute struct containing lifetime
pub struct BorrowedData<'a> {
    data: &'a str,
}

pub struct StaticData {
    data: &'static str,
}

pub fn bad_struct_lifetime_transmute<'a>(borrowed: BorrowedData<'a>) -> StaticData {
    unsafe { transmute::<BorrowedData<'a>, StaticData>(borrowed) }
}

/// PROBLEMATIC: Transmute to remove lifetime bound
pub fn bad_remove_lifetime_bound<'a>(data: &'a [u8]) -> &'static [u8] {
    unsafe { std::mem::transmute(data) }
}

// ============================================================================
// SAFE PATTERNS - Transmute without lifetime changes
// ============================================================================

/// SAFE: Transmute between same-size integer types (no lifetimes)
pub fn safe_integer_transmute(x: u32) -> i32 {
    unsafe { transmute::<u32, i32>(x) }
}

/// SAFE: Transmute between pointer types (same lifetime implicitly)
pub fn safe_pointer_cast(ptr: *const u8) -> *const i8 {
    unsafe { transmute::<*const u8, *const i8>(ptr) }
}

/// SAFE: Transmute between arrays of same size
pub fn safe_array_transmute(arr: [u8; 4]) -> [i8; 4] {
    unsafe { transmute::<[u8; 4], [i8; 4]>(arr) }
}

/// SAFE: Transmute float to bits
pub fn safe_float_to_bits(f: f32) -> u32 {
    unsafe { transmute::<f32, u32>(f) }
}

/// SAFE: Transmute with same lifetime preserved
pub fn safe_same_lifetime<'a>(r: &'a [u8; 4]) -> &'a [i8; 4] {
    // This keeps the same lifetime 'a on both sides
    unsafe { transmute::<&'a [u8; 4], &'a [i8; 4]>(r) }
}

/// SAFE: Using proper lifetime extension pattern
pub fn safe_static_to_static(s: &'static str) -> &'static [u8] {
    // 'static to 'static is fine
    s.as_bytes()
}

fn main() {
    println!("RUSTCOLA095 test cases - transmute lifetime changes");
}
