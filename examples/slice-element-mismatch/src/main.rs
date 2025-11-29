//! Test cases for RUSTCOLA082: Raw pointer to slice of different element size
//! 
//! This rule detects unsafe transmutes between slice/pointer types where the
//! element sizes differ, which can cause memory corruption or undefined behavior.

use std::mem;

// ============================================================================
// PROBLEMATIC PATTERNS - Should be flagged
// ============================================================================

/// BAD: Transmute &[u8] to &[u32] - element size mismatch (1 byte vs 4 bytes)
unsafe fn bad_u8_slice_to_u32_slice(data: &[u8]) -> &[u32] {
    // This is UB: the length field doesn't account for size difference
    mem::transmute(data)
}

/// BAD: Transmute &[u16] to &[u64] - element size mismatch (2 bytes vs 8 bytes)
unsafe fn bad_u16_slice_to_u64_slice(data: &[u16]) -> &[u64] {
    mem::transmute(data)
}

/// BAD: Transmute *const [u8] to *const [u32] - raw pointer slice transmute
unsafe fn bad_raw_ptr_u8_to_u32(ptr: *const [u8]) -> *const [u32] {
    mem::transmute(ptr)
}

/// BAD: Transmute &mut [f32] to &mut [u64] - mutable slice size mismatch (4 vs 8 bytes)
unsafe fn bad_mut_f32_to_u64(data: &mut [f32]) -> &mut [u64] {
    mem::transmute(data)
}

/// BAD: Transmute &[i8] to &[i32] - signed types, size mismatch (1 vs 4 bytes)
unsafe fn bad_i8_slice_to_i32_slice(data: &[i8]) -> &[i32] {
    mem::transmute(data)
}

/// BAD: Using transmute_copy on slice references with different element sizes
unsafe fn bad_transmute_copy_slices(data: &[u8]) -> &[u32] {
    mem::transmute_copy(&data)
}

/// BAD: Cast through raw pointers then transmute - still dangerous
unsafe fn bad_ptr_cast_then_transmute(data: &[u8]) -> &[u32] {
    let ptr = data as *const [u8];
    mem::transmute::<*const [u8], &[u32]>(ptr)
}

/// BAD: Transmute between slices of structs with different sizes
#[repr(C)]
struct Small { a: u8 }

#[repr(C)]
struct Large { a: u64, b: u64 }

unsafe fn bad_struct_slice_transmute(data: &[Small]) -> &[Large] {
    mem::transmute(data)
}

// ============================================================================
// SAFE PATTERNS - Should NOT be flagged
// ============================================================================

/// SAFE: Same element size - u8 to i8 (both 1 byte)
unsafe fn safe_u8_to_i8_slice(data: &[u8]) -> &[i8] {
    mem::transmute(data)
}

/// SAFE: Same element size - u32 to i32 (both 4 bytes)
unsafe fn safe_u32_to_i32_slice(data: &[u32]) -> &[i32] {
    mem::transmute(data)
}

/// SAFE: Same element size - u64 to f64 (both 8 bytes)
unsafe fn safe_u64_to_f64_slice(data: &[u64]) -> &[f64] {
    mem::transmute(data)
}

/// SAFE: Transmute single element pointer (not a slice)
unsafe fn safe_single_element_transmute(ptr: *const u8) -> *const u32 {
    // This is a different issue - single element vs slice
    mem::transmute(ptr)
}

/// SAFE: Proper slice conversion using slice::from_raw_parts
unsafe fn safe_proper_conversion(data: &[u8]) -> &[u32] {
    let ptr = data.as_ptr() as *const u32;
    let len = data.len() / 4;  // Properly adjust length
    std::slice::from_raw_parts(ptr, len)
}

/// SAFE: Using align_to which handles the conversion correctly
fn safe_align_to(data: &[u8]) -> (&[u8], &[u32], &[u8]) {
    unsafe { data.align_to::<u32>() }
}

/// SAFE: Array transmute (not a slice - fixed size known at compile time)
unsafe fn safe_array_transmute(data: [u8; 4]) -> u32 {
    mem::transmute(data)
}

/// SAFE: Box transmute (not a slice)
unsafe fn safe_box_transmute(data: Box<u8>) -> Box<i8> {
    mem::transmute(data)
}

/// SAFE: Vec transmute with same element size
unsafe fn safe_vec_same_size(data: Vec<u8>) -> Vec<i8> {
    mem::transmute(data)
}

/// SAFE: Transmute slice to raw parts struct (not slice-to-slice)
#[repr(C)]
struct SliceParts {
    ptr: *const u8,
    len: usize,
}

unsafe fn safe_slice_to_parts(data: &[u8]) -> SliceParts {
    mem::transmute(data)
}

// ============================================================================
// EDGE CASES
// ============================================================================

/// BAD: Vec transmute with different element sizes is also dangerous
unsafe fn bad_vec_size_mismatch(data: Vec<u8>) -> Vec<u32> {
    // Vec layout includes capacity, this corrupts the allocation
    mem::transmute(data)
}

/// BAD: Through type alias
type ByteSlice<'a> = &'a [u8];
type IntSlice<'a> = &'a [u32];

unsafe fn bad_type_alias_transmute(data: ByteSlice<'_>) -> IntSlice<'_> {
    mem::transmute(data)
}

/// BAD: Generic with concrete instantiation
unsafe fn bad_generic_transmute<T, U>(slice: &[T]) -> &[U] {
    mem::transmute(slice)
}

fn call_bad_generic() {
    let data: &[u8] = &[1, 2, 3, 4];
    unsafe {
        let _: &[u32] = bad_generic_transmute(data);
    }
}

fn main() {
    let data: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    
    unsafe {
        // These are all dangerous
        let _ = bad_u8_slice_to_u32_slice(data);
    }
    
    // Safe alternative
    let (prefix, middle, suffix) = safe_align_to(data);
    println!("Aligned: {:?} {:?} {:?}", prefix, middle, suffix);
}
