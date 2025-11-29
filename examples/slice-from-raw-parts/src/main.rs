//! Test cases for RUSTCOLA083: slice::from_raw_parts length inflation
//!
//! This rule detects when the length argument to slice::from_raw_parts or
//! slice::from_raw_parts_mut may exceed the actual allocation size.

use std::alloc::{alloc, Layout};
use std::slice;

// ============================================================================
// PROBLEMATIC PATTERNS - Should be flagged
// ============================================================================

/// BAD: Length from untrusted source without validation
unsafe fn bad_untrusted_length(ptr: *const u8, len: usize) -> &'static [u8] {
    // len comes from function parameter - could be anything
    slice::from_raw_parts(ptr, len)
}

/// BAD: Length from untrusted source (mutable version)
unsafe fn bad_untrusted_length_mut(ptr: *mut u8, len: usize) -> &'static mut [u8] {
    slice::from_raw_parts_mut(ptr, len)
}

/// BAD: Length inflated by multiplication without overflow check
unsafe fn bad_inflated_multiply(ptr: *const u32, count: usize) -> &'static [u32] {
    let len = count * 4; // Could overflow or exceed allocation
    slice::from_raw_parts(ptr, len)
}

/// BAD: Length from environment variable
unsafe fn bad_env_length(ptr: *const u8) -> &'static [u8] {
    let len_str = std::env::var("SLICE_LEN").unwrap_or("0".to_string());
    let len: usize = len_str.parse().unwrap_or(0);
    slice::from_raw_parts(ptr, len)
}

/// BAD: Length from command line argument
unsafe fn bad_args_length(ptr: *const u8) -> &'static [u8] {
    let args: Vec<String> = std::env::args().collect();
    let len: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    slice::from_raw_parts(ptr, len)
}

/// BAD: Length computed from raw pointer arithmetic
unsafe fn bad_pointer_diff_length(start: *const u8, end: *const u8) -> &'static [u8] {
    // end could be before start or way past allocation
    let len = end.offset_from(start) as usize;
    slice::from_raw_parts(start, len)
}

/// BAD: Hardcoded large constant length
unsafe fn bad_large_constant(ptr: *const u8) -> &'static [u8] {
    slice::from_raw_parts(ptr, 1_000_000)
}

/// BAD: Length divided incorrectly for type size
unsafe fn bad_size_mismatch(bytes: *const u8, byte_len: usize) -> &'static [u32] {
    // Should divide by size_of::<u32>(), but using wrong divisor
    let len = byte_len / 2;  // Wrong! Should be / 4
    slice::from_raw_parts(bytes as *const u32, len)
}

/// BAD: Using allocation size directly without element size adjustment
unsafe fn bad_alloc_size_direct(count: usize) -> &'static [u64] {
    let layout = Layout::array::<u64>(count).unwrap();
    let ptr = alloc(layout) as *const u64;
    // Using layout.size() directly as element count - wrong!
    slice::from_raw_parts(ptr, layout.size())
}

/// BAD: Zero-length check missing, could be called with 0 and null
unsafe fn bad_zero_not_handled(ptr: *const u8, len: usize) -> &'static [u8] {
    // If len is 0 and ptr is null, this is UB
    slice::from_raw_parts(ptr, len)
}

// ============================================================================
// SAFE PATTERNS - Should NOT be flagged
// ============================================================================

/// SAFE: Length from known allocation
unsafe fn safe_from_vec(v: &Vec<u8>) -> &[u8] {
    let ptr = v.as_ptr();
    let len = v.len();
    slice::from_raw_parts(ptr, len)
}

/// SAFE: Length bounded by allocation
unsafe fn safe_bounded_alloc() -> &'static [u32] {
    let count = 10;
    let layout = Layout::array::<u32>(count).unwrap();
    let ptr = alloc(layout) as *const u32;
    // Using count which matches allocation
    slice::from_raw_parts(ptr, count)
}

/// SAFE: Length validated before use
unsafe fn safe_validated_length(ptr: *const u8, len: usize, max_len: usize) -> Option<&'static [u8]> {
    if len > max_len {
        return None;
    }
    Some(slice::from_raw_parts(ptr, len))
}

/// SAFE: Using checked arithmetic
unsafe fn safe_checked_multiply(ptr: *const u32, count: usize) -> Option<&'static [u32]> {
    let len = count.checked_mul(4)?;
    if len > 1024 {
        return None;
    }
    Some(slice::from_raw_parts(ptr, len))
}

/// SAFE: Length from array with known size
unsafe fn safe_from_array<const N: usize>(arr: &[u8; N]) -> &[u8] {
    let ptr = arr.as_ptr();
    slice::from_raw_parts(ptr, N)
}

/// SAFE: Zero-length slice with non-null pointer
unsafe fn safe_empty_slice() -> &'static [u8] {
    static EMPTY: [u8; 0] = [];
    slice::from_raw_parts(EMPTY.as_ptr(), 0)
}

/// SAFE: Using min to clamp length
unsafe fn safe_min_clamped(ptr: *const u8, requested: usize, available: usize) -> &'static [u8] {
    let len = std::cmp::min(requested, available);
    slice::from_raw_parts(ptr, len)
}

/// SAFE: Length from saturating arithmetic
unsafe fn safe_saturating_sub(ptr: *const u8, total: usize, offset: usize) -> &'static [u8] {
    let len = total.saturating_sub(offset);
    slice::from_raw_parts(ptr.add(offset), len)
}

/// SAFE: Using NonNull and proper validation
unsafe fn safe_with_nonnull(ptr: std::ptr::NonNull<u8>, len: usize) -> &'static [u8] {
    // NonNull guarantees non-null, and we trust the caller for len
    slice::from_raw_parts(ptr.as_ptr(), len)
}

// ============================================================================
// EDGE CASES
// ============================================================================

/// EDGE: Length from trusted FFI boundary (might flag, context-dependent)
extern "C" {
    fn get_buffer_len() -> usize;
}

unsafe fn edge_ffi_length(ptr: *const u8) -> &'static [u8] {
    let len = get_buffer_len();
    slice::from_raw_parts(ptr, len)
}

/// EDGE: Length from struct field (trusted if internal)
struct Buffer {
    ptr: *const u8,
    len: usize,
}

impl Buffer {
    unsafe fn as_slice(&self) -> &[u8] {
        slice::from_raw_parts(self.ptr, self.len)
    }
}

/// EDGE: Length after assertion (safe if assertion holds)
unsafe fn edge_asserted_length(ptr: *const u8, len: usize, cap: usize) -> &'static [u8] {
    assert!(len <= cap);
    slice::from_raw_parts(ptr, len)
}

fn main() {
    // Just to compile
    let data = vec![1u8, 2, 3, 4];
    unsafe {
        let slice = safe_from_vec(&data);
        println!("Safe slice len: {}", slice.len());
    }
}
