//! Test cases for RUSTCOLA103: WebAssembly Linear Memory Out-of-Bounds
//!
//! This rule detects patterns in WASM-targeted Rust code where linear
//! memory access is not properly bounds-checked, leading to memory corruption.
//! In WASM, there's no memory protection - OOB reads/writes access other data.

// ============================================================================
// BAD PATTERNS - Unchecked linear memory access in WASM
// ============================================================================

/// BAD: Direct pointer access from external input without bounds check
#[no_mangle]
pub extern "C" fn bad_process_buffer(ptr: *mut u8, len: usize) {
    unsafe {
        // In WASM, this can access ANY linear memory!
        // No bounds checking against actual allocation
        let slice = std::slice::from_raw_parts_mut(ptr, len);
        for byte in slice.iter_mut() {
            *byte = byte.wrapping_add(1);
        }
    }
}

/// BAD: Unchecked offset calculation
#[no_mangle]
pub extern "C" fn bad_read_at_offset(base: *const u8, offset: usize) -> u8 {
    unsafe {
        // Attacker controls offset - can read arbitrary memory
        *base.add(offset)
    }
}

/// BAD: No length validation on external buffer
#[no_mangle]
pub extern "C" fn bad_copy_buffer(src: *const u8, dst: *mut u8, len: usize) {
    unsafe {
        // Trusting external len parameter without validation
        std::ptr::copy_nonoverlapping(src, dst, len);
    }
}

/// BAD: Index from untrusted source without bounds check
#[no_mangle]
pub extern "C" fn bad_array_index(arr: *const i32, index: usize) -> i32 {
    unsafe {
        // Attacker-controlled index with no bounds check
        *arr.add(index)
    }
}

/// BAD: Unchecked slice creation from external pointers
#[no_mangle]
pub extern "C" fn bad_string_from_ptr(ptr: *const u8, len: usize) -> usize {
    unsafe {
        // No validation that ptr+len is within linear memory bounds
        let slice = std::slice::from_raw_parts(ptr, len);
        slice.iter().filter(|&&b| b != 0).count()
    }
}

/// BAD: Write to calculated address without validation
#[no_mangle]
pub extern "C" fn bad_write_computed_addr(base: *mut u8, offset: u32, value: u8) {
    unsafe {
        // offset comes from WASM caller - could overflow
        let target = base.offset(offset as isize);
        *target = value;
    }
}

/// BAD: Double-fetch of length (TOCTOU)
static mut BUFFER_LEN: usize = 0;

#[no_mangle]
pub extern "C" fn bad_toctou_length(ptr: *mut u8) {
    unsafe {
        // Length checked once...
        if BUFFER_LEN > 0 && BUFFER_LEN < 1024 {
            // ...but could be changed by another call before use
            let slice = std::slice::from_raw_parts_mut(ptr, BUFFER_LEN);
            slice[0] = 0;
        }
    }
}

// ============================================================================
// GOOD PATTERNS - Safe WASM memory access
// ============================================================================

/// GOOD: Bounds checking against known allocation size
const MAX_BUFFER_SIZE: usize = 4096;

#[no_mangle]
pub extern "C" fn good_bounded_access(ptr: *mut u8, len: usize) -> i32 {
    // Validate length before access
    if len > MAX_BUFFER_SIZE {
        return -1; // Error: length too large
    }

    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, len);
        for byte in slice.iter_mut() {
            *byte = byte.wrapping_add(1);
        }
    }
    0
}

/// GOOD: Safe checked indexing
#[no_mangle]
pub extern "C" fn good_checked_index(arr: *const i32, arr_len: usize, index: usize) -> i32 {
    // Bounds check before access
    if index >= arr_len {
        return 0; // Return default on OOB
    }

    unsafe { *arr.add(index) }
}

/// GOOD: Validate both pointers and length
#[no_mangle]
pub extern "C" fn good_validated_copy(
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_len: usize,
    copy_len: usize,
) -> i32 {
    // Validate all parameters
    if copy_len > src_len || copy_len > dst_len {
        return -1;
    }

    if src.is_null() || dst.is_null() {
        return -2;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(src, dst, copy_len);
    }
    0
}

/// GOOD: Use checked arithmetic for offset calculations
#[no_mangle]
pub extern "C" fn good_checked_offset(base: *const u8, base_len: usize, offset: usize) -> i32 {
    // Use checked arithmetic
    match offset.checked_add(1) {
        Some(end) if end <= base_len => unsafe { *base.add(offset) as i32 },
        _ => -1, // Offset would overflow or exceed bounds
    }
}

fn main() {
    println!("RUSTCOLA103 test cases");
}
