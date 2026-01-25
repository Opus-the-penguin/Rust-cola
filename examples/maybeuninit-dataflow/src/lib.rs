// Test cases for RUSTCOLA078: MaybeUninit assume_init without write
// This file contains **INTENTIONAL VULNERABILITIES** for testing.
//
// MaybeUninit::assume_init() without preceding initialization causes
// undefined behavior by reading uninitialized memory.

use std::mem::MaybeUninit;

// ========== PROBLEMATIC CASES (should trigger RUSTCOLA078) ==========

/// PROBLEMATIC: assume_init without any write
pub fn assume_without_write() -> i32 {
    let uninit: MaybeUninit<i32> = MaybeUninit::uninit();
    // UB: Reading uninitialized memory
    unsafe { uninit.assume_init() }
}

/// PROBLEMATIC: assume_init_read without write
pub fn assume_init_read_without_write() -> u64 {
    let uninit: MaybeUninit<u64> = MaybeUninit::uninit();
    // UB: Reading uninitialized memory
    unsafe { uninit.assume_init_read() }
}

/// PROBLEMATIC: Array of uninit assumed without initialization
pub fn assume_uninit_array() -> [u8; 16] {
    let uninit: MaybeUninit<[u8; 16]> = MaybeUninit::uninit();
    // UB: Entire array is uninitialized
    unsafe { uninit.assume_init() }
}

/// PROBLEMATIC: Complex type uninit
pub fn assume_uninit_complex() -> (String, Vec<u8>) {
    let uninit: MaybeUninit<(String, Vec<u8>)> = MaybeUninit::uninit();
    // UB: String and Vec have invalid internal pointers
    unsafe { uninit.assume_init() }
}

/// PROBLEMATIC: Conditional init (not all paths write)
pub fn assume_conditional_init(condition: bool) -> i32 {
    let mut uninit: MaybeUninit<i32> = MaybeUninit::uninit();
    if condition {
        uninit.write(42);
    }
    // UB if condition is false
    unsafe { uninit.assume_init() }
}

/// PROBLEMATIC: Init in different function not tracked
pub fn assume_with_external_init() -> i32 {
    let uninit: MaybeUninit<i32> = MaybeUninit::uninit();
    // Even if we called some external init, we can't verify it here
    unsafe { uninit.assume_init() }
}

// ========== SAFE CASES (should NOT trigger RUSTCOLA078) ==========

/// SAFE: write() before assume_init()
pub fn assume_after_write() -> i32 {
    let mut uninit: MaybeUninit<i32> = MaybeUninit::uninit();
    uninit.write(42);
    unsafe { uninit.assume_init() }
}

/// SAFE: MaybeUninit::new() is pre-initialized
pub fn assume_from_new() -> i32 {
    let uninit: MaybeUninit<i32> = MaybeUninit::new(42);
    unsafe { uninit.assume_init() }
}

/// SAFE: MaybeUninit::zeroed() is valid for types where 0 is valid
pub fn assume_from_zeroed() -> u32 {
    let uninit: MaybeUninit<u32> = MaybeUninit::zeroed();
    unsafe { uninit.assume_init() }
}

/// SAFE: ptr::write before assume_init
pub fn assume_after_ptr_write() -> i32 {
    let mut uninit: MaybeUninit<i32> = MaybeUninit::uninit();
    unsafe {
        let ptr = uninit.as_mut_ptr();
        std::ptr::write(ptr, 42);
        uninit.assume_init()
    }
}

/// SAFE: write_slice for arrays
pub fn assume_after_write_slice() -> [u8; 4] {
    let mut uninit: MaybeUninit<[u8; 4]> = MaybeUninit::uninit();
    let data = [1u8, 2, 3, 4];
    unsafe {
        let slice = std::slice::from_raw_parts_mut(uninit.as_mut_ptr() as *mut u8, 4);
        slice.copy_from_slice(&data);
        uninit.assume_init()
    }
}

/// SAFE: Init via ptr::copy_nonoverlapping
pub fn assume_after_copy() -> i32 {
    let mut uninit: MaybeUninit<i32> = MaybeUninit::uninit();
    let src: i32 = 42;
    unsafe {
        std::ptr::copy_nonoverlapping(&src, uninit.as_mut_ptr(), 1);
        uninit.assume_init()
    }
}

/// SAFE: Returning uninit without assuming
pub fn return_uninit() -> MaybeUninit<i32> {
    MaybeUninit::uninit()
}

/// SAFE: Drop without assuming
pub fn drop_uninit() {
    let _uninit: MaybeUninit<i32> = MaybeUninit::uninit();
    // Dropping MaybeUninit without assuming is fine
}
