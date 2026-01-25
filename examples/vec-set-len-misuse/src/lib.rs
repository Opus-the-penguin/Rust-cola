//! ⚠️ SECURITY SCANNER NOTICE ⚠️
//!
//! This crate contains INTENTIONAL security vulnerabilities for testing RUSTCOLA038.
//! DO NOT use these patterns in production code.
//!
//! codeql[rust/vec-set-len-misuse]: Test examples for Vec::set_len misuse detection

// NOSEC: This file contains test patterns for security scanners

/// BAD: Calling set_len on uninitialized vector
/// This leads to undefined behavior when accessing uninitialized memory
pub unsafe fn bad_set_len_uninitialized() -> Vec<u32> {
    let mut vec: Vec<u32> = Vec::with_capacity(10); // NOSEC
    unsafe {
        vec.set_len(10);
    } // NOSEC - UB: Vector elements are uninitialized!
    vec
}

/// BAD: Set length larger than initialization
pub unsafe fn bad_set_len_partial_init() -> Vec<u8> {
    let mut vec = Vec::with_capacity(100); // NOSEC
    vec.push(1); // Only 1 element initialized
    unsafe {
        vec.set_len(100);
    } // NOSEC - UB: 99 elements are uninitialized!
    vec
}

/// BAD: Set length without any initialization
pub unsafe fn bad_set_len_immediate() {
    let mut buffer: Vec<u8> = Vec::with_capacity(256); // NOSEC
    unsafe {
        buffer.set_len(256);
    } // NOSEC - UB: All elements uninitialized!
    // Using buffer here would be undefined behavior
}

/// BAD: Complex case with calculation
pub unsafe fn bad_set_len_calculated(size: usize) -> Vec<i32> {
    let mut data = Vec::with_capacity(size); // NOSEC
    let new_len = size / 2;
    unsafe {
        data.set_len(new_len);
    } // NOSEC - UB: Elements uninitialized!
    data
}

/// GOOD: Initialize with resize
pub fn good_resize() -> Vec<u32> {
    let mut vec: Vec<u32> = Vec::with_capacity(10);
    vec.resize(10, 0); // All elements initialized to 0
    vec
}

/// GOOD: Initialize with resize_with
pub fn good_resize_with() -> Vec<String> {
    let mut vec: Vec<String> = Vec::with_capacity(5);
    vec.resize_with(5, String::new); // All elements properly initialized
    vec
}

/// GOOD: Manual initialization before set_len
pub unsafe fn good_manual_init() -> Vec<u8> {
    let mut vec = Vec::with_capacity(10);
    let ptr: *mut u8 = vec.as_mut_ptr();

    // Initialize all elements
    unsafe {
        for i in 0..10 {
            std::ptr::write(ptr.add(i), i as u8);
        }

        // Safe to set length after full initialization
        vec.set_len(10);
    }
    vec
}

/// GOOD: Use vec! macro for initialization
pub fn good_vec_macro() -> Vec<i32> {
    vec![0; 100] // All elements initialized
}

/// GOOD: Push elements instead of set_len
pub fn good_push_elements() -> Vec<&'static str> {
    let mut vec = Vec::with_capacity(3);
    vec.push("first");
    vec.push("second");
    vec.push("third");
    vec
}

/// GOOD: Extend from iterator
pub fn good_extend() -> Vec<usize> {
    let mut vec = Vec::with_capacity(10);
    vec.extend(0..10); // All elements initialized from range
    vec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_good_patterns() {
        // These should all work safely
        let v1 = good_resize();
        assert_eq!(v1.len(), 10);

        let v2 = good_resize_with();
        assert_eq!(v2.len(), 5);

        let v3 = unsafe { good_manual_init() };
        assert_eq!(v3.len(), 10);

        let v4 = good_vec_macro();
        assert_eq!(v4.len(), 100);

        let v5 = good_push_elements();
        assert_eq!(v5.len(), 3);

        let v6 = good_extend();
        assert_eq!(v6.len(), 10);
    }
}
