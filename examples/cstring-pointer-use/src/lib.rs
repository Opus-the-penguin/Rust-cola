// ⚠️ **SECURITY SCANNER NOTICE** ⚠️
// This file contains **INTENTIONAL VULNERABILITIES** for testing RUSTCOLA036.
// These patterns are test cases for detecting dangling CString pointers.
// Security scanners should recognize these as test cases, not actual vulnerabilities.
// NOSEC: Intentional test vulnerabilities for rust-cola rule validation
// codeql[cpp/commented-out-code]: False positive - test patterns only

#![allow(dead_code)]

use std::ffi::{CString, CStr};
use std::os::raw::c_char;

/// BAD: CString temporary with unwrap().as_ptr()
/// The CString is dropped immediately, creating a dangling pointer
/// This should be flagged by RUSTCOLA036
/// NOSEC: Intentional vulnerability for testing
/// codeql[cpp/use-after-free]: Intentional test pattern
pub unsafe fn bad_cstring_temp_unwrap(name: &str) -> *const c_char {
    CString::new(name).unwrap().as_ptr() // UB: CString dropped, pointer dangles
}

/// BAD: CString temporary with expect().as_ptr()
/// This should be flagged by RUSTCOLA036
/// NOSEC: Intentional vulnerability for testing
/// codeql[cpp/use-after-free]: Intentional test pattern
pub unsafe fn bad_cstring_temp_expect(name: &str) -> *const c_char {
    CString::new(name).expect("Failed to create CString").as_ptr() // UB: CString dropped
}

/// BAD: Direct chaining CString::new().as_ptr()
/// This should be flagged by RUSTCOLA036
/// NOSEC: Intentional vulnerability for testing
/// codeql[cpp/use-after-free]: Intentional test pattern
pub unsafe fn bad_cstring_direct_chain(name: &str) -> *const c_char {
    CString::new(name).unwrap_or_default().as_ptr() // UB: CString dropped
}

/// BAD: Using the pointer after CString goes out of scope
/// This should be flagged by RUSTCOLA036
/// NOSEC: Intentional vulnerability for testing
/// codeql[cpp/use-after-free]: Intentional test pattern
pub unsafe fn bad_cstring_in_call(name: &str) {
    let ptr = CString::new(name).unwrap().as_ptr();
    // CString is already dropped here
    print_c_string(ptr); // UB: using dangling pointer
}

/// GOOD: Store CString before getting pointer
pub unsafe fn good_cstring_stored(name: &str) -> *const c_char {
    let c_string = CString::new(name).unwrap();
    c_string.as_ptr() // Safe: c_string lives for the function scope
}

/// GOOD: Use into_raw() to transfer ownership
pub unsafe fn good_cstring_into_raw(name: &str) -> *mut c_char {
    CString::new(name).unwrap().into_raw() // Safe: caller takes ownership
}

/// GOOD: Function to free the string created by into_raw
pub unsafe fn good_free_cstring(ptr: *mut c_char) {
    let _ = CString::from_raw(ptr); // Takes ownership and drops it
}

/// GOOD: Keep CString alive for the duration of use
pub fn good_with_cstring<F>(name: &str, f: F)
where
    F: FnOnce(*const c_char),
{
    let c_string = CString::new(name).unwrap();
    f(c_string.as_ptr()); // Safe: c_string lives until after f returns
}

/// GOOD: Using as_c_str() and then as_ptr()
pub fn good_as_c_str(name: &str) -> Result<*const c_char, std::ffi::NulError> {
    let c_string = CString::new(name)?;
    Ok(c_string.as_c_str().as_ptr()) // Note: still needs c_string to live
}

/// GOOD: Clone and store before passing
pub unsafe fn good_clone_and_store(source: &CStr) -> *const c_char {
    let owned = source.to_owned();
    owned.as_ptr()
}

unsafe fn print_c_string(_ptr: *const c_char) {
    // Simulated C function call
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_patterns() {
        unsafe {
            // Test good patterns
            let ptr = good_cstring_into_raw("test");
            assert!(!ptr.is_null());
            good_free_cstring(ptr);

            good_with_cstring("test", |ptr| {
                assert!(!ptr.is_null());
            });
        }
    }
}
