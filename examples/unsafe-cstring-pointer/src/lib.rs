// ⚠️ **SECURITY SCANNER NOTICE** ⚠️
// This file contains **INTENTIONAL VULNERABILITIES** for testing RUSTCOLA036.
// These patterns are test cases for detecting unsafe CString pointer usage.
// Security scanners should recognize these as test cases, not actual vulnerabilities.
// NOSEC: Intentional test vulnerabilities for rust-cola rule validation
// codeql[cpp/commented-out-code]: False positive - test patterns only

#![allow(dead_code)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// BAD: CString temporary with as_ptr() creates dangling pointer
/// This should be flagged by RUSTCOLA036
/// NOSEC: Intentional vulnerability for testing
/// codeql[cpp/use-after-free]: Intentional test pattern
/// codeql[rust/dangling-pointer]: Intentional test pattern
pub unsafe fn bad_cstring_unwrap_as_ptr(s: &str) -> *const c_char {
    CString::new(s).unwrap().as_ptr() // NOSEC - Dangling pointer! CString is dropped (intentional test case)
}

/// BAD: CString with expect() and as_ptr()
/// This should be flagged by RUSTCOLA036
/// NOSEC: Intentional vulnerability for testing
/// codeql[cpp/use-after-free]: Intentional test pattern
/// codeql[rust/dangling-pointer]: Intentional test pattern
pub unsafe fn bad_cstring_expect_as_ptr(s: &str) -> *const c_char {
    CString::new(s).expect("CString creation failed").as_ptr() // NOSEC - Dangling pointer (intentional test case)
}

/// BAD: CString with ? operator and as_ptr()
/// This should be flagged by RUSTCOLA036
/// NOSEC: Intentional vulnerability for testing
/// codeql[cpp/use-after-free]: Intentional test pattern
/// codeql[rust/dangling-pointer]: Intentional test pattern
pub unsafe fn bad_cstring_try_as_ptr(s: &str) -> Result<*const c_char, std::ffi::NulError> {
    Ok(CString::new(s)?.as_ptr()) // NOSEC - Dangling pointer (intentional test case)
}

/// BAD: Direct CString::new().as_ptr() without any intermediate
/// This should be flagged by RUSTCOLA036
/// NOSEC: Intentional vulnerability for testing
/// codeql[cpp/use-after-free]: Intentional test pattern
/// codeql[rust/dangling-pointer]: Intentional test pattern
pub unsafe fn bad_direct_chain(s: &str) -> *const c_char {
    CString::new(s.to_string()).ok().unwrap().as_ptr() // NOSEC - Dangling pointer (intentional test case)
}

/// GOOD: Store CString in variable to extend lifetime
pub unsafe fn good_stored_cstring(s: &str) -> *const c_char {
    let c_string = CString::new(s).unwrap();
    c_string.as_ptr() // Safe: c_string lives long enough
}

/// GOOD: Use into_raw() to transfer ownership
pub unsafe fn good_into_raw(s: &str) -> *mut c_char {
    CString::new(s).unwrap().into_raw() // Safe: ownership transferred, caller must free
}

/// GOOD: Return the CString itself
pub fn good_return_cstring(s: &str) -> Result<CString, std::ffi::NulError> {
    CString::new(s)
}

/// GOOD: Use as_ptr() within the same scope with proper lifetime
pub unsafe fn good_immediate_use(s: &str) {
    let c_string = CString::new(s).unwrap();
    let ptr = c_string.as_ptr();
    // Use ptr here while c_string is still alive
    println!("Pointer: {:?}", ptr);
    // c_string is dropped here, ptr should not be used after this
}

/// GOOD: Convert to &CStr which borrows the CString
pub fn good_as_c_str(s: &str) -> Result<(), std::ffi::NulError> {
    let c_string = CString::new(s)?;
    let c_str: &CStr = c_string.as_c_str();
    println!("CStr: {:?}", c_str);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_usage() {
        unsafe {
            let ptr = good_into_raw("test");
            // Must free the pointer
            let _ = CString::from_raw(ptr);
        }

        let _ = good_return_cstring("test");
        let _ = good_as_c_str("test");
    }
}
