use std::ffi::CString;

/// BAD: Box allocated with Rust allocator, freed with libc::free
/// RUSTCOLA033 should flag this
pub unsafe fn box_freed_with_libc() {
    let boxed = Box::new(42);
    let raw_ptr = Box::into_raw(boxed);
    
    // WRONG: Using C allocator to free Rust allocation
    libc::free(raw_ptr as *mut libc::c_void);
}

/// GOOD: Box allocated and freed with matching Rust allocator
pub unsafe fn box_freed_correctly() {
    let boxed = Box::new(42);
    let raw_ptr = Box::into_raw(boxed);
    
    // Correct: Rust allocator
    drop(Box::from_raw(raw_ptr));
}

/// BAD: CString allocated with Rust, freed with libc::free
/// RUSTCOLA033 should flag this
pub unsafe fn cstring_freed_with_libc() {
    let s = CString::new("hello").unwrap();
    let ptr = CString::into_raw(s);
    
    // WRONG: C free on Rust allocation
    libc::free(ptr as *mut libc::c_void);
}

/// GOOD: CString properly deallocated
pub unsafe fn cstring_freed_correctly() {
    let s = CString::new("hello").unwrap();
    let ptr = CString::into_raw(s);
    
    // Correct
    drop(CString::from_raw(ptr));
}

/// BAD: malloc pointer converted to Box
/// RUSTCOLA033 should flag this
pub unsafe fn malloc_to_box() {
    let ptr = libc::malloc(100) as *mut i32;
    
    // WRONG: Rust will try to free with its allocator
    let _boxed = Box::from_raw(ptr);
}

/// GOOD: malloc freed with free
pub unsafe fn malloc_freed_correctly() {
    let ptr = libc::malloc(100);
    
    // Correct: C allocator
    libc::free(ptr);
}

/// BAD: calloc converted to Box
/// RUSTCOLA033 should flag this  
pub unsafe fn calloc_to_box() {
    let ptr = libc::calloc(10, std::mem::size_of::<u64>()) as *mut u64;
    
    // WRONG
    let _boxed = Box::from_raw(ptr);
}

/// GOOD: System allocator functions used consistently
pub unsafe fn system_alloc_consistent() {
    extern "C" {
        fn malloc(size: usize) -> *mut libc::c_void;
        fn free(ptr: *mut libc::c_void);
    }
    
    let ptr = malloc(100);
    free(ptr);
}
