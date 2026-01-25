//! Test cases for RUSTCOLA118: Returned Reference to Local Variable
//!
//! This rule detects functions that return references to local variables,
//! which would result in use-after-free when the function returns.

// Allow the dangling pointer lint - these are intentionally bad examples!
#![allow(dangling_pointers_from_locals)]

// ============================================================================
// BAD PATTERNS - Returning references to locals (UAF)
// ============================================================================

/// BAD: Returning a reference to a local variable
/// This compiles in unsafe code but causes UAF
pub fn bad_return_ref_to_local() -> *const u8 {
    let local = String::from("hello");
    // This is the classic UAF pattern - returning pointer to local
    local.as_ptr() // Pointer to stack local - UAF when function returns
}

/// BAD: Returning pointer that's immediately dereferenced
pub fn bad_return_local_ptr() -> *const i32 {
    let x = 42;
    &x as *const i32 // Pointer to stack local - UAF
}

/// BAD: Using transmute to extend lifetime of local reference
pub fn bad_transmute_local_ref<'a>() -> &'a [u8] {
    let data = vec![1, 2, 3, 4];
    unsafe { std::mem::transmute::<&[u8], &'a [u8]>(&data) }
}

/// BAD: Box::leak pattern but on stack allocation
pub fn bad_fake_leak<'a>() -> &'a mut i32 {
    let mut local = 42i32;
    let ptr = &mut local as *mut i32;
    unsafe { &mut *ptr } // Reference outlives local
}

/// BAD: Returning slice of local array
pub fn bad_local_slice() -> *const [u8] {
    let arr = [1u8, 2, 3, 4];
    &arr as *const [u8] // Points to stack
}

/// BAD: Creating 'static reference via raw pointer to local
pub fn bad_static_from_local() -> &'static str {
    let s = String::from("danger");
    let ptr = s.as_ptr();
    let len = s.len();
    unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(ptr, len)) }
}

// ============================================================================
// GOOD PATTERNS - Safe alternatives
// ============================================================================

/// GOOD: Return owned value
pub fn good_return_owned() -> String {
    let local = String::from("hello");
    local // Move semantics - safe
}

/// GOOD: Use Box::leak for intentional static lifetime
pub fn good_box_leak() -> &'static str {
    let boxed = Box::new(String::from("hello"));
    Box::leak(boxed) // Intentional leak - documented pattern
}

/// GOOD: Return reference to input parameter
pub fn good_return_input_ref(s: &str) -> &str {
    &s[0..s.len()] // Same lifetime as input
}

/// GOOD: Return reference to static data
pub fn good_return_static() -> &'static str {
    "hello world" // String literal is 'static
}

/// GOOD: Use arena allocation
pub fn good_arena_pattern(arena: &Vec<String>) -> Option<&str> {
    arena.first().map(|s| s.as_str()) // Tied to arena lifetime
}

fn main() {
    // These would cause UAF if called
    println!("RUSTCOLA118 test cases");
}
