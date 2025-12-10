//! Test cases for RUSTCOLA096: Raw pointer from reference escaping safe scope
//!
//! When a reference is cast to a raw pointer (`as *const T` or `as *mut T`) and
//! that pointer escapes the scope where the reference is valid, it creates a
//! dangling pointer when the referenced data is dropped or moved.
//!
//! Expected: 8 PROBLEMATIC patterns detected, 8 SAFE patterns not flagged

use std::ptr;

// ============================================================================
// PROBLEMATIC PATTERNS - Raw pointer escaping valid scope
// ============================================================================

/// PROBLEMATIC: Returning raw pointer to local data
pub fn bad_return_local_ptr() -> *const i32 {
    let x = 42;
    &x as *const i32  // x is dropped, pointer dangles
}

/// PROBLEMATIC: Returning raw pointer to local String's data
pub fn bad_return_string_ptr() -> *const u8 {
    let s = String::from("hello");
    s.as_ptr()  // String is dropped, pointer dangles
}

/// PROBLEMATIC: Storing pointer to temporary in struct
pub struct PointerHolder {
    pub ptr: *const i32,
}

pub fn bad_store_temp_ptr() -> PointerHolder {
    let temp = 123;
    PointerHolder {
        ptr: &temp as *const i32,  // temp dropped at end of function
    }
}

/// PROBLEMATIC: Pointer escapes via mutable reference
pub fn bad_escape_via_out_param(out: &mut *const i32) {
    let local = 456;
    *out = &local as *const i32;  // local dropped, out now dangles
}

/// PROBLEMATIC: Pointer to Vec element after potential reallocation
pub fn bad_ptr_after_push() -> *const i32 {
    let mut v = vec![1, 2, 3];
    let ptr = &v[0] as *const i32;
    v.push(4);  // May reallocate, invalidating ptr
    ptr  // May be dangling
}

/// PROBLEMATIC: Raw pointer from temporary expression
pub fn bad_temp_expression_ptr() -> *const str {
    let s = String::from("temp");
    s.as_str() as *const str  // String dropped, pointer dangles
}

/// PROBLEMATIC: Pointer escaping through closure
pub fn bad_closure_escape() -> Box<dyn Fn() -> *const i32> {
    let local = 789;
    let ptr = &local as *const i32;
    Box::new(move || ptr)  // ptr captured, but local is moved/dropped
}

/// PROBLEMATIC: Pointer stored in global/static (if mutable)
static mut GLOBAL_PTR: *const i32 = ptr::null();

pub fn bad_store_in_global() {
    let local = 999;
    unsafe {
        GLOBAL_PTR = &local as *const i32;  // local dropped, global dangles
    }
}

// ============================================================================
// SAFE PATTERNS - Raw pointers with valid lifetime management
// ============================================================================

/// SAFE: Pointer used only within same scope
pub fn safe_local_use() -> i32 {
    let x = 42;
    let ptr = &x as *const i32;
    unsafe { *ptr }  // Used before x goes out of scope
}

/// SAFE: Pointer from 'static data
pub fn safe_static_ptr() -> *const str {
    let s: &'static str = "hello static";
    s as *const str  // 'static lifetime is forever
}

/// SAFE: Pointer from Box (heap allocated, explicit ownership)
pub fn safe_box_ptr() -> (*const i32, Box<i32>) {
    let boxed = Box::new(42);
    let ptr = &*boxed as *const i32;
    (ptr, boxed)  // Returning both keeps Box alive
}

/// SAFE: Pointer from leaked Box (intentional leak)
pub fn safe_leaked_ptr() -> *const i32 {
    let boxed = Box::new(42);
    Box::leak(boxed) as *const i32  // Leaked, lives forever
}

/// SAFE: Pointer used immediately, not stored
pub fn safe_immediate_use(data: &[u8]) -> u8 {
    let ptr = data.as_ptr();
    unsafe { *ptr }  // Reference still valid
}

/// SAFE: Pin<Box<T>> for self-referential structures
use std::pin::Pin;
pub fn safe_pinned_ptr() -> Pin<Box<i32>> {
    Box::pin(42)  // Pinned, can safely create raw pointers
}

/// SAFE: Returning pointer from parameter (caller manages lifetime)
pub fn safe_param_ptr(x: &i32) -> *const i32 {
    x as *const i32  // Caller ensures x lives long enough
}

/// SAFE: ManuallyDrop prevents automatic drop
use std::mem::ManuallyDrop;
pub fn safe_manually_drop() -> *const i32 {
    let md = ManuallyDrop::new(Box::new(42));
    &**md as *const i32  // Won't be dropped automatically
    // Note: Caller must manually handle cleanup
}

fn main() {
    println!("RUSTCOLA096 test cases - raw pointer escape detection");
}
