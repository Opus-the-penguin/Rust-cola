//! Test cases for RUSTCOLA119: Closure Capturing Escaping References
//!
//! This rule detects closures that capture references but are then
//! used in contexts requiring 'static lifetime (spawn, thread, etc.),
//! leading to use-after-free.

use std::thread;

// ============================================================================
// BAD PATTERNS - Closures capturing non-'static refs
// ============================================================================

/// BAD: Closure captures local reference and escapes via spawn
pub fn bad_spawn_with_local_ref() {
    let data = vec![1, 2, 3];
    let data_ref = &data;

    // This closure captures data_ref but thread requires 'static
    // Rust's borrow checker catches this, but unsafe code can bypass
    let _ = move || {
        // Unsafe bypass to force the closure to compile
        let ptr = data_ref as *const Vec<i32>;
        unsafe { (*ptr).len() }
    };
}

/// BAD: Closure transmuted to 'static lifetime
pub fn bad_transmute_closure_lifetime<'a>(data: &'a [u8]) -> Box<dyn Fn() -> usize + 'static> {
    let closure = move || data.len();
    // Transmute to extend closure lifetime - UAF!
    unsafe { std::mem::transmute(Box::new(closure) as Box<dyn Fn() -> usize + 'a>) }
}

/// BAD: Using raw pointer to bypass borrow checker in closure
pub fn bad_raw_pointer_closure_escape() {
    let local = String::from("hello");
    let ptr: *const String = &local;

    // Closure captures raw pointer and might outlive local
    // Note: This is unsafe pattern - raw pointers aren't Send
    let closure: Box<dyn Fn() + 'static> = Box::new(move || {
        unsafe {
            let s: &String = &*ptr; // Explicit ref to avoid autoref lint
            println!("{}", s.len());
        }
    });

    // If this closure escapes (e.g., stored, spawned), UAF occurs
    drop(closure);
}

/// BAD: Closure stored in struct with 'static bound
#[allow(dead_code)]
struct CallbackHolder {
    callback: Box<dyn Fn() + 'static>,
}

pub fn bad_store_ref_capturing_closure() {
    let data = vec![1, 2, 3, 4];
    let data_ptr: *const Vec<i32> = &data;

    let _holder = CallbackHolder {
        callback: Box::new(move || {
            // Uses raw pointer to bypass lifetime check
            unsafe {
                let v: &Vec<i32> = &*data_ptr; // Explicit ref
                println!("{:?}", v);
            }
        }),
    };
    // data dropped here, but callback still holds pointer
}

/// BAD: FnOnce with extended lifetime via transmute
pub fn bad_fnonce_transmute<'a>(s: &'a str) -> Box<dyn FnOnce() -> &'static str> {
    let closure = move || -> &'a str { s };
    unsafe { std::mem::transmute(Box::new(closure) as Box<dyn FnOnce() -> &'a str>) }
}

// ============================================================================
// GOOD PATTERNS - Safe alternatives
// ============================================================================

/// GOOD: Clone data into closure (owns it)
pub fn good_clone_into_closure() {
    let data = vec![1, 2, 3];
    let data_clone = data.clone();

    let _handle = thread::spawn(move || {
        println!("Data: {:?}", data_clone);
    });
}

/// GOOD: Use Arc for shared ownership across threads
pub fn good_arc_for_sharing() {
    use std::sync::Arc;

    let data = Arc::new(vec![1, 2, 3]);
    let data_clone = Arc::clone(&data);

    let _handle = thread::spawn(move || {
        println!("Data: {:?}", data_clone);
    });
}

/// GOOD: Scoped threads that don't require 'static
pub fn good_scoped_threads() {
    let data = vec![1, 2, 3];

    thread::scope(|s| {
        s.spawn(|| {
            println!("Data: {:?}", data);
        });
    });
}

/// GOOD: Closure doesn't capture references
pub fn good_no_capture() {
    let _handle = thread::spawn(|| {
        let local = vec![1, 2, 3];
        println!("Data: {:?}", local);
    });
}

fn main() {
    println!("RUSTCOLA119 test cases");
}
