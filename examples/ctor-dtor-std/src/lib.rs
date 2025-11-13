use ctor::{ctor, dtor};

// PROBLEMATIC: #[ctor] functions calling std APIs

#[ctor]
fn ctor_with_println() {
    // PROBLEMATIC: Calling std::io APIs in constructor
    println!("Initializing...");
}

#[ctor]
fn ctor_with_mutex() {
    // PROBLEMATIC: Using std::sync::Mutex in constructor
    // Can cause deadlocks or initialization issues
    let data = std::sync::Mutex::new(std::collections::HashMap::new());
    let mut map = data.lock().unwrap();
    map.insert("key".to_string(), 42);
    std::mem::drop(map);
}

#[ctor]
fn ctor_with_vec() {
    // PROBLEMATIC: Using std::vec APIs in constructor
    let _data: Vec<i32> = vec![1, 2, 3, 4, 5];
    std::mem::drop(_data);
}

#[dtor]
fn dtor_with_println() {
    // PROBLEMATIC: Calling std::io APIs in destructor
    println!("Cleaning up...");
}

#[dtor]
fn dtor_with_filesystem() {
    // PROBLEMATIC: Using std::fs APIs in destructor
    // Can fail or cause issues during program teardown
    let _ = std::fs::read_to_string("/tmp/log.txt");
}

// SAFE: Functions without #[ctor]/#[dtor] or without std calls

pub fn regular_function_with_std() {
    // SAFE: Regular function can use std APIs
    println!("This is fine");
    let _v: Vec<i32> = vec![1, 2, 3];
}

#[ctor]
fn ctor_without_std() {
    // SAFE: Constructor without std API calls
    // Only doing simple initialization
    let x = 42;
    let y = x + 1;
    let _ = y;
}

#[dtor]
fn dtor_without_std() {
    // SAFE: Destructor without std API calls
    let x = 100;
    let _ = x * 2;
}

// Helper function that ctor might call - but ctor itself doesn't call std
fn helper_safe() -> i32 {
    42
}

#[ctor]
fn ctor_with_safe_helper() {
    // SAFE: Calling non-std function
    let _x = helper_safe();
}

// Note: Empty ctors/dtors are safe
#[ctor]
fn ctor_empty() {
    // SAFE: Does nothing
}

#[dtor]
fn dtor_empty() {
    // SAFE: Does nothing
}
