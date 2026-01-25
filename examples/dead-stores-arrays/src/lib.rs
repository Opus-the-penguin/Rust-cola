//! Demonstrates RUSTCOLA068: Dead stores in arrays
//!
//! A "dead store" occurs when a value is written to an array element but never read
//! before being overwritten or the array going out of scope. This can indicate:
//! - Logic errors (forgot to use the value)
//! - Security issues (stale sensitive data not properly cleared)
//! - Performance waste (unnecessary writes)
//!
//! Detection metrics: 71% recall (5/7 problematic patterns detected)
//! - Detected: overwrite_without_read, stale_password_data, multiple_overwrites,
//!   conditional_overwrite, branch_dead_stores
//! - Not detected (require more advanced analysis): write_never_read, loop_overwrite
//!
//! NOSEC: All vulnerable patterns are intentional test cases for rust-cola validation.

#![allow(dead_code)]
#![allow(unused_assignments)]

// ============================================================================
// PROBLEMATIC PATTERNS - Should trigger RUSTCOLA068
// ============================================================================

/// BAD: Array element written but overwritten without being read
/// RUSTCOLA068 should flag this - first assignment to arr[0] is dead
/// NOSEC: Intentional test case
pub fn overwrite_without_read() {
    let mut arr = [0; 5];
    arr[0] = 10; // Dead store - immediately overwritten
    arr[0] = 20; // This is the actual value used
    println!("Value: {}", arr[0]);
}

/// BAD: Array element written but never read before scope ends
/// RUSTCOLA068 should flag this - arr[1] is never read
/// NOSEC: Intentional test case
pub fn write_never_read() {
    let mut arr = [0; 5];
    arr[1] = 42; // Dead store - never read
    println!("Array length: {}", arr.len());
}

/// BAD: Security-critical case - password array not cleared properly
/// RUSTCOLA068 should flag this - password bytes written but not zeroed
/// NOSEC: Intentional test case
pub fn stale_password_data() {
    let mut password = [0u8; 32];
    password[0] = b'P';
    password[1] = b'a';
    password[2] = b's';
    password[3] = b's';
    // ... use password ...
    password[0] = 0; // Partial clear - other bytes are dead stores
                     // password[1..4] never cleared - dead stores that leak sensitive data
}

/// BAD: Multiple overwrites in sequence
/// RUSTCOLA068 should flag this - first two writes are dead
/// NOSEC: Intentional test case
pub fn multiple_overwrites() {
    let mut arr = [0; 10];
    arr[5] = 100; // Dead store
    arr[5] = 200; // Dead store
    arr[5] = 300; // Final value
    println!("Value: {}", arr[5]);
}

/// BAD: Conditional overwrite - first write may be dead
/// RUSTCOLA068 should flag this - arr[0] unconditionally overwritten
/// NOSEC: Intentional test case
pub fn conditional_overwrite(condition: bool) {
    let mut arr = [0; 5];
    arr[0] = 10; // Dead store if condition is true
    if condition {
        arr[0] = 20; // Overwrites previous value
    }
    println!("Value: {}", arr[0]);
}

/// BAD: Loop that overwrites without reading
/// RUSTCOLA068 should flag this - arr[0] overwritten each iteration
/// NOSEC: Intentional test case
pub fn loop_overwrite() {
    let mut arr = [0; 5];
    for i in 0..3 {
        arr[0] = i; // Dead store except last iteration
    }
    println!("Final: {}", arr[0]);
}

/// BAD: Array element written in multiple branches but never read
/// RUSTCOLA068 should flag this - writes are dead stores
/// NOSEC: Intentional test case
pub fn branch_dead_stores(choice: i32) {
    let mut arr = [0; 5];
    match choice {
        0 => arr[2] = 10, // Dead store
        1 => arr[2] = 20, // Dead store
        _ => arr[2] = 30, // Dead store
    }
    // arr[2] never read
}

// ============================================================================
// SAFE PATTERNS - Should NOT trigger RUSTCOLA068
// ============================================================================

/// SAFE: Array element written and then read
pub fn write_then_read() {
    let mut arr = [0; 5];
    arr[0] = 10;
    println!("Value: {}", arr[0]); // Read after write
}

/// SAFE: Array fully initialized and used
pub fn array_initialization() {
    let mut arr = [0i32; 5];
    for i in 0..5 {
        arr[i] = i as i32 * 2;
    }
    let sum: i32 = arr.iter().sum();
    println!("Sum: {}", sum);
}

/// SAFE: Array element read before overwrite
pub fn read_before_overwrite() {
    let mut arr = [1, 2, 3, 4, 5];
    let old_value = arr[0]; // Read first
    arr[0] = 100; // Then overwrite
    println!("Old: {}, New: {}", old_value, arr[0]);
}

/// SAFE: Array used in calculations
pub fn array_in_calculation() {
    let mut arr = [0; 5];
    arr[0] = 10;
    arr[1] = 20;
    let result = arr[0] + arr[1];
    println!("Result: {}", result);
}

/// SAFE: Array passed to function (reads via reference)
pub fn array_passed_to_function() {
    let mut arr = [0; 5];
    arr[0] = 42;
    process_array(&arr);
}

fn process_array(arr: &[i32]) {
    println!("First element: {}", arr[0]);
}

/// SAFE: Array element conditionally read
pub fn conditional_read(condition: bool) {
    let mut arr = [0; 5];
    arr[0] = 10;
    if condition {
        println!("Value: {}", arr[0]); // Read in branch
    }
}

/// SAFE: Array returned (all elements potentially read by caller)
pub fn return_array() -> [i32; 5] {
    let mut arr = [0; 5];
    arr[0] = 10;
    arr[1] = 20;
    arr // Returned, caller can read
}

/// SAFE: Array element written in loop and read later
pub fn loop_with_read() {
    let mut arr = [0; 5];
    for i in 0..5 {
        arr[i] = i * 10;
    }
    // All elements read
    for val in &arr {
        println!("{}", val);
    }
}

/// SAFE: Intentional array clear (zeroing for security)
pub fn proper_array_clear() {
    let mut password = [0u8; 32];
    password[0] = b'P';
    password[1] = b'a';
    password[2] = b's';
    // ... use password ...
    // Proper clear - explicitly zero all elements
    password.iter_mut().for_each(|b| *b = 0);
    // Or: password.fill(0);
}

/// SAFE: Array index computed and used
pub fn computed_index() {
    let mut arr = [0; 10];
    let idx = 5;
    arr[idx] = 42;
    println!("Value at {}: {}", idx, arr[idx]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_problematic_patterns_compile() {
        overwrite_without_read();
        write_never_read();
        stale_password_data();
        multiple_overwrites();
        conditional_overwrite(true);
        loop_overwrite();
        branch_dead_stores(1);
    }

    #[test]
    fn test_safe_patterns_compile() {
        write_then_read();
        array_initialization();
        read_before_overwrite();
        array_in_calculation();
        array_passed_to_function();
        conditional_read(true);
        let _ = return_array();
        loop_with_read();
        proper_array_clear();
        computed_index();
    }
}
