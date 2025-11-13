//! Demonstrates RUSTCOLA050: Misordered assert_eq arguments detection
//!
//! This example shows why argument order matters in assert_eq! and how
//! misordering leads to confusing error messages.

pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

pub fn multiply(a: i32, b: i32) -> i32 {
    a * b
}

pub fn get_status_code() -> i32 {
    200
}

// ========================================================================
// PROBLEMATIC PATTERN - Misordered arguments
// ========================================================================

pub fn test_add_misordered() {
    let result = add(2, 3);
    // PROBLEMATIC: Literal first, variable second
    // Error message would say "expected 6 but got 5" which is backwards!
    assert_eq!(5, result);
}

pub fn test_multiply_misordered() {
    let result = multiply(3, 4);
    // PROBLEMATIC: Expected value first instead of actual
    assert_eq!(12, result);
}

pub fn test_status_misordered() {
    let status = get_status_code();
    // PROBLEMATIC: Constant before variable
    assert_eq!(200, status);
}

pub fn test_comparison_misordered() {
    let value = 42;
    // PROBLEMATIC: Literal first
    assert_eq!(42, value);
}

// ========================================================================
// CORRECT PATTERN - Proper ordering
// ========================================================================

pub fn test_add_correct() {
    let result = add(2, 3);
    // CORRECT: actual first, expected second
    // Error would say "expected 5 but got X" which makes sense
    assert_eq!(result, 5);
}

pub fn test_multiply_correct() {
    let result = multiply(3, 4);
    // CORRECT: result first, expected value second
    assert_eq!(result, 12);
}

pub fn test_status_correct() {
    let status = get_status_code();
    // CORRECT: variable first, constant second
    assert_eq!(status, 200);
}

pub fn test_comparison_correct() {
    let value = 42;
    // CORRECT: value first, expected second
    assert_eq!(value, 42);
}

// ========================================================================
// WHY IT MATTERS
// ========================================================================

pub fn demonstrate_confusing_error() {
    // When this fails with misordered args:
    let actual_value = 10;
    
    // Misordered version:
    // assert_eq!(5, actual_value);
    // Error: "assertion failed: `(left == right)`
    //         left: `5`,
    //        right: `10`"
    // This says "5 is on the left" but doesn't clearly show
    // which was expected vs actual!
    
    // Correct version:
    assert_eq!(actual_value, 10);
    // Error would say: "assertion failed: `(left == right)`
    //         left: `10`,
    //        right: `5`"
    // Combined with variable names, it's clear that actual_value
    // was 10 but we expected 5
}
