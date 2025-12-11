// Test cases for ADV009: Integer Overflow in Arithmetic
// This file contains **INTENTIONAL VULNERABILITIES** for testing.
//
// Integer overflow from untrusted input without checked arithmetic
// can cause logic bugs, buffer overflows, or denial-of-service.

use std::env;
use std::io::{self, BufRead};

// ========== PROBLEMATIC CASES (should trigger ADV009) ==========

/// PROBLEMATIC: Addition with env var can overflow
pub fn add_env_var_overflow() -> i32 {
    let user_value: i32 = env::var("USER_VALUE")
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);
    // If USER_VALUE is i32::MAX, this wraps/panics in debug mode
    let result = user_value + 1;
    result
}

/// PROBLEMATIC: Multiplication with env var
pub fn multiply_env_var_overflow() -> i64 {
    let count: i64 = env::var("ITEM_COUNT")
        .unwrap_or_default()
        .parse()
        .unwrap_or(1);
    let item_size: i64 = 1024;
    // count * item_size can easily overflow
    let total_size = count * item_size;
    total_size
}

/// PROBLEMATIC: Subtraction causing underflow
pub fn subtract_env_var_underflow() -> usize {
    let offset: usize = env::var("OFFSET")
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);
    let base: usize = 100;
    // If OFFSET > 100, this underflows
    let result = base - offset;
    result
}

/// PROBLEMATIC: Left shift with untrusted amount
pub fn shift_env_var_overflow() -> u32 {
    let shift_amount: u32 = env::var("SHIFT")
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);
    let value: u32 = 1;
    // Shift by >= 32 is undefined behavior
    let result = value << shift_amount;
    result
}

/// PROBLEMATIC: Stdin input to multiplication
pub fn multiply_stdin_overflow() -> i32 {
    let stdin = io::stdin();
    let line = stdin.lock().lines().next().unwrap().unwrap();
    let user_value: i32 = line.parse().unwrap_or(0);
    // User input * constant can overflow
    let result = user_value * 1000;
    result
}

/// PROBLEMATIC: CLI args to arithmetic
pub fn add_cli_args_overflow() -> i32 {
    let args: Vec<String> = env::args().collect();
    let a: i32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let b: i32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    // Both values from untrusted CLI input
    let sum = a + b;
    sum
}

// ========== SAFE CASES (should NOT trigger ADV009) ==========

/// SAFE: Using checked_add
pub fn add_checked() -> Option<i32> {
    let user_value: i32 = env::var("USER_VALUE")
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);
    // checked_add returns None on overflow
    user_value.checked_add(1)
}

/// SAFE: Using saturating_mul
pub fn multiply_saturating() -> i64 {
    let count: i64 = env::var("ITEM_COUNT")
        .unwrap_or_default()
        .parse()
        .unwrap_or(1);
    let item_size: i64 = 1024;
    // Clamps to max value instead of overflowing
    count.saturating_mul(item_size)
}

/// SAFE: Using wrapping_sub (intentional wrapping)
pub fn subtract_wrapping() -> usize {
    let offset: usize = env::var("OFFSET")
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);
    let base: usize = 100;
    // Explicit wrapping behavior
    base.wrapping_sub(offset)
}

/// SAFE: Using overflowing_add with check
pub fn add_overflowing() -> i32 {
    let user_value: i32 = env::var("USER_VALUE")
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);
    let (result, overflowed) = user_value.overflowing_add(1);
    if overflowed {
        eprintln!("Overflow detected!");
        0
    } else {
        result
    }
}

/// SAFE: Constant arithmetic (no untrusted input)
pub fn constant_arithmetic() -> i32 {
    let a = 10;
    let b = 20;
    a + b // Pure constants
}

/// SAFE: Bounded shift
pub fn shift_bounded() -> u32 {
    let shift_amount: u32 = env::var("SHIFT")
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);
    let value: u32 = 1;
    // Clamp shift to valid range
    let safe_shift = shift_amount.min(31);
    value << safe_shift
}

/// SAFE: Validation before arithmetic
pub fn add_validated() -> i32 {
    let user_value: i32 = env::var("USER_VALUE")
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);
    // Only add if we know it won't overflow
    if user_value < i32::MAX {
        user_value + 1
    } else {
        i32::MAX
    }
}
