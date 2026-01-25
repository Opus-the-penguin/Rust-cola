// Test cases for RUSTCOLA077: Division by Untrusted Denominator
// This file contains **INTENTIONAL VULNERABILITIES** for testing.
//
// Division/modulo with untrusted denominators without zero checks
// can cause denial-of-service via panic on divide-by-zero.

use std::env;

// ========== PROBLEMATIC CASES (should trigger RUSTCOLA077) ==========

/// PROBLEMATIC: Direct division by env var
pub fn divide_by_env_var() {
    let divisor: i32 = env::var("DIVISOR").unwrap_or_default().parse().unwrap_or(1);
    let total = 1000;
    // Attacker sets DIVISOR=0 → panic
    let result = total / divisor;
    println!("Result: {}", result);
}

/// PROBLEMATIC: Modulo with env var
pub fn modulo_by_env_var() {
    let modulus: u32 = env::var("MODULUS").unwrap_or_default().parse().unwrap_or(1);
    let value = 42u32;
    // MODULUS=0 → panic
    let remainder = value % modulus;
    println!("Remainder: {}", remainder);
}

/// PROBLEMATIC: CLI arg as denominator
pub fn divide_by_cli_arg() {
    let args: Vec<String> = env::args().collect();
    let divisor: f64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1.0);
    // Float division by zero doesn't panic but gives inf/nan
    // Integer division would panic
    let result = 100.0 / divisor;
    println!("Result: {}", result);
}

/// PROBLEMATIC: Division after arithmetic on untrusted value
pub fn divide_after_arithmetic() {
    let base: i32 = env::var("BASE").unwrap_or_default().parse().unwrap_or(0);
    let divisor = base + 0; // Still zero if base is zero
    let result = 100 / divisor;
    println!("Result: {}", result);
}

/// PROBLEMATIC: Multiple divisions in loop
pub fn divide_in_loop() {
    let count: usize = env::var("COUNT").unwrap_or_default().parse().unwrap_or(1);
    for i in 0..10 {
        // COUNT=0 panics
        let bucket = i % count;
        println!("Item {} goes to bucket {}", i, bucket);
    }
}

/// PROBLEMATIC: Nested untrusted division
pub fn divide_nested() {
    let x: i32 = env::var("X").unwrap_or_default().parse().unwrap_or(1);
    let y: i32 = env::var("Y").unwrap_or_default().parse().unwrap_or(1);
    // Either X=0 or Y=0 causes panic
    let result = 100 / (x * y);
    println!("Result: {}", result);
}

// ========== SAFE CASES (should NOT trigger RUSTCOLA077) ==========

/// SAFE: Zero check before division
pub fn divide_with_zero_check() {
    let divisor: i32 = env::var("DIVISOR").unwrap_or_default().parse().unwrap_or(0);
    if divisor != 0 {
        let result = 100 / divisor;
        println!("Result: {}", result);
    } else {
        println!("Cannot divide by zero");
    }
}

/// SAFE: Using checked_div
pub fn divide_checked() {
    let divisor: i32 = env::var("DIVISOR").unwrap_or_default().parse().unwrap_or(0);
    match 100i32.checked_div(divisor) {
        Some(result) => println!("Result: {}", result),
        None => println!("Division failed"),
    }
}

/// SAFE: Using NonZero type
pub fn divide_with_nonzero() {
    use std::num::NonZeroU32;

    let divisor_raw: u32 = env::var("DIVISOR").unwrap_or_default().parse().unwrap_or(0);

    if let Some(divisor) = NonZeroU32::new(divisor_raw) {
        let result = 100u32 / divisor.get();
        println!("Result: {}", result);
    }
}

/// SAFE: Division by constant
pub fn divide_by_constant() {
    let _env_val = env::var("SOMETHING").unwrap_or_default();
    // Divisor is constant, not from env
    let result = 100 / 5;
    println!("Result: {}", result);
}

/// SAFE: Division with > 0 check
pub fn divide_with_positive_check() {
    let divisor: i32 = env::var("DIVISOR").unwrap_or_default().parse().unwrap_or(0);
    if divisor > 0 {
        let result = 100 / divisor;
        println!("Result: {}", result);
    }
}

/// SAFE: Using saturating_div
pub fn divide_saturating() {
    let divisor: i32 = env::var("DIVISOR").unwrap_or_default().parse().unwrap_or(0);
    // Note: saturating_div still panics on zero, but checking for it
    if divisor != 0 {
        let result = 100i32.saturating_div(divisor);
        println!("Result: {}", result);
    }
}

/// SAFE: Division result unused from env, uses local calculation
pub fn divide_local_only() {
    let _config = env::var("CONFIG").unwrap_or_default();
    // Division uses only local constants
    let total = 100;
    let parts = 4;
    let per_part = total / parts;
    println!("Per part: {}", per_part);
}
