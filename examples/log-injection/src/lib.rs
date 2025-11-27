// Test cases for RUSTCOLA076: Log Injection
// This file contains **INTENTIONAL VULNERABILITIES** for testing.
//
// Log injection occurs when untrusted input containing newline characters
// flows to logging functions, allowing attackers to forge log entries.

use std::env;

// ========== PROBLEMATIC CASES (should trigger RUSTCOLA076) ==========

/// PROBLEMATIC: User input logged without newline sanitization
pub fn log_user_input() {
    let user_input = env::var("USER_INPUT").unwrap_or_default();
    // Attacker can inject: "normal\n[ERROR] FAKE: Admin login from 127.0.0.1"
    println!("User submitted: {}", user_input);
}

/// PROBLEMATIC: Command line arg logged directly  
pub fn log_cli_arg() {
    let arg = env::args().nth(1).unwrap_or_default();
    // Could contain newlines
    eprintln!("Processing argument: {}", arg);
}

/// PROBLEMATIC: Multiple env vars logged
pub fn log_multiple_inputs() {
    let name = env::var("USERNAME").unwrap_or_default();
    let action = env::var("ACTION").unwrap_or_default();
    // Both can contain newlines
    println!("User {} performed: {}", name, action);
}

/// PROBLEMATIC: Formatted error with env var
pub fn log_error_with_input() {
    let path = env::var("FILE_PATH").unwrap_or_default();
    // Could forge error log entries
    panic!("Failed to process: {}", path);
}

/// PROBLEMATIC: Debug output with env var
pub fn debug_env_value() {
    let config = env::var("CONFIG_VALUE").unwrap_or_default();
    // Debug logging is still vulnerable
    println!("{:?}", config);
}

/// PROBLEMATIC: Nested function propagates taint
pub fn log_via_helper() {
    let data = env::var("EXTERNAL_DATA").unwrap_or_default();
    print_data(&data);
}

fn print_data(s: &str) {
    println!("Received: {}", s);
}

// ========== SAFE CASES (should NOT trigger RUSTCOLA076) ==========

/// SAFE: Input trimmed before logging
pub fn log_trimmed_input() {
    let input = env::var("USER_INPUT").unwrap_or_default();
    let clean = input.trim();
    println!("User submitted: {}", clean);
}

/// SAFE: Input sanitized with replace
pub fn log_sanitized_input() {
    let input = env::var("USER_INPUT").unwrap_or_default();
    let safe = input.replace('\n', " ").replace('\r', " ");
    println!("User submitted: {}", safe);
}

/// SAFE: Input split into lines and processed individually
pub fn log_lines_individually() {
    let input = env::var("MULTILINE_INPUT").unwrap_or_default();
    for line in input.lines() {
        println!("Line: {}", line);
    }
}

/// SAFE: Static message logged (no env vars)
pub fn log_static_only() {
    println!("Application started");
    eprintln!("Initializing...");
}

/// SAFE: Derived value logged, not raw input
pub fn log_derived_value() {
    let input = env::var("COUNT").unwrap_or_default();
    let count: usize = input.parse().unwrap_or(0);
    // Parsed number can't contain newlines
    println!("Processing {} items", count);
}

/// SAFE: Input escaped before logging
pub fn log_escaped_input() {
    let input = env::var("USER_INPUT").unwrap_or_default();
    let escaped = input.escape_default().to_string();
    println!("User submitted: {}", escaped);
}
