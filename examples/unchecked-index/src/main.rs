/// RUSTCOLA080: Unchecked Index Arithmetic Detection
/// 
/// This example demonstrates detection of using untrusted input
/// as array/vector indices without proper bounds checking.

use std::io::{self, BufRead};
use std::env;
use std::fs;

// ============================================
// VULNERABLE PATTERNS (should flag)
// ============================================

/// Direct index from user input - no bounds check
fn vulnerable_direct_index() {
    let data = vec![1, 2, 3, 4, 5];
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let index: usize = input.trim().parse().unwrap();
    
    // VULNERABLE: No bounds check before indexing
    let value = data[index];
    println!("Value: {}", value);
}

/// Index from env var without bounds check
fn vulnerable_env_index() {
    let data = [10, 20, 30, 40, 50];
    let index: usize = env::var("INDEX").unwrap().parse().unwrap();
    
    // VULNERABLE: Environment variable used as index without bounds check
    println!("Data: {}", data[index]);
}

/// Computed index without validation
fn vulnerable_computed_index() {
    let buffer = vec![0u8; 1024];
    let mut line = String::new();
    io::stdin().read_line(&mut line).unwrap();
    let user_offset: usize = line.trim().parse().unwrap();
    
    // Compute index from user input
    let computed = user_offset * 4;
    
    // VULNERABLE: Computed index not validated
    let byte = buffer[computed];
    println!("Byte: {}", byte);
}

/// Index from file content
fn vulnerable_file_index() {
    let array = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let content = fs::read_to_string("index.txt").unwrap();
    let idx: usize = content.trim().parse().unwrap();
    
    // VULNERABLE: File content as index
    let val = array[idx];
    println!("{}", val);
}

/// Index used in loop from user input
fn vulnerable_loop_index() {
    let data = vec![1, 2, 3, 4, 5];
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let count: usize = input.trim().parse().unwrap();
    
    // VULNERABLE: Loop bound from user input
    for i in 0..count {
        println!("{}", data[i]);
    }
}

/// Mutable indexing without bounds check
fn vulnerable_mutable_index() {
    let mut data = vec![0i32; 10];
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let idx: usize = input.trim().parse().unwrap();
    
    // VULNERABLE: Mutable access with untrusted index
    data[idx] = 42;
}

/// Two-dimensional indexing with user input
fn vulnerable_2d_index() {
    let matrix = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
    let mut row_input = String::new();
    let mut col_input = String::new();
    io::stdin().read_line(&mut row_input).unwrap();
    io::stdin().read_line(&mut col_input).unwrap();
    let row: usize = row_input.trim().parse().unwrap();
    let col: usize = col_input.trim().parse().unwrap();
    
    // VULNERABLE: Both indices from user input
    println!("{}", matrix[row][col]);
}

/// Index from command line args
fn vulnerable_args_index() {
    let data = [100, 200, 300, 400, 500];
    let args: Vec<String> = env::args().collect();
    let idx: usize = args[1].parse().unwrap();
    
    // VULNERABLE: Command line arg as index
    println!("{}", data[idx]);
}

/// String slice with user-controlled indices
fn vulnerable_string_slice() {
    let text = "Hello, World!";
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let end: usize = input.trim().parse().unwrap();
    
    // VULNERABLE: String indexing with user input
    let slice = &text.as_bytes()[..end];
    println!("{:?}", slice);
}

/// Index propagated through function calls
fn get_user_index() -> usize {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().parse().unwrap()
}

fn vulnerable_indirect_index() {
    let data = vec![1, 2, 3, 4, 5];
    let idx = get_user_index();
    
    // VULNERABLE: Index from function returning user input
    println!("{}", data[idx]);
}

// ============================================
// SAFE PATTERNS (should NOT flag)
// ============================================

/// Safe pattern using .get() for optional access
fn safe_get_method() {
    let data = vec![1, 2, 3, 4, 5];
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let index: usize = input.trim().parse().unwrap();
    
    // SAFE: Using .get() returns Option
    if let Some(value) = data.get(index) {
        println!("Value: {}", value);
    }
}

/// Safe pattern with explicit bounds check before indexing
fn safe_bounds_check() {
    let data = vec![1, 2, 3, 4, 5];
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let index: usize = input.trim().parse().unwrap();
    
    // SAFE: Bounds check before indexing
    if index < data.len() {
        let value = data[index];
        println!("Value: {}", value);
    }
}

/// Safe pattern with assert for bounds
fn safe_assert_bounds() {
    let data = [1, 2, 3, 4, 5];
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let idx: usize = input.trim().parse().unwrap();
    
    // SAFE: Assert validates bounds
    assert!(idx < data.len(), "Index out of bounds");
    println!("{}", data[idx]);
}

/// Safe pattern using saturating arithmetic
fn safe_saturating() {
    let data = vec![1, 2, 3, 4, 5];
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let raw_idx: usize = input.trim().parse().unwrap();
    
    // SAFE: Saturate to valid range
    let idx = raw_idx.min(data.len() - 1);
    println!("{}", data[idx]);
}

/// Safe: using hardcoded indices (not from user input)
fn safe_hardcoded_index() {
    let data = vec![1, 2, 3, 4, 5];
    
    // SAFE: Hardcoded index, not from user input
    let value = data[2];
    println!("Value: {}", value);
}

/// Safe: loop with length-bounded iteration
fn safe_loop_length() {
    let data = vec![1, 2, 3, 4, 5];
    
    // SAFE: Loop bounded by data.len()
    for i in 0..data.len() {
        println!("{}", data[i]);
    }
}

/// Safe: index from trusted computation
fn safe_trusted_computation() {
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    
    // SAFE: Index computed from known bounds
    let midpoint = data.len() / 2;
    println!("Middle: {}", data[midpoint]);
}

/// Safe: get_mut with Option
fn safe_get_mut() {
    let mut data = vec![1, 2, 3, 4, 5];
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let idx: usize = input.trim().parse().unwrap();
    
    // SAFE: get_mut returns Option
    if let Some(val) = data.get_mut(idx) {
        *val = 42;
    }
}

/// Safe: checked_sub for underflow protection
fn safe_checked_arithmetic() {
    let data = vec![1, 2, 3, 4, 5];
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let raw: usize = input.trim().parse().unwrap();
    
    // SAFE: checked arithmetic with validation
    if let Some(idx) = raw.checked_sub(1) {
        if idx < data.len() {
            println!("{}", data[idx]);
        }
    }
}

fn main() {
    // Demonstrate various patterns
    safe_hardcoded_index();
    safe_get_method();
}

// Test counts:
// Vulnerable: 11 functions
// Safe: 9 functions
// Expected: Flag vulnerable_*, not safe_*
