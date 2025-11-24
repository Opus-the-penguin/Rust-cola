//! Test cases for RUSTCOLA067: Commented-out code detection
//!
//! This module contains intentionally commented-out code to test the detection rule.
//! Commented-out code should be removed to keep codebases clean and maintainable.
//!
//! NOSEC: All commented code is intentional for testing purposes.

#![allow(dead_code)]

// ============================================================================
// PROBLEMATIC PATTERNS - Should trigger RUSTCOLA067
// ============================================================================

// BAD: Commented-out function
// pub fn old_implementation() {
//     println!("This was the old way");
// }

// BAD: Commented-out struct
// struct OldConfig {
//     setting1: String,
//     setting2: i32,
// }

// BAD: Commented-out variable declaration
pub fn example_function() {
    // let old_var = 42;
    // let mut data = vec![1, 2, 3];
    let current_var = 100;
    println!("{}", current_var);
}

// BAD: Commented-out impl block
// impl MyTrait for MyStruct {
//     fn method(&self) -> i32 {
//         self.field * 2
//     }
// }

// BAD: Commented-out use statement
// use std::collections::HashMap;
// use serde::{Serialize, Deserialize};

// BAD: Commented-out match arm
pub fn match_example(x: i32) -> String {
    match x {
        1 => "one".to_string(),
        // 2 => "two".to_string(),
        // 3 => "three".to_string(),
        _ => "other".to_string(),
    }
}

// BAD: Commented-out if block
pub fn conditional_example(flag: bool) {
    // if flag {
    //     println!("Flag was true");
    // }
    if !flag {
        println!("Flag was false");
    }
}

// BAD: Multiple consecutive commented lines of code
// fn calculate_total(items: &[i32]) -> i32 {
//     let mut sum = 0;
//     for item in items {
//         sum += item;
//     }
//     sum
// }

// ============================================================================
// SAFE PATTERNS - Should NOT trigger RUSTCOLA067
// ============================================================================

// SAFE: Normal explanatory comment
// This function does something important
pub fn documented_function() {
    // Initialize the counter
    let counter = 0;
    println!("{}", counter);
}

// SAFE: Documentation comments
/// This is a doc comment explaining the function
/// It can span multiple lines
pub fn well_documented() {
    println!("Hello");
}

// SAFE: TODO/FIXME/NOTE comments
// TODO: Implement better error handling
// FIXME: This has a known issue
// NOTE: Performance could be improved
pub fn with_todo_comments() {
    println!("Work in progress");
}

// SAFE: Commented-out text that's not code
// This explains why we chose this approach:
// 1. Better performance
// 2. Easier to maintain
// 3. More idiomatic Rust
pub fn explained_choice() {
    println!("Current implementation");
}

// SAFE: Example code in comments (clearly marked)
// Example usage:
// ```
// let result = my_function(42);
// ```
pub fn with_example() {
    println!("Function");
}

// SAFE: ASCII art or decorative comments
// ====================================
// ||  Section Header               ||
// ====================================
pub fn section_marker() {
    println!("Section");
}

// SAFE: URL or path in comment
// See: https://doc.rust-lang.org/book/
// File path: /usr/local/bin/app
pub fn with_references() {
    println!("Referenced");
}

// SAFE: Inline comment with explanation
pub fn inline_explanations() {
    let x = 42; // This is the answer
    let y = x * 2; // Double it
    println!("{}", y);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_problematic_patterns_compile() {
        example_function();
        assert_eq!(match_example(1), "one");
        conditional_example(true);
    }

    #[test]
    fn test_safe_patterns_compile() {
        documented_function();
        well_documented();
        with_todo_comments();
        explained_choice();
        with_example();
        section_marker();
        with_references();
        inline_explanations();
    }
}
