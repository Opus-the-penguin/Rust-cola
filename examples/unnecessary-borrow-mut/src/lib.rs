// Test cases for RUSTCOLA057: Unnecessary borrow_mut
//
// This module tests detection of RefCell::borrow_mut() calls where
// borrow() would suffice because no actual mutation occurs.

use std::cell::RefCell;

// PROBLEMATIC: borrow_mut() but only read the value
pub fn read_only_borrow_mut() -> i32 {
    let data = RefCell::new(42);
    let borrowed = data.borrow_mut();
    *borrowed  // Only reading, should use borrow()
}

// PROBLEMATIC: borrow_mut() to access nested data read-only
pub fn read_nested_field() -> String {
    let data = RefCell::new(vec!["hello".to_string(), "world".to_string()]);
    let borrowed = data.borrow_mut();
    borrowed[0].clone()  // Only reading, should use borrow()
}

// PROBLEMATIC: borrow_mut() just to check a condition
pub fn check_condition() -> bool {
    let data = RefCell::new(vec![1, 2, 3, 4, 5]);
    let borrowed = data.borrow_mut();
    borrowed.len() > 3  // Only reading, should use borrow()
}

// PROBLEMATIC: borrow_mut() to iterate read-only
pub fn iterate_read_only() -> i32 {
    let data = RefCell::new(vec![1, 2, 3, 4, 5]);
    let borrowed = data.borrow_mut();
    borrowed.iter().sum()  // Only reading, should use borrow()
}

// SAFE: borrow_mut() and actually mutate
pub fn actually_mutate() {
    let data = RefCell::new(vec![1, 2, 3]);
    let mut borrowed = data.borrow_mut();
    borrowed.push(4);  // Actually mutating
}

// SAFE: borrow_mut() to modify field
pub fn modify_field() {
    let data = RefCell::new(vec![1, 2, 3]);
    let mut borrowed = data.borrow_mut();
    borrowed[0] = 10;  // Actually mutating
}

// SAFE: borrow_mut() to clear collection
pub fn clear_collection() {
    let data = RefCell::new(vec![1, 2, 3]);
    let mut borrowed = data.borrow_mut();
    borrowed.clear();  // Actually mutating
}

// SAFE: borrow_mut() to extend collection
pub fn extend_collection() {
    let data = RefCell::new(vec![1, 2, 3]);
    let mut borrowed = data.borrow_mut();
    borrowed.extend(vec![4, 5, 6]);  // Actually mutating
}

// SAFE: borrow() for read-only access (correct pattern)
pub fn correct_read_only() -> i32 {
    let data = RefCell::new(42);
    let borrowed = data.borrow();
    *borrowed  // Correct: using borrow() for read-only
}

// SAFE: borrow_mut() to sort (mutation)
pub fn sort_data() {
    let data = RefCell::new(vec![3, 1, 4, 1, 5]);
    let mut borrowed = data.borrow_mut();
    borrowed.sort();  // Actually mutating
}
