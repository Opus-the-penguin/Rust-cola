// Test cases for RUSTCOLA054: Infinite Iterator Without Termination
//
// This module tests detection of infinite iterators that lack proper termination
// conditions, which can lead to Denial of Service (DoS) through unbounded loops.

use std::iter;

// PROBLEMATIC: std::iter::repeat without termination
pub fn repeat_without_take() -> Vec<u32> {
    iter::repeat(42).collect() // Infinite iterator - would hang forever
}

// PROBLEMATIC: cycle without termination
pub fn cycle_without_take() -> Vec<u32> {
    vec![1, 2, 3].into_iter().cycle().collect() // Infinite iterator - would hang forever
}

// PROBLEMATIC: repeat_with without termination
pub fn repeat_with_without_take() -> Vec<String> {
    iter::repeat_with(|| "hello".to_string()).collect() // Infinite iterator - would hang forever
}

// PROBLEMATIC: Complex chain but still infinite
pub fn complex_infinite_chain() -> Vec<u32> {
    iter::repeat(1)
        .map(|x| x * 2)
        .filter(|x| x > &0)
        .collect() // Still infinite despite transformations
}

// SAFE: repeat with take
pub fn repeat_with_take() -> Vec<u32> {
    iter::repeat(42).take(10).collect() // Properly terminated
}

// SAFE: cycle with take
pub fn cycle_with_take() -> Vec<u32> {
    vec![1, 2, 3].into_iter().cycle().take(100).collect() // Properly terminated
}

// SAFE: repeat_with with take_while
pub fn repeat_with_take_while() -> Vec<u32> {
    let mut count = 0;
    iter::repeat_with(|| {
        count += 1;
        count
    })
    .take_while(|&x| x < 10)
    .collect() // Properly terminated
}

// SAFE: repeat with find (consumes until condition met)
pub fn repeat_with_find() -> Option<u32> {
    let mut count = 0;
    iter::repeat_with(|| {
        count += 1;
        count
    })
    .find(|&x| x == 5) // Terminates when found
}

// SAFE: Manual break in loop
pub fn repeat_with_manual_break() {
    for value in iter::repeat(42) {
        println!("{}", value);
        if value > 0 {
            break; // Manual termination
        }
    }
}

// EDGE CASE: Using any() which consumes until condition
pub fn repeat_with_any() -> bool {
    let mut count = 0;
    iter::repeat_with(|| {
        count += 1;
        count
    })
    .any(|x| x > 5) // Terminates when condition is true
}

// EDGE CASE: Using position() which terminates
pub fn cycle_with_position() -> Option<usize> {
    vec![1, 2, 3]
        .into_iter()
        .cycle()
        .position(|x| x == 2) // Terminates when found
}
