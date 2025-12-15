//! Test cases for RUSTCOLA121: Executor Starvation Detection
//!
//! This rule detects CPU-bound operations in async contexts without
//! yielding, which can starve the executor and prevent other tasks
//! from making progress.

#![allow(unused_imports)]

use std::time::Duration;

// ============================================================================
// BAD PATTERNS - CPU-bound work without yielding
// ============================================================================

/// BAD: Long-running computation in async without yield
pub async fn bad_cpu_bound_no_yield(iterations: u64) -> u64 {
    let mut sum = 0u64;
    for i in 0..iterations {
        // CPU-intensive work - no await/yield
        sum = sum.wrapping_add(i * i);
    }
    sum
}

/// BAD: Infinite loop in async (DoS)
pub async fn bad_infinite_loop() {
    loop {
        // CPU spinning - executor can never switch tasks
        std::hint::spin_loop();
    }
}

/// BAD: Recursive computation without yield (non-async to avoid Rust limitation)
/// In practice, converting this to async would starve the executor
pub fn bad_recursive_fib(n: u64) -> u64 {
    if n <= 1 {
        n
    } else {
        // Recursive CPU work - if called from async context, blocks executor
        bad_recursive_fib(n - 1) + bad_recursive_fib(n - 2)
    }
}

/// BAD: Wrapper that calls CPU-bound recursion from async
pub async fn bad_async_fib_wrapper(n: u64) -> u64 {
    // Calling CPU-bound recursive function from async - starves executor
    bad_recursive_fib(n)
}

/// BAD: while loop doing CPU work
pub async fn bad_while_cpu_loop() -> i32 {
    let mut x = 0i32;
    while x < 1_000_000 {
        x = x.wrapping_add(1);
        // No yield point in loop
    }
    x
}

/// BAD: Hash computation without yield
pub async fn bad_hash_computation(data: &[u8]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    
    let mut hasher = DefaultHasher::new();
    // Process large data without yielding
    for chunk in data.chunks(1024) {
        for byte in chunk {
            hasher.write_u8(*byte);
        }
    }
    hasher.finish()
}

/// BAD: Sorting large array in async
pub async fn bad_sort_in_async(mut data: Vec<i32>) -> Vec<i32> {
    // CPU-bound sort blocks executor
    data.sort();
    data
}

/// BAD: Compression/encoding without yield
pub async fn bad_encode_data(data: &[u8]) -> Vec<u8> {
    // Simulated CPU-intensive encoding
    let mut result = Vec::with_capacity(data.len() * 2);
    for &byte in data {
        result.push(byte);
        result.push(byte ^ 0xFF);
    }
    result
}

/// BAD: Matrix multiplication in async
pub async fn bad_matrix_multiply(a: &[[f64; 100]; 100], b: &[[f64; 100]; 100]) -> [[f64; 100]; 100] {
    let mut result = [[0.0f64; 100]; 100];
    for i in 0..100 {
        for j in 0..100 {
            for k in 0..100 {
                result[i][j] += a[i][k] * b[k][j];
            }
        }
    }
    result
}

// ============================================================================
// GOOD PATTERNS - Proper yielding in async
// ============================================================================

/// GOOD: Using spawn_blocking for CPU work
pub async fn good_spawn_blocking(iterations: u64) -> u64 {
    tokio::task::spawn_blocking(move || {
        let mut sum = 0u64;
        for i in 0..iterations {
            sum = sum.wrapping_add(i * i);
        }
        sum
    }).await.unwrap()
}

/// GOOD: Yielding periodically in long loops
pub async fn good_yield_periodically(iterations: u64) -> u64 {
    let mut sum = 0u64;
    for i in 0..iterations {
        sum = sum.wrapping_add(i * i);
        if i % 10_000 == 0 {
            tokio::task::yield_now().await;  // Let other tasks run
        }
    }
    sum
}

/// GOOD: Using block_in_place for sync work
pub async fn good_block_in_place(data: &[u8]) -> Vec<u8> {
    let data = data.to_vec();
    tokio::task::block_in_place(move || {
        // CPU work runs on blocking thread pool
        let mut result = Vec::with_capacity(data.len() * 2);
        for byte in data {
            result.push(byte);
            result.push(byte ^ 0xFF);
        }
        result
    })
}

/// GOOD: Chunked processing with yield
pub async fn good_chunked_processing(data: Vec<i32>) -> i64 {
    let mut sum = 0i64;
    for chunk in data.chunks(1000) {
        for &x in chunk {
            sum += x as i64;
        }
        tokio::task::yield_now().await;
    }
    sum
}

/// GOOD: Using rayon for parallel CPU work
pub async fn good_rayon_parallel(data: Vec<i32>) -> i64 {
    tokio::task::spawn_blocking(move || {
        // In real code: data.par_iter().sum()
        data.iter().map(|&x| x as i64).sum()
    }).await.unwrap()
}

#[tokio::main]
async fn main() {
    println!("RUSTCOLA121 test cases");
}
