//! ⚠️ SECURITY SCANNER NOTICE ⚠️
//!
//! This crate contains INTENTIONAL security vulnerabilities for testing RUSTCOLA040.
//! DO NOT use these patterns in production code.
//!
//! codeql[rust/panic-in-destructor]: Test examples for panic in Drop detection

// NOSEC: This file contains test patterns for security scanners

use std::fs::File;
use std::io::Write;

/// BAD: Using panic! in Drop implementation
/// Panicking during unwinding causes process abort
pub struct BadPanicDrop {
    data: String,
}

impl Drop for BadPanicDrop {
    fn drop(&mut self) {
        if self.data.is_empty() {
            panic!("Data is empty in Drop!"); // NOSEC - Double panic = abort!
        }
    }
}

/// BAD: Using unwrap() in Drop implementation
pub struct BadUnwrapDrop {
    file: Option<File>,
}

impl Drop for BadUnwrapDrop {
    fn drop(&mut self) {
        if let Some(mut f) = self.file.take() {
            f.write_all(b"cleanup").unwrap(); // NOSEC - Can panic during unwinding!
        }
    }
}

/// BAD: Using expect() in Drop implementation
pub struct BadExpectDrop {
    counter: u32,
}

impl Drop for BadExpectDrop {
    fn drop(&mut self) {
        // NOSEC - expect() can panic
        let _result = std::fs::remove_file("temp.txt").expect("Failed to remove temp file"); // NOSEC
    }
}

/// BAD: Using unreachable! in Drop
pub struct BadUnreachableDrop {
    state: i32,
}

impl Drop for BadUnreachableDrop {
    fn drop(&mut self) {
        match self.state {
            0 => println!("State 0"),
            1 => println!("State 1"),
            _ => unreachable!("Invalid state"), // NOSEC - Can abort if state changes
        }
    }
}

/// BAD: Using todo! in Drop
pub struct BadTodoDrop {
    _data: Vec<u8>,
}

impl Drop for BadTodoDrop {
    fn drop(&mut self) {
        // NOSEC - todo! panics
        todo!("Implement proper cleanup"); // NOSEC
    }
}

/// GOOD: Proper error handling in Drop
pub struct GoodDrop {
    file: Option<File>,
}

impl Drop for GoodDrop {
    fn drop(&mut self) {
        if let Some(mut f) = self.file.take() {
            // Use error handling instead of unwrap
            if let Err(e) = f.write_all(b"cleanup") {
                eprintln!("Failed to write during cleanup: {}", e);
            }
        }
    }
}

/// GOOD: Logging errors instead of panicking
pub struct GoodLogDrop {
    counter: u32,
}

impl Drop for GoodLogDrop {
    fn drop(&mut self) {
        // Log errors instead of panicking
        if let Err(e) = std::fs::remove_file("temp.txt") {
            eprintln!("Warning: Failed to remove temp file: {}", e);
        }
        println!("Dropped with counter: {}", self.counter);
    }
}

/// GOOD: Swallow errors gracefully
pub struct GoodSilentDrop {
    _resources: Vec<String>,
}

impl Drop for GoodSilentDrop {
    fn drop(&mut self) {
        // Explicitly ignore errors without panicking
        let _ = std::fs::remove_file("optional_cache.txt");
    }
}

/// GOOD: Use std::panic::catch_unwind for risky operations
pub struct GoodCatchUnwindDrop {
    cleanup_fn: Option<Box<dyn FnOnce() + std::panic::UnwindSafe>>,
}

impl Drop for GoodCatchUnwindDrop {
    fn drop(&mut self) {
        if let Some(f) = self.cleanup_fn.take() {
            // Catch panics to prevent double-panic
            if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
                eprintln!("Cleanup panicked: {:?}", e);
            }
        }
    }
}

/// GOOD: No panic, just cleanup
pub struct GoodSimpleDrop {
    counter: u32,
}

impl Drop for GoodSimpleDrop {
    fn drop(&mut self) {
        // Simple, infallible cleanup
        println!("Cleaning up counter: {}", self.counter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_good_patterns() {
        // These should drop without panicking
        {
            let _g1 = GoodDrop { file: None };
            let _g2 = GoodLogDrop { counter: 42 };
            let _g3 = GoodSilentDrop { _resources: vec![] };
            let _g4 = GoodSimpleDrop { counter: 100 };
        }
        // All dropped successfully
    }

    #[test]
    #[should_panic]
    fn test_bad_panic_drop() {
        // This demonstrates the panic (don't use in production!)
        let _bad = BadPanicDrop {
            data: String::new(),
        };
        // Drops here and panics
    }
}
