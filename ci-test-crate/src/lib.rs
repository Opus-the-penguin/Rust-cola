//! Minimal test crate for CI self-analysis.
//!
//! This crate contains a small amount of sample code that cargo-cola can analyze
//! quickly during CI. It intentionally includes a few patterns that should trigger
//! findings to verify the analysis is working.

/// A simple function that does nothing problematic
pub fn safe_function(x: i32) -> i32 {
    x + 1
}

/// Example with a hardcoded path (should trigger RUSTCOLA008)
pub fn example_with_path() -> &'static str {
    "/home/user/.config/app"
}

/// Example with env var read (informational)
pub fn read_env() -> Option<String> {
    std::env::var("API_KEY").ok()
}

/// Example with potential division
pub fn divide(a: i32, b: i32) -> Option<i32> {
    if b != 0 {
        Some(a / b)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_function() {
        assert_eq!(safe_function(1), 2);
    }
}
