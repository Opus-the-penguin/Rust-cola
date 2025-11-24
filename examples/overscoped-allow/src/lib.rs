// Test patterns for RUSTCOLA072: Overscoped allow attributes
// This tests detection of crate-wide #![allow(...)] that suppress security-relevant lints

// BAD: Blanket suppression of all warnings across entire crate
#![allow(warnings)]

// BAD: Suppressing unsafe_code across entire crate
#![allow(unsafe_code)]

// BAD: Suppressing dead_code across entire crate (could hide bypassed validation)
#![allow(dead_code)]

// BAD: Suppressing unused_must_use across entire crate (error handling)
#![allow(unused_must_use)]

// BAD: Suppressing clippy::all across entire crate
#![allow(clippy::all)]

// BAD: Suppressing clippy::unwrap_used across entire crate
#![allow(clippy::unwrap_used)]

// SAFE: This demonstrates proper usage - module-level or function-level allows

pub mod safe_examples {
    // SAFE: Module-level allow is more scoped than crate-level
    #[allow(dead_code)]
    fn helper() {
        println!("Module-level allow is acceptable");
    }

    // SAFE: Function-level allow is specific
    #[allow(unused_variables)]
    pub fn with_unused() {
        let x = 5;
        println!("Function-level allow is fine");
    }
}

pub fn example_function() {
    // This code exists so we have something to test
    println!("Example function");
}

// SAFE: Item-level allows are fine
#[allow(clippy::unwrap_used)]
pub fn specific_suppress() {
    Some(5).unwrap();
}
