//! Demonstrates RUSTCOLA047: Environment variable literal detection
//!
//! This example shows why using string literals for environment variable names
//! is problematic and how using constants improves code maintainability.

use std::env;

// ============================================================================
// RECOMMENDED PATTERN - Using constants
// ============================================================================

const HOME_DIR: &str = "HOME";
const PATH_VAR: &str = "PATH";
const USER_NAME: &str = "USER";
const RUST_LOG: &str = "RUST_LOG";

/// SAFE: Using constant for env var name
pub fn safe_read_home_with_const() -> Option<String> {
    env::var(HOME_DIR).ok()
}

/// SAFE: Using constant for env var name
pub fn safe_read_path_with_const() -> Option<String> {
    env::var_os(PATH_VAR).and_then(|s| s.into_string().ok())
}

/// SAFE: Using constant
pub fn safe_read_user_with_const() -> Option<String> {
    env::var(USER_NAME).ok()
}

/// SAFE: Using constant for logging configuration
pub fn safe_configure_logging_with_const() {
    if let Ok(level) = env::var(RUST_LOG) {
        println!("Log level: {}", level);
    }
}

// ============================================================================
// PROBLEMATIC PATTERN - Using string literals (will trigger RUSTCOLA047)
// ============================================================================

/// VULNERABLE: Direct string literal
pub fn vulnerable_read_home_literal() -> Option<String> {
    env::var("HOME").ok()
}

/// VULNERABLE: Direct string literal in var_os
pub fn vulnerable_read_path_literal() -> Option<String> {
    env::var_os("PATH").and_then(|s| s.into_string().ok())
}

/// VULNERABLE: String literal
pub fn vulnerable_read_user_literal() -> Option<String> {
    env::var("USER").ok()
}

/// VULNERABLE: Multiple string literals
pub fn vulnerable_multiple_literals() {
    let _home = env::var("HOME");
    let _path = env::var("PATH");
    let _user = env::var("USER");
}

/// VULNERABLE: String literal in configuration
pub fn vulnerable_configure_logging_literal() {
    if let Ok(level) = env::var("RUST_LOG") {
        println!("Log level: {}", level);
    }
}

/// VULNERABLE: Case-sensitive typo risk
pub fn vulnerable_typo_risk() -> Option<String> {
    // Typo: "HOMR" instead of "HOME" - would be caught if using const
    env::var("HOMR").ok()
}

/// VULNERABLE: Repeated literals (maintenance issue)
pub fn vulnerable_repeated_literal() {
    if env::var("DATABASE_URL").is_ok() {
        // If we need to change "DATABASE_URL" we have to change it everywhere
        println!("Database configured: {}", env::var("DATABASE_URL").unwrap());
    }
}

// ============================================================================
// EDGE CASES
// ============================================================================

/// EDGE: Dynamic env var name (acceptable)
pub fn edge_case_dynamic_var_name(var_name: &str) -> Option<String> {
    env::var(var_name).ok()
}

/// EDGE: Conditional env var based on platform
#[cfg(target_os = "windows")]
pub fn edge_case_platform_specific() -> Option<String> {
    // Platform-specific but still should use const
    env::var("USERPROFILE").ok()
}

// ============================================================================
// WHY THIS MATTERS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demonstrate_const_benefits() {
        // Benefits of using constants:
        
        // 1. Compile-time checking - typos caught immediately
        // const HOME_DIR: &str = "HOMR"; // Oops, typo!
        // But the constant NAME tells us it should be "HOME"
        
        // 2. Single source of truth
        // Change the value once, affects all uses
        
        // 3. Documentation
        // Constants make it clear what env vars the code depends on
        
        // 4. Easier to audit
        // grep for "const.*&str" shows all env vars used
        
        // 5. IDE support
        // Auto-completion, find usages, rename refactoring all work better
        
        assert!(true); // Placeholder
    }

    #[test]
    fn demonstrate_literal_problems() {
        // Problems with string literals:
        
        // 1. Typos only caught at runtime
        let _ = std::env::var("HOMR"); // Typo! But compiles fine
        
        // 2. Multiple occurrences to maintain
        // If "DATABASE_URL" changes, need to find/replace all
        
        // 3. Hard to audit dependencies
        // Literals scattered throughout code
        
        // 4. No type safety
        // Easy to mix up similar var names
        
        assert!(true); // Placeholder
    }
}
