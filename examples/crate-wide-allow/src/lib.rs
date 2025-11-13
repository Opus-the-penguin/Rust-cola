//! Demonstrates RUSTCOLA049: Crate-wide allow attribute detection
//!
//! This example shows why crate-wide #![allow(...)] is problematic
//! and how to use more targeted item-level #[allow(...)] instead.

// NOTE: This file intentionally does NOT contain #![allow(...)] at crate level
// to avoid actually disabling lints. The detection would work on real code.

// ============================================================================
// VULNERABLE PATTERN - Crate-wide allow (DEMONSTRATED IN COMMENTS)
// ============================================================================

// PROBLEMATIC: This would disable the lint for the ENTIRE crate
// #![allow(dead_code)]
//
// Impact:
// - Every unused function, type, constant in the crate is now hidden
// - No warnings for genuinely forgotten code
// - Security-critical dead code paths may remain unnoticed
// - Technical debt accumulates silently

/// This demonstrates where crate-wide allows would be detected
pub fn example_with_crate_wide_allow_commented() {
    // If we had: #![allow(unused_variables)]
    // Then ALL unused variables in ALL functions would be hidden
    println!("This demonstrates the pattern");
}

// ============================================================================
// MORE PROBLEMATIC EXAMPLES (COMMENTED)
// ============================================================================

// VERY BAD: Disabling clippy warnings crate-wide
// #![allow(clippy::all)]
// This disables ALL clippy lints - including security-relevant ones like:
// - clippy::suspicious_else_formatting
// - clippy::suspicious_open_options  
// - clippy::invalid_regex
// - clippy::zombie_processes

// BAD: Disabling multiple important lints
// #![allow(unused_imports, unused_variables, dead_code)]
// This creates a "lint-free zone" where problems hide

// BAD: Disabling specific but important lints
// #![allow(clippy::cognitive_complexity)]
// Complex functions often contain security bugs - this hides them

// ============================================================================
// RECOMMENDED PATTERN - Item-level allow
// ============================================================================

/// GOOD: Targeted suppression on specific item
#[allow(dead_code)]
fn intentionally_unused_helper() {
    // This function is kept for future use or compatibility
    // The #[allow] is scoped to just this function
}

/// GOOD: Suppressing a specific known issue
#[allow(clippy::redundant_closure)]
fn with_justified_suppression() {
    let numbers = vec![1, 2, 3];
    let _doubled: Vec<_> = numbers.iter().map(|x| x * 2).collect();
    // The closure could be replaced with a method reference,
    // but this is more readable in this context
}

/// GOOD: Temporary suppression with TODO
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), deprecated(note = "TODO: Refactor to use a config struct"))]
fn needs_refactoring(
    _arg1: i32,
    _arg2: i32, 
    _arg3: i32,
    _arg4: i32,
    _arg5: i32,
    _arg6: i32,
    _arg7: i32,
    _arg8: i32,
) {
    // Planned refactoring, suppression is temporary and documented
}

// ============================================================================
// SAFE PATTERNS - No allows at all
// ============================================================================

/// BEST: No suppression needed - clean code
pub fn clean_code() {
    let value = 42;
    println!("Value: {}", value);
}

/// BEST: Code that passes all lints naturally
pub fn no_warnings() -> i32 {
    let result = 10 + 20;
    result
}

// ============================================================================
// WHY THIS MATTERS
// ============================================================================

#[cfg(test)]
mod tests {
    #[test]
    fn demonstrate_scope_difference() {
        // Crate-level: #![allow(lint)]
        //   - Affects ENTIRE crate
        //   - Can't see the suppression when reading specific functions
        //   - Easy to forget it's there
        //   - Hides legitimate issues
        
        // Item-level: #[allow(lint)]
        //   - Affects only that specific item
        //   - Visible when reading the code
        //   - Forced to justify each suppression
        //   - Narrowly scoped
        
        assert!(true);
    }
    
    #[test]
    fn demonstrate_security_impact() {
        // Example: #![allow(clippy::suspicious_else_formatting)]
        // could hide code like:
        
        // if authenticated
        //     grant_access();
        // else
        // grant_access(); // BUG! Looks like it's in else, but isn't!
        
        // The suspicious formatting would be flagged by clippy,
        // but a crate-wide allow would hide it
        
        assert!(true);
    }
}
