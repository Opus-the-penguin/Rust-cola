//! Concurrency safety rules.
//!
//! Rules detecting concurrency issues:
//! - Mutex guard held across await
//! - Blocking operations in async context
//! - Unsafe Send/Sync bounds
//! - Non-thread-safe patterns
//! - Underscore lock guard (immediate drop)

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};

// Placeholder - rules will be migrated from lib.rs
// This file will contain:
// - RUSTCOLA015: Mutex guard across await
// - RUSTCOLA037: Blocking sleep in async
// - RUSTCOLA038: Blocking ops in async
// - RUSTCOLA027: Unsafe Send/Sync bounds
// - RUSTCOLA074: Underscore lock guard
// - RUSTCOLA082: Non-thread-safe test patterns

/// Register all concurrency rules with the rule engine.
pub fn register_concurrency_rules(_engine: &mut crate::RuleEngine) {
    // Rules will be registered here after migration
}
