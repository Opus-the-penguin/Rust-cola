//! Resource management rules.
//!
//! Rules detecting resource management issues:
//! - File permissions (world-writable, non-octal)
//! - Open options inconsistent flags
//! - Infinite iterators
//! - Spawned child without wait
//! - Cookie/CORS security attributes

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};

// Placeholder - rules will be migrated from lib.rs
// This file will contain:
// - RUSTCOLA009: Spawned child no wait
// - RUSTCOLA018: Permissions set readonly false
// - RUSTCOLA019: World writable mode
// - RUSTCOLA054: Infinite iterator
// - RUSTCOLA055: Unix permissions not octal
// - RUSTCOLA056: Open options inconsistent flags
// - RUSTCOLA042: Cookie secure attribute
// - RUSTCOLA043: CORS wildcard

/// Register all resource management rules with the rule engine.
pub fn register_resource_rules(_engine: &mut crate::RuleEngine) {
    // Rules will be registered here after migration
}
