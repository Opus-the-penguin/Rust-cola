//! Injection vulnerability rules.
//!
//! Rules detecting injection vulnerabilities:
//! - Command injection
//! - SQL injection  
//! - Path traversal
//! - SSRF (Server-Side Request Forgery)
//! - Template injection
//! - Log injection
//! - Regex injection

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};
use super::command_rule_should_skip;

// Placeholder - rules will be migrated from lib.rs
// This file will contain:
// - RUSTCOLA006: Command injection risk
// - RUSTCOLA076: SQL injection
// - RUSTCOLA079: Path traversal
// - RUSTCOLA089: SSRF
// - RUSTCOLA090: Template injection
// - RUSTCOLA091: Log injection
// - RUSTCOLA092: Regex injection
// - Inter-procedural variants

/// Register all injection rules with the rule engine.
pub fn register_injection_rules(_engine: &mut crate::RuleEngine) {
    // Rules will be registered here after migration
}
