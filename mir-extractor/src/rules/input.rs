//! Input validation rules.
//!
//! Rules detecting input validation issues:
//! - Environment variable handling
//! - Untrimmed stdin input
//! - Unsafe deserialization (JSON, TOML, YAML)
//! - Unbounded reads
//! - Untrusted division

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};

// Placeholder - rules will be migrated from lib.rs
// This file will contain:
// - RUSTCOLA007: Cleartext env var
// - RUSTCOLA008: Untrusted env input
// - RUSTCOLA053: Untrimmed stdin
// - RUSTCOLA086: Insecure YAML deserialization
// - RUSTCOLA087: Insecure JSON/TOML deserialization
// - RUSTCOLA088: Unbounded read
// - RUSTCOLA093: Division by untrusted input

/// Register all input validation rules with the rule engine.
pub fn register_input_rules(_engine: &mut crate::RuleEngine) {
    // Rules will be registered here after migration
}
