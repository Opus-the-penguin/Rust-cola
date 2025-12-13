//! Input validation rules.
//!
//! Rules detecting input validation issues:
//! - Environment variable handling (RUSTCOLA006, RUSTCOLA007, RUSTCOLA047)
//! - Untrimmed stdin input (RUSTCOLA053)
//! - Unsafe deserialization (RUSTCOLA089, RUSTCOLA091)
//! - Unbounded reads (RUSTCOLA090)
//! - Division by untrusted input (RUSTCOLA077)
//! - Unchecked array indexing (RUSTCOLA080)
//!
//! These rules are implemented in lib.rs and registered via register_builtin_rules().

#![allow(unused_imports)]

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};

// ============================================================================
// Input Validation Rules Summary
// ============================================================================
//
// RUSTCOLA006 - CleartextEnvVarRule
//   Detects sensitive data stored in environment variables
//
// RUSTCOLA007 - UntrustedEnvInputRule
//   Detects untrusted environment variable usage
//
// RUSTCOLA047 - EnvVarLiteralRule
//   Detects hardcoded environment variable names
//
// RUSTCOLA053 - UntrimmedStdinRule
//   Detects stdin input used without trimming
//
// RUSTCOLA077 - DivisionByUntrustedRule
//   Detects division by untrusted input (DoS via panic)
//
// RUSTCOLA080 - UncheckedIndexRule
//   Detects unchecked array/slice indexing with untrusted input
//
// RUSTCOLA089 - InsecureYamlDeserializationRule
//   Detects unsafe YAML deserialization
//
// RUSTCOLA090 - UnboundedReadRule
//   Detects unbounded reads from untrusted sources
//
// RUSTCOLA091 - InsecureJsonTomlDeserializationRule
//   Detects unsafe JSON/TOML deserialization
//
// ============================================================================

/// Register all input validation rules with the rule engine.
pub fn register_input_rules(_engine: &mut crate::RuleEngine) {
    // Rules are registered in lib.rs register_builtin_rules()
}
