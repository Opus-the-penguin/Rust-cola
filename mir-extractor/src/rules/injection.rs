//! Injection vulnerability rules.
//!
//! Rules detecting injection vulnerabilities:
//! - Command injection (RUSTCOLA007, RUSTCOLA098)
//! - SQL injection (RUSTCOLA087)
//! - Path traversal (RUSTCOLA086)
//! - SSRF (RUSTCOLA088)
//! - Log injection (RUSTCOLA076)
//! - Regex injection (RUSTCOLA079)
//!
//! These rules are complex dataflow-based rules that remain in lib.rs
//! and are registered directly via register_builtin_rules().
//! This module serves as documentation and future migration target.

#![allow(unused_imports)]

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};

// ============================================================================
// Injection Rules Summary
// ============================================================================
//
// The following injection rules are implemented in lib.rs:
//
// RUSTCOLA007 - CommandInjectionRiskRule
//   Detects std::process::Command usage with tainted arguments
//
// RUSTCOLA019 - CommandArgConcatenationRule  
//   Detects string concatenation in command arguments
//
// RUSTCOLA076 - LogInjectionRule
//   Detects untrusted input in log statements
//
// RUSTCOLA079 - RegexInjectionRule
//   Detects untrusted input in regex patterns
//
// RUSTCOLA086 - PathTraversalRule
//   Detects path traversal via untrusted filesystem paths
//
// RUSTCOLA087 - SqlInjectionRule
//   Detects SQL injection via string concatenation
//
// RUSTCOLA088 - SsrfRule
//   Detects SSRF via untrusted URLs in HTTP clients
//
// RUSTCOLA098 - InterProceduralCommandInjectionRule
//   Cross-function taint tracking for command injection
//
// ============================================================================

/// Register all injection rules with the rule engine.
/// 
/// Note: Injection rules are currently registered in lib.rs via
/// register_builtin_rules(). This function is a placeholder for
/// when rules are fully migrated to this module.
pub fn register_injection_rules(_engine: &mut crate::RuleEngine) {
    // Rules are registered in lib.rs register_builtin_rules()
    // Future: migrate complex dataflow rules here
}
