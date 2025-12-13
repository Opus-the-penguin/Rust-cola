//! FFI safety rules.
//!
//! Rules detecting FFI-related security issues:
//! - Allocator mismatch between Rust and C
//! - Unsafe CString pointer usage
//! - Packed field references
//! - FFI buffer leaks
//! - FFI pointer returns

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};

// Placeholder - rules will be migrated from lib.rs
// This file will contain:
// - RUSTCOLA016: Allocator mismatch FFI
// - RUSTCOLA017: Unsafe CString pointer
// - RUSTCOLA033: Packed field reference
// - RUSTCOLA034: FFI buffer leak
// - RUSTCOLA083: Unsafe FFI pointer return

/// Register all FFI rules with the rule engine.
pub fn register_ffi_rules(_engine: &mut crate::RuleEngine) {
    // Rules will be registered here after migration
}
