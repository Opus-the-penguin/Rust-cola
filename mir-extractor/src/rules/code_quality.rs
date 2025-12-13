//! Code quality and miscellaneous rules.
//!
//! Rules detecting code quality issues:
//! - Commented-out code (RUSTCOLA066)
//! - Dead stores in arrays (RUSTCOLA067)
//! - Misordered assert_eq arguments (RUSTCOLA050)
//! - Crate-wide allow lint (RUSTCOLA049)
//! - Overscoped allow (RUSTCOLA065)
//! - Non-HTTPS URLs (RUSTCOLA012)
//! - Hardcoded home paths (RUSTCOLA013)
//! - Invisible unicode (RUSTCOLA048)
//! - ctor/dtor std API usage (RUSTCOLA059)
//! - Local RefCell patterns (RUSTCOLA058)
//!
//! These rules are implemented in lib.rs and registered via register_builtin_rules().

#![allow(unused_imports)]

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};

// ============================================================================
// Code Quality Rules Summary
// ============================================================================
//
// RUSTCOLA012 - NonHttpsUrlRule
//   Detects non-HTTPS URLs in code
//
// RUSTCOLA013 - HardcodedHomePathRule
//   Detects hardcoded home directory paths
//
// RUSTCOLA048 - InvisibleUnicodeRule
//   Detects invisible/confusable Unicode characters
//
// RUSTCOLA049 - CrateWideAllowRule
//   Detects crate-wide #![allow(...)] attributes
//
// RUSTCOLA050 - MisorderedAssertEqRule
//   Detects swapped expected/actual in assert_eq!
//
// RUSTCOLA051 - TryIoResultRule
//   Detects try operator on IO results without context
//
// RUSTCOLA057 - UnnecessaryBorrowMutRule
//   Detects unnecessary borrow_mut() calls
//
// RUSTCOLA058 - LocalRefCellRule
//   Detects function-local RefCell patterns
//
// RUSTCOLA059 - CtorDtorStdApiRule
//   Detects ctor/dtor crate with std API in callbacks
//
// RUSTCOLA060 - ConnectionStringPasswordRule
//   Detects passwords in connection strings
//
// RUSTCOLA061 - PasswordFieldMaskingRule
//   Detects password fields without Debug masking
//
// RUSTCOLA065 - OverscopedAllowRule
//   Detects overly scoped allow attributes
//
// RUSTCOLA066 - CommentedOutCodeRule
//   Detects commented-out code blocks
//
// RUSTCOLA067 - DeadStoreArrayRule
//   Detects dead stores to array elements
//
// ============================================================================

/// Register all code quality rules with the rule engine.
pub fn register_code_quality_rules(_engine: &mut crate::RuleEngine) {
    // Rules are registered in lib.rs register_builtin_rules()
}
