//! Code quality and miscellaneous rules.
//!
//! Rules detecting code quality issues:
//! - Commented-out code
//! - Dead stores in arrays
//! - Misordered assert_eq arguments
//! - Crate-wide allow lint
//! - Overscoped allow
//! - Non-HTTPS URLs
//! - Hardcoded home paths

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};

// Placeholder - rules will be migrated from lib.rs
// This file will contain:
// - RUSTCOLA047: Env var literal
// - RUSTCOLA048: Invisible unicode
// - RUSTCOLA049: Crate-wide allow
// - RUSTCOLA050: Misordered assert_eq
// - RUSTCOLA051: Try IO result
// - RUSTCOLA052: Local RefCell
// - RUSTCOLA057: Unnecessary borrow_mut
// - RUSTCOLA058: Absolute path in join
// - RUSTCOLA059: ctor/dtor std API
// - RUSTCOLA060: Connection string password
// - RUSTCOLA061: Password field masking
// - RUSTCOLA065: Overscoped allow
// - RUSTCOLA066: Commented out code
// - RUSTCOLA067: Dead store array
// - RUSTCOLA012: Non-HTTPS URL
// - RUSTCOLA013: Hardcoded home path

/// Register all code quality rules with the rule engine.
pub fn register_code_quality_rules(_engine: &mut crate::RuleEngine) {
    // Rules will be registered here after migration
}
