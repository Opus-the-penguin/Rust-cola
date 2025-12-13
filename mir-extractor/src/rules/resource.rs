//! Resource management rules.
//!
//! Rules detecting resource management issues:
//! - File/directory permissions and handling
//! - Path traversal and absolute path issues
//! - Infinite iterators and unbounded operations
//! - Child process management
//! - Cookie/CORS security attributes
//! - Tempfile lifetime issues
//!
//! These rules are implemented in lib.rs and registered via register_builtin_rules().

#![allow(unused_imports)]

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};

// ============================================================================
// Resource Management Rules Summary
// ============================================================================
//
// RUSTCOLA009 - SpawnedChildNoWaitRule
//   Detects spawned child processes without wait()
//
// RUSTCOLA018 - PermissionsSetReadonlyFalseRule
//   Detects unsafe permission settings
//
// RUSTCOLA019 - WorldWritableModeRule
//   Detects world-writable file permissions
//
// RUSTCOLA020 - FileHandleLeakRule
//   Detects potential file handle leaks
//
// RUSTCOLA026 - PathTraversalRule
//   Detects path traversal vulnerabilities
//
// RUSTCOLA027 - AbsolutePathJoinRule
//   Detects absolute paths joined to other paths
//
// RUSTCOLA042 - CookieSecureAttributeRule
//   Detects missing Secure attribute on cookies
//
// RUSTCOLA043 - CorsWildcardRule
//   Detects overly permissive CORS configuration
//
// RUSTCOLA046 - BuildScriptNetworkRule
//   Detects network access in build scripts
//
// RUSTCOLA052 - InfiniteIteratorRule
//   Detects infinite iterators without bounds
//
// RUSTCOLA055 - UnixPermissionsNotOctalRule
//   Detects non-octal Unix permission literals
//
// RUSTCOLA056 - OpenOptionsInconsistentFlagsRule
//   Detects inconsistent OpenOptions flags
//
// RUSTCOLA063 - TempfileDanglingPathRule
//   Detects tempfile paths used after file is dropped
//
// RUSTCOLA078 - SymlinkRaceRule
//   Detects TOCTOU vulnerabilities in symlink handling
//
// ============================================================================

/// Register all resource management rules with the rule engine.
pub fn register_resource_rules(_engine: &mut crate::RuleEngine) {
    // Rules are registered in lib.rs register_builtin_rules()
}
