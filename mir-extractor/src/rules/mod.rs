//! Security rules for Rust-cola static analysis.
//!
//! This module contains all security rules organized by category:
//! - `crypto`: Cryptographic weaknesses (weak hashes, hardcoded keys, weak ciphers)
//! - `memory`: Memory safety issues (transmute, uninit, set_len, raw pointers)
//! - `injection`: Injection vulnerabilities (command, SQL, path traversal, SSRF)
//! - `concurrency`: Concurrency bugs (mutex guards, async blocking, send/sync)
//! - `ffi`: FFI safety issues (allocator mismatch, CString, packed fields)
//! - `input`: Input validation issues (environment, stdin, deserialization)
//! - `resource`: Resource management (file permissions, open options, iterators)
//! - `code_quality`: Code quality issues (dead stores, commented code, assertions)

pub mod crypto;
pub mod memory;
pub mod injection;
pub mod concurrency;
pub mod ffi;
pub mod input;
pub mod resource;
pub mod code_quality;

// Re-export registration functions
pub use crypto::register_crypto_rules;
pub use memory::register_memory_rules;
pub use injection::register_injection_rules;
pub use concurrency::register_concurrency_rules;
pub use ffi::register_ffi_rules;
pub use input::register_input_rules;
pub use resource::register_resource_rules;
pub use code_quality::register_code_quality_rules;

// Re-export rule structs for direct access
pub use crypto::{
    InsecureMd5Rule, InsecureSha1Rule, WeakHashingExtendedRule, HardcodedCryptoKeyRule,
    TimingAttackRule, WeakCipherRule, PredictableRandomnessRule, ModuloBiasRandomRule,
};
pub use memory::{
    BoxIntoRawRule, TransmuteRule, UnsafeUsageRule, NullPointerTransmuteRule,
    ZSTPointerArithmeticRule, VecSetLenRule, MaybeUninitAssumeInitRule, MemUninitZeroedRule,
    NonNullNewUncheckedRule, MemForgetGuardRule,
};

use crate::{Finding, MirFunction, MirPackage, RuleMetadata, Severity, RuleOrigin, SourceSpan};

/// Helper function to collect MIR lines matching any of the given patterns.
pub(crate) fn collect_matches(lines: &[String], patterns: &[&str]) -> Vec<String> {
    lines
        .iter()
        .filter(|line| patterns.iter().any(|needle| line.contains(needle)))
        .map(|line| line.trim().to_string())
        .collect()
}

/// Helper function to check if text contains a word (case-insensitive, word boundary aware).
pub(crate) fn text_contains_word_case_insensitive(text: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }

    let target = needle.to_lowercase();
    text.to_lowercase()
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|token| token == target)
}

/// Helper function to strip comments from a line of code.
pub(crate) fn strip_comments(line: &str, in_block_comment: &mut bool) -> String {
    let mut result = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut idx = 0usize;

    while idx < bytes.len() {
        if *in_block_comment {
            if bytes[idx] == b'*' && idx + 1 < bytes.len() && bytes[idx + 1] == b'/' {
                *in_block_comment = false;
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }

        if bytes[idx] == b'/' && idx + 1 < bytes.len() {
            match bytes[idx + 1] {
                b'/' => break,
                b'*' => {
                    *in_block_comment = true;
                    idx += 2;
                    continue;
                }
                _ => {}
            }
        }

        result.push(bytes[idx] as char);
        idx += 1;
    }
    result
}

/// Helper function to check if a function in mir-extractor should skip command-related rules.
pub(crate) fn command_rule_should_skip(function: &MirFunction, package: &MirPackage) -> bool {
    if package.crate_name == "mir-extractor" {
        matches!(
            function.name.as_str(),
            "detect_rustc_version"
                | "run_cargo_rustc"
                | "discover_rustc_targets"
                | "detect_crate_name"
        )
    } else {
        false
    }
}
