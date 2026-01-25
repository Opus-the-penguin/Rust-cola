//! Test cases for RUSTCOLA079: Regex Injection Detection
//!
//! This module contains examples of vulnerable and safe regex pattern construction
//! to test the regex injection detection rule.

use regex::{Regex, RegexBuilder, RegexSet};
use std::env;
use std::fs;
use std::io::{self, BufRead};

// ============================================================================
// PROBLEMATIC: Should trigger RUSTCOLA079
// ============================================================================

/// PROBLEMATIC: Regex from env var - direct injection
pub fn regex_from_env() -> Option<Regex> {
    let pattern = env::var("SEARCH_PATTERN").ok()?;
    // Vulnerable: untrusted pattern goes directly to Regex::new
    Regex::new(&pattern).ok()
}

/// PROBLEMATIC: Regex from CLI args
pub fn regex_from_cli_arg() -> Option<Regex> {
    let pattern = env::args().nth(1)?;
    // Vulnerable: CLI argument used as regex pattern
    Regex::new(&pattern).ok()
}

/// PROBLEMATIC: RegexBuilder from env var
pub fn regex_builder_from_env() -> Option<Regex> {
    let pattern = env::var("PATTERN").ok()?;
    // Vulnerable: untrusted pattern to RegexBuilder
    RegexBuilder::new(&pattern)
        .case_insensitive(true)
        .build()
        .ok()
}

/// PROBLEMATIC: RegexSet from env var
pub fn regex_set_from_env() -> Option<RegexSet> {
    let patterns: Vec<String> = env::var("PATTERNS")
        .ok()?
        .split(',')
        .map(String::from)
        .collect();
    // Vulnerable: untrusted patterns to RegexSet
    RegexSet::new(&patterns).ok()
}

/// PROBLEMATIC: Regex from stdin input
pub fn regex_from_stdin() -> Option<Regex> {
    let stdin = io::stdin();
    let mut pattern = String::new();
    stdin.lock().read_line(&mut pattern).ok()?;
    // Vulnerable: user input from stdin as regex pattern
    Regex::new(pattern.trim()).ok()
}

/// PROBLEMATIC: Regex from file contents
pub fn regex_from_file(path: &str) -> Option<Regex> {
    let pattern = fs::read_to_string(path).ok()?;
    // Vulnerable: file contents as regex pattern
    Regex::new(pattern.trim()).ok()
}

/// PROBLEMATIC: Regex with format string but still untrusted core
pub fn regex_with_prefix_from_env() -> Option<Regex> {
    let user_pattern = env::var("PARTIAL_PATTERN").ok()?;
    // Still vulnerable: user controls significant part of pattern
    let full_pattern = format!("^{}$", user_pattern);
    Regex::new(&full_pattern).ok()
}

/// PROBLEMATIC: Indirect flow through intermediate variable
pub fn regex_indirect_flow() -> Option<Regex> {
    let input = env::var("INPUT").ok()?;
    let pattern = input.clone();
    let another = pattern;
    // Vulnerable: taint flows through assignments
    Regex::new(&another).ok()
}

// ============================================================================
// SAFE: Should NOT trigger RUSTCOLA079
// ============================================================================

/// SAFE: Static hardcoded pattern
pub fn regex_hardcoded() -> Option<Regex> {
    // Safe: pattern is hardcoded
    Regex::new(r"^\d{3}-\d{2}-\d{4}$").ok()
}

/// SAFE: Const pattern
pub fn regex_const() -> Option<Regex> {
    const PATTERN: &str = r"^[a-zA-Z0-9_]+$";
    // Safe: pattern is a constant
    Regex::new(PATTERN).ok()
}

/// SAFE: Static pattern reference
pub fn regex_static() -> Option<Regex> {
    static PATTERN: &str = r"^\w+@\w+\.\w+$";
    // Safe: pattern is static
    Regex::new(PATTERN).ok()
}

/// SAFE: Escaped user input (literal matching)
pub fn regex_escaped_input() -> Option<Regex> {
    let user_input = env::var("SEARCH_TERM").ok()?;
    // Safe: regex::escape converts to literal match
    let escaped = regex::escape(&user_input);
    Regex::new(&escaped).ok()
}

/// SAFE: Pattern from allowlist
pub fn regex_from_allowlist() -> Option<Regex> {
    let choice = env::var("PATTERN_CHOICE").ok()?;
    // Safe: pattern selected from known-good list
    let allowed_patterns = ["email", "phone", "ssn"];
    let pattern = match choice.as_str() {
        "email" => r"^[\w.+-]+@[\w.-]+\.\w{2,}$",
        "phone" => r"^\d{3}-\d{3}-\d{4}$",
        "ssn" => r"^\d{3}-\d{2}-\d{4}$",
        _ => return None,
    };
    if allowed_patterns.contains(&choice.as_str()) {
        Regex::new(pattern).ok()
    } else {
        None
    }
}

/// SAFE: Validated pattern (hypothetical validation function)
fn validate_pattern(p: &str) -> bool {
    // Simple validation: only allow alphanumeric and basic regex chars
    p.chars()
        .all(|c| c.is_alphanumeric() || ".-_^$[]".contains(c))
        && p.len() < 50
}

pub fn regex_validated() -> Option<Regex> {
    let pattern = env::var("PATTERN").ok()?;
    // Safe: pattern is validated before use
    if validate_pattern(&pattern) {
        Regex::new(&pattern).ok()
    } else {
        None
    }
}

/// SAFE: Using env var for data matching, not pattern
pub fn regex_match_env_data() -> bool {
    let data = env::var("DATA_TO_MATCH").unwrap_or_default();
    // Safe: env var is the DATA being matched, not the pattern
    let pattern = Regex::new(r"^\d+$").unwrap();
    pattern.is_match(&data)
}

/// SAFE: Literal string pattern
pub fn regex_literal_string() -> Option<Regex> {
    let pattern = String::from(r"^test\d+$");
    // Safe: pattern is from literal, not external input
    Regex::new(&pattern).ok()
}

// ============================================================================
// EDGE CASES
// ============================================================================

/// EDGE: Pattern partially from env (prefix is safe, suffix from env)
/// This should probably still flag since user controls part of pattern
pub fn regex_partial_user_control() -> Option<Regex> {
    let suffix = env::var("SUFFIX").ok()?;
    // Risky: user controls suffix which could break out of intended pattern
    let pattern = format!(r"^prefix_{}", suffix);
    Regex::new(&pattern).ok()
}

/// EDGE: Complex flow with Option handling
pub fn regex_option_flow() -> Option<Regex> {
    env::var("PATTERN").ok().and_then(|p| Regex::new(&p).ok())
}
