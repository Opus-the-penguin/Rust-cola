//! Shared utilities for rule implementations.
//!
//! This module contains helper functions and types used across multiple rules,
//! particularly for source code analysis that needs to handle string literals correctly.

/// State machine for tracking string literal boundaries across lines.
///
/// Used by `strip_string_literals` to correctly handle multi-line strings
/// and avoid false positives from pattern matching inside string content.
#[derive(Clone, Copy, Default)]
pub struct StringLiteralState {
    /// Currently inside a regular `"..."` string
    pub in_normal_string: bool,
    /// Currently inside a raw string `r#"..."#` with this many hashes
    pub raw_hashes: Option<usize>,
}

const STRIP_STRING_INITIAL_CAPACITY: usize = 256;

/// Replaces string literal content with spaces while preserving line length.
///
/// This function is essential for source-level rules that need to search for
/// patterns without matching inside string literals. It handles:
/// - Regular strings: `"..."`
/// - Raw strings: `r#"..."#` with any number of hashes
/// - Character literals: `'x'`
/// - Lifetimes: `'a` (preserved, not stripped)
///
/// # Arguments
/// * `state` - Current parsing state from previous line
/// * `line` - The source line to process
///
/// # Returns
/// A tuple of (sanitized line with string content replaced by spaces, new state)
///
/// # Example
/// ```ignore
/// let (sanitized, state) = strip_string_literals(StringLiteralState::default(), r#"let x = "hello world";"#);
/// assert!(sanitized.contains("let x ="));
/// assert!(!sanitized.contains("hello"));
/// ```
pub fn strip_string_literals(
    mut state: StringLiteralState,
    line: &str,
) -> (String, StringLiteralState) {
    let bytes = line.as_bytes();
    let mut result = String::with_capacity(STRIP_STRING_INITIAL_CAPACITY);
    let mut i = 0usize;

    while i < bytes.len() {
        // Handle raw string content
        if let Some(hashes) = state.raw_hashes {
            result.push(' ');
            if bytes[i] == b'"' {
                let mut matched = true;
                for k in 0..hashes {
                    if i + 1 + k >= bytes.len() || bytes[i + 1 + k] != b'#' {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    for _ in 0..hashes {
                        result.push(' ');
                    }
                    state.raw_hashes = None;
                    i += 1 + hashes;
                    continue;
                }
            }
            i += 1;
            continue;
        }

        // Handle regular string content
        if state.in_normal_string {
            result.push(' ');
            if bytes[i] == b'\\' {
                i += 1;
                if i < bytes.len() {
                    result.push(' ');
                    i += 1;
                    continue;
                } else {
                    break;
                }
            }
            if bytes[i] == b'"' {
                state.in_normal_string = false;
            }
            i += 1;
            continue;
        }

        let ch = bytes[i];

        // Start of regular string
        if ch == b'"' {
            state.in_normal_string = true;
            result.push(' ');
            i += 1;
            continue;
        }

        // Check for raw string start
        if ch == b'r' {
            let mut j = i + 1;
            let mut hashes = 0usize;
            while j < bytes.len() && bytes[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                state.raw_hashes = Some(hashes);
                result.push(' ');
                for _ in 0..hashes {
                    result.push(' ');
                }
                result.push(' ');
                i = j + 1;
                continue;
            }
        }

        // Handle character literals vs lifetimes
        if ch == b'\'' {
            // Check if this looks like a lifetime ('a, 'static, etc.)
            if i + 1 < bytes.len() {
                let next = bytes[i + 1];
                let looks_like_lifetime = next == b'_' || next.is_ascii_alphabetic();
                let following = bytes.get(i + 2).copied();
                if looks_like_lifetime && following != Some(b'\'') {
                    // It's a lifetime, preserve it
                    result.push('\'');
                    i += 1;
                    continue;
                }
            }

            // It's a character literal, find the closing quote
            let mut j = i + 1;
            let mut escaped = false;
            let mut found_closing = false;

            while j < bytes.len() {
                let current = bytes[j];
                if escaped {
                    escaped = false;
                } else if current == b'\\' {
                    escaped = true;
                } else if current == b'\'' {
                    found_closing = true;
                    break;
                }

                j += 1;
            }

            if found_closing {
                // Replace entire character literal with spaces
                result.push(' ');
                i += 1;
                while i <= j {
                    result.push(' ');
                    i += 1;
                }
                continue;
            } else {
                // Unclosed, treat as regular quote
                result.push('\'');
                i += 1;
                continue;
            }
        }

        result.push(ch as char);
        i += 1;
    }

    (result, state)
}

/// Strip comments from a line of code.
///
/// Handles both single-line (`//`) and block (`/* */`) comments, tracking
/// multi-line block comment state across calls.
///
/// # Arguments
/// * `line` - The source line to process
/// * `in_block_comment` - Mutable state tracking if we're inside a block comment
///
/// # Returns
/// The line with comment content removed
pub fn strip_comments(line: &str, in_block_comment: &mut bool) -> String {
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

/// Collect lines that match any of the given patterns after sanitizing string literals.
///
/// This is useful for rules that need to find code patterns while ignoring
/// matches that occur inside string literals.
#[allow(dead_code)]
pub fn collect_sanitized_matches(lines: &[String], patterns: &[&str]) -> Vec<String> {
    let mut state = StringLiteralState::default();

    lines
        .iter()
        .filter_map(|line| {
            let (sanitized, next_state) = strip_string_literals(state, line);
            state = next_state;

            if patterns.iter().any(|needle| sanitized.contains(needle)) {
                Some(line.trim().to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Check if a function should be skipped for command injection rules.
///
/// This excludes mir-extractor's own build infrastructure functions that
/// legitimately spawn external processes (rustc, cargo, etc.).
pub fn command_rule_should_skip(function: &crate::MirFunction, package: &crate::MirPackage) -> bool {
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

/// Log sink patterns in MIR (desugarings of print/log macros).
/// Used by both CleartextLoggingRule and LogInjectionRule.
pub const LOG_SINK_PATTERNS: &[&str] = &[
    "_print(",           // println!, print! desugaring
    "eprint",            // eprintln!, eprint!
    "::fmt(",            // format! and Debug/Display impl calls
    "Arguments::new",    // format_args! macro
    "panic_fmt",         // panic! with formatting
    "begin_panic",       // older panic desugaring
    "::log(",            // log crate macros
    "::info(",
    "::warn(",
    "::error(",
    "::debug(",
    "::trace(",
];

/// Input source patterns for untrusted data origins.
/// Used by multiple injection rules.
pub const INPUT_SOURCE_PATTERNS: &[&str] = &[
    "= var::<",       // env::var::<T> - generic call (MIR format)
    "= var(",         // env::var - standard call
    "var_os(",        // env::var_os
    "::args(",        // env::args
    "args_os(",       // env::args_os
    "::nth(",         // iterator nth (often on args)
    "read_line(",     // stdin
    "read_to_string(", // file/stdin reads
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_string_literals_basic() {
        let (sanitized, _) = strip_string_literals(StringLiteralState::default(), r#"let x = "hello";"#);
        assert!(sanitized.contains("let x ="));
        assert!(!sanitized.contains("hello"));
        assert!(sanitized.ends_with(";"));
    }

    #[test]
    fn test_strip_string_literals_preserves_lifetimes() {
        let input = "fn foo<'a>(x: &'a str) -> &'a str";
        let (sanitized, _) = strip_string_literals(StringLiteralState::default(), input);
        assert!(sanitized.contains("'a"));
        assert_eq!(sanitized.matches("'a").count(), 3);
    }

    #[test]
    fn test_strip_string_literals_raw_string() {
        let (sanitized, _) = strip_string_literals(StringLiteralState::default(), r##"let x = r#"raw string"#;"##);
        assert!(sanitized.contains("let x ="));
        assert!(!sanitized.contains("raw string"));
    }

    #[test]
    fn test_strip_string_literals_multiline_state() {
        let (_, state1) = strip_string_literals(StringLiteralState::default(), r#"let x = "start"#);
        assert!(state1.in_normal_string);
        
        let (sanitized, state2) = strip_string_literals(state1, r#"end of string";"#);
        assert!(!state2.in_normal_string);
        assert!(!sanitized.contains("end of string"));
    }

    #[test]
    fn test_strip_char_literal() {
        let (sanitized, _) = strip_string_literals(StringLiteralState::default(), "let c = 'x';");
        assert!(sanitized.contains("let c ="));
        assert!(!sanitized.contains("'x'"));
    }

    #[test]
    fn test_strip_comments_line_comment() {
        let mut in_block = false;
        let result = strip_comments("let x = 1; // comment", &mut in_block);
        assert_eq!(result, "let x = 1; ");
        assert!(!in_block);
    }

    #[test]
    fn test_strip_comments_block_comment() {
        let mut in_block = false;
        let result = strip_comments("let x = /* inline */ 2;", &mut in_block);
        assert_eq!(result, "let x =  2;");
        assert!(!in_block);
    }

    #[test]
    fn test_strip_comments_multiline_block() {
        let mut in_block = false;
        let line1 = strip_comments("let x = /* start", &mut in_block);
        assert_eq!(line1, "let x = ");
        assert!(in_block);
        
        let line2 = strip_comments("still in comment */ done;", &mut in_block);
        assert_eq!(line2, " done;");
        assert!(!in_block);
    }
}
