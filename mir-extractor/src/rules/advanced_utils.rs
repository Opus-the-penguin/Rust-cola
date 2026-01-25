//! Shared utilities for advanced dataflow-based rules.
//!
//! These utilities are used by the migrated rules from mir-advanced-rules
//! for MIR text parsing and taint tracking.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

/// Detect variable assignment in MIR line (e.g., `_1 = ...`)
pub fn detect_assignment(line: &str) -> Option<String> {
    static RE_ASSIGN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(_\d+)\s*=").expect("assign regex"));

    if let Some(caps) = RE_ASSIGN.captures(line) {
        return Some(caps[1].to_string());
    }

    if line.starts_with("(*_") {
        if let Some(end) = line.find(')') {
            return Some(line[2..end].to_string());
        }
    }

    None
}

/// Extract call arguments (move/copy _N) from a MIR line
pub fn extract_call_args(line: &str) -> Vec<String> {
    static RE_ARG: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?:copy|move)\s+(_\d+)").expect("arg regex"));

    RE_ARG
        .captures_iter(line)
        .map(|caps| caps[1].to_string())
        .collect()
}

/// Detect length call pattern (e.g., `_1 = slice::len(move _2)`)
pub fn detect_len_call(line: &str) -> Option<(String, String)> {
    static RE_LEN: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^(_\d+)\s*=.*::len\((?:move|copy)\s+(_\d+)").expect("len regex"));

    RE_LEN
        .captures(line)
        .map(|caps| (caps[1].to_string(), caps[2].to_string()))
}

/// Detect length comparison pattern (e.g., `Gt(move _1, const 100)`)
pub fn detect_len_comparison(line: &str) -> Option<String> {
    static RE_LEN_CMP: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?:Gt|Lt|Ge|Le)\((?:move|copy)\s+(_\d+),\s*const").expect("len cmp regex")
    });

    RE_LEN_CMP.captures(line).map(|caps| caps[1].to_string())
}

/// Check if text contains a variable reference
pub fn contains_var(text: &str, var: &str) -> bool {
    if text.contains(var) {
        return true;
    }

    let var_num = var.trim_start_matches('_');
    text.contains(&format!("move _{}", var_num))
        || text.contains(&format!("copy _{}", var_num))
        || text.contains(&format!("_{}.0", var_num))
        || text.contains(&format!("_{}.1", var_num))
        || text.contains(&format!("&_{}", var_num))
        || text.contains(&format!("(*_{})", var_num))
}

/// Detect constant string assignment (e.g., `_1 = const "pattern"`)
pub fn detect_const_string_assignment(line: &str) -> Option<(String, String)> {
    static RE_CONST_STR: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"^(_\d+)\s*=\s*const\s*\"((?:\\.|[^\"])*)\""#).expect("const string regex")
    });

    RE_CONST_STR.captures(line).map(|caps| {
        let var = caps[1].to_string();
        let literal = caps[2].to_string();
        (var, literal)
    })
}

/// Detect variable alias assignment (e.g., `_1 = copy _2`)
pub fn detect_var_alias(line: &str) -> Option<(String, String)> {
    static RE_ALIAS: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^(_\d+)\s*=\s*(?:copy|move)\s+(_\d+)").expect("alias regex"));

    RE_ALIAS
        .captures(line)
        .map(|caps| (caps[1].to_string(), caps[2].to_string()))
}

/// Detect drop calls
#[allow(dead_code)]
pub fn detect_drop_calls(line: &str) -> Vec<String> {
    static RE_DROP: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"drop\(\s*(?:move\s+)?(_\d+)\s*\)").expect("drop call regex"));

    RE_DROP
        .captures_iter(line)
        .map(|caps| caps[1].to_string())
        .collect()
}

/// Detect StorageDead statements
#[allow(dead_code)]
pub fn detect_storage_dead_vars(line: &str) -> Vec<String> {
    static RE_DEAD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"StorageDead\(\s*(_\d+)\s*\)").expect("storage dead regex"));

    RE_DEAD
        .captures_iter(line)
        .map(|caps| caps[1].to_string())
        .collect()
}

/// Extract constant string literals from a line
pub fn extract_const_literals(line: &str) -> Vec<String> {
    static RE_LITERAL: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"const\s*\"((?:\\.|[^\"])*)\""#).expect("literal regex"));

    RE_LITERAL
        .captures_iter(line)
        .map(|caps| caps[1].to_string())
        .collect()
}

/// Unescape Rust string literal escape sequences
pub fn unescape_rust_literal(raw: &str) -> String {
    let mut result = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                match next {
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    '\\' => result.push('\\'),
                    '"' => result.push('"'),
                    other => {
                        result.push(other);
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }
    result
}

/// Check if a regex pattern is high-risk for catastrophic backtracking
pub fn pattern_is_high_risk(pattern: &str) -> bool {
    static RE_NESTED_QUANTIFIERS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\((?:[^()]|\\.)*[+*](?:[^()]|\\.)*\)[+*{]").expect("nested quantifier regex")
    });

    static RE_DOT_STAR_LOOP: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\(\?:?\.\*(?:[^()]|\\.)*\)[+*{]").expect("dot-star loop regex"));

    let simplified = pattern.replace(' ', "");
    RE_NESTED_QUANTIFIERS.is_match(&simplified) || RE_DOT_STAR_LOOP.is_match(&simplified)
}

/// Common untrusted source patterns
pub const UNTRUSTED_PATTERNS: &[&str] = &[
    "env::var",
    "env::var_os",
    "env::args",
    "std::env::var",
    "std::env::args",
    "stdin",
    "TcpStream",
    "read_to_string",
    "read_to_end",
    "fs::read",
    "File::open",
];

/// Check if a MIR line contains an untrusted source
pub fn is_untrusted_source(line: &str) -> bool {
    UNTRUSTED_PATTERNS
        .iter()
        .any(|pattern| line.contains(pattern))
}

/// Detect derive macro generated functions by name pattern
pub fn is_derive_macro_function(func_name: &str) -> bool {
    static RE_DERIVE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"<impl at [^>]+:\d+:\d+:\s*\d+:\d+>::").expect("derive macro regex")
    });
    RE_DERIVE.is_match(func_name)
}

/// Detect safe trait methods that commonly take references
pub fn is_safe_trait_method(func_name: &str, _func_signature: &str) -> bool {
    let safe_methods = [
        "::eq",
        "::ne",
        "::partial_cmp",
        "::cmp",
        "::hash",
        "::fmt",
        "::clone",
        "::default",
        "::drop",
    ];
    safe_methods.iter().any(|m| func_name.ends_with(m))
}

/// Simple taint tracker for dataflow analysis
#[derive(Default)]
pub struct TaintTracker {
    pub tainted: HashSet<String>,
    pub taint_roots: std::collections::HashMap<String, String>,
    pub sanitized_roots: HashSet<String>,
    pub sources: std::collections::HashMap<String, String>,
}

impl TaintTracker {
    pub fn mark_source(&mut self, var: &str, origin: &str) {
        let var = var.to_string();
        self.tainted.insert(var.clone());
        self.taint_roots.insert(var.clone(), var.clone());
        self.sources
            .entry(var)
            .or_insert_with(|| origin.trim().to_string());
    }

    pub fn mark_alias(&mut self, dest: &str, source: &str) {
        if !self.tainted.contains(source) {
            return;
        }

        if let Some(root) = self.taint_roots.get(source).cloned() {
            self.tainted.insert(dest.to_string());
            self.taint_roots.insert(dest.to_string(), root);
        }
    }

    pub fn find_tainted_in_line(&self, line: &str) -> Option<String> {
        self.tainted
            .iter()
            .find(|var| contains_var(line, var))
            .cloned()
    }

    pub fn is_sanitized(&self, var: &str) -> bool {
        if let Some(root) = self.taint_roots.get(var) {
            self.sanitized_roots.contains(root)
        } else {
            false
        }
    }

    pub fn sanitize_root(&mut self, root: &str) {
        self.sanitized_roots.insert(root.to_string());
    }
}
