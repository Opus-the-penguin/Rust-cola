//! Input validation rules.
//!
//! Rules detecting input validation issues:
//! - Environment variable handling (RUSTCOLA065, RUSTCOLA047)
//! - Untrimmed stdin input (RUSTCOLA053)
//! - Invisible Unicode detection (RUSTCOLA048)
//! - Infinite iterators (RUSTCOLA054)
//! - Unsafe deserialization (RUSTCOLA089, RUSTCOLA091)
//! - Unbounded reads (RUSTCOLA090)
//! - Division by untrusted input (RUSTCOLA077)
//! - Unchecked timestamp multiplication (RUSTCOLA106)

#![allow(dead_code)]

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

use crate::{Confidence, Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};
use super::utils::filter_entry;

// Shared input source patterns used by multiple rules
const INPUT_SOURCE_PATTERNS: &[&str] = &[
    "= var::<",       // env::var::<T> - generic call (MIR format)
    "= var(",         // env::var - standard call
    "var_os(",        // env::var_os
    "::args(",        // env::args
    "args_os(",       // env::args_os
    "::nth(",         // iterator nth (often on args)
    "read_line(",     // stdin
    "read_to_string(", // file/stdin reads
];

// ============================================================================
// RUSTCOLA065: Cleartext Sensitive Data in Environment Variables
// ============================================================================

/// Detects sensitive data (passwords, secrets, keys) stored via env::set_var.
/// Environment variables can be read by child processes and are often logged.
pub struct CleartextEnvVarRule {
    metadata: RuleMetadata,
}

impl CleartextEnvVarRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA065".to_string(),
                name: "cleartext-env-var".to_string(),
                short_description: "Sensitive data in environment variable".to_string(),
                full_description: "Detects sensitive data (passwords, secrets, tokens, keys) \
                    being stored in environment variables via std::env::set_var. Environment \
                    variables can be read by child processes, logged, and are often visible \
                    in /proc filesystem on Linux. Consider using dedicated secret management \
                    solutions instead.".to_string(),
                help_uri: Some("https://cwe.mitre.org/data/definitions/526.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    const SENSITIVE_PATTERNS: &'static [&'static str] = &[
        "password", "passwd", "pwd",
        "secret", "token", "apikey", "api_key",
        "auth", "credential", "cred",
        "private_key", "privatekey",
        "access_key", "secret_key",
    ];

    fn looks_like_sensitive_env_set(&self, function: &MirFunction) -> bool {
        for line in &function.body {
            // Look for set_var calls
            if line.contains("set_var") {
                // Check if the variable name contains sensitive patterns
                let line_lower = line.to_lowercase();
                for pattern in Self::SENSITIVE_PATTERNS {
                    if line_lower.contains(pattern) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

impl Rule for CleartextEnvVarRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.looks_like_sensitive_env_set(function) {
                let mut evidence = Vec::new();
                for line in &function.body {
                    if line.contains("set_var") {
                        evidence.push(line.trim().to_string());
                        if evidence.len() >= 3 {
                            break;
                        }
                    }
                }

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Sensitive data stored in environment variable in `{}`. \
                        Environment variables are inherited by child processes and \
                        may be logged. Use dedicated secret management instead.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence,
                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA047: Environment Variable Literal Names
// ============================================================================

/// Detects string literals passed to env::var() - potential config leakage.
pub struct EnvVarLiteralRule {
    metadata: RuleMetadata,
}

impl EnvVarLiteralRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA047".to_string(),
                name: "env-var-literal".to_string(),
                short_description: "Hardcoded environment variable name".to_string(),
                full_description: "Detects string literals passed directly to std::env::var(). \
                    Hardcoded environment variable names can leak configuration expectations \
                    and make it harder to configure applications in different environments. \
                    Consider using constants or configuration structs.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    fn has_env_var_literal(&self, function: &MirFunction) -> bool {
        let body_str = function.body.join("\n");
        
        // Look for env::var with a const string argument
        // MIR shows: var::<&str>(const "VAR_NAME")
        body_str.contains("env::var") && body_str.contains("const \"")
    }
}

impl Rule for EnvVarLiteralRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.has_env_var_literal(function) {
                let mut evidence = Vec::new();
                for line in &function.body {
                    if (line.contains("env::var") || line.contains("var::<"))
                        && line.contains("const \"")
                    {
                        evidence.push(line.trim().to_string());
                        if evidence.len() >= 3 {
                            break;
                        }
                    }
                }

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: "Hardcoded environment variable name detected. Consider using \
                        constants or configuration structs for better maintainability."
                        .to_string(),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence,
                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA048: Invisible Unicode Characters
// ============================================================================

/// Detects invisible Unicode characters in source code.
pub struct InvisibleUnicodeRule {
    metadata: RuleMetadata,
}

impl InvisibleUnicodeRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA048".to_string(),
                name: "invisible-unicode".to_string(),
                short_description: "Invisible Unicode characters in source".to_string(),
                full_description: "Detects invisible Unicode characters in source code. \
                    These can be used to create Trojan Source attacks where code appears \
                    benign but executes differently. Includes zero-width characters, \
                    bidirectional overrides, and other invisible control characters."
                    .to_string(),
                help_uri: Some("https://trojansource.codes/".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    const INVISIBLE_CHARS: &'static [char] = &[
        '\u{200B}', // Zero-width space
        '\u{200C}', // Zero-width non-joiner
        '\u{200D}', // Zero-width joiner
        '\u{FEFF}', // Byte order mark
        '\u{2060}', // Word joiner
        '\u{202A}', // Left-to-right embedding
        '\u{202B}', // Right-to-left embedding
        '\u{202C}', // Pop directional formatting
        '\u{202D}', // Left-to-right override
        '\u{202E}', // Right-to-left override
        '\u{2066}', // Left-to-right isolate
        '\u{2067}', // Right-to-left isolate
        '\u{2068}', // First strong isolate
        '\u{2069}', // Pop directional isolate
    ];

    fn has_invisible_chars(&self, function: &MirFunction) -> bool {
        let body_str = function.body.join("\n");
        for &c in Self::INVISIBLE_CHARS {
            if body_str.contains(c) {
                return true;
            }
        }
        false
    }
}

impl Rule for InvisibleUnicodeRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.has_invisible_chars(function) {
                let mut evidence = Vec::new();
                for line in &function.body {
                    let has_invisible = Self::INVISIBLE_CHARS.iter().any(|&c| line.contains(c));
                    if has_invisible {
                        evidence.push(line.trim().to_string());
                        if evidence.len() >= 3 {
                            break;
                        }
                    }
                }

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Invisible Unicode characters detected in `{}`. These may be \
                        Trojan Source attacks where code appears benign but executes \
                        differently. Remove or replace with visible equivalents.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence,
                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA053: Untrimmed Stdin Input
// ============================================================================

/// Detects stdin input used without trimming trailing newlines.
pub struct UntrimmedStdinRule {
    metadata: RuleMetadata,
}

impl UntrimmedStdinRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA053".to_string(),
                name: "untrimmed-stdin".to_string(),
                short_description: "Stdin input not trimmed".to_string(),
                full_description: "Detects stdin().read_line() usage without subsequent \
                    trim() call. read_line() includes the trailing newline which can cause \
                    subtle bugs in file paths, passwords, or comparisons. Always call \
                    .trim() or .trim_end() on stdin input.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    fn has_untrimmed_stdin(&self, function: &MirFunction) -> bool {
        let body_str = function.body.join("\n");
        
        // Check for stdin read_line
        let has_read_line = body_str.contains("stdin")
            && (body_str.contains("read_line") || body_str.contains("BufRead"));
        
        if !has_read_line {
            return false;
        }
        
        // Check for trim calls
        let has_trim = body_str.contains("trim") || body_str.contains("trim_end");
        
        !has_trim
    }
}

impl Rule for UntrimmedStdinRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.has_untrimmed_stdin(function) {
                let mut evidence = Vec::new();
                for line in &function.body {
                    if line.contains("stdin") || line.contains("read_line") {
                        evidence.push(line.trim().to_string());
                        if evidence.len() >= 3 {
                            break;
                        }
                    }
                }

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: "Stdin read_line() without trim(). The trailing newline can \
                        cause bugs in paths, passwords, or comparisons. Call .trim() on input."
                        .to_string(),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence,
                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA054: Infinite Iterator Detection
// ============================================================================

/// Detects infinite iterators (repeat, cycle, repeat_with) without termination.
pub struct InfiniteIteratorRule {
    metadata: RuleMetadata,
}

impl InfiniteIteratorRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA054".to_string(),
                name: "infinite-iterator".to_string(),
                short_description: "Infinite iterator without termination".to_string(),
                full_description: "Detects infinite iterators (std::iter::repeat, cycle, \
                    repeat_with) without termination methods (take, take_while, any, find, \
                    position, zip). Consuming an infinite iterator without bounds leads to \
                    infinite loops or memory exhaustion.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    fn looks_like_infinite_iterator(&self, function: &MirFunction) -> bool {
        let body_str = function.body.join("\n");
        
        // Skip if function name contains "mir_extractor" or is infrastructure
        if function.name.contains("mir_extractor") || function.name.contains("mir-extractor") {
            return false;
        }
        
        // Skip functions that are just defining string constants
        if function.name.contains("::new") 
            || body_str.contains("const \"iter::repeat")
            || body_str.contains("const \"std::iter::repeat") {
            return false;
        }
        
        // Check for infinite iterator constructors
        let has_repeat = body_str.contains("std::iter::repeat")
            || body_str.contains("core::iter::repeat")
            || body_str.contains("Repeat<");
        let has_cycle = body_str.contains("::cycle") || body_str.contains("Cycle<");
        let has_repeat_with = body_str.contains("std::iter::repeat_with")
            || body_str.contains("core::iter::repeat_with")
            || body_str.contains("repeat_with::<")
            || body_str.contains("RepeatWith<");
        
        if !has_repeat && !has_cycle && !has_repeat_with {
            return false;
        }
        
        // Check if there are termination methods
        let has_take = body_str.contains("::take(") || body_str.contains(">::take::<");
        let has_take_while = body_str.contains("::take_while") || body_str.contains(">::take_while::<");
        let has_any = body_str.contains("::any(") || body_str.contains(">::any::<");
        let has_find = body_str.contains("::find(") || body_str.contains(">::find::<");
        let has_position = body_str.contains("::position") || body_str.contains(">::position::<");
        let has_zip = body_str.contains("::zip");
        let has_nth = body_str.contains("::nth(") || body_str.contains(">::nth::<");
        
        // Check for early return (break in loop)
        let return_count = body_str.matches("return;").count();
        let has_early_return = return_count > 1;
        
        // Flag if we have infinite iterator but no termination
        !has_take && !has_take_while && !has_any && !has_find && !has_position 
            && !has_zip && !has_nth && !has_early_return
    }
}

impl Rule for InfiniteIteratorRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.looks_like_infinite_iterator(function) {
                let mut evidence = Vec::new();
                for line in &function.body {
                    if line.contains("std::iter::repeat") 
                        || line.contains("core::iter::repeat")
                        || line.contains("::cycle")
                        || line.contains("repeat_with") {
                        evidence.push(line.trim().to_string());
                        if evidence.len() >= 3 {
                            break;
                        }
                    }
                }
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: "Infinite iterator (repeat, cycle, or repeat_with) without \
                        termination method (take, take_while, any, find, position, zip). \
                        This can cause unbounded loops leading to DoS.".to_string(),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence,
                    span: None,
                    ..Default::default()
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA077: Division by Untrusted Input
// ============================================================================

/// Detects division operations using untrusted input as denominator without validation.
pub struct DivisionByUntrustedRule {
    metadata: RuleMetadata,
}

impl DivisionByUntrustedRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA077".to_string(),
                name: "division-by-untrusted".to_string(),
                short_description: "Division by untrusted input without validation".to_string(),
                full_description: "Division or modulo operations use untrusted input as \
                    the denominator without checking for zero. If the input is zero, this \
                    causes a panic (DoS). Use checked_div/checked_rem or validate the \
                    denominator before the operation.".to_string(),
                help_uri: Some("https://cwe.mitre.org/data/definitions/369.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    const DIVISION_PATTERNS: &'static [&'static str] = &[
        "Div(", "Rem(",  // MIR binary ops
        "div(", "rem(",  // Method calls
        " / ", " % ",    // Source patterns
    ];

    const ZERO_CHECK_PATTERNS: &'static [&'static str] = &[
        "checked_div", "checked_rem",
        "saturating_div", "wrapping_div",
        "!= 0", "!= 0_", "> 0", ">= 1",
        "is_zero", "NonZero",
    ];

    /// Track untrusted numeric variables
    fn track_untrusted_numerics(body: &[String]) -> HashSet<String> {
        let mut untrusted_vars = HashSet::new();
        
        for line in body {
            let trimmed = line.trim();
            
            let is_source = INPUT_SOURCE_PATTERNS.iter().any(|p| trimmed.contains(p));
            if is_source {
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    if let Some(var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        untrusted_vars.insert(var.to_string());
                    }
                }
            }
            
            // Track .parse() results from untrusted data
            if trimmed.contains("::parse::") {
                let uses_untrusted = untrusted_vars.iter().any(|v| trimmed.contains(v));
                if uses_untrusted {
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let target = trimmed[..eq_pos].trim();
                        if let Some(var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                            .find(|s| s.starts_with('_'))
                        {
                            untrusted_vars.insert(var.to_string());
                        }
                    }
                }
            }
            
            // Propagate through assignments
            if trimmed.contains(" = ") && !is_source {
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    let source = trimmed[eq_pos + 3..].trim();
                    
                    let uses_untrusted = untrusted_vars.iter().any(|v| source.contains(v));
                    if uses_untrusted {
                        if let Some(target_var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                            .find(|s| s.starts_with('_'))
                        {
                            untrusted_vars.insert(target_var.to_string());
                        }
                    }
                }
            }
        }
        
        untrusted_vars
    }

    fn has_zero_validation(body: &[String], untrusted_vars: &HashSet<String>) -> bool {
        for line in body {
            let trimmed = line.trim();
            let has_check = Self::ZERO_CHECK_PATTERNS.iter().any(|p| trimmed.contains(p));
            if has_check {
                for var in untrusted_vars {
                    if trimmed.contains(var) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn find_unsafe_divisions(body: &[String], untrusted_vars: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        
        for line in body {
            let trimmed = line.trim();
            let is_division = Self::DIVISION_PATTERNS.iter().any(|p| trimmed.contains(p));
            if is_division {
                for var in untrusted_vars {
                    if trimmed.contains(var) {
                        evidence.push(trimmed.to_string());
                        break;
                    }
                }
            }
        }
        
        evidence
    }
}

impl Rule for DivisionByUntrustedRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("mir_extractor") || function.name.contains("mir-extractor") {
                continue;
            }

            let untrusted_vars = Self::track_untrusted_numerics(&function.body);
            if untrusted_vars.is_empty() {
                continue;
            }

            if Self::has_zero_validation(&function.body, &untrusted_vars) {
                continue;
            }

            let unsafe_divs = Self::find_unsafe_divisions(&function.body, &untrusted_vars);
            if !unsafe_divs.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Division in `{}` uses untrusted input as denominator without \
                        zero validation. Use checked_div/checked_rem or validate != 0.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: unsafe_divs.into_iter().take(3).collect(),
                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA089: Insecure YAML Deserialization
// ============================================================================

/// Detects untrusted input passed to YAML deserialization functions.
pub struct InsecureYamlDeserializationRule {
    metadata: RuleMetadata,
}

impl InsecureYamlDeserializationRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA089".to_string(),
                name: "insecure-yaml-deserialization".to_string(),
                short_description: "Untrusted input in YAML deserialization".to_string(),
                full_description: "User-controlled input is passed to serde_yaml \
                    deserialization functions without validation. Attackers can craft \
                    malicious YAML using anchors/aliases for exponential expansion \
                    (billion laughs), deeply nested structures, or unexpected type \
                    coercion to cause denial of service or unexpected behavior.".to_string(),
                help_uri: Some("https://owasp.org/www-project-web-security-testing-guide/".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    const YAML_SINKS: &'static [&'static str] = &[
        "serde_yaml::from_str", "serde_yaml::from_slice", "serde_yaml::from_reader",
        "serde_yaml::from_str::", "serde_yaml::from_slice::", "serde_yaml::from_reader::",
    ];

    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        "env::var", "env::var_os", "std::env::var", "var::<", "var_os::<",
        "env::args", "std::env::args", "args::<", "= args()", "Args>",
        "stdin", "Stdin",
        "read_to_string", "read_to_end", "BufRead::read_line",
        "TcpStream", "::connect(",
    ];

    const SANITIZERS: &'static [&'static str] = &[
        r#"contains("&")"#, r#"contains("*")"#,
        ".len()", "len() >", "len() <",
        "serde_json::from_str",  // JSON is safer alternative
        "validate", "sanitize", "allowlist",
    ];

    fn track_untrusted_vars(&self, function: &MirFunction) -> HashSet<String> {
        let mut tainted: HashSet<String> = HashSet::new();
        
        for line in &function.body {
            for source in Self::UNTRUSTED_SOURCES {
                if line.contains(source) {
                    if let Some(var) = self.extract_assigned_var(line) {
                        tainted.insert(var);
                    }
                }
            }
            
            // Taint propagation
            if line.contains(" = ") {
                if let Some((dest, src_part)) = line.split_once(" = ") {
                    let dest_var = dest.trim().to_string();
                    for tvar in tainted.clone() {
                        if self.contains_var(src_part, &tvar) {
                            tainted.insert(dest_var.clone());
                            break;
                        }
                    }
                }
            }
        }
        
        tainted
    }

    fn extract_assigned_var(&self, line: &str) -> Option<String> {
        let line = line.trim();
        if let Some(eq_pos) = line.find(" = ") {
            let lhs = line[..eq_pos].trim();
            if lhs.starts_with('_') && lhs.chars().skip(1).all(|c| c.is_ascii_digit()) {
                return Some(lhs.to_string());
            }
            if lhs.starts_with("(*_") {
                if let Some(end) = lhs.find(')') {
                    return Some(lhs[2..end].to_string());
                }
            }
        }
        None
    }

    fn contains_var(&self, text: &str, var: &str) -> bool {
        if text.contains(var) {
            return true;
        }
        let var_num = var.trim_start_matches('_');
        text.contains(&format!("move _{}", var_num))
            || text.contains(&format!("copy _{}", var_num))
            || text.contains(&format!("&_{}", var_num))
            || text.contains(&format!("(*_{})", var_num))
    }

    fn find_unsafe_yaml_operations(&self, function: &MirFunction, tainted: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        
        // Check for sanitization
        for line in &function.body {
            for sanitizer in Self::SANITIZERS {
                if line.contains(sanitizer) {
                    return evidence;  // Has sanitization, no finding
                }
            }
        }
        
        // Look for YAML sinks with tainted arguments
        for line in &function.body {
            for sink in Self::YAML_SINKS {
                if line.contains(sink) {
                    for tvar in tainted {
                        if self.contains_var(line, tvar) {
                            evidence.push(line.trim().to_string());
                            break;
                        }
                    }
                }
            }
        }
        
        evidence
    }
}

impl Rule for InsecureYamlDeserializationRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("test") {
                continue;
            }
            
            let tainted = self.track_untrusted_vars(function);
            if tainted.is_empty() {
                continue;
            }
            
            let unsafe_ops = self.find_unsafe_yaml_operations(function, &tainted);
            if !unsafe_ops.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: Severity::Medium,
                    message: format!(
                        "Insecure YAML deserialization in `{}`. User-controlled input \
                        passed to serde_yaml without validation. Malicious YAML can use \
                        anchors/aliases for billion laughs attacks.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: unsafe_ops.into_iter().take(3).collect(),
                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                });
            }
        }

        // Inter-procedural analysis (use shared analysis if available)
        if let Some(analysis) = inter_analysis {
            let flows = analysis.detect_inter_procedural_flows(package);
            let mut reported_functions: HashSet<String> = findings
                .iter().map(|f| f.function.clone()).collect();
            
            for flow in flows {
                if flow.sink_type != "yaml" {
                    continue;
                }
                if flow.sink_function.contains("mir_extractor") || flow.sanitized {
                    continue;
                }
                if reported_functions.contains(&flow.sink_function) {
                    continue;
                }
                
                let sink_func = package.functions.iter().find(|f| f.name == flow.sink_function);
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: Severity::Medium,
                    message: format!(
                        "Inter-procedural YAML injection: untrusted input from `{}` \
                        flows to YAML deserialization in `{}`.",
                        flow.source_function, flow.sink_function
                    ),
                    function: flow.sink_function.clone(),
                    function_signature: sink_func.map(|f| f.signature.clone()).unwrap_or_default(),
                    evidence: vec![flow.describe()],
                    span: sink_func.map(|f| f.span.clone()).unwrap_or_default(),
                    ..Default::default()
                });
                reported_functions.insert(flow.sink_function);
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA090: Unbounded Read Operations
// ============================================================================

/// Detects read_to_end/read_to_string on untrusted sources without size limits.
pub struct UnboundedReadRule {
    metadata: RuleMetadata,
}

impl UnboundedReadRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA090".to_string(),
                name: "unbounded-read-to-end".to_string(),
                short_description: "Unbounded read on untrusted source".to_string(),
                full_description: "read_to_end() or read_to_string() is called on an \
                    untrusted source (network stream, stdin, user-controlled file) without \
                    size limits. Attackers can send arbitrarily large payloads to exhaust \
                    server memory. Use .take(max_size) to limit bytes read.".to_string(),
                help_uri: Some("https://cwe.mitre.org/data/definitions/400.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        "TcpStream::connect", "TcpListener::accept", "UnixStream::connect",
        "::connect(", "::accept(", "<TcpStream", "<UnixStream",
        "io::stdin", "stdin()", "Stdin",
        "env::var", "env::args", "var::<", "args::<", "Args>",
        "File::open",
    ];

    const UNBOUNDED_SINKS: &'static [&'static str] = &[
        "read_to_end", "read_to_string",
        "Read>::read_to_end", "Read>::read_to_string",
    ];

    const SAFE_PATTERNS: &'static [&'static str] = &[
        ".take(", "take(", "metadata(", ".len()", "MAX_SIZE", "max_size", "limit", "chunk",
    ];

    fn has_untrusted_source(&self, function: &MirFunction) -> bool {
        for line in &function.body {
            for source in Self::UNTRUSTED_SOURCES {
                if line.contains(source) {
                    return true;
                }
            }
        }
        false
    }

    fn has_safe_limit(&self, function: &MirFunction) -> bool {
        for line in &function.body {
            for pattern in Self::SAFE_PATTERNS {
                if line.to_lowercase().contains(&pattern.to_lowercase()) {
                    return true;
                }
            }
        }
        false
    }

    fn find_unbounded_reads(&self, function: &MirFunction) -> Vec<String> {
        let mut evidence = Vec::new();
        for line in &function.body {
            for sink in Self::UNBOUNDED_SINKS {
                if line.contains(sink) {
                    evidence.push(line.trim().to_string());
                }
            }
        }
        evidence
    }
}

impl Rule for UnboundedReadRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("test") {
                continue;
            }
            if !self.has_untrusted_source(function) {
                continue;
            }
            if self.has_safe_limit(function) {
                continue;
            }
            
            let unbounded_reads = self.find_unbounded_reads(function);
            if !unbounded_reads.is_empty() {
                let body_str = function.body.join("\n");
                let severity = if body_str.contains("TcpStream") || body_str.contains("UnixStream") {
                    Severity::High
                } else {
                    Severity::Medium
                };
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity,
                    message: format!(
                        "Unbounded read in `{}`. read_to_end()/read_to_string() without \
                        size limits. Use .take(max_bytes) to limit the read size.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: unbounded_reads.into_iter().take(3).collect(),
                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA091: Insecure JSON/TOML Deserialization
// ============================================================================

/// Detects untrusted input passed to JSON/TOML deserialization functions.
pub struct InsecureJsonTomlDeserializationRule {
    metadata: RuleMetadata,
}

impl InsecureJsonTomlDeserializationRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA091".to_string(),
                name: "insecure-json-toml-deserialization".to_string(),
                short_description: "Untrusted input in JSON/TOML deserialization".to_string(),
                full_description: "User-controlled input is passed to serde_json or toml \
                    deserialization functions without validation. Attackers can craft \
                    deeply nested structures to cause stack overflow, or very large \
                    payloads to cause memory exhaustion.".to_string(),
                help_uri: Some("https://owasp.org/www-project-web-security-testing-guide/".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    const SINKS: &'static [&'static str] = &[
        "serde_json::from_str", "serde_json::from_slice", "serde_json::from_reader",
        "serde_json::from_str::", "serde_json::from_slice::", "serde_json::from_reader::",
        "toml::from_str", "toml::de::from_str",
    ];

    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        "env::var", "env::var_os", "std::env::var", "var::<", "var_os::<",
        "env::args", "std::env::args", "args::<", "= args()", "Args>",
        "stdin", "Stdin",
        "read_to_string", "read_to_end", "File::open",
        "TcpStream", "::connect(",
    ];

    fn track_untrusted_vars(&self, function: &MirFunction) -> HashSet<String> {
        let mut tainted: HashSet<String> = HashSet::new();
        
        for line in &function.body {
            for source in Self::UNTRUSTED_SOURCES {
                if line.contains(source) {
                    if let Some(var) = self.extract_assigned_var(line) {
                        tainted.insert(var);
                    }
                }
            }
            
            if line.contains(" = ") {
                if let Some((dest, src_part)) = line.split_once(" = ") {
                    let dest_var = dest.trim().to_string();
                    for tvar in tainted.clone() {
                        if self.contains_var(src_part, &tvar) {
                            tainted.insert(dest_var.clone());
                            break;
                        }
                    }
                }
            }
        }
        
        tainted
    }

    fn extract_assigned_var(&self, line: &str) -> Option<String> {
        let line = line.trim();
        if let Some(eq_pos) = line.find(" = ") {
            let lhs = line[..eq_pos].trim();
            if lhs.starts_with('_') && lhs.chars().skip(1).all(|c| c.is_ascii_digit()) {
                return Some(lhs.to_string());
            }
        }
        None
    }

    fn contains_var(&self, text: &str, var: &str) -> bool {
        if text.contains(var) {
            return true;
        }
        let var_num = var.trim_start_matches('_');
        text.contains(&format!("move _{}", var_num))
            || text.contains(&format!("copy _{}", var_num))
    }

    fn has_size_limit_check(&self, function: &MirFunction, tainted: &HashSet<String>) -> bool {
        let mut len_result_vars: HashSet<String> = HashSet::new();
        
        for line in &function.body {
            let is_string_len = (line.contains("String::len(") || line.contains("str::len("))
                && !line.contains("Vec<");
                
            if is_string_len {
                for tvar in tainted {
                    if self.contains_var(line, tvar) {
                        if let Some(var) = self.extract_assigned_var(line) {
                            len_result_vars.insert(var);
                        }
                    }
                }
            }
            
            if line.contains("Gt(") || line.contains("Lt(") || line.contains("Ge(") || line.contains("Le(") {
                for len_var in &len_result_vars {
                    if self.contains_var(line, len_var) {
                        return true;
                    }
                }
            }
        }
        
        false
    }

    fn find_unsafe_operations(&self, function: &MirFunction, tainted: &HashSet<String>) -> Vec<String> {
        let mut unsafe_ops = Vec::new();
        
        if self.has_size_limit_check(function, tainted) {
            return unsafe_ops;
        }
        
        for line in &function.body {
            let is_sink = Self::SINKS.iter().any(|sink| line.contains(sink));
            if !is_sink {
                continue;
            }
            
            let taint_flows = tainted.iter().any(|t| self.contains_var(line, t));
            if taint_flows {
                unsafe_ops.push(line.trim().to_string());
            }
        }
        
        unsafe_ops
    }
}

impl Rule for InsecureJsonTomlDeserializationRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("test") {
                continue;
            }
            
            let tainted = self.track_untrusted_vars(function);
            if tainted.is_empty() {
                continue;
            }
            
            let unsafe_ops = self.find_unsafe_operations(function, &tainted);
            if !unsafe_ops.is_empty() {
                let is_toml = unsafe_ops.iter().any(|op| op.contains("toml::"));
                let format_name = if is_toml { "TOML" } else { "JSON" };
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: Severity::Medium,
                    message: format!(
                        "Insecure {} deserialization in `{}`. User-controlled input \
                        passed without validation. Deeply nested structures can cause \
                        stack overflow.",
                        format_name, function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: unsafe_ops.into_iter().take(3).collect(),
                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA081: Serde serialize_* length mismatch
// ============================================================================

/// Detects when the declared length argument to serialize_struct/serialize_tuple/etc
/// doesn't match the actual number of serialize_field/serialize_element calls.
pub struct SerdeLengthMismatchRule {
    metadata: RuleMetadata,
}

impl SerdeLengthMismatchRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA081".to_string(),
                name: "serde-length-mismatch".to_string(),
                short_description: "Serde serialize_* length mismatch".to_string(),
                full_description: "Detects when the declared field/element count in \
                    serialize_struct/serialize_tuple/etc doesn't match the actual number \
                    of serialize_field/serialize_element calls. This mismatch can cause \
                    deserialization failures, data corruption, or panics in binary formats \
                    like bincode, postcard, or MessagePack that rely on precise length hints."
                    .to_string(),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                help_uri: None,
            },
        }
    }

    fn find_serializer_declarations(body: &[String]) -> Vec<(String, String, usize, String)> {
        let mut declarations = Vec::new();
        
        let mut var_values: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for line in body {
            let trimmed = line.trim();
            if trimmed.contains("Option::<usize>::Some(const ") {
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let var_name = trimmed[..eq_pos].trim().to_string();
                    if let Some(start) = trimmed.find("Some(const ") {
                        let after = &trimmed[start + 11..];
                        if let Some(end) = after.find("_usize") {
                            if let Ok(val) = after[..end].trim().parse::<usize>() {
                                var_values.insert(var_name, val);
                            }
                        }
                    }
                }
            }
        }
        
        for line in body {
            let trimmed = line.trim();
            
            if trimmed.contains("serialize_struct(") && !trimmed.contains("serialize_struct_variant") {
                if let Some(decl) = Self::extract_struct_declaration(trimmed) {
                    declarations.push(("struct".to_string(), decl.0, decl.1, trimmed.to_string()));
                }
            }
            
            if trimmed.contains("serialize_tuple(") && !trimmed.contains("serialize_tuple_struct") && !trimmed.contains("serialize_tuple_variant") {
                if let Some(len) = Self::extract_tuple_length(trimmed) {
                    declarations.push(("tuple".to_string(), "".to_string(), len, trimmed.to_string()));
                }
            }
            
            if trimmed.contains("serialize_tuple_struct(") {
                if let Some(decl) = Self::extract_struct_declaration(trimmed) {
                    declarations.push(("tuple_struct".to_string(), decl.0, decl.1, trimmed.to_string()));
                }
            }
            
            if trimmed.contains("serialize_seq(") {
                if let Some(len) = Self::extract_seq_length(trimmed) {
                    declarations.push(("seq".to_string(), "".to_string(), len, trimmed.to_string()));
                } else if let Some(len) = Self::extract_seq_length_from_var(trimmed, &var_values) {
                    declarations.push(("seq".to_string(), "".to_string(), len, trimmed.to_string()));
                }
            }
            
            if trimmed.contains("serialize_map(") {
                if let Some(len) = Self::extract_map_length(trimmed) {
                    declarations.push(("map".to_string(), "".to_string(), len, trimmed.to_string()));
                } else if let Some(len) = Self::extract_map_length_from_var(trimmed, &var_values) {
                    declarations.push(("map".to_string(), "".to_string(), len, trimmed.to_string()));
                }
            }
        }
        
        declarations
    }

    fn extract_struct_declaration(line: &str) -> Option<(String, usize)> {
        let name_start = line.find("const \"")? + 7;
        let name_end = line[name_start..].find("\"")? + name_start;
        let name = line[name_start..name_end].to_string();
        
        let after_name = &line[name_end..];
        if let Some(const_pos) = after_name.find("const ") {
            let len_start = const_pos + 6;
            let len_str = &after_name[len_start..];
            if let Some(usize_pos) = len_str.find("_usize") {
                let num_str = &len_str[..usize_pos];
                if let Ok(len) = num_str.trim().parse::<usize>() {
                    return Some((name, len));
                }
            }
        }
        
        None
    }

    fn extract_tuple_length(line: &str) -> Option<usize> {
        if let Some(const_pos) = line.rfind("const ") {
            let after_const = &line[const_pos + 6..];
            if let Some(usize_pos) = after_const.find("_usize") {
                let num_str = &after_const[..usize_pos];
                if let Ok(len) = num_str.trim().parse::<usize>() {
                    return Some(len);
                }
            }
        }
        None
    }

    fn extract_seq_length(line: &str) -> Option<usize> {
        if line.contains("Option::<usize>::None") || line.contains("None::<usize>") {
            return None;
        }
        
        if let Some(const_pos) = line.rfind("const ") {
            let after_const = &line[const_pos + 6..];
            if let Some(usize_pos) = after_const.find("_usize") {
                let num_str = &after_const[..usize_pos];
                if let Ok(len) = num_str.trim().parse::<usize>() {
                    return Some(len);
                }
            }
        }
        
        None
    }

    fn extract_map_length(line: &str) -> Option<usize> {
        Self::extract_seq_length(line)
    }

    fn extract_seq_length_from_var(line: &str, var_values: &std::collections::HashMap<String, usize>) -> Option<usize> {
        if let Some(paren_start) = line.find("serialize_seq(") {
            let after = &line[paren_start..];
            for (var, val) in var_values {
                if after.contains(&format!("move {}", var)) || after.contains(&format!(", {})", var)) {
                    return Some(*val);
                }
            }
        }
        None
    }

    fn extract_map_length_from_var(line: &str, var_values: &std::collections::HashMap<String, usize>) -> Option<usize> {
        if let Some(paren_start) = line.find("serialize_map(") {
            let after = &line[paren_start..];
            for (var, val) in var_values {
                if after.contains(&format!("move {}", var)) || after.contains(&format!(", {})", var)) {
                    return Some(*val);
                }
            }
        }
        None
    }

    fn count_serialize_fields(body: &[String]) -> usize {
        body.iter()
            .filter(|line| {
                let trimmed = line.trim();
                trimmed.contains("SerializeStruct>::serialize_field") ||
                trimmed.contains("SerializeStructVariant>::serialize_field")
            })
            .count()
    }

    fn count_serialize_elements(body: &[String]) -> usize {
        body.iter()
            .filter(|line| {
                let trimmed = line.trim();
                trimmed.contains("SerializeTuple>::serialize_element") ||
                trimmed.contains("SerializeTupleStruct>::serialize_field")
            })
            .count()
    }

    fn count_seq_elements(body: &[String]) -> usize {
        body.iter()
            .filter(|line| {
                let trimmed = line.trim();
                trimmed.contains("SerializeSeq>::serialize_element")
            })
            .count()
    }

    fn count_map_entries(body: &[String]) -> usize {
        body.iter()
            .filter(|line| {
                let trimmed = line.trim();
                trimmed.contains("SerializeMap>::serialize_entry") ||
                trimmed.contains("SerializeMap>::serialize_key")
            })
            .count()
    }

    fn has_loop_serialization(body: &[String]) -> bool {
        let body_str = body.join("\n");
        
        body_str.contains("switchInt") && 
        (body_str.contains("IntoIterator") || 
         body_str.contains("Iterator>::next") ||
         body_str.contains("Range"))
    }
}

impl Rule for SerdeLengthMismatchRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if !function.name.contains("serialize") && !function.signature.contains("Serialize") {
                continue;
            }

            let declarations = Self::find_serializer_declarations(&function.body);
            
            if declarations.is_empty() {
                continue;
            }

            for (ser_type, name, declared_len, decl_line) in &declarations {
                let has_loop = Self::has_loop_serialization(&function.body);
                
                let actual_count = match ser_type.as_str() {
                    "struct" => Self::count_serialize_fields(&function.body),
                    "tuple" | "tuple_struct" => Self::count_serialize_elements(&function.body),
                    "seq" => {
                        if has_loop {
                            usize::MAX
                        } else {
                            Self::count_seq_elements(&function.body)
                        }
                    }
                    "map" => {
                        if has_loop {
                            usize::MAX
                        } else {
                            Self::count_map_entries(&function.body)
                        }
                    }
                    _ => continue,
                };

                if actual_count == usize::MAX {
                    let type_desc = match ser_type.as_str() {
                        "seq" => "sequence",
                        "map" => "map",
                        _ => "collection",
                    };

                    let name_info = if name.is_empty() {
                        String::new()
                    } else {
                        format!(" for `{}`", name)
                    };

                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "Serde serialize_{}{} declares constant length {} but uses loop-based serialization. \
                            The hardcoded length hint will likely not match the actual number of {} entries. \
                            Use `None` for dynamic-length collections or use `self.{}.len()` instead.",
                            ser_type, name_info, declared_len, type_desc,
                            if ser_type == "seq" { "data" } else { "items" }
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![decl_line.clone()],
                        span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                    });
                    continue;
                }

                if actual_count != *declared_len {
                    let type_desc = match ser_type.as_str() {
                        "struct" => "struct fields",
                        "tuple" | "tuple_struct" => "tuple elements",
                        "seq" => "sequence elements",
                        "map" => "map entries",
                        _ => "elements",
                    };

                    let name_info = if name.is_empty() {
                        String::new()
                    } else {
                        format!(" for `{}`", name)
                    };

                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "Serde serialize_{}{} declares {} {} but actually serializes {}. \
                            This mismatch can cause deserialization failures in binary formats. \
                            Update the length argument to match the actual count.",
                            ser_type, name_info, declared_len, type_desc, actual_count
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![decl_line.clone()],
                        span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                    });
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA106: Unchecked Timestamp Multiplication Rule
// ============================================================================

/// Detects unchecked multiplication when converting time units (seconds to nanos, etc.).
/// 
/// Time unit conversions often involve multiplying by large constants (1_000_000_000 for
/// seconds to nanoseconds). Without overflow checks, this can silently wrap around,
/// causing incorrect timestamps.
pub struct UncheckedTimestampMultiplicationRule {
    metadata: RuleMetadata,
}

impl UncheckedTimestampMultiplicationRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA106".to_string(),
                name: "unchecked-timestamp-multiplication".to_string(),
                short_description: "Unchecked multiplication in timestamp conversion".to_string(),
                full_description: "Detects unchecked multiplication when converting time units. \
                    Conversions like seconds to nanoseconds (multiply by 1_000_000_000) can \
                    overflow for large values. Use checked_mul() or saturating_mul() to handle \
                    overflow correctly. Pattern found in InfluxDB research.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    /// Large multipliers that indicate time unit conversion
    fn time_multipliers() -> &'static [(&'static str, &'static str)] {
        &[
            ("1_000_000_000", "seconds to nanoseconds"),
            ("1000000000", "seconds to nanoseconds"),
            ("1_000_000", "seconds to microseconds or millis to nanos"),
            ("1000000", "seconds to microseconds or millis to nanos"),
            ("1_000", "seconds to milliseconds or millis to micros"),
            ("86_400", "days to seconds"),
            ("86400", "days to seconds"),
            ("3_600", "hours to seconds"),
            ("3600", "hours to seconds"),
        ]
    }
}

impl Rule for UncheckedTimestampMultiplicationRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let crate_root = Path::new(&package.crate_root);

        if !crate_root.exists() {
            return findings;
        }

        for entry in WalkDir::new(crate_root)
            .into_iter()
            .filter_entry(|e| filter_entry(e))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            if path.extension() != Some(OsStr::new("rs")) {
                continue;
            }

            let rel_path = path
                .strip_prefix(crate_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let lines: Vec<&str> = content.lines().collect();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Skip if already using checked/saturating operations
                if trimmed.contains("checked_mul") || trimmed.contains("saturating_mul")
                    || trimmed.contains("overflowing_mul") || trimmed.contains("wrapping_mul") {
                    continue;
                }

                // Check for unchecked multiplication with time constants
                for (multiplier, conversion_type) in Self::time_multipliers() {
                    // Look for patterns like: value * 1_000_000_000 or 1_000_000_000 * value
                    if trimmed.contains(multiplier) && trimmed.contains('*') {
                        // Additional check: is this likely a timestamp context?
                        let is_time_context = trimmed.contains("sec")
                            || trimmed.contains("time")
                            || trimmed.contains("nano")
                            || trimmed.contains("micro")
                            || trimmed.contains("milli")
                            || trimmed.contains("duration")
                            || trimmed.contains("timestamp")
                            || trimmed.contains("epoch");

                        // Also flag if function name suggests time handling
                        let fn_context = lines[..idx].iter().rev().take(15)
                            .any(|l| l.contains("fn ") && (
                                l.contains("time") || l.contains("sec") || 
                                l.contains("nano") || l.contains("duration") ||
                                l.contains("timestamp") || l.contains("to_")
                            ));

                        if is_time_context || fn_context {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Unchecked multiplication by {} ({}). \
                                    This can overflow for large values. Use checked_mul() \
                                    or saturating_mul() for safe conversion.",
                                    multiplier, conversion_type
                                ),
                                function: location,
                                function_signature: String::new(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                    ..Default::default()
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// Registration
// ============================================================================

/// Register all input validation rules with the rule engine.
pub fn register_input_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(CleartextEnvVarRule::new()));
    engine.register_rule(Box::new(EnvVarLiteralRule::new()));
    engine.register_rule(Box::new(InvisibleUnicodeRule::new()));
    engine.register_rule(Box::new(UntrimmedStdinRule::new()));
    engine.register_rule(Box::new(InfiniteIteratorRule::new()));
    engine.register_rule(Box::new(DivisionByUntrustedRule::new()));
    engine.register_rule(Box::new(InsecureYamlDeserializationRule::new()));
    engine.register_rule(Box::new(UnboundedReadRule::new()));
    engine.register_rule(Box::new(InsecureJsonTomlDeserializationRule::new()));
    engine.register_rule(Box::new(SerdeLengthMismatchRule::new()));
    engine.register_rule(Box::new(UncheckedTimestampMultiplicationRule::new()));
}
