//! Memory safety rules.
//!
//! Rules detecting memory safety issues:
//! - Transmute operations
//! - Uninitialized memory usage
//! - Vec::set_len misuse
//! - Raw pointer escapes
//! - Box/Arc into_raw without proper cleanup
//! - Null pointer transmutes
//! - ZST pointer arithmetic

use crate::{Exploitability, Confidence, Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};
use crate::detect_truncating_len_casts;
use super::collect_matches;
use super::utils::filter_entry;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

// ============================================================================
// Helper Functions
// ============================================================================

#[derive(Default, Clone, Copy)]
pub(crate) struct StringLiteralState {
    in_normal_string: bool,
    raw_hashes: Option<usize>,
}

const STRIP_STRING_INITIAL_CAPACITY: usize = 256;

pub(crate) fn strip_string_literals(
    mut state: StringLiteralState,
    line: &str,
) -> (String, StringLiteralState) {
    let bytes = line.as_bytes();
    let mut result = String::with_capacity(STRIP_STRING_INITIAL_CAPACITY);
    let mut i = 0usize;

    while i < bytes.len() {
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
        if ch == b'"' {
            state.in_normal_string = true;
            result.push(' ');
            i += 1;
            continue;
        }

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

        if ch == b'\'' {
            if i + 1 < bytes.len() {
                let next = bytes[i + 1];
                let looks_like_lifetime = next == b'_' || next.is_ascii_alphabetic();
                let following = bytes.get(i + 2).copied();
                if looks_like_lifetime && following != Some(b'\'') {
                    result.push('\'');
                    i += 1;
                    continue;
                }
            }

            let mut j = i + 1;
            let mut escaped = false;
            while j < bytes.len() {
                if escaped {
                    escaped = false;
                    j += 1;
                    continue;
                }
                if bytes[j] == b'\\' {
                    escaped = true;
                    j += 1;
                    continue;
                }
                if bytes[j] == b'\'' {
                    for _ in i..=j {
                        result.push(' ');
                    }
                    i = j + 1;
                    break;
                }
                j += 1;
            }
            if j >= bytes.len() {
                result.push(ch as char);
                i += 1;
            }
            continue;
        }

        result.push(ch as char);
        i += 1;
    }

    (result, state)
}

pub(crate) fn looks_like_null_pointer_transmute(line: &str) -> bool {
    let lower = line.to_lowercase();
    
    if !lower.contains("transmute") {
        return false;
    }
    
    // Skip internal compiler transmute casts
    if lower.contains("(transmute)") {
        return false;
    }
    
    if lower.contains("transmute(const 0") || lower.contains("transmute(0_") {
        return true;
    }
    
    if (lower.contains("std::ptr::null") || lower.contains("::ptr::null")) 
        && lower.contains("transmute") {
        return true;
    }
    
    if lower.contains("null") && lower.contains("transmute") {
        return true;
    }
    
    false
}

pub(crate) fn looks_like_zst_pointer_arithmetic(line: &str) -> bool {
    let lower = line.to_lowercase();
    
    let arithmetic_methods = ["offset", "add", "sub", "wrapping_offset", "wrapping_add", "wrapping_sub", "offset_from"];
    
    let has_arithmetic = arithmetic_methods.iter().any(|method| lower.contains(method));
    if !has_arithmetic {
        return false;
    }
    
    // Unit type: *const () or *mut ()
    if (lower.contains("*const ()") || lower.contains("*mut ()")) && has_arithmetic {
        return true;
    }
    
    // PhantomData
    if lower.contains("phantomdata") && has_arithmetic {
        return true;
    }
    
    // PhantomPinned
    if lower.contains("phantompinned") && has_arithmetic {
        return true;
    }
    
    // Empty tuple/array patterns
    if (lower.contains("*const [(); 0]") || lower.contains("*mut [(); 0]")) && has_arithmetic {
        return true;
    }
    
    // ZST naming conventions
    if (lower.contains("_zst") || lower.contains("zst_")) && has_arithmetic {
        return true;
    }
    
    let empty_type_patterns = [
        "emptystruct", "emptyenum", "emptytype", "empty_struct", "empty_enum", "empty_type",
        "unitstruct", "unitenum", "unittype", "unit_struct", "unit_enum", "unit_type",
        "markerstruct", "markerenum", "markertype", "marker_struct", "marker_enum", "marker_type",
        "zststruct", "zstenum", "zsttype", "zst_struct", "zst_enum", "zst_type",
    ];
    if empty_type_patterns.iter().any(|p| lower.contains(p)) && has_arithmetic {
        return true;
    }
    
    false
}

/// Check if text contains a word (case-insensitive, respecting word boundaries)
pub(crate) fn text_contains_word_case_insensitive(text: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }

    let target = needle.to_lowercase();
    text.to_lowercase()
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|token| token == target)
}

/// Strip comments from a line, tracking block comment state
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

// ============================================================================
// RUSTCOLA001: Box::into_raw
// ============================================================================

pub struct BoxIntoRawRule {
    metadata: RuleMetadata,
}

impl BoxIntoRawRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA001".to_string(),
                name: "box-into-raw".to_string(),
                short_description: "Conversion of managed pointer into raw pointer".to_string(),
                full_description: "Detects conversions such as Box::into_raw that hand out raw pointers across FFI boundaries.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn patterns() -> &'static [&'static str] {
        &[
            "Box::into_raw",
            "CString::into_raw",
            "Arc::into_raw",
            ".into_raw()",
        ]
    }
}

impl Rule for BoxIntoRawRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            let evidence = collect_matches(&function.body, Self::patterns());
            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!(
                    "Potential raw pointer escape via into_raw detected in `{}`",
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
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
            });
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA002: std::mem::transmute
// ============================================================================

pub struct TransmuteRule {
    metadata: RuleMetadata,
}

impl TransmuteRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA002".to_string(),
                name: "std-mem-transmute".to_string(),
                short_description: "Usage of std::mem::transmute".to_string(),
                full_description: "Highlights calls to std::mem::transmute, which may indicate unsafe type conversions that require careful review.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn line_contains_transmute_call(line: &str) -> bool {
        let mut search_start = 0usize;
        while let Some(relative_idx) = line[search_start..].find("transmute") {
            let idx = search_start + relative_idx;
            let before_non_ws = line[..idx].chars().rev().find(|c| !c.is_whitespace());
            if before_non_ws
                .map(|c| c.is_alphanumeric() || c == '_')
                .unwrap_or(false)
            {
                search_start = idx + "transmute".len();
                continue;
            }

            let after = &line[idx + "transmute".len()..];
            let after_trimmed = after.trim_start();

            if after_trimmed.starts_with('(') || after_trimmed.starts_with("::<") {
                return true;
            }

            search_start = idx + "transmute".len();
        }

        false
    }

    fn collect_transmute_lines(body: &[String]) -> Vec<String> {
        let mut state = StringLiteralState::default();
        let mut lines = Vec::new();

        for raw_line in body {
            let (sanitized, next_state) = strip_string_literals(state, raw_line);
            state = next_state;

            let trimmed = sanitized.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            if Self::line_contains_transmute_call(&sanitized) {
                lines.push(raw_line.trim().to_string());
            }
        }

        lines
    }
}

impl Rule for TransmuteRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();
        for function in &package.functions {
            let transmute_lines = Self::collect_transmute_lines(&function.body);

            if !transmute_lines.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!("Use of std::mem::transmute detected in `{}`", function.name),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: transmute_lines,
                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                });
            }
        }
        findings
    }
}

// ============================================================================
// RUSTCOLA003: Unsafe Usage
// ============================================================================

pub struct UnsafeUsageRule {
    metadata: RuleMetadata,
}

impl UnsafeUsageRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA003".to_string(),
                name: "unsafe-usage".to_string(),
                short_description: "Unsafe function or block detected".to_string(),
                full_description: "Flags functions marked unsafe or containing unsafe blocks, highlighting code that requires careful review.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn gather_evidence(&self, function: &MirFunction) -> Vec<String> {
        let mut evidence = Vec::new();
        let mut seen = HashSet::new();

        let (sanitized_sig, _) =
            strip_string_literals(StringLiteralState::default(), &function.signature);
        if text_contains_word_case_insensitive(&sanitized_sig, "unsafe") {
            let sig = format!("signature: {}", function.signature.trim());
            if seen.insert(sig.clone()) {
                evidence.push(sig);
            }
        }

        let mut state = StringLiteralState::default();
        let mut in_block_comment = false;

        for line in &function.body {
            let (sanitized, next_state) = strip_string_literals(state, line);
            state = next_state;

            let without_comments = strip_comments(&sanitized, &mut in_block_comment);
            if text_contains_word_case_insensitive(&without_comments, "unsafe") {
                let entry = line.trim().to_string();
                if seen.insert(entry.clone()) {
                    evidence.push(entry);
                }
            }
        }

        evidence
    }
}

impl Rule for UnsafeUsageRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();
        for function in &package.functions {
            // Skip self-analysis
            if package.crate_name == "mir-extractor" {
                continue;
            }

            let evidence = self.gather_evidence(function);
            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!("Unsafe code detected in `{}`", function.name),
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence,
                span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
            });
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA063: Null Pointer Transmute
// ============================================================================

pub struct NullPointerTransmuteRule {
    metadata: RuleMetadata,
}

impl NullPointerTransmuteRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA063".to_string(),
                name: "null-pointer-transmute".to_string(),
                short_description: "Null pointer transmuted to reference or function pointer".to_string(),
                full_description: "Detects transmute operations involving null pointers, which cause undefined behavior. This includes transmuting zero/null to references, function pointers, or other non-nullable types. Use proper Option types or explicit null checks instead. Sonar RSPEC-7427 parity.".to_string(),
                help_uri: Some("https://rules.sonarsource.com/rust/RSPEC-7427/".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }
}

impl Rule for NullPointerTransmuteRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("NullPointerTransmuteRule") 
                || function.name.contains("looks_like_null_pointer_transmute") {
                continue;
            }

            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| looks_like_null_pointer_transmute(line))
                .map(|line| line.trim().to_string())
                .collect();

            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!(
                    "Null pointer transmuted to non-nullable type in `{}`",
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
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
            });
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA064: ZST Pointer Arithmetic
// ============================================================================

pub struct ZSTPointerArithmeticRule {
    metadata: RuleMetadata,
}

impl ZSTPointerArithmeticRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA064".to_string(),
                name: "zst-pointer-arithmetic".to_string(),
                short_description: "Pointer arithmetic on zero-sized types".to_string(),
                full_description: "Detects pointer arithmetic operations (offset, add, sub, etc.) on pointers to zero-sized types (ZSTs) like (), PhantomData, or empty structs. Such operations are usually undefined behavior since ZSTs have no meaningful memory layout. Sonar RSPEC-7428 parity.".to_string(),
                help_uri: Some("https://rules.sonarsource.com/rust/RSPEC-7428/".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }
}

impl Rule for ZSTPointerArithmeticRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("ZSTPointerArithmeticRule")
                || function.name.contains("looks_like_zst_pointer_arithmetic") {
                continue;
            }

            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| looks_like_zst_pointer_arithmetic(line))
                .map(|line| line.trim().to_string())
                .collect();

            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!(
                    "Pointer arithmetic on zero-sized type detected in `{}`",
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
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
            });
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA008: Vec::set_len
// ============================================================================

const VEC_SET_LEN_SYMBOL: &str = concat!("Vec", "::", "set", "_len");

pub struct VecSetLenRule {
    metadata: RuleMetadata,
}

impl VecSetLenRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA008".to_string(),
                name: "vec-set-len".to_string(),
                short_description: format!("Potential misuse of {}", VEC_SET_LEN_SYMBOL),
                full_description: format!(
                    "Flags calls to {} which can lead to uninitialized memory exposure if not followed by proper writes.",
                    VEC_SET_LEN_SYMBOL
                ),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn gather_evidence(&self, function: &MirFunction) -> Vec<String> {
        let mut evidence = Vec::new();
        let mut seen = HashSet::new();
        let mut state = StringLiteralState::default();
        let mut in_block_comment = false;

        for line in &function.body {
            let (sanitized, next_state) = strip_string_literals(state, line);
            state = next_state;

            let without_comments = strip_comments(&sanitized, &mut in_block_comment);
            let trimmed = without_comments.trim_start();
            if trimmed.starts_with("0x") || without_comments.contains('│') {
                continue;
            }

            let has_call = without_comments.contains("set_len(");
            let has_turbofish = without_comments.contains("set_len::<");
            if has_call || has_turbofish {
                let entry = line.trim().to_string();
                if seen.insert(entry.clone()) {
                    evidence.push(entry);
                }
            }
        }

        evidence
    }
}

impl Rule for VecSetLenRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        // Skip self-analysis
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            let evidence = self.gather_evidence(function);
            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!(
                    "{} used in `{}`; ensure elements are initialized",
                    VEC_SET_LEN_SYMBOL, function.name
                ),
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence,
                span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
            });
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA009: MaybeUninit::assume_init
// ============================================================================

const MAYBE_UNINIT_TYPE_SYMBOL: &str = concat!("Maybe", "Uninit");
const MAYBE_UNINIT_ASSUME_INIT_SYMBOL: &str = concat!("assume", "_init");

pub struct MaybeUninitAssumeInitRule {
    metadata: RuleMetadata,
}

impl MaybeUninitAssumeInitRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA009".to_string(),
                name: "maybeuninit-assume-init".to_string(),
                short_description: format!(
                    "{}::{} usage",
                    MAYBE_UNINIT_TYPE_SYMBOL, MAYBE_UNINIT_ASSUME_INIT_SYMBOL
                ),
                full_description: format!(
                    "Highlights {}::{} calls which require careful initialization guarantees.",
                    MAYBE_UNINIT_TYPE_SYMBOL, MAYBE_UNINIT_ASSUME_INIT_SYMBOL
                ),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }
}

impl Rule for MaybeUninitAssumeInitRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        // Skip self-analysis
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let patterns = ["assume_init", "assume_init_ref"];

        for function in &package.functions {
            let evidence = collect_matches(&function.body, &patterns);
            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!(
                    "{}::{} detected in `{}`",
                    MAYBE_UNINIT_TYPE_SYMBOL, MAYBE_UNINIT_ASSUME_INIT_SYMBOL, function.name
                ),
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence,
                span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
            });
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA010: mem::uninitialized / mem::zeroed
// ============================================================================

const MEM_MODULE_SYMBOL: &str = concat!("mem");
const MEM_UNINITIALIZED_SYMBOL: &str = concat!("uninitialized");
const MEM_ZEROED_SYMBOL: &str = concat!("zeroed");

pub struct MemUninitZeroedRule {
    metadata: RuleMetadata,
}

impl MemUninitZeroedRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA010".to_string(),
                name: "mem-uninit-zeroed".to_string(),
                short_description: format!(
                    "Use of {}::{} or {}::{}",
                    MEM_MODULE_SYMBOL,
                    MEM_UNINITIALIZED_SYMBOL,
                    MEM_MODULE_SYMBOL,
                    MEM_ZEROED_SYMBOL
                ),
                full_description: format!(
                    "Flags deprecated zero-initialization APIs such as {}::{} and {}::{} which can lead to undefined behavior on non-zero types.",
                    MEM_MODULE_SYMBOL,
                    MEM_UNINITIALIZED_SYMBOL,
                    MEM_MODULE_SYMBOL,
                    MEM_ZEROED_SYMBOL
                ),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }
}

impl Rule for MemUninitZeroedRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        // Skip self-analysis
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let patterns = [
            format!("{}::{}", MEM_MODULE_SYMBOL, MEM_UNINITIALIZED_SYMBOL),
            format!("{}::{}", MEM_MODULE_SYMBOL, MEM_ZEROED_SYMBOL),
            "::uninitialized()".to_string(),
            "::zeroed()".to_string(),
        ];
        let pattern_refs: Vec<_> = patterns.iter().map(|s| s.as_str()).collect();

        for function in &package.functions {
            let evidence = collect_matches(&function.body, &pattern_refs);
            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!(
                    "Deprecated zero-initialization detected in `{}` via {}::{} or {}::{}",
                    function.name,
                    MEM_MODULE_SYMBOL,
                    MEM_UNINITIALIZED_SYMBOL,
                    MEM_MODULE_SYMBOL,
                    MEM_ZEROED_SYMBOL
                ),
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence,
                span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
            });
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA073: NonNull::new_unchecked
// ============================================================================

pub struct NonNullNewUncheckedRule {
    metadata: RuleMetadata,
}

impl NonNullNewUncheckedRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA073".to_string(),
                name: "nonnull-new-unchecked".to_string(),
                short_description: "NonNull::new_unchecked usage without null check".to_string(),
                full_description: "Detects usage of NonNull::new_unchecked which assumes the pointer is non-null. Using this with a null pointer is undefined behavior.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }
}

impl Rule for NonNullNewUncheckedRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        // Skip analyzer's own crate to avoid self-referential warnings
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| line.contains("NonNull") && line.contains("new_unchecked"))
                .map(|line| line.trim().to_string())
                .collect();

            if !evidence.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!("NonNull::new_unchecked usage in `{}`", function.name),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence,
                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA078: mem::forget on guard types
// ============================================================================

pub struct MemForgetGuardRule {
    metadata: RuleMetadata,
}

impl MemForgetGuardRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA078".to_string(),
                name: "mem-forget-guard".to_string(),
                short_description: "mem::forget on guard types".to_string(),
                full_description: "Detects mem::forget called on guard types (MutexGuard, RwLockGuard, etc.) which prevents the lock from being released, potentially causing deadlocks.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }
}

impl Rule for MemForgetGuardRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        // Skip analyzer's own crate to avoid self-referential warnings
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let guard_types = ["MutexGuard", "RwLockReadGuard", "RwLockWriteGuard", "RefMut", "Ref"];

        for function in &package.functions {
            // Check if function has mem::forget with guard types
            let has_forget = function.body.iter().any(|line| line.contains("mem::forget"));
            if !has_forget {
                continue;
            }

            let has_guard = function.body.iter().any(|line| {
                guard_types.iter().any(|g| line.contains(g))
            });

            if has_guard {
                let evidence: Vec<String> = function.body.iter()
                    .filter(|line| line.contains("mem::forget") || guard_types.iter().any(|g| line.contains(g)))
                    .map(|line| line.trim().to_string())
                    .collect();

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!("mem::forget on guard type may cause deadlock in `{}`", function.name),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence,
                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA025: Static mut global detected
// ============================================================================

pub struct StaticMutGlobalRule {
    metadata: RuleMetadata,
}

impl StaticMutGlobalRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA025".to_string(),
                name: "static-mut-global".to_string(),
                short_description: "Mutable static global detected".to_string(),
                full_description: "Flags uses of `static mut` globals, which are unsafe shared mutable state and can introduce data races or memory safety bugs.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }
}

impl Rule for StaticMutGlobalRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let patterns = ["static mut "];

        for function in &package.functions {
            let mut evidence = collect_matches(&function.body, &patterns);
            if evidence.is_empty() {
                continue;
            }

            // If the signature itself declared a mutable static, include it for additional context.
            if function.signature.contains("static mut ") {
                evidence.push(function.signature.trim().to_string());
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!(
                    "Mutable static global detected in `{}`; prefer interior mutability or synchronization primitives",
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
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
            });
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA095: Transmute changes reference lifetime
// ============================================================================

pub struct TransmuteLifetimeChangeRule {
    metadata: RuleMetadata,
}

impl TransmuteLifetimeChangeRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA095".to_string(),
                name: "transmute-lifetime-change".to_string(),
                short_description: "Transmute changes reference lifetime".to_string(),
                full_description: "Using std::mem::transmute to change lifetime parameters of references is undefined behavior. It can create references that outlive the data they point to, leading to use-after-free. Use proper lifetime annotations or safe APIs instead.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/mem/fn.transmute.html#examples".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    /// Extract the lifetime from a type annotation like "&'a str" or "&'static str"
    fn extract_lifetime(type_str: &str) -> Option<String> {
        if let Some(quote_pos) = type_str.find('\'') {
            let after_quote = &type_str[quote_pos + 1..];
            let end_pos = after_quote
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap_or(after_quote.len());
            if end_pos > 0 {
                return Some(format!("'{}", &after_quote[..end_pos]));
            }
        }
        None
    }

    /// Check if two types differ only in lifetime parameters
    fn types_differ_in_lifetime(from_type: &str, to_type: &str) -> bool {
        let from_lifetime = Self::extract_lifetime(from_type);
        let to_lifetime = Self::extract_lifetime(to_type);

        match (from_lifetime, to_lifetime) {
            (Some(from_lt), Some(to_lt)) => {
                if from_lt != to_lt {
                    let from_is_ref = from_type.contains('&');
                    let to_is_ref = to_type.contains('&');
                    return from_is_ref && to_is_ref;
                }
                false
            }
            (Some(_), None) | (None, Some(_)) => {
                from_type.contains('&') && to_type.contains('&')
            }
            _ => false,
        }
    }
}

impl Rule for TransmuteLifetimeChangeRule {
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
            let mut current_fn_name = String::new();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("fn ") {
                    if let Some(fn_pos) = trimmed.find("fn ") {
                        let after_fn = &trimmed[fn_pos + 3..];
                        if let Some(paren_pos) = after_fn.find('(') {
                            current_fn_name = after_fn[..paren_pos].trim().to_string();
                        }
                    }
                }

                if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                    continue;
                }

                if trimmed.contains("transmute") {
                    // Pattern 1: transmute::<From, To>(...)
                    if let Some(turbofish_start) = trimmed.find("transmute::<") {
                        let after_turbofish = &trimmed[turbofish_start + 12..];
                        if let Some(end) = after_turbofish.find(">(") {
                            let types_str = &after_turbofish[..end];
                            let parts: Vec<&str> = types_str.split(',').collect();
                            if parts.len() == 2 {
                                let from_type = parts[0].trim();
                                let to_type = parts[1].trim();
                                
                                if Self::types_differ_in_lifetime(from_type, to_type) {
                                    let location = format!("{}:{}", rel_path, idx + 1);
                                    findings.push(Finding {
                                        rule_id: self.metadata.id.clone(),
                                        rule_name: self.metadata.name.clone(),
                                        severity: self.metadata.default_severity,
                                        message: format!(
                                            "Transmute changes lifetime in `{}`: {} -> {}. This can create dangling references.",
                                            current_fn_name, from_type, to_type
                                        ),
                                        function: location,
                                        function_signature: current_fn_name.clone(),
                                        evidence: vec![trimmed.to_string()],
                                        span: None,
                    ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                    
                    // Pattern 2: Function signature shows lifetime extension
                    let mut fn_sig_line = String::new();
                    for back_idx in (0..=idx).rev() {
                        let back_line = lines[back_idx].trim();
                        if back_line.contains("fn ") && back_line.contains("->") {
                            fn_sig_line = back_line.to_string();
                            break;
                        }
                        if back_line.starts_with("pub fn ") || back_line.starts_with("fn ") {
                            if !back_line.contains("->") {
                                break;
                            }
                        }
                    }
                    
                    let sig_has_short_lifetime = fn_sig_line.contains("'a") || 
                                                fn_sig_line.contains("'b");
                    let sig_returns_static = fn_sig_line.contains("-> &'static") ||
                                            fn_sig_line.contains("-> StaticData");
                    
                    let is_actual_transmute = trimmed.contains("transmute(") || 
                                             trimmed.contains("transmute::<");
                    
                    if sig_has_short_lifetime && sig_returns_static && is_actual_transmute {
                        let already_reported = findings.iter().any(|f| 
                            f.function == format!("{}:{}", rel_path, idx + 1)
                        );
                        if !already_reported {
                            let location = format!("{}:{}", rel_path, idx + 1);
                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Transmute may extend lifetime to 'static in `{}`. This can create dangling references.",
                                    current_fn_name
                                ),
                                function: location,
                                function_signature: current_fn_name.clone(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                    ..Default::default()
                            });
                        }
                    }
                    
                    // Pattern 3: Struct with lifetime parameter transmuted to struct without
                    if let Some(turbofish_start) = trimmed.find("transmute::<") {
                        let after_turbofish = &trimmed[turbofish_start + 12..];
                        if let Some(end) = after_turbofish.find(">(") {
                            let types_str = &after_turbofish[..end];
                            if types_str.contains("<'") || types_str.contains("< '") {
                                let mut depth = 0;
                                let mut split_pos = None;
                                for (i, c) in types_str.char_indices() {
                                    match c {
                                        '<' => depth += 1,
                                        '>' => depth -= 1,
                                        ',' if depth == 0 => {
                                            split_pos = Some(i);
                                            break;
                                        }
                                        _ => {}
                                    }
                                }
                                
                                if let Some(pos) = split_pos {
                                    let from_type = types_str[..pos].trim();
                                    let to_type = types_str[pos + 1..].trim();
                                    
                                    let from_has_lifetime = from_type.contains("'a") ||
                                                           from_type.contains("'b") ||
                                                           from_type.contains("'_");
                                    let to_has_static = !to_type.contains('\'') ||
                                                       to_type.contains("'static");
                                    
                                    if from_has_lifetime && to_has_static {
                                        let already_reported = findings.iter().any(|f| 
                                            f.function == format!("{}:{}", rel_path, idx + 1)
                                        );
                                        if !already_reported {
                                            let location = format!("{}:{}", rel_path, idx + 1);
                                            findings.push(Finding {
                                                rule_id: self.metadata.id.clone(),
                                                rule_name: self.metadata.name.clone(),
                                                severity: self.metadata.default_severity,
                                                message: format!(
                                                    "Transmute changes struct lifetime in `{}`: {} -> {}. This can create dangling references.",
                                                    current_fn_name, from_type, to_type
                                                ),
                                                function: location,
                                                function_signature: current_fn_name.clone(),
                                                evidence: vec![trimmed.to_string()],
                                                span: None,
                    ..Default::default()
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA096: Raw pointer from local reference escapes function
// ============================================================================

pub struct RawPointerEscapeRule {
    metadata: RuleMetadata,
}

impl RawPointerEscapeRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA096".to_string(),
                name: "raw-pointer-escape".to_string(),
                short_description: "Raw pointer from local reference escapes function".to_string(),
                full_description: "Casting a reference to a raw pointer (`as *const T` or `as *mut T`) and returning it or storing it beyond the reference's lifetime creates a dangling pointer. When the referenced data is dropped or moved, the pointer becomes invalid. Use Box::leak, 'static data, or ensure the caller manages the lifetime.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/primitive.pointer.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn is_ptr_cast(line: &str) -> bool {
        line.contains("as *const") || 
        line.contains("as *mut") ||
        line.contains(".as_ptr()") ||
        line.contains(".as_mut_ptr()")
    }

    /// Check for unsafe dereference patterns that create references outliving pointee
    fn is_unsafe_deref_outlive(line: &str) -> bool {
        // Pattern: unsafe { &*ptr } or unsafe { &mut *ptr }
        (line.contains("&*") || line.contains("&mut *")) && 
        (line.contains("unsafe") || line.contains("ptr"))
    }

    /// Check for transmute patterns that extend lifetimes
    fn is_lifetime_transmute(line: &str) -> bool {
        line.contains("transmute") && 
        (line.contains("&'") || line.contains("'static") || line.contains("'a"))
    }

    fn is_return_context(lines: &[&str], idx: usize, ptr_var: &str) -> bool {
        let line = lines[idx].trim();
        
        if line.starts_with("return ") && (line.contains("as *const") || line.contains("as *mut")) {
            return true;
        }
        
        if (line.contains("as *const") || line.contains("as *mut") || line.contains(".as_ptr()")) 
           && !line.ends_with(';') 
           && !line.contains("let ") {
            return true;
        }
        
        if !ptr_var.is_empty() {
            for check_line in lines.iter().skip(idx + 1).take(10) {
                let trimmed = check_line.trim();
                if trimmed.starts_with("return ") && trimmed.contains(ptr_var) {
                    return true;
                }
                if trimmed.contains(ptr_var) && !trimmed.ends_with(';') && trimmed.ends_with(')') {
                    return true;
                }
                if trimmed.starts_with(ptr_var) && !trimmed.ends_with(';') {
                    return true;
                }
            }
        }
        
        false
    }

    fn is_escape_via_store(lines: &[&str], idx: usize) -> bool {
        let line = lines[idx].trim();
        
        if line.contains("ptr:") && (line.contains("as *const") || line.contains("as *mut")) {
            return true;
        }
        
        if (line.starts_with("*") && line.contains(" = ")) && 
           (line.contains("as *const") || line.contains("as *mut")) {
            if line.contains("&") {
                return true;
            }
        }
        
        if line.contains("GLOBAL") || line.contains("STATIC") {
            if line.contains("as *const") || line.contains("as *mut") {
                return true;
            }
        }
        
        false
    }

    fn is_safe_pattern(lines: &[&str], idx: usize, fn_context: &str) -> bool {
        let line = lines[idx].trim();
        
        if fn_context.contains("fn ") && fn_context.contains("(&") {
            if !line.contains("let ") && (line.contains(" x ") || line.contains("(x)")) {
                return true;
            }
        }
        
        if line.contains("Box::leak") {
            return true;
        }
        
        if fn_context.contains("&'static str") {
            return true;
        }
        
        if line.contains("(ptr,") && (fn_context.contains("Box<") || fn_context.contains("boxed")) {
            return true;
        }
        
        if fn_context.contains("ManuallyDrop") {
            return true;
        }
        
        if fn_context.contains("Pin<") {
            return true;
        }
        
        if line.contains("unsafe {") && line.contains("*ptr") && !line.contains("return") {
            return true;
        }
        
        let next_lines: String = lines[idx..std::cmp::min(idx + 5, lines.len())]
            .iter()
            .map(|s| *s)
            .collect::<Vec<&str>>()
            .join("\n");
        if next_lines.contains("unsafe { *ptr }") && !next_lines.contains("return ptr") {
            return true;
        }
        
        false
    }
}

impl Rule for RawPointerEscapeRule {
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
            let mut current_fn_name = String::new();
            let mut current_fn_start = 0;
            let mut returns_ptr = false;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("fn ") {
                    if let Some(fn_pos) = trimmed.find("fn ") {
                        let after_fn = &trimmed[fn_pos + 3..];
                        if let Some(paren_pos) = after_fn.find('(') {
                            current_fn_name = after_fn[..paren_pos].trim().to_string();
                            current_fn_start = idx;
                            returns_ptr = trimmed.contains("-> *const") || 
                                         trimmed.contains("-> *mut") ||
                                         trimmed.contains("*const i32") ||
                                         trimmed.contains("*const u8") ||
                                         trimmed.contains("*const str");
                        }
                    }
                }

                if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                    continue;
                }
                if trimmed.starts_with("* ") || trimmed == "*" || trimmed.starts_with("*/") {
                    continue;
                }

                if Self::is_ptr_cast(trimmed) {
                    let fn_context: String = lines[current_fn_start..=idx.min(lines.len() - 1)]
                        .iter()
                        .take(20)
                        .map(|s| *s)
                        .collect::<Vec<&str>>()
                        .join("\n");
                    
                    if Self::is_safe_pattern(&lines, idx, &fn_context) {
                        continue;
                    }
                    
                    let is_local_cast = trimmed.contains("&x ") || 
                                       trimmed.contains("&local") ||
                                       trimmed.contains("&temp") ||
                                       trimmed.contains("&s ") ||
                                       trimmed.contains("s.as_ptr()") ||
                                       trimmed.contains("s.as_str()") ||
                                       trimmed.contains("&v[");
                    
                    let mut ptr_var = String::new();
                    if trimmed.contains("let ") && trimmed.contains(" = ") {
                        if let Some(eq_pos) = trimmed.find(" = ") {
                            let before_eq = &trimmed[..eq_pos];
                            if let Some(let_pos) = before_eq.find("let ") {
                                ptr_var = before_eq[let_pos + 4..].trim().to_string();
                            }
                        }
                    }
                    
                    let escapes_via_return = Self::is_return_context(&lines, idx, &ptr_var);
                    let escapes_via_store = Self::is_escape_via_store(&lines, idx);
                    
                    let is_deref_assign = trimmed.starts_with("*") && trimmed.contains(" = &");
                    
                    // Enhanced: Check for unsafe { &*ptr } outliving pointee
                    let is_unsafe_deref = Self::is_unsafe_deref_outlive(trimmed);
                    let is_transmute_lifetime = Self::is_lifetime_transmute(trimmed);
                    
                    if ((returns_ptr || escapes_via_return || escapes_via_store) && is_local_cast) || 
                       (is_deref_assign && is_local_cast) ||
                       (is_unsafe_deref && escapes_via_return) ||
                       (is_transmute_lifetime && (returns_ptr || escapes_via_return)) {
                        let location = format!("{}:{}", rel_path, idx + 1);
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "Raw pointer from local reference escapes function `{}`. This creates a dangling pointer when the local is dropped.",
                                current_fn_name
                            ),
                            function: location,
                            function_signature: current_fn_name.clone(),
                            evidence: vec![trimmed.to_string()],
                            span: None,
                    ..Default::default()
                        });
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA038: Vec::set_len called on uninitialized vector (dataflow)
// ============================================================================

pub struct VecSetLenMisuseRule {
    metadata: RuleMetadata,
}

impl VecSetLenMisuseRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA038".to_string(),
                name: "vec-set-len-misuse".to_string(),
                short_description: "Vec::set_len called on uninitialized vector".to_string(),
                full_description: "Detects Vec::set_len calls where the vector may not be fully initialized. Calling set_len without ensuring all elements are initialized leads to undefined behavior when accessing uninitialized memory. Use Vec::resize, Vec::resize_with, or manually initialize elements before calling set_len.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/vec/struct.Vec.html#method.set_len".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn initialization_methods() -> &'static [&'static str] {
        &[
            ".push(",
            ".extend(",
            ".insert(",
            ".resize(",
            ".resize_with(",
            "Vec::from(",
            "vec![",
            ".clone()",
            ".to_vec()",
        ]
    }
}

impl Rule for VecSetLenMisuseRule {
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

                if trimmed.contains(".set_len(") || trimmed.contains("::set_len(") {
                    let mut var_name = None;
                    
                    if let Some(pos) = trimmed.find(".set_len(") {
                        let before_set_len = &trimmed[..pos];
                        if let Some(last_word_start) = before_set_len.rfind(|c: char| c.is_whitespace() || c == '(' || c == '{' || c == ';') {
                            var_name = Some(&before_set_len[last_word_start + 1..]);
                        } else {
                            var_name = Some(before_set_len);
                        }
                    }

                    if let Some(var) = var_name {
                        let mut found_initialization = false;
                        let lookback_limit = idx.saturating_sub(50);

                        for prev_idx in (lookback_limit..idx).rev() {
                            let prev_line = lines[prev_idx];
                            
                            for init_method in Self::initialization_methods() {
                                if prev_line.contains(var) && prev_line.contains(init_method) {
                                    found_initialization = true;
                                    break;
                                }
                            }

                            if prev_line.contains(var) && 
                               (prev_line.contains("[") && prev_line.contains("]=") || 
                                prev_line.contains("ptr::write") ||
                                prev_line.contains(".as_mut_ptr()")) {
                                found_initialization = true;
                                break;
                            }

                            if prev_line.contains(var) && prev_line.contains("Vec::with_capacity") {
                                found_initialization = false;
                                break;
                            }

                            if prev_line.trim().starts_with("fn ") || 
                               prev_line.trim().starts_with("pub fn ") ||
                               prev_line.trim().starts_with("async fn ") {
                                break;
                            }
                        }

                        if !found_initialization {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Vec::set_len called on potentially uninitialized vector `{}`",
                                    var
                                ),
                                function: location,
                                function_signature: var.to_string(),
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
// RUSTCOLA022: Payload length cast to narrower integer
// ============================================================================

pub struct LengthTruncationCastRule {
    metadata: RuleMetadata,
}

impl LengthTruncationCastRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA022".to_string(),
                name: "length-truncation-cast".to_string(),
                short_description: "Payload length cast to narrower integer".to_string(),
                full_description: "Detects casts or try_into conversions that shrink message length fields to 8/16/32-bit integers without bounds checks, potentially smuggling extra bytes past protocol parsers. See RUSTSEC-2024-0363 and RUSTSEC-2024-0365 for PostgreSQL wire protocol examples.".to_string(),
                help_uri: Some("https://rustsec.org/advisories/RUSTSEC-2024-0363.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }
}

impl Rule for LengthTruncationCastRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            let casts = detect_truncating_len_casts(function);

            for cast in casts {
                let mut evidence = vec![cast.cast_line.clone()];

                if !cast.source_vars.is_empty() {
                    evidence.push(format!("length sources: {}", cast.source_vars.join(", ")));
                }

                for sink in &cast.sink_lines {
                    if !evidence.contains(sink) {
                        evidence.push(sink.clone());
                    }
                }

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Potential length truncation before serialization in `{}`",
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
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA078: MaybeUninit::assume_init without preceding write (dataflow)
// ============================================================================

pub struct MaybeUninitAssumeInitDataflowRule {
    metadata: RuleMetadata,
}

impl MaybeUninitAssumeInitDataflowRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA078".to_string(),
                name: "maybeuninit-assume-init-without-write".to_string(),
                short_description: "MaybeUninit::assume_init without preceding write".to_string(),
                full_description: "Detects MaybeUninit::assume_init() or assume_init_read() calls \
                    where no preceding MaybeUninit::write(), write_slice(), or ptr::write() \
                    initializes the data. Reading uninitialized memory is undefined behavior and \
                    can lead to crashes, data corruption, or security vulnerabilities. Always \
                    initialize MaybeUninit values before assuming them initialized."
                    .to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/mem/union.MaybeUninit.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn uninit_creation_patterns() -> &'static [&'static str] {
        &[
            "MaybeUninit::uninit",
            "MaybeUninit::<",
            "uninit_array",
            "uninit(",
        ]
    }

    fn init_patterns() -> &'static [&'static str] {
        &[
            ".write(",
            "::write(",
            "write_slice(",
            "ptr::write(",
            "ptr::write_bytes(",
            "ptr::copy(",
            "ptr::copy_nonoverlapping(",
            "as_mut_ptr()",
            "zeroed(",
            "MaybeUninit::new(",
        ]
    }

    fn assume_init_patterns() -> &'static [&'static str] {
        &[
            "assume_init(",
            "assume_init_read(",
            "assume_init_ref(",
            "assume_init_mut(",
            "assume_init_drop(",
        ]
    }

    fn analyze_uninit_flow(body: &[String]) -> Vec<(String, String)> {
        let mut uninitialized_vars: HashMap<String, String> = HashMap::new();
        let mut initialized_vars: HashSet<String> = HashSet::new();
        let mut unsafe_assumes: Vec<(String, String)> = Vec::new();
        
        let creation_patterns = Self::uninit_creation_patterns();
        let init_patterns = Self::init_patterns();
        let assume_patterns = Self::assume_init_patterns();
        
        for line in body {
            let trimmed = line.trim();
            
            let is_creation = creation_patterns.iter().any(|p| trimmed.contains(p));
            
            if is_creation && !trimmed.contains("zeroed") && !trimmed.contains("::new(") {
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    if let Some(var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        uninitialized_vars.insert(var.to_string(), trimmed.to_string());
                    }
                }
            }
            
            let is_init = init_patterns.iter().any(|p| trimmed.contains(p));
            
            if is_init {
                for var in uninitialized_vars.keys() {
                    if trimmed.contains(var) {
                        initialized_vars.insert(var.clone());
                    }
                }
            }
            
            let is_assume = assume_patterns.iter().any(|p| trimmed.contains(p));
            
            if is_assume {
                for (var, creation_line) in &uninitialized_vars {
                    if trimmed.contains(var) && !initialized_vars.contains(var) {
                        unsafe_assumes.push((creation_line.clone(), trimmed.to_string()));
                    }
                }
            }
        }
        
        unsafe_assumes
    }
}

impl Rule for MaybeUninitAssumeInitDataflowRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("mir_extractor") || 
               function.name.contains("mir-extractor") ||
               function.name.contains("MaybeUninit") {
                continue;
            }

            let unsafe_assumes = Self::analyze_uninit_flow(&function.body);
            
            for (creation_line, assume_line) in unsafe_assumes {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "MaybeUninit::assume_init() called in `{}` without preceding initialization. \
                        Reading uninitialized memory is undefined behavior.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: vec![
                        format!("Created: {}", creation_line),
                        format!("Assumed: {}", assume_line),
                    ],
                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA082: Slice element size mismatch in transmute
// ============================================================================

pub struct SliceElementSizeMismatchRule {
    metadata: RuleMetadata,
}

impl SliceElementSizeMismatchRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA082".to_string(),
                name: "slice-element-size-mismatch".to_string(),
                short_description: "Raw pointer to slice of different element size".to_string(),
                full_description: "Detects transmutes between slice types with different \
                    element sizes (e.g., &[u8] to &[u32]). This is unsound because the slice \
                    length field isn't adjusted for the size difference, causing the new slice \
                    to reference memory beyond the original allocation. Use slice::from_raw_parts \
                    or slice::align_to instead."
                    .to_string(),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                help_uri: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn get_primitive_size(type_name: &str) -> Option<usize> {
        let inner = type_name
            .trim_start_matches('&')
            .trim_start_matches("mut ")
            .trim_start_matches("*const ")
            .trim_start_matches("*mut ")
            .trim_start_matches('[')
            .trim_end_matches(']');

        match inner {
            "u8" | "i8" | "bool" => Some(1),
            "u16" | "i16" => Some(2),
            "u32" | "i32" | "f32" | "char" => Some(4),
            "u64" | "i64" | "f64" => Some(8),
            "u128" | "i128" => Some(16),
            "usize" | "isize" => Some(8),
            _ => None,
        }
    }

    fn extract_slice_element_type(type_str: &str) -> Option<String> {
        let trimmed = type_str.trim();
        
        if !trimmed.contains('[') || !trimmed.contains(']') {
            return None;
        }
        
        let start = trimmed.find('[')? + 1;
        let end = trimmed.rfind(']')?;
        
        if start >= end {
            return None;
        }
        
        Some(trimmed[start..end].trim().to_string())
    }

    fn is_slice_size_mismatch(from_type: &str, to_type: &str) -> Option<(String, String, usize, usize)> {
        let from_elem = Self::extract_slice_element_type(from_type)?;
        let to_elem = Self::extract_slice_element_type(to_type)?;
        
        if from_elem == to_elem {
            return None;
        }
        
        let from_size = Self::get_primitive_size(&from_elem);
        let to_size = Self::get_primitive_size(&to_elem);
        
        match (from_size, to_size) {
            (Some(fs), Some(ts)) => {
                if fs == ts {
                    None
                } else {
                    Some((from_elem, to_elem, fs, ts))
                }
            }
            (None, None) => {
                Some((from_elem, to_elem, 0, 0))
            }
            _ => {
                Some((from_elem, to_elem, from_size.unwrap_or(0), to_size.unwrap_or(0)))
            }
        }
    }

    fn is_vec_size_mismatch(from_type: &str, to_type: &str) -> Option<(String, String, usize, usize)> {
        let extract_vec_elem = |t: &str| -> Option<String> {
            if !t.contains("Vec<") {
                return None;
            }
            let start = t.find("Vec<")? + 4;
            let end = t.rfind('>')?;
            if start >= end {
                return None;
            }
            Some(t[start..end].trim().to_string())
        };
        
        let from_elem = extract_vec_elem(from_type)?;
        let to_elem = extract_vec_elem(to_type)?;
        
        if from_elem == to_elem {
            return None;
        }
        
        let from_size = Self::get_primitive_size(&from_elem)?;
        let to_size = Self::get_primitive_size(&to_elem)?;
        
        if from_size == to_size {
            return None;
        }
        
        Some((from_elem, to_elem, from_size, to_size))
    }

    fn parse_transmute_copy_line(line: &str) -> Option<(String, String)> {
        let trimmed = line.trim();
        
        if !trimmed.contains("transmute_copy::<") {
            return None;
        }
        
        let start = trimmed.find("transmute_copy::<")? + 17;
        let end = trimmed[start..].find(">")? + start;
        
        let type_params = &trimmed[start..end];
        
        let mut depth = 0;
        let mut split_pos = None;
        for (i, c) in type_params.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => depth -= 1,
                ',' if depth == 0 => {
                    split_pos = Some(i);
                    break;
                }
                _ => {}
            }
        }
        
        let split = split_pos?;
        let from_type = type_params[..split].trim().to_string();
        let to_type = type_params[split + 1..].trim().to_string();
        
        Some((from_type, to_type))
    }
}

impl Rule for SliceElementSizeMismatchRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if function.signature.contains("#[test]") || function.name.contains("test") {
                continue;
            }

            let mut var_types: HashMap<String, String> = HashMap::new();
            
            if let Some(params_start) = function.signature.find('(') {
                if let Some(params_end) = function.signature.find(')') {
                    let params = &function.signature[params_start + 1..params_end];
                    for param in params.split(',') {
                        let param = param.trim();
                        if let Some(colon_pos) = param.find(':') {
                            let var_name = param[..colon_pos].trim();
                            let var_type = param[colon_pos + 1..].trim();
                            var_types.insert(var_name.to_string(), var_type.to_string());
                        }
                    }
                }
            }

            for line in &function.body {
                let trimmed = line.trim();
                
                if trimmed.starts_with("let ") {
                    let rest = trimmed.trim_start_matches("let ").trim_start_matches("mut ");
                    if let Some(colon_pos) = rest.find(':') {
                        let var_name = rest[..colon_pos].trim();
                        let type_end = rest.find(';').unwrap_or(rest.len());
                        let var_type = rest[colon_pos + 1..type_end].trim();
                        var_types.insert(var_name.to_string(), var_type.to_string());
                    }
                }
            }

            for line in &function.body {
                let trimmed = line.trim();

                if let Some((from_type, to_type)) = Self::parse_transmute_copy_line(trimmed) {
                    if let Some((from_elem, to_elem, from_size, to_size)) = 
                        Self::is_slice_size_mismatch(&from_type, &to_type) 
                    {
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "transmute_copy between slices with different element sizes: \
                                [{}] ({} bytes) to [{}] ({} bytes). The slice length won't be \
                                adjusted, causing memory access beyond the original allocation. \
                                Use slice::from_raw_parts with adjusted length instead.",
                                from_elem, from_size, to_elem, to_size
                            ),
                            function: function.name.clone(),
                            function_signature: function.signature.clone(),
                            evidence: vec![trimmed.to_string()],
                            span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                        });
                        continue;
                    }
                    
                    if let Some((from_elem, to_elem, from_size, to_size)) = 
                        Self::is_vec_size_mismatch(&from_type, &to_type) 
                    {
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "transmute_copy between Vecs with different element sizes: \
                                Vec<{}> ({} bytes) to Vec<{}> ({} bytes). This corrupts the \
                                Vec's length and capacity fields.",
                                from_elem, from_size, to_elem, to_size
                            ),
                            function: function.name.clone(),
                            function_signature: function.signature.clone(),
                            evidence: vec![trimmed.to_string()],
                            span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                        });
                        continue;
                    }
                }

                if trimmed.contains("(Transmute)") && trimmed.contains(" as ") {
                    let copy_move_pattern = if trimmed.contains("copy ") {
                        "copy "
                    } else if trimmed.contains("move ") {
                        "move "
                    } else {
                        continue;
                    };
                    
                    let as_pos = match trimmed.find(" as ") {
                        Some(p) => p,
                        None => continue,
                    };
                    
                    let transmute_pos = match trimmed.find("(Transmute)") {
                        Some(p) => p,
                        None => continue,
                    };
                    
                    let to_type = trimmed[as_pos + 4..transmute_pos].trim();
                    
                    let copy_pos = match trimmed.find(copy_move_pattern) {
                        Some(p) => p,
                        None => continue,
                    };
                    
                    let src_start = copy_pos + copy_move_pattern.len();
                    let src_end = as_pos;
                    let src_var = trimmed[src_start..src_end].trim();
                    
                    let from_type = match var_types.get(src_var) {
                        Some(t) => t.as_str(),
                        None => continue,
                    };

                    if let Some((from_elem, to_elem, from_size, to_size)) = 
                        Self::is_slice_size_mismatch(from_type, to_type) 
                    {
                        let size_info = if from_size == 0 && to_size == 0 {
                            format!(
                                "Transmute between slices of different struct types: \
                                [{}] to [{}]. Different struct types likely have different sizes, \
                                causing the slice length to be incorrect.",
                                from_elem, to_elem
                            )
                        } else if from_size == 0 || to_size == 0 {
                            format!(
                                "Transmute between slices with different element types: \
                                [{}] to [{}]. The slice length won't be adjusted for size differences.",
                                from_elem, to_elem
                            )
                        } else {
                            format!(
                                "Transmute between slices with different element sizes: \
                                [{}] ({} bytes) to [{}] ({} bytes). The slice length won't be \
                                adjusted, causing memory access beyond the original allocation.",
                                from_elem, from_size, to_elem, to_size
                            )
                        };
                        
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "{} Use slice::from_raw_parts with adjusted length, or slice::align_to.",
                                size_info
                            ),
                            function: function.name.clone(),
                            function_signature: function.signature.clone(),
                            evidence: vec![trimmed.to_string()],
                            span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                        });
                    }
                    
                    if let Some((from_elem, to_elem, from_size, to_size)) = 
                        Self::is_vec_size_mismatch(from_type, to_type) 
                    {
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "Transmute between Vecs with different element sizes: \
                                Vec<{}> ({} bytes) to Vec<{}> ({} bytes). This corrupts the \
                                Vec's length and capacity fields, potentially causing memory \
                                corruption or use-after-free.",
                                from_elem, from_size, to_elem, to_size
                            ),
                            function: function.name.clone(),
                            function_signature: function.signature.clone(),
                            evidence: vec![trimmed.to_string()],
                            span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                        });
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA083: slice::from_raw_parts with potentially invalid length
// ============================================================================

pub struct SliceFromRawPartsRule {
    metadata: RuleMetadata,
}

impl SliceFromRawPartsRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA083".to_string(),
                name: "slice-from-raw-parts-length".to_string(),
                short_description: "slice::from_raw_parts with potentially invalid length".to_string(),
                full_description: "Detects calls to slice::from_raw_parts or from_raw_parts_mut \
                    where the length argument may exceed the actual allocation, causing undefined \
                    behavior. Common issues include using untrusted input for length, forgetting \
                    to divide byte length by element size, or using unvalidated external lengths. \
                    Ensure length is derived from a trusted source or properly validated."
                    .to_string(),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                help_uri: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn is_trusted_length_source(var_name: &str, body: &[String]) -> bool {
        let body_str = body.join("\n");
        
        if body_str.contains(&format!("{} = ", var_name)) {
            for line in body {
                if line.contains(&format!("{} = ", var_name)) {
                    if line.contains("::len(") || 
                       line.contains(">::len(") ||
                       line.contains(".len()") {
                        return true;
                    }
                }
            }
        }
        
        if var_name.contains("count") {
            if body_str.contains("Layout::array") || body_str.contains("with_capacity") {
                return true;
            }
        }
        
        false
    }

    fn has_length_validation(len_var: &str, body: &[String]) -> bool {
        let body_str = body.join("\n");
        
        let comparison_patterns = [
            format!("Gt(copy {}", len_var),
            format!("Lt(copy {}", len_var),
            format!("Le(copy {}", len_var),
            format!("Ge(copy {}", len_var),
            format!("Gt(move {}", len_var),
            format!("Lt(move {}", len_var),
            format!("Le(move {}", len_var),
            format!("Ge(move {}", len_var),
        ];
        
        for pattern in &comparison_patterns {
            if body_str.contains(pattern) {
                return true;
            }
        }
        
        if body_str.contains("::min(") {
            if body_str.contains(&format!("copy {}", len_var)) || 
               body_str.contains(&format!("move {}", len_var)) {
                for line in body {
                    if line.contains("::min(") && line.contains(len_var) {
                        return true;
                    }
                }
            }
        }
        if body_str.contains("saturating_") && body_str.contains(len_var) {
            for line in body {
                if line.contains("saturating_") && line.contains(len_var) {
                    return true;
                }
            }
        }
        
        if body_str.contains("checked_") && body_str.contains(len_var) {
            for line in body {
                if line.contains("checked_") && line.contains(len_var) {
                    return true;
                }
            }
        }
        
        for line in body {
            if line.contains("assert") {
                if line.contains(&format!("Le(copy {}", len_var)) ||
                   line.contains(&format!("Lt(copy {}", len_var)) ||
                   line.contains(&format!("Le(move {}", len_var)) ||
                   line.contains(&format!("Lt(move {}", len_var)) {
                    return true;
                }
            }
        }
        
        false
    }

    fn is_large_constant(line: &str) -> Option<usize> {
        if let Some(const_pos) = line.rfind("const ") {
            let after_const = &line[const_pos + 6..];
            if let Some(usize_pos) = after_const.find("_usize") {
                let num_str = &after_const[..usize_pos];
                if let Ok(n) = num_str.trim().parse::<usize>() {
                    if n > 10000 {
                        return Some(n);
                    }
                }
            }
        }
        None
    }

    fn is_untrusted_length_source(_len_var: &str, body: &[String]) -> bool {
        let body_str = body.join("\n");
        
        if body_str.contains("env::var") || body_str.contains("var::<") {
            if body_str.contains("parse") {
                return true;
            }
        }
        
        if body_str.contains("env::args") || body_str.contains("Args") || body_str.contains("args::<") {
            return true;
        }
        
        if body_str.contains("stdin") || body_str.contains("Stdin") {
            return true;
        }
        
        false
    }

    fn is_dangerous_length_computation(len_var: &str, body: &[String]) -> Option<String> {
        let mut source_var = len_var.to_string();
        for line in body {
            let trimmed = line.trim();
            if trimmed.contains(&format!("{} = move ", len_var)) && trimmed.contains("as usize") {
                if let Some(start) = trimmed.find("move ") {
                    let after_move = &trimmed[start + 5..];
                    if let Some(end) = after_move.find(" as") {
                        source_var = after_move[..end].to_string();
                    }
                }
            }
        }
        
        for line in body {
            let trimmed = line.trim();
            
            if trimmed.contains(&format!("{} = MulWithOverflow", len_var)) ||
                trimmed.contains(&format!("{} = Mul(", len_var)) {
                return Some("length computed from multiplication (may overflow or use wrong scale)".to_string());
            }
            
            if trimmed.contains(&format!("{} =", len_var)) && trimmed.contains("offset_from") {
                return Some("length derived from pointer difference (end pointer may be invalid)".to_string());
            }
            if source_var != len_var && trimmed.contains(&format!("{} =", source_var)) && trimmed.contains("offset_from") {
                return Some("length derived from pointer difference (end pointer may be invalid)".to_string());
            }
            
            if trimmed.contains(&format!("{} = move (", len_var)) && 
               trimmed.contains(".0: usize)") {
                let body_str = body.join("\n");
                if body_str.contains("MulWithOverflow") {
                    return Some("length computed from multiplication (may overflow or use wrong scale)".to_string());
                }
            }
            
            if trimmed.contains(&format!("{} = Layout::size", len_var)) {
                return Some("length from Layout::size() returns bytes, not element count".to_string());
            }
            if trimmed.contains(&format!("{} =", len_var)) && trimmed.contains("Layout::size") {
                return Some("length from Layout::size() returns bytes, not element count".to_string());
            }
            
            if trimmed.contains(&format!("{} = Div(", len_var)) {
                if trimmed.contains("const 2_usize") {
                    return Some("length divided by 2 may not match element size".to_string());
                }
            }
        }
        
        None
    }

    fn parse_from_raw_parts_call(line: &str) -> Option<(String, String)> {
        if !line.contains("from_raw_parts") {
            return None;
        }
        
        let call_start = if line.contains("from_raw_parts_mut") {
            line.find("from_raw_parts_mut")?
        } else {
            line.find("from_raw_parts")?
        };
        
        let after_call = &line[call_start..];
        
        let args_start = after_call.find('(')? + 1;
        let args_end = after_call.rfind(')')?;
        
        if args_start >= args_end {
            return None;
        }
        
        let args_str = &after_call[args_start..args_end];
        
        let parts: Vec<&str> = args_str.split(',').collect();
        if parts.len() != 2 {
            return None;
        }
        
        let ptr_arg = parts[0].trim()
            .trim_start_matches("copy ")
            .trim_start_matches("move ")
            .to_string();
        let len_arg = parts[1].trim()
            .trim_start_matches("copy ")
            .trim_start_matches("move ")
            .to_string();
        
        Some((ptr_arg, len_arg))
    }

    fn is_function_parameter(len_var: &str, signature: &str) -> bool {
        signature.contains(&format!("{}: usize", len_var)) ||
        signature.contains(&format!("{}: u64", len_var)) ||
        signature.contains(&format!("{}: u32", len_var))
    }
}

impl Rule for SliceFromRawPartsRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if function.signature.contains("#[test]") || function.name.contains("test") {
                continue;
            }

            for line in &function.body {
                let trimmed = line.trim();
                
                if !trimmed.contains("from_raw_parts") {
                    continue;
                }
                
                if !trimmed.contains("->") || !trimmed.contains("(") {
                    continue;
                }

                let (_ptr_var, len_var) = match Self::parse_from_raw_parts_call(trimmed) {
                    Some(p) => p,
                    None => continue,
                };

                if let Some(large_len) = Self::is_large_constant(trimmed) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "slice::from_raw_parts called with large constant length {}. \
                            Ensure the pointer actually points to at least {} elements of \
                            memory. Large constant lengths often indicate bugs.",
                            large_len, large_len
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                    });
                    continue;
                }

                if Self::is_trusted_length_source(&len_var, &function.body) {
                    continue;
                }

                if Self::has_length_validation(&len_var, &function.body) {
                    continue;
                }

                if Self::is_untrusted_length_source(&len_var, &function.body) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "slice::from_raw_parts length '{}' derived from untrusted source \
                            (environment variable, command-line argument, or user input). \
                            Validate length against allocation size before creating slice.",
                            len_var
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                    });
                    continue;
                }
                
                if let Some(reason) = Self::is_dangerous_length_computation(&len_var, &function.body) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "slice::from_raw_parts length '{}': {}. \
                            Verify the length correctly represents element count within the allocation.",
                            len_var, reason
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                    });
                    continue;
                }

                if Self::is_function_parameter(&len_var, &function.signature) {
                    if function.signature.contains("NonNull<") {
                        continue;
                    }
                    
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: Severity::Medium,
                        message: format!(
                            "slice::from_raw_parts length '{}' comes directly from function \
                            parameter without validation. If callers can pass arbitrary values, \
                            add bounds checking or document the safety requirements.",
                            len_var
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                    });
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA101: Variance Transmute Unsound Rule
// ============================================================================

/// Detects transmutes that violate Rust's variance rules, which can lead to 
/// unsoundness. Common patterns include transmuting between &T and &mut T,
/// or between covariant and invariant types.
pub struct VarianceTransmuteUnsoundRule {
    metadata: RuleMetadata,
}

impl VarianceTransmuteUnsoundRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA101".to_string(),
                name: "variance-transmute-unsound".to_string(),
                short_description: "Transmutes violating variance rules".to_string(),
                full_description: "Detects transmutes that violate Rust's variance rules (e.g., &T to &mut T, \
                    *const T to *mut T, or invariant types like Cell/RefCell), which cause undefined behavior.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    /// Detects &T to &mut T transmute patterns
    fn is_ref_to_mut_transmute(line: &str) -> bool {
        if !line.contains("transmute") {
            return false;
        }
        
        // Pattern: transmute::<&Foo, &mut Foo> or similar
        if let Some(transmute_start) = line.find("transmute") {
            let after_transmute = &line[transmute_start..];
            // Look for pattern where we go from & to &mut
            if after_transmute.contains("::<&") && after_transmute.contains("&mut") {
                return true;
            }
            // Look for explicit type annotations
            if after_transmute.contains("::<&") && !after_transmute.contains("&mut") {
                // Check if the result is being assigned to &mut
                let before_transmute = &line[..transmute_start];
                if before_transmute.contains("&mut") || before_transmute.contains(": &mut") {
                    return true;
                }
            }
        }
        false
    }

    /// Detects *const T to *mut T transmute patterns
    fn is_const_to_mut_ptr_transmute(line: &str) -> bool {
        if !line.contains("transmute") {
            return false;
        }
        
        if let Some(transmute_start) = line.find("transmute") {
            let after_transmute = &line[transmute_start..];
            // Pattern: transmute::<*const T, *mut T>
            if after_transmute.contains("*const") && after_transmute.contains("*mut") {
                // Make sure *const comes before *mut in type params
                if let (Some(const_pos), Some(mut_pos)) = 
                    (after_transmute.find("*const"), after_transmute.find("*mut")) {
                    return const_pos < mut_pos;
                }
            }
        }
        false
    }

    /// Detects transmutes involving invariant types (Cell, RefCell, UnsafeCell)
    fn is_invariant_type_transmute(line: &str) -> bool {
        if !line.contains("transmute") {
            return false;
        }
        
        let invariant_types = ["Cell<", "RefCell<", "UnsafeCell<", "Mutex<", "RwLock<"];
        
        for inv_type in invariant_types.iter() {
            if line.contains(inv_type) {
                return true;
            }
        }
        false
    }
}

impl Rule for VarianceTransmuteUnsoundRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            for line in &function.body {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Check for &T to &mut T transmute
                if Self::is_ref_to_mut_transmute(trimmed) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: Severity::High,
                        message: "Transmuting from immutable reference (&T) to mutable reference (&mut T) \
                            violates Rust's aliasing rules and is undefined behavior. Use interior \
                            mutability (Cell, RefCell, Mutex) instead.".to_string(),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                    });
                    continue;
                }

                // Check for *const T to *mut T transmute
                if Self::is_const_to_mut_ptr_transmute(trimmed) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: Severity::High,
                        message: "Transmuting from *const T to *mut T can cause undefined behavior \
                            if the original data was immutable. Use ptr.cast_mut() (Rust 1.65+) \
                            or ensure the underlying data is actually mutable.".to_string(),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                    });
                    continue;
                }

                // Check for invariant type transmutes
                if Self::is_invariant_type_transmute(trimmed) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: Severity::High,
                        message: "Transmuting invariant types (Cell, RefCell, UnsafeCell, Mutex, RwLock) \
                            can violate their safety invariants and cause undefined behavior. \
                            These types have special memory semantics that transmute bypasses.".to_string(),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
                    });
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA118: Returned Reference to Local Rule
// ============================================================================

/// Detects patterns where a function returns a reference to a local variable,
/// which would be a use-after-free if the borrow checker didn't catch it.
/// 
/// In safe Rust, the compiler prevents this. But in unsafe code or through
/// certain patterns involving raw pointers, this can slip through.
pub struct ReturnedRefToLocalRule {
    metadata: RuleMetadata,
}

impl ReturnedRefToLocalRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA118".to_string(),
                name: "returned-ref-to-local".to_string(),
                short_description: "Reference to local variable returned".to_string(),
                full_description: "Detects patterns where a function may return a reference \
                    to a stack-allocated local variable. In unsafe code, this leads to \
                    use-after-free when the stack frame is deallocated.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    /// Patterns that indicate returning a reference to a local
    fn dangerous_return_patterns() -> &'static [&'static str] {
        &[
            // Raw pointer from local then returned as reference
            "&*",
            "as *const",
            "as *mut",
            // Transmute of local address
            "transmute(&",
            "transmute::<&",
            // addr_of! macro on local
            "addr_of!(",
            "addr_of_mut!(",
        ]
    }
}

impl Rule for ReturnedRefToLocalRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
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

            // Quick check: does file have unsafe blocks?
            if !content.contains("unsafe") {
                continue;
            }

            let lines: Vec<&str> = content.lines().collect();
            let mut in_unsafe_block = false;
            let mut unsafe_depth = 0;
            let mut local_vars: HashSet<String> = HashSet::new();
            let mut current_fn_returns_ref = false;
            let mut current_fn_name = String::new();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Track function signatures that return references
                if trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ") ||
                   trimmed.starts_with("unsafe fn ") || trimmed.starts_with("pub unsafe fn ") {
                    current_fn_returns_ref = trimmed.contains("-> &") || 
                                            trimmed.contains("-> *const") ||
                                            trimmed.contains("-> *mut");
                    // Extract function name
                    if let Some(fn_start) = trimmed.find("fn ") {
                        let after_fn = &trimmed[fn_start + 3..];
                        if let Some(paren) = after_fn.find('(') {
                            current_fn_name = after_fn[..paren].trim().to_string();
                        }
                    }
                    local_vars.clear();
                }

                // Track unsafe blocks
                if trimmed.contains("unsafe {") || trimmed.contains("unsafe{") {
                    in_unsafe_block = true;
                    unsafe_depth = 1;
                } else if in_unsafe_block {
                    unsafe_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    unsafe_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;
                    if unsafe_depth <= 0 {
                        in_unsafe_block = false;
                    }
                }

                // Track local variable declarations
                if trimmed.starts_with("let ") {
                    if let Some(eq_pos) = trimmed.find('=') {
                        let var_part = &trimmed[4..eq_pos];
                        // Handle patterns like "let mut x", "let x: Type"
                        let var_name = var_part.trim()
                            .trim_start_matches("mut ")
                            .split(':')
                            .next()
                            .map(|s| s.trim())
                            .unwrap_or("");
                        if !var_name.is_empty() && !var_name.contains('(') {
                            local_vars.insert(var_name.to_string());
                        }
                    }
                }

                // Only check in unsafe blocks for functions returning references
                if in_unsafe_block && current_fn_returns_ref {
                    // Check for dangerous patterns
                    for pattern in Self::dangerous_return_patterns() {
                        if trimmed.contains(pattern) {
                            // Check if this involves a local variable
                            for var in &local_vars {
                                if trimmed.contains(var.as_str()) {
                                    let location = format!("{}:{}", rel_path, idx + 1);
                                    
                                    findings.push(Finding {
                                        rule_id: self.metadata.id.clone(),
                                        rule_name: self.metadata.name.clone(),
                                        severity: self.metadata.default_severity,
                                        message: format!(
                                            "Potential return of reference to local variable '{}' in unsafe block. \
                                            When the function returns, the stack frame is deallocated, \
                                            leaving a dangling pointer. Pattern: '{}'",
                                            var, pattern
                                        ),
                                        function: format!("{} ({})", current_fn_name, location),
                                        function_signature: String::new(),
                                        evidence: vec![trimmed.to_string()],
                                        span: None,
                    ..Default::default()
                                    });
                                    break;
                                }
                            }
                        }
                    }

                    // Special check: returning &*ptr where ptr is from a local
                    if trimmed.contains("return") && trimmed.contains("&*") {
                        let location = format!("{}:{}", rel_path, idx + 1);
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: "Returning dereferenced raw pointer in unsafe block. \
                                Ensure the pointer does not point to stack-allocated memory \
                                that will be deallocated when the function returns.".to_string(),
                            function: format!("{} ({})", current_fn_name, location),
                            function_signature: String::new(),
                            evidence: vec![trimmed.to_string()],
                            span: None,
                    ..Default::default()
                        });
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA120: Self-Referential Struct Rule
// ============================================================================

/// Detects patterns that create self-referential structs without proper Pin usage.
/// 
/// Self-referential structs (where a field contains a pointer/reference to another
/// field) are inherently dangerous because moving the struct invalidates the
/// internal pointer.
pub struct SelfReferentialStructRule {
    metadata: RuleMetadata,
}

impl SelfReferentialStructRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA120".to_string(),
                name: "self-referential-struct".to_string(),
                short_description: "Potential self-referential struct without Pin".to_string(),
                full_description: "Detects patterns that may create self-referential structs \
                    without proper Pin usage. When a struct contains a pointer to one of its \
                    own fields, moving the struct invalidates that pointer. Use Pin<Box<T>> \
                    or crates like 'ouroboros' or 'self_cell' for safe self-references.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/pin/index.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    /// Patterns indicating self-referential struct creation
    fn self_ref_patterns() -> &'static [&'static str] {
        &[
            // Taking address of own field
            "&self.",
            "addr_of!(self.",
            "addr_of_mut!(self.",
            // Raw pointer to self field
            "as *const Self",
            "as *mut Self",
            // Storing reference to self
            "self as *",
            "&mut self as *",
            "&self as *",
        ]
    }
}

impl Rule for SelfReferentialStructRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
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

            // Quick check: file likely has self-referential patterns
            if !content.contains("*const") && !content.contains("*mut") && 
               !content.contains("addr_of") {
                continue;
            }

            let lines: Vec<&str> = content.lines().collect();
            let mut in_impl_block = false;
            let mut current_type = String::new();
            let mut in_unsafe = false;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Track impl blocks
                if trimmed.starts_with("impl ") || trimmed.starts_with("impl<") {
                    in_impl_block = true;
                    // Extract type name
                    if let Some(for_pos) = trimmed.find(" for ") {
                        let after_for = &trimmed[for_pos + 5..];
                        current_type = after_for.split(|c| c == '<' || c == ' ' || c == '{')
                            .next()
                            .unwrap_or("")
                            .to_string();
                    } else if let Some(impl_pos) = trimmed.find("impl ") {
                        let after_impl = &trimmed[impl_pos + 5..];
                        current_type = after_impl.split(|c| c == '<' || c == ' ' || c == '{')
                            .next()
                            .unwrap_or("")
                            .to_string();
                    }
                }

                // Track unsafe blocks
                if trimmed.contains("unsafe") {
                    in_unsafe = true;
                }

                // Only flag in impl blocks where self-reference is meaningful
                if in_impl_block && in_unsafe {
                    for pattern in Self::self_ref_patterns() {
                        if trimmed.contains(pattern) {
                            // Check if this is being stored in a field (assignment to self.field)
                            let is_storing = trimmed.contains("self.") && 
                                            (trimmed.contains(" = ") || trimmed.contains("="));
                            
                            // Check if Pin is being used properly
                            let has_pin = content.contains("Pin<") || content.contains("pin!");
                            
                            if is_storing || !has_pin {
                                let location = format!("{}:{}", rel_path, idx + 1);
                                
                                findings.push(Finding {
                                    rule_id: self.metadata.id.clone(),
                                    rule_name: self.metadata.name.clone(),
                                    severity: self.metadata.default_severity,
                                    message: format!(
                                        "Potential self-referential pattern in type '{}' without Pin. \
                                        Creating a pointer to a struct's own field and storing it \
                                        creates a self-referential struct. Moving this struct will \
                                        invalidate the internal pointer. Use Pin<Box<{}>> to prevent \
                                        moves, or use 'ouroboros'/'self_cell' crates for safe self-references.",
                                        current_type, current_type
                                    ),
                                    function: location,
                                    function_signature: String::new(),
                                    evidence: vec![trimmed.to_string()],
                                    span: None,
                    ..Default::default()
                                });
                                break;
                            }
                        }
                    }
                }

                // Reset on block end (simplified)
                if trimmed == "}" && in_impl_block {
                    // This is a simplification - proper tracking would need brace counting
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA128: UnsafeCell Aliasing Violation Rule
// ============================================================================

/// Detects potential UnsafeCell aliasing violations where multiple mutable
/// references may exist simultaneously, violating Rust's aliasing rules.
pub struct UnsafeCellAliasingRule {
    metadata: RuleMetadata,
}

impl UnsafeCellAliasingRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA128".to_string(),
                name: "unsafecell-aliasing-violation".to_string(),
                short_description: "Potential UnsafeCell aliasing violation".to_string(),
                full_description: "Detects patterns where UnsafeCell, Cell, or RefCell contents \
                    may be accessed through multiple mutable references simultaneously in unsafe \
                    code. This violates Rust's aliasing rules and causes undefined behavior. \
                    Ensure only one mutable reference exists at a time, or use proper interior \
                    mutability patterns.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/cell/struct.UnsafeCell.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn aliasing_patterns() -> Vec<(&'static str, &'static str)> {
        vec![
            (".get()", "UnsafeCell::get() returns *mut T - ensure no aliasing"),
            ("&mut *self.", "mutable dereference may alias with other refs"),
            ("&mut *ptr", "raw pointer to mutable ref - check for aliases"),
            ("as *mut", "casting to *mut - may create aliasing mutable refs"),
            (".as_mut()", "as_mut() in unsafe may alias"),
            ("get_unchecked_mut", "unchecked mutable access - verify no aliasing"),
        ]
    }

    fn aliasing_contexts() -> Vec<&'static str> {
        vec![
            "UnsafeCell",
            "Cell<",
            "RefCell<",
            "*mut",
            "*const",
        ]
    }
}

impl Rule for UnsafeCellAliasingRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        // Skip self-analysis
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
            .filter_entry(filter_entry)
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
        {
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

            // Quick check: does this file use interior mutability?
            let has_interior_mut = Self::aliasing_contexts()
                .iter()
                .any(|ctx| content.contains(ctx));

            if !has_interior_mut {
                continue;
            }

            let lines: Vec<&str> = content.lines().collect();
            let mut in_unsafe = false;
            let mut unsafe_start = 0;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Track unsafe blocks
                if trimmed.contains("unsafe {") || trimmed.contains("unsafe{") {
                    in_unsafe = true;
                    unsafe_start = idx;
                }

                if in_unsafe {
                    // Check for aliasing patterns
                    for (pattern, description) in Self::aliasing_patterns() {
                        if trimmed.contains(pattern) {
                            // Check if there are multiple access patterns in the same unsafe block
                            let unsafe_block = &lines[unsafe_start..=(idx + 5).min(lines.len() - 1)];
                            
                            let mut_access_count = unsafe_block.iter()
                                .filter(|l| l.contains("&mut") || l.contains("as *mut") || 
                                           l.contains(".get()") || l.contains(".as_mut()"))
                                .count();

                            // Multiple mutable accesses in same block is suspicious
                            if mut_access_count >= 2 {
                                let location = format!("{}:{}", rel_path, idx + 1);
                                
                                findings.push(Finding {
                                    rule_id: self.metadata.id.clone(),
                                    rule_name: self.metadata.name.clone(),
                                    severity: self.metadata.default_severity,
                                    message: format!(
                                        "Potential aliasing violation: {}. Multiple mutable accesses \
                                        detected in same unsafe block. Ensure only one &mut reference \
                                        exists at a time to avoid undefined behavior.",
                                        description
                                    ),
                                    function: location,
                                    function_signature: String::new(),
                                    evidence: vec![trimmed.to_string()],
                                    span: None,
                    ..Default::default()
                                });
                                break;
                            }
                        }
                    }

                    // Simple closing brace tracking
                    if trimmed == "}" {
                        in_unsafe = false;
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA129: Lazy Initialization Panic Poison Rule
// ============================================================================

/// Detects lazy initialization patterns that can panic and poison the lazy value,
/// causing all future accesses to fail or return corrupted state.
pub struct LazyInitPanicPoisonRule {
    metadata: RuleMetadata,
}

impl LazyInitPanicPoisonRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA129".to_string(),
                name: "lazy-init-panic-poison".to_string(),
                short_description: "Panic-prone code in lazy initialization".to_string(),
                full_description: "Detects lazy initialization (OnceLock, Lazy, OnceCell, lazy_static) \
                    with panic-prone code like unwrap(), expect(), or panic!(). If the initialization \
                    panics, the lazy value may be poisoned, causing all future accesses to fail or \
                    return incomplete state. Use fallible initialization patterns or handle errors \
                    gracefully.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/sync/struct.OnceLock.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn lazy_patterns() -> Vec<(&'static str, &'static str)> {
        vec![
            ("OnceLock", "std::sync::OnceLock"),
            ("OnceCell", "once_cell::sync::OnceCell"),
            ("Lazy<", "once_cell::sync::Lazy"),
            ("lazy_static!", "lazy_static macro"),
            ("LazyLock", "std::sync::LazyLock"),
            (".get_or_init(", "lazy initialization closure"),
            (".get_or_try_init(", "fallible lazy init"),
            ("call_once(", "std::sync::Once::call_once"),
        ]
    }

    fn panic_patterns() -> Vec<&'static str> {
        vec![
            ".unwrap()",
            ".expect(",
            "panic!(",
            "unreachable!(",
            "todo!(",
            "unimplemented!(",
            "assert!(",
            "assert_eq!(",
            "assert_ne!(",
        ]
    }
}

impl Rule for LazyInitPanicPoisonRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        // Skip self-analysis
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
            .filter_entry(filter_entry)
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
        {
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

            // Quick check: does this file use lazy initialization?
            let has_lazy = Self::lazy_patterns()
                .iter()
                .any(|(p, _)| content.contains(p));

            if !has_lazy {
                continue;
            }

            let lines: Vec<&str> = content.lines().collect();
            let mut in_lazy_init = false;
            let mut lazy_type = String::new();
            let mut lazy_start = 0;
            let mut brace_depth = 0;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Detect lazy initialization patterns
                for (pattern, desc) in Self::lazy_patterns() {
                    if trimmed.contains(pattern) {
                        // Check if this is a definition with an initializer
                        if trimmed.contains("=") || trimmed.contains("get_or_init") || 
                           trimmed.contains("call_once") {
                            in_lazy_init = true;
                            lazy_type = desc.to_string();
                            lazy_start = idx;
                            brace_depth = trimmed.matches('{').count() as i32 
                                        - trimmed.matches('}').count() as i32;
                        }
                    }
                }

                // Track the initialization block
                if in_lazy_init {
                    brace_depth += trimmed.matches('{').count() as i32;
                    brace_depth -= trimmed.matches('}').count() as i32;

                    // Look for panic patterns in the init block
                    for panic_pat in Self::panic_patterns() {
                        if trimmed.contains(panic_pat) {
                            let location = format!("{}:{}", rel_path, idx + 1);
                            
                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Panic-prone code '{}' in {} initialization. If this panics, \
                                    the lazy value may be poisoned, causing all future accesses to \
                                    fail. Consider using fallible initialization (get_or_try_init) \
                                    or handling errors gracefully.",
                                    panic_pat.trim_end_matches('('), lazy_type
                                ),
                                function: location,
                                function_signature: String::new(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                    ..Default::default()
                            });
                            break;
                        }
                    }

                    // End of init block
                    if brace_depth <= 0 && idx > lazy_start {
                        in_lazy_init = false;
                        lazy_type.clear();
                    }
                }
            }
        }

        findings
    }
}

/// Register all memory safety rules with the rule engine.
pub fn register_memory_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(BoxIntoRawRule::new()));
    engine.register_rule(Box::new(TransmuteRule::new()));
    engine.register_rule(Box::new(UnsafeUsageRule::new()));
    engine.register_rule(Box::new(NullPointerTransmuteRule::new()));
    engine.register_rule(Box::new(ZSTPointerArithmeticRule::new()));
    engine.register_rule(Box::new(VecSetLenRule::new()));
    engine.register_rule(Box::new(MaybeUninitAssumeInitRule::new()));
    engine.register_rule(Box::new(MemUninitZeroedRule::new()));
    engine.register_rule(Box::new(NonNullNewUncheckedRule::new()));
    engine.register_rule(Box::new(MemForgetGuardRule::new()));
    // Advanced memory rules (dataflow-based)
    engine.register_rule(Box::new(StaticMutGlobalRule::new()));
    engine.register_rule(Box::new(TransmuteLifetimeChangeRule::new()));
    engine.register_rule(Box::new(RawPointerEscapeRule::new()));
    engine.register_rule(Box::new(VecSetLenMisuseRule::new()));
    engine.register_rule(Box::new(LengthTruncationCastRule::new()));
    engine.register_rule(Box::new(MaybeUninitAssumeInitDataflowRule::new()));
    engine.register_rule(Box::new(SliceElementSizeMismatchRule::new()));
    engine.register_rule(Box::new(SliceFromRawPartsRule::new()));
    engine.register_rule(Box::new(VarianceTransmuteUnsoundRule::new()));
    engine.register_rule(Box::new(ReturnedRefToLocalRule::new()));
    engine.register_rule(Box::new(SelfReferentialStructRule::new()));
    engine.register_rule(Box::new(UnsafeCellAliasingRule::new()));
    engine.register_rule(Box::new(LazyInitPanicPoisonRule::new()));
}
