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

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};
use super::collect_matches;
use std::collections::HashSet;

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

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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
            },
        }
    }
}

impl Rule for NullPointerTransmuteRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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
            },
        }
    }
}

impl Rule for ZSTPointerArithmeticRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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
            },
        }
    }
}

impl Rule for MaybeUninitAssumeInitRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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
            },
        }
    }
}

impl Rule for MemUninitZeroedRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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
            },
        }
    }
}

impl Rule for NonNullNewUncheckedRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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
            },
        }
    }
}

impl Rule for MemForgetGuardRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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
                });
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
}
