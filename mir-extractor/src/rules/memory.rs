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

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity, SourceSpan};
use super::collect_matches;

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
                short_description: "Usage of unsafe block".to_string(),
                full_description: "Flags functions containing unsafe blocks for audit.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for UnsafeUsageRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| line.contains("unsafe"))
                .map(|line| line.trim().to_string())
                .collect();

            if !evidence.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Function `{}` contains unsafe blocks",
                        function.name
                    ),
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
// RUSTCOLA026: Vec::set_len
// ============================================================================

pub struct VecSetLenRule {
    metadata: RuleMetadata,
}

impl VecSetLenRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA026".to_string(),
                name: "vec-set-len".to_string(),
                short_description: "Unsafe Vec::set_len usage".to_string(),
                full_description: "Detects usage of Vec::set_len, which is unsafe and can lead to memory safety issues if the new length exceeds the allocated capacity or if uninitialized memory is exposed.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for VecSetLenRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| line.contains("set_len") && line.contains("Vec"))
                .map(|line| line.trim().to_string())
                .collect();

            if !evidence.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!("Unsafe Vec::set_len usage in `{}`", function.name),
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
// RUSTCOLA035: MaybeUninit::assume_init
// ============================================================================

pub struct MaybeUninitAssumeInitRule {
    metadata: RuleMetadata,
}

impl MaybeUninitAssumeInitRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA035".to_string(),
                name: "maybe-uninit-assume-init".to_string(),
                short_description: "MaybeUninit::assume_init without initialization".to_string(),
                full_description: "Detects calls to MaybeUninit::assume_init which assumes the value has been properly initialized. Using this on uninitialized memory is undefined behavior.".to_string(),
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
        let mut findings = Vec::new();

        for function in &package.functions {
            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| line.contains("assume_init") && line.contains("MaybeUninit"))
                .map(|line| line.trim().to_string())
                .collect();

            if !evidence.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!("MaybeUninit::assume_init usage in `{}`", function.name),
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
// RUSTCOLA036: mem::uninitialized / mem::zeroed
// ============================================================================

pub struct MemUninitZeroedRule {
    metadata: RuleMetadata,
}

impl MemUninitZeroedRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA036".to_string(),
                name: "mem-uninitialized-zeroed".to_string(),
                short_description: "Usage of deprecated mem::uninitialized or potentially dangerous mem::zeroed".to_string(),
                full_description: "Detects use of std::mem::uninitialized (deprecated and UB) and std::mem::zeroed (dangerous for non-zero types). Use MaybeUninit instead.".to_string(),
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
        let mut findings = Vec::new();

        for function in &package.functions {
            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| {
                    let lower = line.to_lowercase();
                    (lower.contains("mem::uninitialized") || lower.contains("mem::zeroed"))
                        && !lower.contains("maybeuninit")
                })
                .map(|line| line.trim().to_string())
                .collect();

            if !evidence.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!("Dangerous mem::uninitialized or mem::zeroed usage in `{}`", function.name),
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
