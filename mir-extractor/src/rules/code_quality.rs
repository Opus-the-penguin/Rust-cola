//! Code quality and miscellaneous rules.
//!
//! Rules detecting code quality issues:
//! - Crate-wide allow lint (RUSTCOLA049)
//! - Misordered assert_eq arguments (RUSTCOLA050)
//! - Try operator on io::Result (RUSTCOLA051)
//! - Local RefCell patterns (RUSTCOLA052)
//! - Unnecessary borrow_mut (RUSTCOLA057)
//! - Dead stores in arrays (RUSTCOLA068)
//! - Overscoped allow attributes (RUSTCOLA072)
//! - Commented-out code (RUSTCOLA092)

#![allow(dead_code)]

use crate::{Confidence, Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity, SourceFile};
use std::collections::HashMap;
use std::path::Path;

// ============================================================================
// RUSTCOLA049: Crate-Wide Allow Attribute
// ============================================================================

/// Detects crate-wide #![allow(...)] attributes that disable lints.
pub struct CrateWideAllowRule {
    metadata: RuleMetadata,
}

impl CrateWideAllowRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA049".to_string(),
                name: "crate-wide-allow".to_string(),
                short_description: "Crate-wide allow attribute disables lints".to_string(),
                full_description: "Detects crate-level #![allow(...)] attributes that disable \
                    lints for the entire crate. This reduces security coverage. Use more \
                    targeted #[allow(...)] on specific items instead.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    fn has_crate_wide_allow(line: &str) -> bool {
        line.trim().starts_with("#![allow")
    }

    fn extract_allowed_lints(line: &str) -> Vec<String> {
        if let Some(start) = line.find("#![allow(") {
            if let Some(end) = line[start..].find(')') {
                let content = &line[start + 9..start + end];
                return content
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
        Vec::new()
    }
}

impl Rule for CrateWideAllowRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut reported = false;

        for function in &package.functions {
            for line in &function.body {
                if Self::has_crate_wide_allow(line) && !reported {
                    let lints = Self::extract_allowed_lints(line);
                    let lint_list = if lints.is_empty() {
                        "unknown lints".to_string()
                    } else {
                        lints.join(", ")
                    };

                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "Crate-wide #![allow(...)] disables lints for entire crate: {}. \
                            Consider item-level #[allow(...)] for more targeted suppression.",
                            lint_list
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![line.clone()],
                        span: None,
                    ..Default::default()
                    });
                    reported = true;
                    break;
                }
            }
            if reported {
                break;
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA050: Misordered assert_eq Arguments
// ============================================================================

/// Detects assert_eq! calls where literal appears as first argument instead of second.
pub struct MisorderedAssertEqRule {
    metadata: RuleMetadata,
}

impl MisorderedAssertEqRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA050".to_string(),
                name: "misordered-assert-eq".to_string(),
                short_description: "assert_eq arguments may be misordered".to_string(),
                full_description: "Detects assert_eq! calls where a literal or constant appears \
                    as the first argument instead of the second. Convention is assert_eq!(actual, expected) \
                    so error messages show 'expected X but got Y' correctly.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    fn looks_like_misordered_assert(&self, function: &MirFunction) -> bool {
        let mut has_misordered_promoted = false;
        let mut has_assert_failed = false;
        
        for line in &function.body {
            let trimmed = line.trim();
            
            // Check for promoted constant in FIRST position (_3)
            if trimmed.starts_with("_3 = const") && trimmed.contains("::promoted[") {
                has_misordered_promoted = true;
            }
            
            if trimmed.contains("assert_failed") {
                has_assert_failed = true;
            }
        }
        
        has_misordered_promoted && has_assert_failed
    }
}

impl Rule for MisorderedAssertEqRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.looks_like_misordered_assert(function) {
                let mut evidence = vec![];
                for line in &function.body {
                    if line.contains("::promoted[") || line.contains("assert_failed") {
                        evidence.push(line.clone());
                    }
                }
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: "assert_eq! may have misordered arguments. Convention is \
                        assert_eq!(actual, expected) where 'expected' is typically a literal.".to_string(),
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
// RUSTCOLA051: Try Operator on io::Result
// ============================================================================

/// Detects use of ? operator on io::Result without additional context.
pub struct TryIoResultRule {
    metadata: RuleMetadata,
}

impl TryIoResultRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA051".to_string(),
                name: "try-io-result".to_string(),
                short_description: "Try operator (?) used on io::Result".to_string(),
                full_description: "Detects use of the ? operator on std::io::Result, which can \
                    obscure IO errors. Prefer explicit error handling with .map_err() to add context.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    fn looks_like_io_result_try(&self, function: &MirFunction) -> bool {
        let mut has_io_error_type = false;
        let mut has_discriminant_check = false;
        
        if function.signature.contains("std::io::Error") || function.signature.contains("io::Error") {
            has_io_error_type = true;
        }
        
        for line in &function.body {
            if line.contains("discriminant(") {
                has_discriminant_check = true;
                break;
            }
        }
        
        has_io_error_type && has_discriminant_check
    }
}

impl Rule for TryIoResultRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.looks_like_io_result_try(function) {
                let mut evidence = vec![];
                for line in &function.body {
                    if line.to_lowercase().contains("io::error") 
                        || line.to_lowercase().contains("discriminant") {
                        evidence.push(line.clone());
                        if evidence.len() >= 3 {
                            break;
                        }
                    }
                }
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: "Using ? operator on io::Result may lose error context. \
                        Consider using .map_err() to add file paths or operation details.".to_string(),
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
// RUSTCOLA052: Local RefCell Usage
// ============================================================================

/// Detects RefCell used for purely local mutable state.
pub struct LocalRefCellRule {
    metadata: RuleMetadata,
}

impl LocalRefCellRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA052".to_string(),
                name: "local-ref-cell".to_string(),
                short_description: "RefCell used for local mutable state".to_string(),
                full_description: "Detects RefCell<T> used for purely local mutable state where \
                    a regular mutable variable would suffice. RefCell adds runtime borrow \
                    checking overhead and panic risk.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    fn looks_like_local_refcell(&self, function: &MirFunction) -> bool {
        let mut has_refcell_new = false;
        let mut has_borrow_mut = false;
        
        for line in &function.body {
            let lower = line.to_lowercase();
            
            if lower.contains("refcell") && lower.contains("::new") {
                has_refcell_new = true;
            }
            
            if lower.contains("borrow_mut") || (lower.contains("borrow(") && !lower.contains("borrow_mut")) {
                has_borrow_mut = true;
            }
        }
        
        has_refcell_new && has_borrow_mut
    }
}

impl Rule for LocalRefCellRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.looks_like_local_refcell(function) {
                let mut evidence = vec![];
                for line in &function.body {
                    if line.to_lowercase().contains("refcell") 
                        || line.to_lowercase().contains("borrow") {
                        evidence.push(line.clone());
                        if evidence.len() >= 3 {
                            break;
                        }
                    }
                }
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: "RefCell used for local mutable state. Consider using a regular \
                        mutable variable. RefCell adds runtime overhead and panic risk.".to_string(),
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
// RUSTCOLA057: Unnecessary borrow_mut()
// ============================================================================

/// Detects borrow_mut() on RefCell where borrow() would suffice.
pub struct UnnecessaryBorrowMutRule {
    metadata: RuleMetadata,
}

impl UnnecessaryBorrowMutRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA057".to_string(),
                name: "unnecessary-borrow-mut".to_string(),
                short_description: "Unnecessary borrow_mut() on RefCell".to_string(),
                full_description: "Detects RefCell::borrow_mut() calls where the mutable borrow \
                    is never actually used for mutation. Using borrow_mut() when borrow() suffices \
                    creates unnecessary runtime overhead and increases panic risk.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    fn looks_like_unnecessary_borrow_mut(&self, function: &MirFunction) -> bool {
        let body_str = function.body.join("\n");
        
        if function.name.contains("::new") {
            return false;
        }
        
        let has_borrow_mut = body_str.contains("RefCell") && body_str.contains("borrow_mut");
        if !has_borrow_mut {
            return false;
        }
        
        // Check for actual mutation patterns
        let mutation_methods = [
            "::push(", "::insert(", "::remove(", "::clear(", "::extend(",
            "::swap(", "::sort(", "::reverse(", "::drain(", "::append(",
            "::pop(", "::entry(", "::get_mut(",
        ];
        let has_mutation_method = mutation_methods.iter().any(|m| body_str.contains(m));
        let has_refmut_deref_mut = body_str.contains("RefMut") && body_str.contains("DerefMut");
        let has_index_mut = body_str.contains("IndexMut") || body_str.contains("index_mut");
        
        let has_mutation = has_mutation_method || has_refmut_deref_mut || has_index_mut;
        
        has_borrow_mut && !has_mutation
    }
}

impl Rule for UnnecessaryBorrowMutRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.looks_like_unnecessary_borrow_mut(function) {
                let mut evidence = Vec::new();

                for line in &function.body {
                    if line.contains("borrow_mut") || line.contains("RefCell") {
                        evidence.push(line.trim().to_string());
                        if evidence.len() >= 5 {
                            break;
                        }
                    }
                }
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: "RefCell::borrow_mut() called but mutable borrow may not be necessary. \
                        If only read (not modified), use borrow() instead.".to_string(),
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
// RUSTCOLA068: Dead Store in Array
// ============================================================================

/// Detects array elements written but never read before being overwritten.
pub struct DeadStoreArrayRule {
    metadata: RuleMetadata,
}

impl DeadStoreArrayRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA068".to_string(),
                name: "dead-store-array".to_string(),
                short_description: "Dead store in array".to_string(),
                full_description: "Detects array elements that are written but never read before \
                    being overwritten or going out of scope. Dead stores can indicate logic errors \
                    or wasted computation.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    fn is_array_write(line: &str) -> Option<(&str, &str)> {
        let trimmed = line.trim();
        
        if let Some(eq_pos) = trimmed.find(" = ") {
            let left_side = trimmed[..eq_pos].trim();
            
            if let Some(bracket_start) = left_side.find('[') {
                if let Some(bracket_end) = left_side.find(']') {
                    if bracket_start < bracket_end && bracket_end == left_side.len() - 1 {
                        let var = left_side[..bracket_start].trim();
                        let index = left_side[bracket_start + 1..bracket_end].trim();
                        
                        if var.starts_with('_') && !index.is_empty() {
                            return Some((var, index));
                        }
                    }
                }
            }
        }
        
        None
    }

    fn is_array_read(line: &str, var: &str) -> bool {
        let trimmed = line.trim();
        
        // Check for array passed to function
        if trimmed.contains("(copy ") || trimmed.contains("(&") || trimmed.contains("(move ") {
            let patterns = [
                format!("(copy {})", var),
                format!("(&{})", var),
                format!("(move {})", var),
            ];
            if patterns.iter().any(|p| trimmed.contains(p)) {
                return true;
            }
        }
        
        let pattern = format!("{}[", var);
        if !trimmed.contains(&pattern) {
            return false;
        }
        
        // Exclude writes (left side of assignment)
        if let Some(eq_pos) = trimmed.find(" = ") {
            let left_side = trimmed[..eq_pos].trim();
            if left_side.contains(&pattern) {
                return false;
            }
            if trimmed[eq_pos + 3..].contains(&pattern) {
                return true;
            }
        }
        
        trimmed.contains(&pattern)
    }
}

impl Rule for DeadStoreArrayRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            if function.signature.contains("-> [") && function.signature.contains("; ") {
                continue;
            }
            if function.signature.contains("&mut [") {
                continue;
            }
            
            let mut const_values: HashMap<String, String> = HashMap::new();
            
            for line in &function.body {
                let trimmed = line.trim();
                if let Some(eq_pos) = trimmed.find(" = const ") {
                    let left = trimmed[..eq_pos].trim();
                    let right = trimmed[eq_pos + 9..].trim();
                    if let Some(semicolon) = right.find(';') {
                        let value = right[..semicolon].trim();
                        const_values.insert(left.to_string(), value.to_string());
                    }
                }
            }
            
            let mut all_writes: Vec<(usize, String, String, String)> = Vec::new();
            
            for (line_idx, line) in function.body.iter().enumerate() {
                let trimmed = line.trim();
                if let Some((var, index)) = Self::is_array_write(trimmed) {
                    let resolved_index = const_values.get(index).unwrap_or(&index.to_string()).clone();
                    all_writes.push((line_idx, var.to_string(), resolved_index, line.clone()));
                }
            }
            
            for (i, (write_line_idx, write_var, write_resolved_idx, write_line)) in all_writes.iter().enumerate() {
                let key = format!("{}[{}]", write_var, write_resolved_idx);
                
                for (j, (overwrite_line_idx, overwrite_var, overwrite_resolved_idx, overwrite_line)) in all_writes.iter().enumerate() {
                    if j <= i {
                        continue;
                    }
                    
                    let overwrite_key = format!("{}[{}]", overwrite_var, overwrite_resolved_idx);
                    if key != overwrite_key {
                        continue;
                    }
                    
                    let mut has_read_between = false;
                    for (between_idx, between_line) in function.body.iter().enumerate() {
                        if between_idx <= *write_line_idx || between_idx >= *overwrite_line_idx {
                            continue;
                        }
                        
                        let trimmed = between_line.trim();
                        if trimmed.starts_with("bb") || trimmed.starts_with("goto") 
                            || trimmed.starts_with("assert") || trimmed.starts_with("switchInt")
                            || trimmed.starts_with("return") {
                            continue;
                        }
                        
                        if Self::is_array_read(trimmed, write_var) {
                            has_read_between = true;
                            break;
                        }
                    }
                    
                    if !has_read_between {
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "Dead store: array element {} written but overwritten without read in `{}`",
                                key, function.name
                            ),
                            function: function.name.clone(),
                            function_signature: function.signature.clone(),
                            evidence: vec![
                                format!("Line {}: {}", write_line_idx, write_line.trim()),
                                format!("Line {}: {} (overwrites)", overwrite_line_idx, overwrite_line.trim()),
                            ],
                            span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                        });
                        break;  // Only report first overwrite
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA072: Overscoped Allow Attributes
// ============================================================================

/// Detects crate-level #![allow(...)] that suppresses security-relevant lints.
pub struct OverscopedAllowRule {
    metadata: RuleMetadata,
}

impl OverscopedAllowRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA072".to_string(),
                name: "overscoped-allow".to_string(),
                short_description: "Crate-wide allow attribute suppresses security lints".to_string(),
                full_description: "Detects #![allow(...)] attributes at crate level that suppress warnings across the entire crate. Such broad suppression can hide security issues that should be addressed. Prefer module-level or item-level allows that target specific warnings in specific contexts.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    /// Check if this attribute path is a security-relevant lint
    fn is_security_relevant_lint(path: &str) -> bool {
        matches!(path,
            "warnings" |
            "unsafe_code" |
            "unused_must_use" |
            "dead_code" |
            "deprecated" |
            "non_snake_case" |
            "non_camel_case_types" |
            "clippy::all" |
            "clippy::pedantic" |
            "clippy::restriction" |
            "clippy::unwrap_used" |
            "clippy::expect_used" |
            "clippy::panic" |
            "clippy::indexing_slicing" |
            "clippy::mem_forget" |
            "clippy::cast_ptr_alignment" |
            "clippy::integer_arithmetic"
        )
    }
}

impl Rule for OverscopedAllowRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        let crate_root = Path::new(&package.crate_root);
        let sources = match SourceFile::collect_crate_sources(crate_root) {
            Ok(s) => s,
            Err(_) => return findings,
        };

        for source in sources {
            let syntax_tree = match syn::parse_file(&source.content) {
                Ok(tree) => tree,
                Err(_) => continue,
            };

            for attr in &syntax_tree.attrs {
                match attr.style {
                    syn::AttrStyle::Inner(_) => {},
                    syn::AttrStyle::Outer => continue,
                }

                if !attr.path().is_ident("allow") {
                    continue;
                }

                if let syn::Meta::List(meta_list) = &attr.meta {
                    let nested = match meta_list.parse_args_with(
                        syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                    ) {
                        Ok(n) => n,
                        Err(_) => continue,
                    };

                    for meta in nested {
                        if let syn::Meta::Path(path) = meta {
                            let lint_name = path.segments.iter()
                                .map(|s| s.ident.to_string())
                                .collect::<Vec<_>>()
                                .join("::");

                            if Self::is_security_relevant_lint(&lint_name) {
                                let relative_path = source.path.strip_prefix(crate_root)
                                    .unwrap_or(&source.path)
                                    .display()
                                    .to_string();

                                findings.push(Finding {
                                    rule_id: self.metadata.id.clone(),
                                    rule_name: self.metadata.name.clone(),
                                    severity: self.metadata.default_severity,
                                    message: format!(
                                        "Crate-level #![allow({})] in {} suppresses warnings across entire crate. \
                                        Consider module-level or item-level suppression instead.",
                                        lint_name,
                                        relative_path
                                    ),
                                    function: relative_path,
                                    function_signature: String::new(),
                                    evidence: vec![format!("#![allow({})]", lint_name)],
                                    span: None,
                    ..Default::default()
                                });
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
// RUSTCOLA092: Commented-Out Code Detection
// ============================================================================

/// Detects commented-out code that should be removed.
pub struct CommentedOutCodeRule {
    metadata: RuleMetadata,
}

impl CommentedOutCodeRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA092".to_string(),
                name: "commented-out-code".to_string(),
                short_description: "Commented-out code detected".to_string(),
                full_description: "Detects commented-out code that should be removed to maintain clean, analyzable codebases. Commented-out code creates maintenance burden, confuses readers about actual functionality, and should be removed in favor of version control for historical reference.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    /// Check if a comment line looks like commented-out code
    fn looks_like_commented_code(line: &str) -> bool {
        let trimmed = line.trim();
        
        if !trimmed.starts_with("//") {
            return false;
        }
        
        let content = trimmed.trim_start_matches('/').trim();
        
        if content.is_empty() {
            return false;
        }
        
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            return false;
        }
        
        let lowercase = content.to_lowercase();
        if lowercase.starts_with("todo:") 
            || lowercase.starts_with("fixme:") 
            || lowercase.starts_with("note:") 
            || lowercase.starts_with("hack:")
            || lowercase.starts_with("xxx:")
            || lowercase.starts_with("see:")
            || lowercase.starts_with("example")
            || lowercase.starts_with("usage:")
            || lowercase.contains("http://")
            || lowercase.contains("https://")
            || content.starts_with('=')
            || content.starts_with('|')
            || content.starts_with('-')
            || content.chars().all(|c| c == '=' || c == '-' || c.is_whitespace()) {
            return false;
        }
        
        let code_keywords = [
            "pub fn", "fn ", "let ", "let mut", "struct ", "enum ", "impl ", 
            "use ", "mod ", "trait ", "const ", "static ", "match ", "if ", 
            "for ", "while ", "loop ", "return ", "self.", "println!", "format!",
            "=> ", ".unwrap()", ".expect(", "Vec<", "HashMap<", "Option<", "Result<",
        ];
        
        for keyword in &code_keywords {
            if content.contains(keyword) {
                return true;
            }
        }
        
        if content.contains(" = ") && !content.ends_with(':') {
            if !lowercase.contains("means") && !lowercase.contains("where") 
                && !lowercase.contains("when") && !lowercase.contains("if ") {
                return true;
            }
        }
        
        let has_semicolon = content.ends_with(';');
        let has_braces = content.contains('{') || content.contains('}');
        let has_brackets = content.contains('[') || content.contains(']');
        
        if has_semicolon || (has_braces && has_brackets) {
            if !lowercase.starts_with("this ") && !lowercase.starts_with("the ") 
                && !lowercase.starts_with("a ") && !lowercase.starts_with("an ") {
                return true;
            }
        }
        
        false
    }
}

impl Rule for CommentedOutCodeRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        let crate_root = Path::new(&package.crate_root);
        let sources = match SourceFile::collect_crate_sources(crate_root) {
            Ok(s) => s,
            Err(_) => return findings,
        };
        
        for source in sources {
            let mut evidence = Vec::new();
            let mut consecutive_code_lines = 0;
            let mut first_code_line_num = 0;
            
            for (line_num, line) in source.content.lines().enumerate() {
                if Self::looks_like_commented_code(line) {
                    if consecutive_code_lines == 0 {
                        first_code_line_num = line_num + 1;
                    }
                    consecutive_code_lines += 1;
                    
                    if evidence.len() < 3 {
                        evidence.push(format!("Line {}: {}", line_num + 1, line.trim()));
                    }
                } else {
                    if consecutive_code_lines >= 2 {
                        let relative_path = source.path.strip_prefix(crate_root)
                            .unwrap_or(&source.path)
                            .display()
                            .to_string();
                        
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "Commented-out code detected in {} starting at line {} ({} consecutive lines)",
                                relative_path,
                                first_code_line_num,
                                consecutive_code_lines
                            ),
                            function: relative_path.clone(),
                            function_signature: String::new(),
                            evidence: evidence.clone(),
                            span: None,
                    ..Default::default()
                        });
                        
                        evidence.clear();
                    }
                    consecutive_code_lines = 0;
                }
            }
            
            if consecutive_code_lines >= 2 {
                let relative_path = source.path.strip_prefix(crate_root)
                    .unwrap_or(&source.path)
                    .display()
                    .to_string();
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Commented-out code detected in {} starting at line {} ({} consecutive lines)",
                        relative_path,
                        first_code_line_num,
                        consecutive_code_lines
                    ),
                    function: relative_path,
                    function_signature: String::new(),
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
// RUSTCOLA123: Unwrap/Expect in Hot Paths Rule
// ============================================================================

use std::ffi::OsStr;
use walkdir::WalkDir;
use crate::rules::utils::filter_entry;

/// Detects panic-prone code in performance-critical paths.
/// Panics in hot paths can cause cascading failures under load.
pub struct UnwrapInHotPathRule {
    metadata: RuleMetadata,
}

impl UnwrapInHotPathRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA123".to_string(),
                name: "unwrap-in-hot-path".to_string(),
                short_description: "Panic-prone code in performance-critical path".to_string(),
                full_description: "Detects unwrap(), expect(), and indexing operations in \
                    performance-critical code paths like loops, iterators, async poll functions, \
                    and request handlers. Panics in these paths can cause cascading failures. \
                    Use Result propagation, .get(), or pattern matching instead.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    /// Hot path indicators
    fn hot_path_indicators() -> &'static [&'static str] {
        &[
            "for ",
            "while ",
            "loop {",
            ".iter()",
            ".map(",
            ".filter(",
            ".fold(",
            ".for_each(",
            "fn poll(",
            "impl Future",
            "impl Stream",
            "async fn handle",
            "fn handle_request",
            "fn process",
            "#[inline]",
            "#[hot]",
        ]
    }

    /// Panic-prone patterns
    fn panic_patterns() -> &'static [(&'static str, &'static str)] {
        &[
            (".unwrap()", "Use ? operator, .unwrap_or(), .unwrap_or_else(), or pattern match"),
            (".expect(", "Use ? operator, .unwrap_or(), .unwrap_or_else(), or pattern match"),
            ("[", "Use .get() for safe indexing"),
        ]
    }
}

impl Rule for UnwrapInHotPathRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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

            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let lines: Vec<&str> = content.lines().collect();
            let mut in_hot_path = false;
            let mut hot_path_type = String::new();
            let mut brace_depth = 0;
            let mut hot_path_start_depth = 0;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Check for hot path entry
                for indicator in Self::hot_path_indicators() {
                    if trimmed.contains(indicator) {
                        in_hot_path = true;
                        hot_path_start_depth = brace_depth;
                        hot_path_type = (*indicator).to_string();
                        break;
                    }
                }

                // Track brace depth
                brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                // Check if we've exited the hot path
                if in_hot_path && brace_depth <= hot_path_start_depth && trimmed.contains('}') {
                    in_hot_path = false;
                    hot_path_type.clear();
                }

                // Check for panic patterns in hot path
                if in_hot_path {
                    for (pattern, advice) in Self::panic_patterns() {
                        if trimmed.contains(pattern) {
                            // Filter out false positives
                            // Skip comments
                            if let Some(comment_pos) = trimmed.find("//") {
                                if trimmed.find(pattern).map(|p| p > comment_pos).unwrap_or(false) {
                                    continue;
                                }
                            }

                            // For indexing, be more specific
                            if *pattern == "[" {
                                // Skip if it's a slice pattern, array type, or already uses .get()
                                if trimmed.contains(".get(") ||
                                   trimmed.contains("[..]") ||
                                   trimmed.contains(": [") ||
                                   trimmed.contains("-> [") ||
                                   trimmed.contains("Vec<") ||
                                   !trimmed.contains("]") {
                                    continue;
                                }
                            }

                            let location = format!("{}:{}", rel_path, idx + 1);
                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Panic-prone code '{}' in hot path ({}). {}",
                                    pattern.trim_end_matches('('), hot_path_type, advice
                                ),
                                function: location,
                                function_signature: String::new(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                    ..Default::default()
                            });
                            break; // One finding per line
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

/// Register all code quality rules with the rule engine.
pub fn register_code_quality_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(CrateWideAllowRule::new()));
    engine.register_rule(Box::new(MisorderedAssertEqRule::new()));
    engine.register_rule(Box::new(TryIoResultRule::new()));
    engine.register_rule(Box::new(LocalRefCellRule::new()));
    engine.register_rule(Box::new(UnnecessaryBorrowMutRule::new()));
    engine.register_rule(Box::new(DeadStoreArrayRule::new()));
    engine.register_rule(Box::new(OverscopedAllowRule::new()));
    engine.register_rule(Box::new(CommentedOutCodeRule::new()));
    engine.register_rule(Box::new(UnwrapInHotPathRule::new()));
}
