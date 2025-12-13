//! Code quality and miscellaneous rules.
//!
//! Rules detecting code quality issues:
//! - Crate-wide allow lint (RUSTCOLA049)
//! - Misordered assert_eq arguments (RUSTCOLA050)
//! - Try operator on io::Result (RUSTCOLA051)
//! - Local RefCell patterns (RUSTCOLA052)
//! - Unnecessary borrow_mut (RUSTCOLA057)
//! - Dead stores in arrays (RUSTCOLA068)

#![allow(dead_code)]

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};
use std::collections::HashMap;

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
}
