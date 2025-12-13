//! FFI safety rules.
//!
//! Rules detecting FFI-related security issues:
//! - Allocator mismatch between Rust and C (RUSTCOLA017)
//! - Unsafe CString pointer usage (RUSTCOLA036)
//! - Packed field references (RUSTCOLA035)
//! - FFI buffer leaks (RUSTCOLA016)
//! - FFI pointer returns (RUSTCOLA073)

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};
use super::filter_entry;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

// ============================================================================
// RUSTCOLA017: Allocator Mismatch FFI Rule
// ============================================================================

/// Detects functions that mix Rust and foreign allocation APIs.
pub struct AllocatorMismatchFfiRule {
    metadata: RuleMetadata,
}

impl AllocatorMismatchFfiRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA017".to_string(),
                name: "allocator-mismatch".to_string(),
                short_description: "Mixed allocator/deallocator usage".to_string(),
                full_description: "Detects functions that mix Rust and foreign allocation APIs, \
                    such as freeing Box/CString allocations with libc::free or wrapping \
                    libc::malloc pointers with Box::from_raw.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/boxed/struct.Box.html#method.from_raw".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for AllocatorMismatchFfiRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn cache_key(&self) -> String {
        format!("{}:v1", self.metadata.id)
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Track Rust-allocated pointers (Box::into_raw, CString::into_raw)
            let mut rust_allocated_vars = Vec::new();
            
            // Track C-allocated pointers (malloc, calloc, realloc)
            let mut c_allocated_vars = Vec::new();
            
            // Track variable aliases (e.g., _4 = copy _2)
            let mut var_aliases: HashMap<String, String> = HashMap::new();

            for (idx, line) in function.body.iter().enumerate() {
                // Track variable aliases: "_4 = copy _2" or "_4 = move _2"
                if (line.contains(" = copy ") || line.contains(" = move "))
                    && line.trim().starts_with('_')
                {
                    let parts: Vec<&str> = line.split('=').collect();
                    if parts.len() >= 2 {
                        let lhs = parts[0].trim();
                        let rhs = parts[1].trim();
                        if let Some(src_var) = rhs.split_whitespace().nth(1) {
                            if src_var.starts_with('_') {
                                var_aliases.insert(lhs.to_string(), src_var.to_string());
                            }
                        }
                    }
                }
                
                // Detect Rust allocations: Box::into_raw, CString::into_raw
                if (line.contains("Box::") && line.contains("::into_raw") 
                    || line.contains("CString::") && line.contains("::into_raw"))
                    && line.contains(" = ")
                {
                    if let Some(var_name) = line.trim().split('=').next() {
                        let var = var_name.trim().to_string();
                        rust_allocated_vars.push((var.clone(), idx, line.trim().to_string()));
                    }
                }

                // Detect C allocations: malloc, calloc, realloc
                if (line.contains("malloc(") || line.contains("calloc(") || line.contains("realloc("))
                    && line.contains(" = ")
                {
                    if let Some(var_name) = line.trim().split('=').next() {
                        let var = var_name.trim().to_string();
                        c_allocated_vars.push((var.clone(), idx, line.trim().to_string()));
                    }
                }

                // Check for libc::free on Rust-allocated pointers
                if line.contains("free(") {
                    for (rust_var, alloc_idx, alloc_line) in &rust_allocated_vars {
                        let mut is_freed = line.contains(rust_var);
                        
                        for (alias, original) in &var_aliases {
                            if original == rust_var && line.contains(alias) {
                                is_freed = true;
                                break;
                            }
                        }
                        
                        if is_freed && idx > *alloc_idx && idx < alloc_idx + 50 {
                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Rust-allocated pointer freed with libc::free in `{}`",
                                    function.name
                                ),
                                function: function.name.clone(),
                                function_signature: function.signature.clone(),
                                evidence: vec![
                                    format!("Rust allocation: {}", alloc_line),
                                    format!("C deallocation: {}", line.trim()),
                                ],
                                span: function.span.clone(),
                            });
                        }
                    }
                }

                // Check for Box::from_raw on C-allocated pointers
                if line.contains("Box::") && line.contains("::from_raw(") {
                    for (c_var, alloc_idx, alloc_line) in &c_allocated_vars {
                        let mut is_converted = line.contains(c_var);
                        
                        for (alias, original) in &var_aliases {
                            if original == c_var && line.contains(alias) {
                                is_converted = true;
                                break;
                            }
                        }
                        
                        if is_converted && idx > *alloc_idx && idx < alloc_idx + 50 {
                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "C-allocated pointer converted to Box::from_raw in `{}`",
                                    function.name
                                ),
                                function: function.name.clone(),
                                function_signature: function.signature.clone(),
                                evidence: vec![
                                    format!("C allocation: {}", alloc_line),
                                    format!("Rust deallocation: {}", line.trim()),
                                ],
                                span: function.span.clone(),
                            });
                        }
                    }
                }

                // Check for CString::from_raw on C-allocated strings
                if line.contains("CString::") && line.contains("::from_raw(") {
                    for (c_var, alloc_idx, alloc_line) in &c_allocated_vars {
                        let mut is_converted = line.contains(c_var);
                        
                        for (alias, original) in &var_aliases {
                            if original == c_var && line.contains(alias) {
                                is_converted = true;
                                break;
                            }
                        }
                        
                        if is_converted && idx > *alloc_idx && idx < alloc_idx + 50 {
                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "C-allocated pointer converted to CString::from_raw in `{}`",
                                    function.name
                                ),
                                function: function.name.clone(),
                                function_signature: function.signature.clone(),
                                evidence: vec![
                                    format!("C allocation: {}", alloc_line),
                                    format!("Rust deallocation: {}", line.trim()),
                                ],
                                span: function.span.clone(),
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
// RUSTCOLA073: Unsafe FFI Pointer Return Rule
// ============================================================================

/// Detects extern "C" functions that return raw pointers without safety documentation.
pub struct UnsafeFfiPointerReturnRule {
    metadata: RuleMetadata,
}

impl UnsafeFfiPointerReturnRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA073".to_string(),
                name: "unsafe-ffi-pointer-return".to_string(),
                short_description: "FFI function returns raw pointer without safety invariants".to_string(),
                full_description: "Detects extern \"C\" functions that return raw pointers (*const T or *mut T). \
                    These functions expose memory that must be managed correctly by callers, but the Rust \
                    type system cannot enforce this across FFI boundaries. Functions returning raw pointers \
                    should document ownership semantics (who frees the memory), lifetime requirements, \
                    and validity invariants.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/nomicon/ffi.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Check if a function signature indicates an extern "C" function returning a pointer
    fn is_ffi_returning_pointer(signature: &str, body: &[String]) -> Option<String> {
        if !signature.contains("extern \"C\"") && !signature.contains("extern \"system\"") {
            return None;
        }

        if let Some(arrow_pos) = signature.find("->") {
            let return_type = signature[arrow_pos + 2..].trim();
            if return_type.starts_with("*const") || return_type.starts_with("*mut") {
                let has_safety_doc = body.iter().any(|line| {
                    let lower = line.to_lowercase();
                    lower.contains("safety:") || 
                    lower.contains("# safety") ||
                    lower.contains("invariant") ||
                    lower.contains("ownership") ||
                    lower.contains("caller must") ||
                    lower.contains("must be freed")
                });

                if !has_safety_doc {
                    return Some(return_type.to_string());
                }
            }
        }

        None
    }
}

impl Rule for UnsafeFfiPointerReturnRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if let Some(return_type) = Self::is_ffi_returning_pointer(&function.signature, &function.body) {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "extern \"C\" function `{}` returns raw pointer `{}` without documented safety invariants.",
                        function.name,
                        return_type
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: vec![
                        format!("Returns: {}", return_type),
                        "No safety documentation found".to_string(),
                    ],
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA035: Packed Field Reference Rule  
// ============================================================================

/// Detects taking references to fields of #[repr(packed)] structs (undefined behavior).
pub struct PackedFieldReferenceRule {
    metadata: RuleMetadata,
}

impl PackedFieldReferenceRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA035".to_string(),
                name: "repr-packed-field-reference".to_string(),
                short_description: "Reference to packed struct field".to_string(),
                full_description: "Detects taking references to fields of #[repr(packed)] structs. \
                    Creating references to packed struct fields creates unaligned references, which \
                    is undefined behavior in Rust. Use ptr::addr_of! or ptr::addr_of_mut! instead.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/nomicon/other-reprs.html#reprpacked".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for PackedFieldReferenceRule {
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

        // First pass: identify packed structs
        let mut packed_structs = HashSet::new();

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

            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let lines: Vec<&str> = content.lines().collect();
            
            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                if trimmed.starts_with("#[repr(packed") {
                    for j in (idx + 1).min(lines.len())..lines.len() {
                        let struct_line = lines[j].trim();
                        if struct_line.starts_with("struct ") || struct_line.starts_with("pub struct ") {
                            let after_struct = if struct_line.starts_with("pub struct ") {
                                &struct_line[11..]
                            } else {
                                &struct_line[7..]
                            };
                            
                            if let Some(name_end) = after_struct.find(|c: char| !c.is_alphanumeric() && c != '_') {
                                let struct_name = &after_struct[..name_end];
                                packed_structs.insert(struct_name.to_string());
                            }
                            break;
                        }
                    }
                }
            }
        }

        // Second pass: look for references to packed struct fields
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
                
                for struct_name in &packed_structs {
                    if (trimmed.contains(&format!("&{}", struct_name.to_lowercase()))
                        || trimmed.contains(&format!("&mut {}", struct_name.to_lowercase()))
                        || trimmed.contains("&self.")
                        || trimmed.contains("&mut self."))
                        && trimmed.contains('.')
                        && !trimmed.contains("ptr::addr_of")
                    {
                        let location = format!("{}:{}", rel_path, idx + 1);
                        
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "Potential reference to packed struct field (possibly {})",
                                struct_name
                            ),
                            function: location.clone(),
                            function_signature: String::new(),
                            evidence: vec![trimmed.to_string()],
                            span: None,
                        });
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA036: Unsafe CString Pointer Rule
// ============================================================================

/// Detects CString::new(...).unwrap().as_ptr() patterns where the CString
/// temporary is dropped immediately, creating a dangling pointer.
pub struct UnsafeCStringPointerRule {
    metadata: RuleMetadata,
}

impl UnsafeCStringPointerRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA036".to_string(),
                name: "unsafe-cstring-pointer".to_string(),
                short_description: "Unsafe CString pointer from temporary".to_string(),
                full_description: "Detects patterns like CString::new(...).unwrap().as_ptr() where \
                    the CString is a temporary that gets dropped immediately, leaving a dangling pointer. \
                    The pointer must outlive the CString it came from. Store the CString in a variable \
                    to extend its lifetime.".to_string(),
                help_uri: Some("https://www.jetbrains.com/help/inspectopedia/RsCStringPointer.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn is_cstring_temp_pattern(line: &str) -> bool {
        if !line.contains("CString::new") || !line.contains(".as_ptr()") {
            return false;
        }

        let has_intermediate_method = line.contains(".unwrap()") 
            || line.contains(".expect(") 
            || line.contains(".unwrap_or")
            || line.contains("?");

        let looks_temporary = has_intermediate_method && !line.contains("let ");
        let direct_chain = line.contains("CString::new(") && line.contains(").as_ptr()");

        looks_temporary || direct_chain
    }
}

impl Rule for UnsafeCStringPointerRule {
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

            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let lines: Vec<&str> = content.lines().collect();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if Self::is_cstring_temp_pattern(trimmed) {
                    let location = format!("{}:{}", rel_path, idx + 1);

                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: "CString temporary used with as_ptr() creates dangling pointer"
                            .to_string(),
                        function: location,
                        function_signature: String::new(),
                        evidence: vec![trimmed.to_string()],
                        span: None,
                    });
                }
            }
        }

        findings
    }
}

// ============================================================================
// Registration
// ============================================================================

/// Register all FFI rules with the rule engine.
pub fn register_ffi_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(AllocatorMismatchFfiRule::new()));
    engine.register_rule(Box::new(UnsafeFfiPointerReturnRule::new()));
    engine.register_rule(Box::new(PackedFieldReferenceRule::new()));
    engine.register_rule(Box::new(UnsafeCStringPointerRule::new()));
    // Note: FfiBufferLeakRule requires strip_string_literals helper and remains in lib.rs
}
