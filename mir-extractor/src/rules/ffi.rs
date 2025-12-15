//! FFI safety rules.
//!
//! Rules detecting FFI-related security issues:
//! - Allocator mismatch between Rust and C (RUSTCOLA017)
//! - Unsafe CString pointer usage (RUSTCOLA036)
//! - Packed field references (RUSTCOLA035)
//! - FFI buffer leaks (RUSTCOLA016)
//! - FFI pointer returns (RUSTCOLA073)

use crate::{Finding, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};
use super::filter_entry;
use super::utils::{StringLiteralState, strip_string_literals};
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
// RUSTCOLA059: Ctor/Dtor Std API Rule
// ============================================================================

/// Detects functions annotated with #[ctor] or #[dtor] that call std:: APIs.
pub struct CtorDtorStdApiRule {
    metadata: RuleMetadata,
}

impl CtorDtorStdApiRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA059".to_string(),
                name: "ctor-dtor-std-api".to_string(),
                short_description: "#[ctor]/#[dtor] invoking std APIs".to_string(),
                full_description: "Detects functions annotated with #[ctor] or #[dtor] that call std:: APIs. Code running in constructors/destructors (before main or during program teardown) can cause initialization ordering issues, deadlocks, or undefined behavior when calling standard library functions that expect a fully initialized runtime. Mirrors CodeQL rust/ctor-initialization.".to_string(),
                help_uri: Some("https://docs.rs/ctor/latest/ctor/".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_ctor_dtor_with_std_calls(&self, function: &crate::MirFunction) -> bool {
        let name = &function.name;
        
        // Exclude the rule implementation itself
        if name.contains("CtorDtorStdApiRule") || name.contains("looks_like_ctor_dtor_with_std_calls") {
            return false;
        }
        
        // Heuristic: Look for functions that start with ctor_ or dtor_
        // These are likely annotated with #[ctor] or #[dtor]
        // Note: This won't catch all cases (e.g., different naming), but is a reasonable heuristic
        let looks_like_ctor_dtor_name = name.starts_with("ctor_") || name.starts_with("dtor_");
        
        if !looks_like_ctor_dtor_name {
            return false;
        }

        // Check for std:: API calls or common std patterns in the body or signature
        let has_std_refs = function.body.iter().any(|line| {
            line.contains("std::") 
                || line.contains("_print(") // println!/print! desugars to _print
        }) || function.signature.contains("std::");
        
        has_std_refs
    }
}

impl Rule for CtorDtorStdApiRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.looks_like_ctor_dtor_with_std_calls(function) {
                // Collect evidence of std:: calls or _print
                let mut evidence = vec![];
                for line in &function.body {
                    if line.contains("std::") || line.contains("_print(") {
                        evidence.push(line.clone());
                        if evidence.len() >= 3 {
                            break;
                        }
                    }
                }
                
                if !evidence.is_empty() {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: "Constructor/destructor function calls std library APIs. Code running before main() or during program teardown can cause initialization issues, deadlocks, or undefined behavior.".to_string(),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence,
                        span: None,
                    });
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA016: FFI Buffer Leak Rule
// ============================================================================

/// Detects extern functions that hand out raw pointers or heap buffers and contain
/// early-return code paths, risking leaks or dangling pointers when cleanup is skipped.
pub struct FfiBufferLeakRule {
    metadata: RuleMetadata,
}

impl FfiBufferLeakRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA016".to_string(),
                name: "ffi-buffer-leak-early-return".to_string(),
                short_description: "FFI buffer escapes with early return".to_string(),
                full_description: "Detects extern functions that hand out raw pointers or heap buffers and contain early-return code paths, risking leaks or dangling pointers when cleanup is skipped.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn pointer_escape_patterns() -> &'static [&'static str] {
        &[
            "Box::into_raw",
            "Vec::into_raw_parts",
            "Vec::with_capacity",
            "CString::into_raw",
            ".as_mut_ptr()",
            ".as_ptr()",
        ]
    }

    fn captures_early_exit(line: &str, position: usize, last_index: usize) -> bool {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return false;
        }

        if trimmed.contains('?') {
            return true;
        }

        if trimmed.contains("return Err") {
            return true;
        }

        if (trimmed.starts_with("return ") || trimmed.contains(" return ")) && position < last_index
        {
            return true;
        }

        false
    }

    fn is_pointer_escape(line: &str) -> bool {
        Self::pointer_escape_patterns()
            .iter()
            .any(|needle| line.contains(needle))
    }
}

impl Rule for FfiBufferLeakRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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

            if entry.path().extension().and_then(OsStr::to_str) != Some("rs") {
                continue;
            }

            let Ok(source) = fs::read_to_string(entry.path()) else {
                continue;
            };

            let rel_path = entry
                .path()
                .strip_prefix(crate_root)
                .unwrap_or_else(|_| entry.path())
                .to_string_lossy()
                .replace('\\', "/");

            let lines: Vec<&str> = source.lines().collect();
            let mut idx = 0usize;
            let mut string_state = StringLiteralState::default();
            let mut pending_no_mangle: Option<usize> = None;
            let mut pending_extern: Option<usize> = None;

            while idx < lines.len() {
                let raw_line = lines[idx];
                let (sanitized_line, state_after_line) =
                    strip_string_literals(string_state, raw_line);
                let trimmed = sanitized_line.trim();
                let trimmed_original = raw_line.trim();

                if trimmed.starts_with("#[no_mangle") {
                    pending_no_mangle = Some(idx);
                    string_state = state_after_line;
                    idx += 1;
                    continue;
                }

                if trimmed.contains("extern \"C\"") && !trimmed.contains("fn ") {
                    pending_extern = Some(idx);
                    string_state = state_after_line;
                    idx += 1;
                    continue;
                }

                let mut is_ffi_fn = false;
                let mut start_idx = idx;

                if trimmed.contains("extern \"C\"") && trimmed.contains("fn ") {
                    is_ffi_fn = true;
                } else if pending_extern.is_some() && trimmed.contains("fn ") {
                    is_ffi_fn = true;
                    start_idx = pending_extern.unwrap();
                } else if pending_no_mangle.is_some() && trimmed.contains("fn ") {
                    is_ffi_fn = true;
                    start_idx = pending_no_mangle.unwrap();
                }

                if !is_ffi_fn {
                    if !trimmed.is_empty() && !trimmed.starts_with("#[") {
                        pending_no_mangle = None;
                        pending_extern = None;
                    }
                    string_state = state_after_line;
                    idx += 1;
                    continue;
                }

                let mut block_lines: Vec<String> = Vec::new();
                let mut sanitized_block: Vec<String> = Vec::new();
                if start_idx < idx {
                    for attr_idx in start_idx..idx {
                        let attr_line = lines[attr_idx].trim();
                        if !attr_line.is_empty() {
                            block_lines.push(attr_line.to_string());
                            sanitized_block.push(attr_line.to_string());
                        }
                    }
                }

                if !trimmed_original.is_empty() {
                    block_lines.push(trimmed_original.to_string());
                    sanitized_block.push(trimmed.to_string());
                }

                let mut brace_balance: i32 = 0;
                let mut body_started = false;
                let mut j = idx;
                let mut current_state = state_after_line;
                let mut current_sanitized = sanitized_line;

                loop {
                    let trimmed_sanitized = current_sanitized.trim();
                    let opens = current_sanitized.chars().filter(|c| *c == '{').count() as i32;
                    let closes = current_sanitized.chars().filter(|c| *c == '}').count() as i32;
                    brace_balance += opens;
                    if brace_balance > 0 {
                        body_started = true;
                    }
                    brace_balance -= closes;

                    let body_done = if body_started && brace_balance <= 0 {
                        true
                    } else if !body_started && trimmed_sanitized.ends_with(';') {
                        true
                    } else {
                        false
                    };

                    if body_done {
                        j += 1;
                        break;
                    }

                    j += 1;
                    if j >= lines.len() {
                        break;
                    }

                    let next_line = lines[j];
                    let (next_sanitized, next_state) =
                        strip_string_literals(current_state, next_line);
                    current_state = next_state;

                    let trimmed_original_next = next_line.trim();
                    if !trimmed_original_next.is_empty() {
                        block_lines.push(trimmed_original_next.to_string());
                        sanitized_block.push(next_sanitized.trim().to_string());
                    }

                    current_sanitized = next_sanitized;
                }

                let signature_line = block_lines
                    .iter()
                    .find(|line| line.contains("fn "))
                    .cloned()
                    .unwrap_or_else(|| block_lines.first().cloned().unwrap_or_default());

                let last_index = sanitized_block
                    .iter()
                    .rposition(|line| !line.trim().is_empty())
                    .unwrap_or(0);

                let pointer_lines: Vec<String> = block_lines
                    .iter()
                    .zip(sanitized_block.iter())
                    .filter_map(|(line, sanitized)| {
                        if Self::is_pointer_escape(sanitized) {
                            Some(line.clone())
                        } else {
                            None
                        }
                    })
                    .collect();

                let early_lines: Vec<(usize, String)> = sanitized_block
                    .iter()
                    .enumerate()
                    .filter_map(|(pos, sanitized)| {
                        if Self::captures_early_exit(sanitized, pos, last_index) {
                            Some((pos, block_lines[pos].clone()))
                        } else {
                            None
                        }
                    })
                    .collect();

                if !pointer_lines.is_empty() && !early_lines.is_empty() {
                    let mut evidence = Vec::new();
                    let mut seen = HashSet::new();

                    for line in pointer_lines
                        .iter()
                        .chain(early_lines.iter().map(|(_, l)| l))
                    {
                        if seen.insert(line.clone()) {
                            evidence.push(line.clone());
                        }
                    }

                    let location = format!("{}:{}", rel_path, start_idx + 1);
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: "Potential FFI buffer leak due to early return before cleanup"
                            .to_string(),
                        function: location,
                        function_signature: signature_line,
                        evidence,
                        span: None,
                    });
                }

                pending_no_mangle = None;
                pending_extern = None;
                string_state = current_state;
                idx = j;
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA116: Panic in FFI Boundary Rule
// ============================================================================

/// Detects potential panics in extern "C" functions which cause undefined behavior.
/// 
/// Unwinding across FFI boundaries (from Rust into C code) is undefined behavior.
/// This rule detects panic-prone operations inside `extern "C"` functions.
pub struct PanicInFfiBoundaryRule {
    metadata: RuleMetadata,
}

impl PanicInFfiBoundaryRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA116".to_string(),
                name: "panic-in-ffi-boundary".to_string(),
                short_description: "Potential panic in extern \"C\" function".to_string(),
                full_description: "Detects potential panics in extern \"C\" functions. Unwinding \
                    across FFI boundaries is undefined behavior in Rust. Operations like unwrap(), \
                    expect(), panic!(), assert!(), and indexing can all panic. Use catch_unwind \
                    or return error codes instead.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/nomicon/ffi.html#ffi-and-panics".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Patterns that can cause panics
    fn panic_patterns() -> &'static [(&'static str, &'static str)] {
        &[
            (".unwrap()", "unwrap() can panic on None/Err"),
            (".expect(", "expect() can panic on None/Err"),
            ("panic!", "explicit panic"),
            ("unreachable!", "unreachable! panics if reached"),
            ("unimplemented!", "unimplemented! always panics"),
            ("todo!", "todo! always panics"),
            ("assert!", "assert! panics on false"),
            ("assert_eq!", "assert_eq! panics on mismatch"),
            ("assert_ne!", "assert_ne! panics on match"),
            ("debug_assert!", "debug_assert! panics in debug builds"),
            ("[", "array/slice indexing can panic on out-of-bounds"),
        ]
    }
}

impl Rule for PanicInFfiBoundaryRule {
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
            let mut in_extern_c_fn = false;
            let mut extern_fn_start = 0;
            let mut extern_fn_name = String::new();
            let mut brace_depth = 0;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Detect extern "C" fn or #[no_mangle] pub extern "C" fn
                if (trimmed.contains("extern \"C\"") || trimmed.contains("extern \"system\""))
                    && trimmed.contains("fn ") 
                {
                    in_extern_c_fn = true;
                    extern_fn_start = idx;
                    brace_depth = 0;
                    
                    // Extract function name
                    if let Some(fn_pos) = trimmed.find("fn ") {
                        let after_fn = &trimmed[fn_pos + 3..];
                        extern_fn_name = after_fn
                            .split(|c: char| c == '(' || c == '<' || c.is_whitespace())
                            .next()
                            .unwrap_or("")
                            .to_string();
                    }
                }

                if in_extern_c_fn {
                    brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                    // Check for panic-prone patterns
                    for (pattern, reason) in Self::panic_patterns() {
                        // Special handling for indexing - only flag if it looks like array access
                        if *pattern == "[" {
                            // Look for variable[index] pattern but not slice declarations
                            if trimmed.contains('[') && trimmed.contains(']') 
                                && !trimmed.contains("&[") 
                                && !trimmed.contains(": [")
                                && !trimmed.contains("-> [")
                                && !trimmed.starts_with("let ")
                                && !trimmed.starts_with("const ")
                                && !trimmed.starts_with("static ")
                            {
                                // Check if it's an actual indexing operation
                                let has_index_op = trimmed.chars()
                                    .zip(trimmed.chars().skip(1))
                                    .any(|(a, b)| a.is_alphanumeric() && b == '[');
                                
                                if has_index_op {
                                    let location = format!("{}:{}", rel_path, idx + 1);

                                    findings.push(Finding {
                                        rule_id: self.metadata.id.clone(),
                                        rule_name: self.metadata.name.clone(),
                                        severity: Severity::Medium, // Lower for indexing
                                        message: format!(
                                            "Potential panic in extern \"C\" fn `{}`: {}. \
                                            Consider using .get() with bounds checking.",
                                            extern_fn_name, reason
                                        ),
                                        function: location,
                                        function_signature: String::new(),
                                        evidence: vec![trimmed.to_string()],
                                        span: None,
                                    });
                                }
                            }
                        } else if trimmed.contains(pattern) {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Potential panic in extern \"C\" fn `{}`: {}. \
                                    Unwinding across FFI boundaries is undefined behavior. \
                                    Use catch_unwind or return error codes.",
                                    extern_fn_name, reason
                                ),
                                function: location,
                                function_signature: String::new(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                            });
                        }
                    }

                    // End of function
                    if brace_depth <= 0 && idx > extern_fn_start {
                        in_extern_c_fn = false;
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA107: Embedded Interpreter Usage Rule
// ============================================================================

/// Detects usage of embedded interpreters which create code injection attack surfaces.
/// 
/// Embedded interpreters like PyO3, rlua, v8, deno_core can execute arbitrary code
/// if not properly sandboxed. This rule flags their usage for security review.
pub struct EmbeddedInterpreterUsageRule {
    metadata: RuleMetadata,
}

impl EmbeddedInterpreterUsageRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA107".to_string(),
                name: "embedded-interpreter-usage".to_string(),
                short_description: "Embedded interpreter creates code injection surface".to_string(),
                full_description: "Detects usage of embedded interpreters like PyO3 (Python), \
                    rlua/mlua (Lua), rusty_v8/deno_core (JavaScript). These create potential \
                    code injection attack surfaces if user input reaches the interpreter. \
                    Ensure proper sandboxing and input validation.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Interpreter crates and their initialization patterns
    fn interpreter_patterns() -> &'static [(&'static str, &'static str, &'static str)] {
        &[
            ("pyo3", "Python::with_gil", "Python interpreter (PyO3)"),
            ("pyo3", "Python::acquire_gil", "Python interpreter (PyO3)"),
            ("pyo3", "prepare_freethreaded_python", "Python interpreter (PyO3)"),
            ("rlua", "Lua::new", "Lua interpreter (rlua)"),
            ("mlua", "Lua::new", "Lua interpreter (mlua)"),
            ("rusty_v8", "v8::Isolate", "V8 JavaScript engine"),
            ("deno_core", "JsRuntime::new", "Deno JavaScript runtime"),
            ("rhai", "Engine::new", "Rhai scripting engine"),
            ("rquickjs", "Context::new", "QuickJS runtime"),
            ("wasmer", "Instance::new", "WebAssembly runtime (Wasmer)"),
            ("wasmtime", "Instance::new", "WebAssembly runtime (Wasmtime)"),
        ]
    }
}

impl Rule for EmbeddedInterpreterUsageRule {
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

            // Quick check: does file use any interpreter crate?
            let mut relevant_crates: Vec<&str> = Vec::new();
            for (crate_name, _, _) in Self::interpreter_patterns() {
                if content.contains(crate_name) && !relevant_crates.contains(crate_name) {
                    relevant_crates.push(crate_name);
                }
            }

            if relevant_crates.is_empty() {
                continue;
            }

            let lines: Vec<&str> = content.lines().collect();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                for (crate_name, pattern, description) in Self::interpreter_patterns() {
                    if relevant_crates.contains(crate_name) && trimmed.contains(pattern) {
                        let location = format!("{}:{}", rel_path, idx + 1);

                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "{} detected. Embedded interpreters can execute arbitrary code. \
                                Ensure user input is validated before evaluation and consider \
                                sandboxing the interpreter context.",
                                description
                            ),
                            function: location,
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
// RUSTCOLA103: WASM Linear Memory OOB Rule
// ============================================================================

/// Detects patterns in WASM-targeted code that may cause linear memory 
/// out-of-bounds access.
/// 
/// In WebAssembly, memory is a contiguous linear array. Unchecked pointer
/// arithmetic or slice creation from raw pointers can access arbitrary memory.
pub struct WasmLinearMemoryOobRule {
    metadata: RuleMetadata,
}

impl WasmLinearMemoryOobRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA103".to_string(),
                name: "wasm-linear-memory-oob".to_string(),
                short_description: "WASM linear memory out-of-bounds risk".to_string(),
                full_description: "Detects patterns in WASM-targeted code that may allow \
                    out-of-bounds access to linear memory. In WASM, memory is a contiguous \
                    array and unchecked pointer operations can access arbitrary memory. \
                    Use bounds checking or safe abstractions like wasm-bindgen.".to_string(),
                help_uri: Some("https://webassembly.org/docs/security/".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Patterns indicating WASM memory operations
    fn wasm_memory_patterns() -> &'static [(&'static str, &'static str)] {
        &[
            // Raw pointer operations in WASM exports
            ("slice::from_raw_parts", "Creating slice from raw pointer without bounds check"),
            ("slice::from_raw_parts_mut", "Creating mutable slice from raw pointer without bounds check"),
            ("std::ptr::read", "Reading from raw pointer without bounds check"),
            ("std::ptr::write", "Writing to raw pointer without bounds check"),
            ("ptr::read", "Reading from raw pointer"),
            ("ptr::write", "Writing to raw pointer"),
            ("ptr::copy", "Copying via raw pointer"),
            ("ptr::copy_nonoverlapping", "Copying via raw pointer"),
            // Pointer arithmetic
            (".offset(", "Pointer offset without bounds validation"),
            (".add(", "Pointer addition without bounds validation"),
            (".sub(", "Pointer subtraction without bounds validation"),
        ]
    }

    /// WASM-specific attributes and patterns
    fn wasm_export_indicators() -> &'static [&'static str] {
        &[
            "#[no_mangle]",
            "#[wasm_bindgen]",
            "extern \"C\"",
            "#[export_name",
        ]
    }
}

impl Rule for WasmLinearMemoryOobRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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

            // Quick check: is this likely WASM code?
            let is_wasm_target = content.contains("wasm_bindgen") || 
                                 content.contains("wasm32") ||
                                 content.contains("#[no_mangle]") ||
                                 package.crate_name.contains("wasm");
            
            if !is_wasm_target {
                continue;
            }

            let lines: Vec<&str> = content.lines().collect();
            let mut in_wasm_export = false;
            let mut export_fn_name = String::new();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Track WASM export functions
                for indicator in Self::wasm_export_indicators() {
                    if trimmed.contains(indicator) {
                        in_wasm_export = true;
                    }
                }

                // Extract function name if we're at a function definition
                if in_wasm_export && (trimmed.starts_with("pub fn ") || 
                                      trimmed.starts_with("pub unsafe fn ") ||
                                      trimmed.starts_with("fn ") ||
                                      trimmed.starts_with("unsafe fn ")) {
                    if let Some(fn_pos) = trimmed.find("fn ") {
                        let after_fn = &trimmed[fn_pos + 3..];
                        export_fn_name = after_fn.split(|c| c == '(' || c == '<')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string();
                    }
                }

                // Reset on function end (simplified)
                if trimmed == "}" && in_wasm_export && !export_fn_name.is_empty() {
                    // Could track brace depth for accuracy
                }

                // Check for dangerous memory patterns in WASM exports
                if in_wasm_export {
                    for (pattern, description) in Self::wasm_memory_patterns() {
                        if trimmed.contains(pattern) {
                            // Check if there's bounds checking nearby
                            let has_bounds_check = lines[idx.saturating_sub(3)..=(idx + 1).min(lines.len() - 1)]
                                .iter()
                                .any(|l| l.contains("if ") && (l.contains(" < ") || l.contains(" <= ") || 
                                     l.contains(".len()") || l.contains("bounds")));

                            if !has_bounds_check {
                                let location = format!("{}:{}", rel_path, idx + 1);
                                
                                findings.push(Finding {
                                    rule_id: self.metadata.id.clone(),
                                    rule_name: self.metadata.name.clone(),
                                    severity: self.metadata.default_severity,
                                    message: format!(
                                        "Potential WASM linear memory OOB in export '{}': {}. \
                                        In WebAssembly, this can access arbitrary memory. \
                                        Add bounds checking or use wasm-bindgen's safe abstractions.",
                                        export_fn_name, description
                                    ),
                                    function: location,
                                    function_signature: String::new(),
                                    evidence: vec![trimmed.to_string()],
                                    span: None,
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
// Registration
// ============================================================================

/// Register all FFI rules with the rule engine.
pub fn register_ffi_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(AllocatorMismatchFfiRule::new()));
    engine.register_rule(Box::new(UnsafeFfiPointerReturnRule::new()));
    engine.register_rule(Box::new(PackedFieldReferenceRule::new()));
    engine.register_rule(Box::new(UnsafeCStringPointerRule::new()));
    engine.register_rule(Box::new(CtorDtorStdApiRule::new()));
    engine.register_rule(Box::new(FfiBufferLeakRule::new()));
    engine.register_rule(Box::new(PanicInFfiBoundaryRule::new()));
    engine.register_rule(Box::new(EmbeddedInterpreterUsageRule::new()));
    engine.register_rule(Box::new(WasmLinearMemoryOobRule::new()));
}
