//! Resource management rules.
//!
//! Rules detecting resource management issues:
//! - File/directory permissions and handling
//! - Path traversal and absolute path issues
//! - Child process management
//! - OpenOptions configuration issues
//! - Hardcoded home paths
//! - Build script network access
//! - Unbounded allocations from untrusted input

#![allow(dead_code)]

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use crate::{Confidence, Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};
use crate::prototypes;
use crate::line_has_world_writable_mode;

// ============================================================================
// RUSTCOLA067: Spawned Child Process Not Waited On
// ============================================================================

/// Detects child processes spawned but not waited on, creating zombie processes.
pub struct SpawnedChildNoWaitRule {
    metadata: RuleMetadata,
}

impl SpawnedChildNoWaitRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA067".to_string(),
                name: "spawned-child-no-wait".to_string(),
                short_description: "Spawned child process not waited on".to_string(),
                full_description: "Detects child processes spawned via Command::spawn() that are \
                    not waited on via wait(), status(), or wait_with_output(). Failing to wait \
                    on spawned children creates zombie processes that consume system resources. \
                    Implements Clippy's zombie_processes lint.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }
}

impl Rule for SpawnedChildNoWaitRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("SpawnedChildNoWaitRule") {
                continue;
            }

            let body_str = function.body.join("\n");
            let lower = body_str.to_lowercase();
            
            let spawn_count = lower.matches("::spawn(").count();
            if spawn_count == 0 {
                continue;
            }
            
            let wait_count = lower.matches("child::wait(").count()
                + lower.matches("::wait_with_output(").count();
            
            let mut child_status_count = 0;
            for line in &function.body {
                let line_lower = line.to_lowercase();
                if line_lower.contains("child") && line_lower.contains("::status(") {
                    child_status_count += 1;
                }
            }
            
            let total_wait_count = wait_count + child_status_count;
            
            if spawn_count > total_wait_count {
                let evidence: Vec<String> = function.body
                    .iter()
                    .filter(|line| line.to_lowercase().contains("::spawn("))
                    .take(5)
                    .map(|line| line.trim().to_string())
                    .collect();
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Child process spawned in `{}` but not waited on - call wait(), \
                        status(), or wait_with_output() to prevent zombie processes",
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
// RUSTCOLA028: Permissions::set_readonly(false)
// ============================================================================

/// Detects permissions being set to non-readonly, potentially exposing files.
pub struct PermissionsSetReadonlyFalseRule {
    metadata: RuleMetadata,
}

impl PermissionsSetReadonlyFalseRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA028".to_string(),
                name: "permissions-set-readonly-false".to_string(),
                short_description: "Permissions::set_readonly(false) detected".to_string(),
                full_description: "Flags calls to std::fs::Permissions::set_readonly(false) \
                    which downgrade filesystem permissions and can leave files world-writable \
                    on Unix targets.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }
}

impl Rule for PermissionsSetReadonlyFalseRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            let mut evidence = Vec::new();

            for line in &function.body {
                if line.contains("set_readonly(") && line.contains("false") {
                    evidence.push(line.trim().to_string());
                }
            }

            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!(
                    "Permissions::set_readonly(false) used in `{}`",
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

        findings
    }
}

// ============================================================================
// RUSTCOLA029: World-Writable File Mode
// ============================================================================

/// Detects world-writable file permissions (0o777, 0o666, etc.).
pub struct WorldWritableModeRule {
    metadata: RuleMetadata,
}

impl WorldWritableModeRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA029".to_string(),
                name: "world-writable-mode".to_string(),
                short_description: "World-writable file mode detected".to_string(),
                full_description: "Detects explicit world-writable permission masks (e.g., 0o777/0o666) \
                    passed to PermissionsExt::set_mode, OpenOptionsExt::mode, or similar builders.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }
}

impl Rule for WorldWritableModeRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            let mut evidence = Vec::new();

            for line in &function.body {
                if line_has_world_writable_mode(line) {
                    evidence.push(line.trim().to_string());
                }
            }

            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!("World-writable permission mask set in `{}`", function.name),
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

        findings
    }
}

// ============================================================================
// RUSTCOLA032: OpenOptions Missing Truncate
// ============================================================================

/// Detects OpenOptions with write+create but no truncate or append.
pub struct OpenOptionsMissingTruncateRule {
    metadata: RuleMetadata,
}

impl OpenOptionsMissingTruncateRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA032".to_string(),
                name: "openoptions-missing-truncate".to_string(),
                short_description: "File created with write(true) without truncate or append".to_string(),
                full_description: "Detects OpenOptions::new().write(true).create(true) patterns \
                    that don't specify .truncate(true) or .append(true). Old file contents may remain, \
                    leading to stale data disclosure or corruption.".to_string(),
                help_uri: Some("https://rust-lang.github.io/rust-clippy/master/index.html#suspicious_open_options".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }
}

impl Rule for OpenOptionsMissingTruncateRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn cache_key(&self) -> String {
        format!("{}:v1", self.metadata.id)
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            let mut has_write_true = false;
            let mut has_create_true = false;
            let mut has_truncate_or_append = false;
            let mut open_options_start_line = None;
            let mut evidence_lines = Vec::new();

            for (idx, line) in function.body.iter().enumerate() {
                if line.contains("OpenOptions::new()") {
                    open_options_start_line = Some(idx);
                    has_write_true = false;
                    has_create_true = false;
                    has_truncate_or_append = false;
                    evidence_lines.clear();
                    evidence_lines.push(line.trim().to_string());
                }

                if let Some(start) = open_options_start_line {
                    if idx <= start + 20 {
                        if line.contains(".write(true)") || (line.contains("OpenOptions::write") && line.contains("const true")) {
                            has_write_true = true;
                            if !evidence_lines.iter().any(|e| e.contains(line.trim())) {
                                evidence_lines.push(line.trim().to_string());
                            }
                        }
                        
                        if line.contains(".create(true)") || (line.contains("OpenOptions::create") && line.contains("const true")) {
                            has_create_true = true;
                            if !evidence_lines.iter().any(|e| e.contains(line.trim())) {
                                evidence_lines.push(line.trim().to_string());
                            }
                        }
                        
                        if line.contains(".truncate(true)") || line.contains(".append(true)") ||
                           (line.contains("OpenOptions::truncate") && line.contains("const true")) ||
                           (line.contains("OpenOptions::append") && line.contains("const true")) {
                            has_truncate_or_append = true;
                        }

                        if line.contains(".open(") || line.contains("OpenOptions::open") {
                            if has_write_true && has_create_true && !has_truncate_or_append {
                                findings.push(Finding {
                                    rule_id: self.metadata.id.clone(),
                                    rule_name: self.metadata.name.clone(),
                                    severity: self.metadata.default_severity,
                                    message: format!(
                                        "File opened with write(true) and create(true) but no truncate(true) or append(true) in `{}`",
                                        function.name
                                    ),
                                    function: function.name.clone(),
                                    function_signature: function.signature.clone(),
                                    evidence: evidence_lines.clone(),
                                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                                });
                            }
                            open_options_start_line = None;
                        }
                    } else {
                        open_options_start_line = None;
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA055: Unix Permissions Not Octal
// ============================================================================

/// Detects Unix permissions passed as decimal instead of octal notation.
pub struct UnixPermissionsNotOctalRule {
    metadata: RuleMetadata,
}

impl UnixPermissionsNotOctalRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA055".to_string(),
                name: "unix-permissions-not-octal".to_string(),
                short_description: "Unix file permissions not in octal notation".to_string(),
                full_description: "Detects Unix file permissions passed as decimal literals instead \
                    of octal notation. Decimal literals like 644 or 755 are confusing because they \
                    look like octal but are interpreted as decimal. Use explicit octal notation \
                    with 0o prefix (e.g., 0o644, 0o755).".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    fn looks_like_decimal_permission(&self, function: &MirFunction) -> bool {
        let body_str = format!("{:?}", function.body);
        
        let has_permission_api = body_str.contains("from_mode")
            || body_str.contains("set_mode")
            || body_str.contains("chmod")
            || body_str.contains("DirBuilder");
        
        if !has_permission_api {
            return false;
        }
        
        let suspicious_decimals = [
            "644_u32", "755_u32", "777_u32", "666_u32",
            "600_u32", "700_u32", "750_u32", "640_u32",
            "= 644", "= 755", "= 777", "= 666",
            "= 600", "= 700", "= 750", "= 640",
        ];
        
        for pattern in &suspicious_decimals {
            if body_str.contains(pattern) {
                let context_check = format!("0o{}", pattern);
                if !body_str.contains(&context_check) {
                    return true;
                }
            }
        }
        
        false
    }
}

impl Rule for UnixPermissionsNotOctalRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.looks_like_decimal_permission(function) {
                let body_str = format!("{:?}", function.body);
                let mut evidence = Vec::new();

                for line in body_str.lines().take(200) {
                    if (line.contains("from_mode") || line.contains("set_mode") 
                        || line.contains("chmod") || line.contains("DirBuilder"))
                        && (line.contains("644") || line.contains("755") 
                            || line.contains("777") || line.contains("666")
                            || line.contains("600") || line.contains("700")) {
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
                    message: "Unix file permissions use decimal notation instead of octal. \
                        Use 0o prefix (e.g., 0o644 for rw-r--r--, 0o755 for rwxr-xr-x).".to_string(),
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
// RUSTCOLA056: OpenOptions Inconsistent Flags
// ============================================================================

/// Detects OpenOptions with dangerous or inconsistent flag combinations.
pub struct OpenOptionsInconsistentFlagsRule {
    metadata: RuleMetadata,
}

impl OpenOptionsInconsistentFlagsRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA056".to_string(),
                name: "openoptions-inconsistent-flags".to_string(),
                short_description: "OpenOptions with inconsistent flag combinations".to_string(),
                full_description: "Detects OpenOptions with dangerous or inconsistent flag \
                    combinations: create without write, truncate without write, or append with truncate.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    fn check_openoptions_flags(&self, function: &MirFunction) -> Option<String> {
        let body_str = function.body.join("\n");
        
        if !body_str.contains("OpenOptions") {
            return None;
        }
        
        let has_write = body_str.contains(".write(true)") || (body_str.contains("OpenOptions::write") && body_str.contains("const true"));
        let has_create = body_str.contains(".create(true)") || (body_str.contains("OpenOptions::create") && body_str.contains("const true"));
        let has_create_new = body_str.contains(".create_new(true)") || (body_str.contains("OpenOptions::create_new") && body_str.contains("const true"));
        let has_truncate = body_str.contains(".truncate(true)") || (body_str.contains("OpenOptions::truncate") && body_str.contains("const true"));
        let has_append = body_str.contains(".append(true)") || (body_str.contains("OpenOptions::append") && body_str.contains("const true"));
        
        if (has_create || has_create_new) && !has_write && !has_append {
            return Some("create(true) without write(true) or append(true). File will be created but not writable.".to_string());
        }
        
        if has_truncate && !has_write && !has_append {
            return Some("truncate(true) without write(true). This would truncate the file but not allow writing.".to_string());
        }
        
        if has_append && has_truncate {
            return Some("append(true) with truncate(true). These flags are contradictory.".to_string());
        }
        
        None
    }
}

impl Rule for OpenOptionsInconsistentFlagsRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if let Some(issue_description) = self.check_openoptions_flags(function) {
                let mut evidence = Vec::new();

                for line in &function.body {
                    if line.contains("OpenOptions") || line.contains(".write") 
                        || line.contains(".create") || line.contains(".truncate")
                        || line.contains(".append") {
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
                    message: format!("OpenOptions has inconsistent flag combination: {}", issue_description),
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
// RUSTCOLA058: Absolute Path in Join
// ============================================================================

/// Detects absolute paths passed to Path::join() or PathBuf::push().
pub struct AbsolutePathInJoinRule {
    metadata: RuleMetadata,
}

impl AbsolutePathInJoinRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA058".to_string(),
                name: "absolute-path-in-join".to_string(),
                short_description: "Absolute path passed to Path::join() or PathBuf::push()".to_string(),
                full_description: "Detects when Path::join() or PathBuf::push() receives an \
                    absolute path argument. Absolute paths nullify the base path, defeating \
                    sanitization and potentially enabling path traversal attacks.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    fn looks_like_absolute_path_join(&self, function: &MirFunction) -> bool {
        let body_str = format!("{:?}", function.body);
        
        let has_path_ops = body_str.contains("Path::join") || 
                          body_str.contains("PathBuf::join") ||
                          body_str.contains("PathBuf::push");
        
        if !has_path_ops {
            return false;
        }
        
        let absolute_patterns = [
            "\"/", "\"C:", "\"D:", "\"E:", "\"F:",
            "\"/etc", "\"/usr", "\"/var", "\"/tmp", "\"/home",
            "\"/root", "\"/sys", "\"/proc", "\"/dev",
            "\"C:\\\\", "\"/Users", "\"/Applications",
        ];
        
        for pattern in &absolute_patterns {
            if body_str.contains(pattern) {
                return true;
            }
        }
        
        false
    }
}

impl Rule for AbsolutePathInJoinRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.looks_like_absolute_path_join(function) {
                let mut evidence = Vec::new();

                for line in &function.body {
                    let has_join_or_push = (line.contains("Path::join") || 
                                           line.contains("PathBuf::join") || 
                                           line.contains("PathBuf::push")) &&
                                          line.contains("const");
                    
                    if !has_join_or_push {
                        continue;
                    }
                    
                    let has_absolute = line.contains("const \"/") || 
                                      line.contains("const \"C:") || 
                                      line.contains("const \"D:");
                    
                    if has_absolute {
                        evidence.push(line.trim().to_string());
                        if evidence.len() >= 5 {
                            break;
                        }
                    }
                }
                
                if !evidence.is_empty() {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: "Absolute path passed to Path::join() or PathBuf::push(). \
                            This nullifies the base path, potentially enabling path traversal.".to_string(),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence,
                        span: None,
                    ..Default::default()
                    });
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA014: Hardcoded Home Path Rule
// ============================================================================

/// Detects hard-coded paths to user home directories.
pub struct HardcodedHomePathRule {
    metadata: RuleMetadata,
}

impl HardcodedHomePathRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA014".to_string(),
                name: "hardcoded-home-path".to_string(),
                short_description: "Hard-coded home directory path detected".to_string(),
                full_description: "Detects absolute paths to user home directories hard-coded in string literals. Hard-coded home paths reduce portability and create security issues: (1) Code breaks when run under different users or in containers/CI, (2) Exposes username information in source code, (3) Prevents proper multi-user deployments, (4) Makes code non-portable across operating systems. Use environment variables (HOME, USERPROFILE), std::env::home_dir(), or the dirs crate instead. Detects patterns like /home/username, /Users/username, C:\\Users\\username, and ~username (with username).".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }
}

impl Rule for HardcodedHomePathRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            // Self-exclusion
            if function.name.contains("HardcodedHomePathRule") {
                continue;
            }

            let body_str = function.body.join("\n");
            
            // Patterns for hard-coded home directory paths
            // Unix/Linux: /home/username
            // macOS: /Users/username  
            // Windows: C:\Users\username or C:/Users/username
            // Tilde with username: ~username (but not ~/something)
            let home_patterns = [
                "\"/home/",
                "\"/Users/",
                "\"C:\\\\Users\\\\",
                "\"C:/Users/",
            ];
            
            let mut found_hardcoded = false;
            
            for pattern in &home_patterns {
                if body_str.contains(pattern) {
                    found_hardcoded = true;
                    break;
                }
            }
            
            // Check for ~username (tilde with username, not just ~/)
            // Look for "~ followed by non-slash characters
            if body_str.contains("\"~") && !body_str.contains("\"~/") {
                found_hardcoded = true;
            }
            
            if !found_hardcoded {
                continue;
            }

            // Collect evidence lines
            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| {
                    home_patterns.iter().any(|p| line.contains(p)) ||
                    (line.contains("\"~") && !line.contains("\"~/"))
                })
                .take(5)
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
                    "Hard-coded home directory path in `{}` - use environment variables (HOME/USERPROFILE) or std::env::home_dir() instead",
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

        findings
    }
}

// ============================================================================
// RUSTCOLA097: Build Script Network Access Rule
// ============================================================================

/// Detects network access in build scripts, which is a supply-chain security risk.
pub struct BuildScriptNetworkRule {
    metadata: RuleMetadata,
}

impl BuildScriptNetworkRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA097".to_string(),
                name: "build-script-network-access".to_string(),
                short_description: "Network access detected in build script".to_string(),
                full_description: "Build scripts (build.rs) should not perform network requests, download files, or spawn processes that contact external systems. This is a supply-chain security risk - malicious dependencies could exfiltrate data or download malware at build time. Use vendored dependencies or pre-downloaded assets instead.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/cargo/reference/build-scripts.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }

    /// Network-related patterns to detect
    fn network_patterns() -> &'static [(&'static str, &'static str)] {
        &[
            // HTTP client libraries
            ("reqwest::blocking::get", "reqwest HTTP client"),
            ("reqwest::get", "reqwest HTTP client"),
            ("reqwest::Client", "reqwest HTTP client"),
            ("ureq::get", "ureq HTTP client"),
            ("ureq::post", "ureq HTTP client"),
            ("ureq::Agent", "ureq HTTP client"),
            ("hyper::Client", "hyper HTTP client"),
            ("curl::easy::Easy", "curl library"),
            ("attohttpc::", "attohttpc HTTP client"),
            ("minreq::", "minreq HTTP client"),
            ("isahc::", "isahc HTTP client"),
            
            // Network primitives
            ("TcpStream::connect", "raw TCP connection"),
            ("UdpSocket::bind", "raw UDP socket"),
            ("std::net::TcpStream", "TCP network access"),
            ("tokio::net::", "tokio network access"),
            ("async_std::net::", "async-std network access"),
            ("to_socket_addrs", "DNS lookup"),
            
            // Dangerous commands
            ("Command::new(\"curl\")", "curl command"),
            ("Command::new(\"wget\")", "wget command"),
            ("Command::new(\"fetch\")", "fetch command"),
            ("Command::new(\"git\")", "git command (may clone from network)"),
            ("Command::new(\"npm\")", "npm command (network access)"),
            ("Command::new(\"pip\")", "pip command (network access)"),
            ("Command::new(\"cargo\")", "cargo command (may download crates)"),
        ]
    }

    /// Safe patterns that shouldn't trigger even if they look like network access
    fn safe_patterns() -> &'static [&'static str] {
        &[
            "// SAFE:",
            "// Safe:",
            "#[allow(",
            "mock",
            "test",
            "localhost",
            "127.0.0.1",
            "::1",
        ]
    }
}

impl Rule for BuildScriptNetworkRule {
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

        // Only scan build.rs files
        let build_rs = crate_root.join("build.rs");
        if !build_rs.exists() {
            return findings;
        }

        let content = match fs::read_to_string(&build_rs) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let lines: Vec<&str> = content.lines().collect();
        let mut current_fn_name = String::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Track function names
            if trimmed.contains("fn ") {
                if let Some(fn_pos) = trimmed.find("fn ") {
                    let after_fn = &trimmed[fn_pos + 3..];
                    if let Some(paren_pos) = after_fn.find('(') {
                        current_fn_name = after_fn[..paren_pos].trim().to_string();
                    }
                }
            }

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            // Check for safe patterns first
            let is_safe = Self::safe_patterns().iter().any(|p| line.contains(p));
            if is_safe {
                continue;
            }

            // Check for network patterns
            for (pattern, description) in Self::network_patterns() {
                if line.contains(pattern) {
                    let location = format!("build.rs:{}", idx + 1);
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "{} detected in build script function `{}`. Build scripts should not perform network requests - this is a supply-chain security risk.",
                            description, current_fn_name
                        ),
                        function: location,
                        function_signature: current_fn_name.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: None,
                    ..Default::default()
                    });
                    break; // Only report once per line
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA024: Unbounded allocation from tainted input
// ============================================================================

pub struct UnboundedAllocationRule {
    metadata: RuleMetadata,
}

impl UnboundedAllocationRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA024".to_string(),
                name: "unbounded-allocation".to_string(),
                short_description: "Allocation sized from tainted length without guard".to_string(),
                full_description: "Detects allocations (`with_capacity`, `reserve*`) that rely on tainted length values (parameters, `.len()` on attacker data, etc.) without bounding them, enabling memory exhaustion.".to_string(),
                help_uri: Some("https://github.com/Opus-the-penguin/Rust-cola/blob/main/docs/security-rule-backlog.md#resource-management--dos".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
            },
        }
    }
}

impl Rule for UnboundedAllocationRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let options = prototypes::PrototypeOptions::default();

        for function in &package.functions {
            let specialized =
                prototypes::detect_content_length_allocations_with_options(function, &options);
            let specialized_lines: HashSet<_> = specialized
                .iter()
                .map(|alloc| alloc.allocation_line.clone())
                .collect();

            let allocations =
                prototypes::detect_unbounded_allocations_with_options(function, &options);

            for allocation in allocations {
                if specialized_lines.contains(&allocation.allocation_line) {
                    continue;
                }

                let mut evidence = vec![allocation.allocation_line.clone()];

                let mut tainted: Vec<_> = allocation.tainted_vars.iter().cloned().collect();
                tainted.sort();
                tainted.dedup();
                if !tainted.is_empty() {
                    evidence.push(format!("tainted length symbols: {}", tainted.join(", ")));
                }

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Potential unbounded allocation from tainted input in `{}`",
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
// Registration
// ============================================================================

/// Register all resource management rules with the rule engine.
pub fn register_resource_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(SpawnedChildNoWaitRule::new()));
    engine.register_rule(Box::new(PermissionsSetReadonlyFalseRule::new()));
    engine.register_rule(Box::new(WorldWritableModeRule::new()));
    engine.register_rule(Box::new(OpenOptionsMissingTruncateRule::new()));
    engine.register_rule(Box::new(UnixPermissionsNotOctalRule::new()));
    engine.register_rule(Box::new(OpenOptionsInconsistentFlagsRule::new()));
    engine.register_rule(Box::new(AbsolutePathInJoinRule::new()));
    engine.register_rule(Box::new(HardcodedHomePathRule::new()));
    engine.register_rule(Box::new(BuildScriptNetworkRule::new()));
    engine.register_rule(Box::new(UnboundedAllocationRule::new()));
}
