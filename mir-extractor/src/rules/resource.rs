//! Resource management rules.
//!
//! Rules detecting resource management issues:
//! - File/directory permissions and handling
//! - Path traversal and absolute path issues
//! - Child process management
//! - OpenOptions configuration issues

#![allow(dead_code)]

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};
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

/// Register all resource management rules with the rule engine.
pub fn register_resource_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(SpawnedChildNoWaitRule::new()));
    engine.register_rule(Box::new(PermissionsSetReadonlyFalseRule::new()));
    engine.register_rule(Box::new(WorldWritableModeRule::new()));
    engine.register_rule(Box::new(OpenOptionsMissingTruncateRule::new()));
    engine.register_rule(Box::new(UnixPermissionsNotOctalRule::new()));
    engine.register_rule(Box::new(OpenOptionsInconsistentFlagsRule::new()));
    engine.register_rule(Box::new(AbsolutePathInJoinRule::new()));
}
