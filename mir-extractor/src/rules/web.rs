//! Web security rules.
//!
//! Rules detecting web application security issues:
//! - AWS S3 unscoped access
//! - Cleartext logging of sensitive data
//! - Connection string password exposure
//! - Cookie security attributes
//! - CORS wildcard configuration
//! - Password field masking
//! - TLS verification disabled

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};
use std::collections::HashSet;

// ============================================================================
// RUSTCOLA011: Non-HTTPS URL Rule
// ============================================================================

/// Detects HTTP URLs in code where HTTPS should be used.
pub struct NonHttpsUrlRule {
    metadata: RuleMetadata,
}

impl NonHttpsUrlRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA011".to_string(),
                name: "non-https-url".to_string(),
                short_description: "HTTP URL usage".to_string(),
                full_description: "Flags string literals using http:// URLs in networking code where HTTPS is expected.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for NonHttpsUrlRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let patterns = ["\"http://", "http://"];

        for function in &package.functions {
            let evidence: Vec<String> = function.body.iter()
                .filter(|line| patterns.iter().any(|p| line.contains(p)))
                .map(|line| line.trim().to_string())
                .collect();
            
            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!("HTTP URL literal detected in `{}`", function.name),
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
// RUSTCOLA012: Danger Accept Invalid Certs Rule
// ============================================================================

const DANGER_ACCEPT_INVALID_CERTS_SYMBOL: &str = concat!("danger", "_accept", "_invalid", "_certs");
const DANGER_ACCEPT_INVALID_HOSTNAMES_SYMBOL: &str = concat!("danger", "_accept", "_invalid", "_hostnames");

fn line_disables_tls_verification(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_lowercase();

    if lower.contains(DANGER_ACCEPT_INVALID_CERTS_SYMBOL) && lower.contains("true") {
        return true;
    }

    if lower.contains(DANGER_ACCEPT_INVALID_HOSTNAMES_SYMBOL) && lower.contains("true") {
        return true;
    }

    let touches_dangerous_client = lower.contains("dangerous::dangerousclientconfig");
    let sets_custom_verifier = lower.contains("set_certificate_verifier");
    let sets_custom_resolver = lower.contains("set_certificate_resolver");

    if touches_dangerous_client && (sets_custom_verifier || sets_custom_resolver) {
        return true;
    }

    if (sets_custom_verifier || sets_custom_resolver)
        && (lower.contains("noverifier")
            || lower.contains("nocertificateverification")
            || lower.contains("no_certificate_verifier"))
    {
        return true;
    }

    if lower.contains("dangerous()") && (sets_custom_verifier || sets_custom_resolver) {
        return true;
    }

    false
}

/// Detects TLS certificate validation being disabled.
pub struct DangerAcceptInvalidCertRule {
    metadata: RuleMetadata,
}

impl DangerAcceptInvalidCertRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA012".to_string(),
                name: "danger-accept-invalid-certs".to_string(),
                short_description: "TLS certificate validation disabled".to_string(),
                full_description: "Detects calls enabling reqwest's danger_accept_invalid_certs(true), which disables certificate validation.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for DangerAcceptInvalidCertRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            let mut lines = Vec::new();
            let mut seen = HashSet::new();

            for raw_line in &function.body {
                if line_disables_tls_verification(raw_line) {
                    let trimmed = raw_line.trim().to_string();
                    if seen.insert(trimmed.clone()) {
                        lines.push(trimmed);
                    }
                }
            }

            if lines.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!(
                    "TLS validation disabled via danger_accept_invalid_* in `{}`",
                    function.name
                ),
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence: lines,
                span: function.span.clone(),
            });
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA013: OpenSSL Verify None Rule
// ============================================================================

struct OpensslVerifyNoneInvocation {
    call_line: String,
    supporting_lines: Vec<String>,
}

fn detect_openssl_verify_none(function: &MirFunction) -> Vec<OpensslVerifyNoneInvocation> {
    let mut invocations = Vec::new();
    
    for (i, line) in function.body.iter().enumerate() {
        let lower = line.to_lowercase();
        
        // Check for set_verify with NONE
        if lower.contains("set_verify") && lower.contains("none") {
            let mut supporting = Vec::new();
            // Look for context in nearby lines
            for j in i.saturating_sub(3)..=(i + 3).min(function.body.len() - 1) {
                if j != i {
                    supporting.push(function.body[j].trim().to_string());
                }
            }
            invocations.push(OpensslVerifyNoneInvocation {
                call_line: line.trim().to_string(),
                supporting_lines: supporting,
            });
        }
        
        // Check for SslVerifyMode::NONE
        if lower.contains("sslverifymode::none") || lower.contains("ssl_verify_none") {
            invocations.push(OpensslVerifyNoneInvocation {
                call_line: line.trim().to_string(),
                supporting_lines: Vec::new(),
            });
        }
    }
    
    invocations
}

/// Detects OpenSSL configurations that disable certificate verification.
pub struct OpensslVerifyNoneRule {
    metadata: RuleMetadata,
}

impl OpensslVerifyNoneRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA013".to_string(),
                name: "openssl-verify-none".to_string(),
                short_description: "SslContext configured with VerifyNone".to_string(),
                full_description: "Detects OpenSSL configurations that disable certificate verification (VerifyNone).".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for OpensslVerifyNoneRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            let invocations = detect_openssl_verify_none(function);
            if invocations.is_empty() {
                continue;
            }

            for invocation in invocations {
                let mut evidence = vec![invocation.call_line.clone()];
                for line in invocation.supporting_lines {
                    if !evidence.contains(&line) {
                        evidence.push(line);
                    }
                }

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "OpenSSL certificate verification disabled in `{}`",
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
// RUSTCOLA042: Cookie Secure Attribute Rule
// ============================================================================

/// Detects cookies without Secure attribute.
pub struct CookieSecureAttributeRule {
    metadata: RuleMetadata,
}

impl CookieSecureAttributeRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA042".to_string(),
                name: "cookie-secure-attribute".to_string(),
                short_description: "Cookie missing Secure attribute".to_string(),
                full_description: "Detects cookies set without the Secure attribute, which allows transmission over unencrypted connections.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for CookieSecureAttributeRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Look for cookie-related patterns
            let cookie_lines: Vec<&String> = function.body.iter()
                .filter(|line| {
                    let lower = line.to_lowercase();
                    lower.contains("cookie") && lower.contains("new")
                })
                .collect();
            
            if cookie_lines.is_empty() {
                continue;
            }
            
            // Check if secure is set anywhere in the function
            let has_secure = function.body.iter().any(|line| {
                let lower = line.to_lowercase();
                lower.contains("secure(true)") || lower.contains("set_secure")
            });
            
            if !has_secure {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!("Cookie created without Secure attribute in `{}`", function.name),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: cookie_lines.iter().map(|s| s.trim().to_string()).collect(),
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA043: CORS Wildcard Rule
// ============================================================================

/// Detects CORS configurations with wildcard origins.
pub struct CorsWildcardRule {
    metadata: RuleMetadata,
}

impl CorsWildcardRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA043".to_string(),
                name: "cors-wildcard".to_string(),
                short_description: "CORS wildcard origin configured".to_string(),
                full_description: "Detects CORS configurations that allow any origin (*), which can enable cross-site request attacks.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for CorsWildcardRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            let evidence: Vec<String> = function.body.iter()
                .filter(|line| {
                    let lower = line.to_lowercase();
                    // Look for CORS with wildcard patterns
                    (lower.contains("cors") || lower.contains("access-control-allow-origin")) &&
                    (lower.contains("\"*\"") || lower.contains("any()") || lower.contains("permissive()"))
                })
                .map(|s| s.trim().to_string())
                .collect();
            
            if !evidence.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!("CORS wildcard origin in `{}`", function.name),
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
// RUSTCOLA060: Connection String Password Rule
// ============================================================================

/// Detects hardcoded passwords in connection strings.
pub struct ConnectionStringPasswordRule {
    metadata: RuleMetadata,
}

impl ConnectionStringPasswordRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA060".to_string(),
                name: "connection-string-password".to_string(),
                short_description: "Password in connection string".to_string(),
                full_description: "Detects hardcoded passwords in database connection strings.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for ConnectionStringPasswordRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            let evidence: Vec<String> = function.body.iter()
                .filter(|line| {
                    let lower = line.to_lowercase();
                    // Connection string patterns with embedded passwords
                    (lower.contains("password=") || lower.contains("pwd=")) &&
                    (lower.contains("postgres") || lower.contains("mysql") || 
                     lower.contains("mongodb") || lower.contains("redis") ||
                     lower.contains("connection") || lower.contains("database"))
                })
                .map(|s| s.trim().to_string())
                .collect();
            
            if !evidence.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!("Hardcoded password in connection string in `{}`", function.name),
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
// RUSTCOLA061: Password Field Masking Rule
// ============================================================================

/// Detects password fields that may not be properly masked.
pub struct PasswordFieldMaskingRule {
    metadata: RuleMetadata,
}

impl PasswordFieldMaskingRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA061".to_string(),
                name: "password-field-masking".to_string(),
                short_description: "Password field not masked".to_string(),
                full_description: "Detects password fields in Debug or Display implementations that may leak sensitive data.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for PasswordFieldMaskingRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Look for Debug/Display implementations with password fields
            let is_debug_impl = function.name.contains("fmt") && 
                (function.signature.contains("Debug") || function.signature.contains("Display"));
            
            if !is_debug_impl {
                continue;
            }
            
            let has_password_field = function.body.iter().any(|line| {
                let lower = line.to_lowercase();
                lower.contains("password") || lower.contains("secret") || lower.contains("token")
            });
            
            if has_password_field {
                let evidence: Vec<String> = function.body.iter()
                    .filter(|line| {
                        let lower = line.to_lowercase();
                        lower.contains("password") || lower.contains("secret") || lower.contains("token")
                    })
                    .map(|s| s.trim().to_string())
                    .collect();
                    
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!("Password field exposed in Debug/Display in `{}`", function.name),
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
// RUSTCOLA075: Cleartext Logging Rule
// ============================================================================

/// Detects logging of sensitive data in cleartext.
pub struct CleartextLoggingRule {
    metadata: RuleMetadata,
}

impl CleartextLoggingRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA075".to_string(),
                name: "cleartext-logging".to_string(),
                short_description: "Sensitive data in logs".to_string(),
                full_description: "Detects logging of sensitive data (passwords, tokens, keys) without masking.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for CleartextLoggingRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            let evidence: Vec<String> = function.body.iter()
                .filter(|line| {
                    let lower = line.to_lowercase();
                    // Log macros with sensitive data
                    let has_log = lower.contains("log::") || lower.contains("tracing::") ||
                                  lower.contains("println!") || lower.contains("eprintln!");
                    let has_sensitive = lower.contains("password") || lower.contains("secret") ||
                                       lower.contains("token") || lower.contains("api_key");
                    has_log && has_sensitive
                })
                .map(|s| s.trim().to_string())
                .collect();
            
            if !evidence.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!("Sensitive data logged in cleartext in `{}`", function.name),
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
// RUSTCOLA084: TLS Verification Disabled Rule
// ============================================================================

/// Comprehensive detection of disabled TLS certificate verification across
/// multiple HTTP/TLS libraries.
///
/// Covered libraries:
/// - native-tls: danger_accept_invalid_certs, danger_accept_invalid_hostnames
/// - rustls: .dangerous(), DangerousClientConfigBuilder, ServerCertVerified::assertion()
/// - reqwest: danger_accept_invalid_certs(true), danger_accept_invalid_hostnames(true)
/// - hyper-tls: native-tls connector with verification disabled
/// - OpenSSL: SSL_VERIFY_NONE
pub struct TlsVerificationDisabledRule {
    metadata: RuleMetadata,
}

impl TlsVerificationDisabledRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA084".to_string(),
                name: "tls-verification-disabled".to_string(),
                short_description: "TLS certificate verification disabled".to_string(),
                full_description: "Detects disabled TLS certificate verification in HTTP/TLS \
                    client libraries including native-tls, rustls, reqwest, and hyper-tls. \
                    Disabling certificate verification allows man-in-the-middle attacks. \
                    Only disable in controlled environments (e.g., testing with self-signed certs) \
                    and never in production code."
                    .to_string(),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                help_uri: None,
            },
        }
    }
}

impl Rule for TlsVerificationDisabledRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Skip test functions (common to disable TLS verification in tests)
            if function.signature.contains("#[test]") || 
               function.name.contains("test") ||
               function.signature.contains("#[cfg(test)]") {
                continue;
            }

            let mut found_dangers: Vec<(String, String)> = Vec::new();

            for line in &function.body {
                let trimmed = line.trim();

                // --- native-tls patterns ---
                // Pattern: TlsConnectorBuilder::danger_accept_invalid_certs(_, const true)
                if trimmed.contains("danger_accept_invalid_certs") && trimmed.contains("const true") {
                    let library = if trimmed.contains("native_tls") || trimmed.contains("TlsConnectorBuilder") {
                        "native-tls"
                    } else if trimmed.contains("reqwest") || trimmed.contains("ClientBuilder") {
                        "reqwest"
                    } else {
                        "TLS library"
                    };
                    found_dangers.push((
                        format!("{}: danger_accept_invalid_certs(true) disables certificate validation", library),
                        trimmed.to_string(),
                    ));
                }

                // Pattern: TlsConnectorBuilder::danger_accept_invalid_hostnames(_, const true)
                if trimmed.contains("danger_accept_invalid_hostnames") && trimmed.contains("const true") {
                    let library = if trimmed.contains("native_tls") || trimmed.contains("TlsConnectorBuilder") {
                        "native-tls"
                    } else if trimmed.contains("reqwest") || trimmed.contains("ClientBuilder") {
                        "reqwest"
                    } else {
                        "TLS library"
                    };
                    found_dangers.push((
                        format!("{}: danger_accept_invalid_hostnames(true) disables hostname verification", library),
                        trimmed.to_string(),
                    ));
                }

                // --- rustls patterns ---
                // Pattern: ConfigBuilder::dangerous() - entering dangerous mode
                if (trimmed.contains(">::dangerous(") || trimmed.contains("::dangerous(move")) &&
                   (trimmed.contains("rustls") || trimmed.contains("ConfigBuilder") || trimmed.contains("WantsVerifier")) {
                    found_dangers.push((
                        "rustls: .dangerous() enables unsafe TLS configuration".to_string(),
                        trimmed.to_string(),
                    ));
                }

                // Pattern: DangerousClientConfigBuilder::with_custom_certificate_verifier
                if trimmed.contains("DangerousClientConfigBuilder") && trimmed.contains("with_custom_certificate_verifier") {
                    found_dangers.push((
                        "rustls: custom certificate verifier may bypass validation".to_string(),
                        trimmed.to_string(),
                    ));
                }

                // Pattern: ServerCertVerified::assertion() - always-accept verifier
                if trimmed.contains("ServerCertVerified::assertion()") {
                    found_dangers.push((
                        "rustls: ServerCertVerified::assertion() unconditionally accepts certificates".to_string(),
                        trimmed.to_string(),
                    ));
                }

                // --- openssl patterns (if using openssl crate) ---
                // Pattern: set_verify(SslVerifyMode::NONE) or SSL_VERIFY_NONE
                if (trimmed.contains("set_verify") && trimmed.contains("NONE")) ||
                   trimmed.contains("SSL_VERIFY_NONE") {
                    found_dangers.push((
                        "OpenSSL: SSL_VERIFY_NONE disables certificate verification".to_string(),
                        trimmed.to_string(),
                    ));
                }

                // --- Generic danger patterns ---
                // Pattern: "danger" in function name being called with true
                if trimmed.contains("danger") && trimmed.contains("const true") && 
                   !found_dangers.iter().any(|(_, e)| e == trimmed) {
                    found_dangers.push((
                        "TLS danger method called with true - verification may be disabled".to_string(),
                        trimmed.to_string(),
                    ));
                }
            }

            // Create findings for each dangerous pattern found
            for (message, evidence) in found_dangers {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "{}. This allows man-in-the-middle attacks. \
                        Only disable in controlled test environments, never in production.",
                        message
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: vec![evidence],
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA085: AWS S3 Unscoped Access Rule
// ============================================================================

/// Detects AWS S3 operations where bucket names, keys, or prefixes come from
/// untrusted sources (env vars, CLI args, etc.) without validation.
/// This can enable data exfiltration, unauthorized deletions, or path traversal.
pub struct AwsS3UnscopedAccessRule {
    metadata: RuleMetadata,
}

impl AwsS3UnscopedAccessRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA085".to_string(),
                name: "aws-s3-unscoped-access".to_string(),
                short_description: "AWS S3 operation with untrusted bucket/key/prefix".to_string(),
                full_description: "Detects AWS S3 SDK operations (list_objects, put_object, \
                    delete_object, get_object, etc.) where bucket names, keys, or prefixes \
                    come from untrusted sources (environment variables, CLI arguments) without \
                    validation. Attackers can exploit this to access, modify, or delete arbitrary \
                    S3 objects. Use allowlists, starts_with validation, or path sanitization.".to_string(),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                help_uri: None,
            },
        }
    }

    /// Check if there's validation before the S3 call
    fn has_validation(&self, lines: &[&str], s3_call_idx: usize) -> bool {
        // Look for validation patterns before the S3 call
        for i in 0..s3_call_idx {
            let trimmed = lines[i].trim();
            
            // Allowlist check: contains() call typically used for allowlist validation
            if trimmed.contains("::contains(") && !trimmed.contains("str>::contains") {
                return true;
            }
            
            // starts_with validation for prefix scoping
            if trimmed.contains("starts_with") && !trimmed.contains("trim_start") {
                return true;
            }
            
            // Path traversal sanitization: replace("..", "")
            if trimmed.contains("replace") && trimmed.contains("\"..\"") {
                return true;
            }
            
            // Explicit assertion/panic for invalid input
            if (trimmed.contains("assert!") || trimmed.contains("panic!")) && 
               (trimmed.contains("bucket") || trimmed.contains("key") || trimmed.contains("prefix")) {
                return true;
            }
            
            // filter() for character sanitization
            if trimmed.contains("filter::<") && trimmed.contains("Chars") {
                return true;
            }
        }
        false
    }

    /// Get the S3 operation severity based on the method
    fn get_operation_severity(&self, method: &str) -> Severity {
        if method.contains("delete") || method.contains("Delete") {
            Severity::High  // Deletion is most dangerous (using High since no Critical)
        } else if method.contains("put") || method.contains("Put") || method.contains("copy") {
            Severity::High  // Write operations
        } else {
            Severity::Medium  // Read operations (list, get, head)
        }
    }
}

impl Rule for AwsS3UnscopedAccessRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Skip test functions
            if function.name.contains("test") || function.name.starts_with("test_") ||
               function.signature.contains("#[test]") || function.signature.contains("#[cfg(test)]") {
                continue;
            }

            let lines: Vec<&str> = function.body.iter().map(|s| s.as_str()).collect();
            
            // Track untrusted variable sources
            let mut untrusted_vars: HashSet<String> = HashSet::new();
            
            // First pass: identify untrusted sources (env::var, args)
            for (_idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Detect env::var Result variable declarations
                // Pattern: let mut _4: std::result::Result<std::string::String, std::env::VarError>;
                if trimmed.contains("Result<") && trimmed.contains("VarError") {
                    if let Some(colon_pos) = trimmed.find(':') {
                        let var_part = trimmed[..colon_pos].trim().trim_start_matches("let").trim().trim_start_matches("mut").trim();
                        if var_part.starts_with('_') {
                            untrusted_vars.insert(var_part.to_string());
                        }
                    }
                }
                
                // env::var call (older pattern)
                if trimmed.contains("var::<") && trimmed.contains("const \"") {
                    // Extract the target variable: _X = var::<&str>(...)
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let var_part = trimmed[..eq_pos].trim();
                        if var_part.starts_with('_') {
                            untrusted_vars.insert(var_part.to_string());
                        }
                    }
                }
                
                // env::args() collection
                if trimmed.contains("env::args") || trimmed.contains("Args") {
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let var_part = trimmed[..eq_pos].trim();
                        if var_part.starts_with('_') {
                            untrusted_vars.insert(var_part.to_string());
                        }
                    }
                }
                
                // Propagate taint through Result::unwrap with VarError
                // Pattern: (((*_21) as variant#3).0: std::string::String) = Result::<std::string::String, VarError>::unwrap(move _4)
                if trimmed.contains("VarError>::unwrap") || 
                   (trimmed.contains("unwrap") && trimmed.contains("move _") && 
                    untrusted_vars.iter().any(|v| trimmed.contains(&format!("move {}", v)))) {
                    // Extract the destination variable
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let dest_part = trimmed[..eq_pos].trim();
                        // Handle async closure patterns like (((*_21) as variant#3).0: std::string::String)
                        if dest_part.contains(".0:") || dest_part.starts_with('_') {
                            // Mark the unwrapped result as tainted
                            if dest_part.starts_with('_') {
                                untrusted_vars.insert(dest_part.to_string());
                            }
                            // Also track the complex field reference
                            untrusted_vars.insert(dest_part.to_string());
                        }
                    }
                }
                
                // Propagate taint through unwrap
                if trimmed.contains("unwrap::<") && trimmed.contains("Result<std::string::String") {
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let var_part = trimmed[..eq_pos].trim();
                        // Check if source is tainted
                        for tainted in untrusted_vars.clone() {
                            if trimmed.contains(&format!("move {}", tainted)) || 
                               trimmed.contains(&format!("copy {}", tainted)) {
                                untrusted_vars.insert(var_part.to_string());
                                break;
                            }
                        }
                    }
                }
                
                // Propagate through index operations (args[1])
                if trimmed.contains("Index>::index") || trimmed.contains("[") {
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let var_part = trimmed[..eq_pos].trim();
                        for tainted in untrusted_vars.clone() {
                            if trimmed.contains(&tainted) {
                                untrusted_vars.insert(var_part.to_string());
                                break;
                            }
                        }
                    }
                }
                
                // Propagate through simple assignments and copies
                if trimmed.contains(" = copy ") || trimmed.contains(" = move ") {
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let var_part = trimmed[..eq_pos].trim();
                        for tainted in untrusted_vars.clone() {
                            if trimmed.contains(&format!("copy {}", tainted)) || 
                               trimmed.contains(&format!("move {}", tainted)) ||
                               trimmed.contains(&format!("&{}", tainted)) {
                                untrusted_vars.insert(var_part.to_string());
                                break;
                            }
                        }
                    }
                }
                
                // Propagate through reference operations to async state fields
                // Pattern: _10 = &(((*_22) as variant#3).0: std::string::String);
                if trimmed.contains(" = &") && trimmed.contains("variant#") && trimmed.contains(".0:") {
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let var_part = trimmed[..eq_pos].trim();
                        // Check if this references a tainted async state field
                        // The tainted field may be through any _N deref, so match on the field pattern
                        for tainted in untrusted_vars.clone() {
                            if tainted.contains("variant#") && tainted.contains(".0:") {
                                // Both are async state fields - likely same data
                                untrusted_vars.insert(var_part.to_string());
                                break;
                            }
                        }
                    }
                }
                
                // Propagate through format! and string operations
                if trimmed.contains("format_argument") || trimmed.contains("Arguments::") {
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let var_part = trimmed[..eq_pos].trim();
                        for tainted in untrusted_vars.clone() {
                            if trimmed.contains(&tainted) {
                                untrusted_vars.insert(var_part.to_string());
                                break;
                            }
                        }
                    }
                }
            }
            
            // Second pass: find S3 operations with untrusted parameters
            let s3_methods = [
                "ListObjectsV2FluentBuilder::bucket",
                "ListObjectsV2FluentBuilder::prefix",
                "PutObjectFluentBuilder::bucket",
                "PutObjectFluentBuilder::key",
                "DeleteObjectFluentBuilder::bucket",
                "DeleteObjectFluentBuilder::key",
                "GetObjectFluentBuilder::bucket",
                "GetObjectFluentBuilder::key",
                "HeadObjectFluentBuilder::bucket",
                "HeadObjectFluentBuilder::key",
                "CopyObjectFluentBuilder::bucket",
                "CopyObjectFluentBuilder::key",
            ];
            
            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                for method in &s3_methods {
                    if trimmed.contains(method) {
                        // Skip if using const (hardcoded value - safe)
                        if trimmed.contains("const \"") || 
                           trimmed.contains("const safe_") ||
                           trimmed.contains("::ALLOWED_") {
                            continue;
                        }
                        
                        // Check if any untrusted variable flows to this call
                        let mut tainted_param = None;
                        for tainted in &untrusted_vars {
                            if trimmed.contains(&format!("move {}", tainted)) ||
                               trimmed.contains(&format!("copy {}", tainted)) ||
                               trimmed.contains(&format!("&{}", tainted)) {
                                tainted_param = Some(tainted.clone());
                                break;
                            }
                        }
                        
                        if let Some(_param) = tainted_param {
                            // Check if there's validation before this call
                            if self.has_validation(&lines, idx) {
                                continue; // Validation found, skip
                            }
                            
                            // Determine operation type and severity
                            let op_type = if method.contains("bucket") { "bucket" } 
                                         else if method.contains("prefix") { "prefix" }
                                         else { "key" };
                            
                            let severity = self.get_operation_severity(method);
                            
                            let operation = if method.contains("List") { "list_objects" }
                                           else if method.contains("Put") { "put_object" }
                                           else if method.contains("Delete") { "delete_object" }
                                           else if method.contains("Get") { "get_object" }
                                           else if method.contains("Head") { "head_object" }
                                           else if method.contains("Copy") { "copy_object" }
                                           else { "S3 operation" };
                            
                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity,
                                message: format!(
                                    "S3 {} receives untrusted {} parameter from environment variable or CLI argument. \
                                    Attackers can manipulate this to access, modify, or delete arbitrary S3 objects. \
                                    Use allowlist validation, starts_with scoping, or input sanitization.",
                                    operation, op_type
                                ),
                                function: function.name.clone(),
                                function_signature: function.signature.clone(),
                                evidence: vec![trimmed.to_string()],
                                span: function.span.clone(),
                            });
                            
                            break; // Only report once per S3 call
                        }
                    }
                }
            }
        }

        findings
    }
}

/// Register all web security rules with the rule engine.
pub fn register_web_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(NonHttpsUrlRule::new()));
    engine.register_rule(Box::new(DangerAcceptInvalidCertRule::new()));
    engine.register_rule(Box::new(OpensslVerifyNoneRule::new()));
    engine.register_rule(Box::new(CookieSecureAttributeRule::new()));
    engine.register_rule(Box::new(CorsWildcardRule::new()));
    engine.register_rule(Box::new(ConnectionStringPasswordRule::new()));
    engine.register_rule(Box::new(PasswordFieldMaskingRule::new()));
    engine.register_rule(Box::new(CleartextLoggingRule::new()));
    engine.register_rule(Box::new(TlsVerificationDisabledRule::new()));
    engine.register_rule(Box::new(AwsS3UnscopedAccessRule::new()));
}
