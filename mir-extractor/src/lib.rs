#![cfg_attr(feature = "hir-driver", feature(rustc_private))]
// TODO: Remove this once legacy rule implementations are fully cleaned up
// Legacy rules have been migrated to rules/ module but old implementations remain
#![allow(dead_code)]

#[cfg(feature = "hir-driver")]
extern crate rustc_ast;
#[cfg(feature = "hir-driver")]
extern crate rustc_driver;
#[cfg(feature = "hir-driver")]
extern crate rustc_hir;
#[cfg(feature = "hir-driver")]
extern crate rustc_infer;
#[cfg(feature = "hir-driver")]
extern crate rustc_interface;
#[cfg(feature = "hir-driver")]
extern crate rustc_middle;
#[cfg(feature = "hir-driver")]
extern crate rustc_session;
#[cfg(feature = "hir-driver")]
extern crate rustc_span;
#[cfg(feature = "hir-driver")]
extern crate rustc_trait_selection;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::{DirEntry, WalkDir};

pub mod dataflow;
#[cfg(feature = "hir-driver")]
mod hir;
#[cfg(feature = "hir-driver")]
mod hir_query;
#[cfg(feature = "hir-driver")]
mod type_analyzer;
mod prototypes;
pub mod interprocedural;
pub mod rules;
pub mod memory_profiler;

pub use dataflow::{Assignment, MirDataflow};
#[cfg(feature = "hir-driver")]
pub use hir::{
    capture_hir, capture_root_from_env, collect_crate_snapshot, target_spec_from_env,
    HirFunctionBody, HirIndex, HirItem, HirPackage, HirTargetSpec, HirTypeMetadata,
};
#[cfg(feature = "hir-driver")]
pub use hir_query::HirQuery;
#[cfg(feature = "hir-driver")]
pub use type_analyzer::{TypeAnalyzer, CacheStats};
pub use prototypes::{
    detect_broadcast_unsync_payloads, detect_command_invocations,
    detect_content_length_allocations, detect_openssl_verify_none, detect_truncating_len_casts,
    detect_unbounded_allocations, BroadcastUnsyncUsage, CommandInvocation, ContentLengthAllocation,
    LengthTruncationCast, OpensslVerifyNoneInvocation,
};

#[cfg(feature = "hir-driver")]
pub const HIR_CAPTURE_ICE_LOG_PREFIX: &str = "rust-cola: rustc ICE while capturing HIR";

/// Severity levels for security findings (CVSS-aligned)
/// - Critical: Exploitable remotely without authentication, leads to full system compromise
/// - High: Serious vulnerability, likely exploitable
/// - Medium: Moderate risk, requires specific conditions
/// - Low: Minor issue, limited impact
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn sarif_level(&self) -> &'static str {
        match self {
            Severity::Low => "note",
            Severity::Medium => "warning",
            Severity::High => "error",
            Severity::Critical => "error",
        }
    }
    
    /// Get a human-readable label with emoji
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Low => "🟢 Low",
            Severity::Medium => "🟡 Medium", 
            Severity::High => "🟠 High",
            Severity::Critical => "🔴 Critical",
        }
    }
    
    /// Get CVSS score range for this severity
    pub fn cvss_range(&self) -> &'static str {
        match self {
            Severity::Low => "0.1-3.9",
            Severity::Medium => "4.0-6.9",
            Severity::High => "7.0-8.9",
            Severity::Critical => "9.0-10.0",
        }
    }
}

/// Confidence level for analysis findings
/// - High: Strong evidence, low false positive likelihood
/// - Medium: Moderate evidence, may require manual review
/// - Low: Weak evidence, higher false positive likelihood
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::Low => "Low",
            Confidence::Medium => "Medium",
            Confidence::High => "High",
        }
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Confidence::Medium
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleOrigin {
    BuiltIn,
    RulePack { source: String },
    Wasm { module: String },
}

impl RuleOrigin {
    pub fn label(&self) -> String {
        match self {
            RuleOrigin::BuiltIn => "built-in".to_string(),
            RuleOrigin::RulePack { source } => format!("rulepack:{source}"),
            RuleOrigin::Wasm { module } => format!("wasm:{module}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub id: String,
    pub name: String,
    pub short_description: String,
    pub full_description: String,
    pub help_uri: Option<String>,
    pub default_severity: Severity,
    pub origin: RuleOrigin,
    /// CWE (Common Weakness Enumeration) identifiers
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_ids: Vec<String>,
    /// Fix suggestion template
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_suggestion: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub file: String,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    /// Confidence level of this specific finding
    #[serde(default)]
    pub confidence: Confidence,
    pub message: String,
    pub function: String,
    pub function_signature: String,
    pub evidence: Vec<String>,
    pub span: Option<SourceSpan>,
    /// CWE identifiers for this finding
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_ids: Vec<String>,
    /// Actionable fix suggestion
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_suggestion: Option<String>,
    /// Code snippet showing the vulnerable code
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_snippet: Option<String>,
}

impl Finding {
    /// Create a new finding with default confidence and optional fields
    pub fn new(
        rule_id: impl Into<String>,
        rule_name: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
        function: impl Into<String>,
        function_signature: impl Into<String>,
        evidence: Vec<String>,
        span: Option<SourceSpan>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_name: rule_name.into(),
            severity,
            confidence: Confidence::Medium,
            message: message.into(),
            function: function.into(),
            function_signature: function_signature.into(),
            evidence,
            span,
            cwe_ids: Vec::new(),
            fix_suggestion: None,
            code_snippet: None,
        }
    }
    
    /// Set confidence level
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }
    
    /// Set CWE identifiers
    pub fn with_cwe(mut self, cwe_ids: Vec<String>) -> Self {
        self.cwe_ids = cwe_ids;
        self
    }
    
    /// Set fix suggestion
    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix_suggestion = Some(fix.into());
        self
    }
    
    /// Set code snippet
    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.code_snippet = Some(snippet.into());
        self
    }
}

impl Default for Finding {
    fn default() -> Self {
        Self {
            rule_id: String::new(),
            rule_name: String::new(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            message: String::new(),
            function: String::new(),
            function_signature: String::new(),
            evidence: Vec::new(),
            span: None,
            cwe_ids: Vec::new(),
            fix_suggestion: None,
            code_snippet: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MirFunctionHirMetadata {
    pub def_path_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MirFunction {
    pub name: String,
    pub signature: String,
    pub body: Vec<String>,
    pub span: Option<SourceSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hir: Option<MirFunctionHirMetadata>,
}

impl Default for MirFunction {
    fn default() -> Self {
        Self {
            name: String::new(),
            signature: String::new(),
            body: Vec::new(),
            span: None,
            hir: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MirPackage {
    pub crate_name: String,
    pub crate_root: String,
    pub functions: Vec<MirFunction>,
}

// ============================================================================
// Source-Level Analysis Infrastructure (Tier 2)
// ============================================================================

/// Represents parsed source code for a Rust file
#[derive(Clone, Debug)]
pub struct SourceFile {
    pub path: PathBuf,
    pub content: String,
    pub syntax_tree: Option<syn::File>,
}

impl SourceFile {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read source file: {}", path.display()))?;
        
        let syntax_tree = syn::parse_file(&content).ok();
        
        Ok(Self {
            path,
            content,
            syntax_tree,
        })
    }
    
    /// Get all source files in a crate recursively
    pub fn collect_crate_sources(crate_root: impl AsRef<Path>) -> Result<Vec<Self>> {
        let mut sources = Vec::new();
        let crate_root = crate_root.as_ref();
        
        for entry in WalkDir::new(crate_root)
            .into_iter()
            .filter_entry(|e| {
                // Skip target, .git, and hidden directories
                let file_name = e.file_name().to_string_lossy();
                !file_name.starts_with('.') && file_name != "target"
            })
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Some(ext) = entry.path().extension() {
                    if ext == "rs" {
                        if let Ok(source) = Self::from_path(entry.path()) {
                            sources.push(source);
                        }
                    }
                }
            }
        }
        
        Ok(sources)
    }
}

/// Package with both MIR and source-level information
#[derive(Clone, Debug)]
pub struct EnrichedPackage {
    pub mir: MirPackage,
    pub sources: Vec<SourceFile>,
}

impl EnrichedPackage {
    pub fn new(mir: MirPackage, crate_root: impl AsRef<Path>) -> Result<Self> {
        let sources = SourceFile::collect_crate_sources(crate_root)?;
        Ok(Self { mir, sources })
    }
}

// ============================================================================
// End Source-Level Analysis Infrastructure
// ============================================================================

#[derive(Clone, Debug)]
pub struct ExtractionArtifacts {
    pub mir: MirPackage,
    #[cfg(feature = "hir-driver")]
    pub hir: Option<HirPackage>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub rules: Vec<RuleMetadata>,
}

pub trait Rule: Send + Sync {
    fn metadata(&self) -> &RuleMetadata;
    
    /// Evaluate this rule against a MIR package.
    /// 
    /// The optional `inter_analysis` parameter provides shared interprocedural
    /// analysis (call graph, function summaries) for rules that need cross-function
    /// taint tracking. Rules that don't need it should ignore the parameter.
    fn evaluate(
        &self,
        package: &MirPackage,
        inter_analysis: Option<&interprocedural::InterProceduralAnalysis>,
    ) -> Vec<Finding>;

    fn cache_key(&self) -> String {
        serde_json::to_string(self.metadata()).unwrap_or_default()
    }
}

fn collect_matches(lines: &[String], patterns: &[&str]) -> Vec<String> {
    lines
        .iter()
        .filter(|line| patterns.iter().any(|needle| line.contains(needle)))
        .map(|line| line.trim().to_string())
        .collect()
}

#[allow(dead_code)]
fn collect_case_insensitive_matches(lines: &[String], patterns: &[&str]) -> Vec<String> {
    let lowered_patterns: Vec<String> = patterns.iter().map(|p| p.to_lowercase()).collect();
    lines
        .iter()
        .filter_map(|line| {
            let lower = line.to_lowercase();
            if lowered_patterns.iter().any(|needle| lower.contains(needle)) {
                Some(line.trim().to_string())
            } else {
                None
            }
        })
        .collect()
}

fn extract_octal_literals(line: &str) -> Vec<u32> {
    let mut values = Vec::new();
    let mut search_start = 0;

    while let Some(relative_idx) = line[search_start..].find("0o") {
        let idx = search_start + relative_idx + 2;
        let remainder = &line[idx..];
        let mut digits = String::new();
        let mut consumed = 0;

        for (byte_idx, ch) in remainder.char_indices() {
            match ch {
                '0'..='7' => {
                    digits.push(ch);
                    consumed = byte_idx + ch.len_utf8();
                }
                '_' => {
                    consumed = byte_idx + ch.len_utf8();
                }
                _ => break,
            }
        }

        if !digits.is_empty() {
            if let Ok(value) = u32::from_str_radix(&digits, 8) {
                values.push(value);
            }
        }

        search_start = idx + consumed + 1;
    }

    values
}

fn line_has_world_writable_mode(line: &str) -> bool {
    let contains_mode_call = [
        "set_mode(",
        ".mode(",
        "::mode(",
        "from_mode(",
        "::from_mode(",
    ]
    .iter()
    .any(|pattern| line.contains(pattern));

    if !contains_mode_call && !line.contains("GENERIC_ALL") {
        return false;
    }

    if line.contains("GENERIC_ALL") {
        return true;
    }

    extract_octal_literals(line)
        .into_iter()
        .any(|value| (value & 0o022) != 0)
}

// =============================================================================
// LEGACY RULE IMPLEMENTATIONS
// These rules have been migrated to the rules/ module but kept here temporarily
// to avoid breaking changes. They will be removed in a future cleanup.
// =============================================================================
#[allow(dead_code)]
fn line_contains_md5_usage(line: &str) -> bool {
    let lower = line.to_lowercase();
    let mut search_start = 0;

    while let Some(relative_idx) = lower[search_start..].find("md5") {
        let idx = search_start + relative_idx;

        let mut before_chars = lower[..idx].chars().rev().skip_while(|c| c.is_whitespace());
        let mut after_chars = lower[idx + 3..].chars().skip_while(|c| c.is_whitespace());

        let after_matches = matches!(
            (after_chars.next(), after_chars.next()),
            (Some(':'), Some(':'))
        );

        let before_first = before_chars.next();
        let before_second = before_chars.next();
        let before_matches = matches!((before_first, before_second), (Some(':'), Some(':')));

        if before_matches || after_matches {
            return true;
        }

        search_start = idx + 3;
    }

    false
}

fn line_contains_sha1_usage(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("sha1::") || lower.contains("::sha1")
}

fn line_contains_weak_hash_extended(line: &str) -> bool {
    let lower = line.to_lowercase();
    
    // Skip const string assignments and hex dumps entirely
    // This catches MIR patterns like: _1 = [const "error message with adler32 or crc"]
    // These are often error messages or documentation, not actual weak hash usage
    if lower.contains("= [const \"") || lower.contains("const \"") {
        return false;
    }
    // Skip hex dumps (MIR allocator debug output)
    if lower.starts_with("0x") || (lower.contains("0x") && lower.contains("│")) {
        return false;
    }
    
    // RIPEMD family (all variants are deprecated)
    if lower.contains("ripemd") {
        if lower.contains("ripemd::") 
            || lower.contains("::ripemd") 
            || lower.contains("ripemd128") 
            || lower.contains("ripemd160")
            || lower.contains("ripemd256")
            || lower.contains("ripemd320") {
            return true;
        }
    }
    
    // CRC family (non-cryptographic checksums)
    if lower.contains("crc") {
        // Be specific to avoid false positives on words containing "crc"
        if lower.contains("crc::") 
            || lower.contains("::crc") 
            || lower.contains("crc32")
            || lower.contains("crc_32")
            || lower.contains("crc16")
            || lower.contains("crc_16")
            || lower.contains("crc64")
            || lower.contains("crc_64") {
            return true;
        }
    }
    
    // Adler32 (non-cryptographic checksum)
    if lower.contains("adler") && (lower.contains("adler::") || lower.contains("::adler") || lower.contains("adler32")) {
        return true;
    }
    
    false
}

fn looks_like_null_pointer_transmute(line: &str) -> bool {
    let lower = line.to_lowercase();
    
    // Must contain transmute
    if !lower.contains("transmute") {
        return false;
    }
    
    // Skip internal compiler transmute casts (shown as "(Transmute)")
    // These are type conversions like Unique<T> → NonNull<T>, not user-written transmute calls
    if lower.contains("(transmute)") {
        return false;
    }
    
    // Pattern 1: transmute(0) or transmute(0usize) - transmuting zero
    if lower.contains("transmute(const 0") || lower.contains("transmute(0_") {
        return true;
    }
    
    // Pattern 2: transmute(std::ptr::null()) or transmute(std::ptr::null_mut())
    if (lower.contains("std::ptr::null") || lower.contains("::ptr::null")) 
        && lower.contains("transmute") {
        return true;
    }
    
    // Pattern 3: Look for transmute in context with "null" keyword
    if lower.contains("null") && lower.contains("transmute") {
        return true;
    }
    
    false
}

fn looks_like_zst_pointer_arithmetic(line: &str) -> bool {
    let lower = line.to_lowercase();
    
    // Pointer arithmetic methods to detect
    let arithmetic_methods = ["offset", "add", "sub", "wrapping_offset", "wrapping_add", "wrapping_sub", "offset_from"];
    
    // Must have pointer arithmetic
    let has_arithmetic = arithmetic_methods.iter().any(|method| lower.contains(method));
    if !has_arithmetic {
        return false;
    }
    
    // Enhanced zero-sized type detection
    
    // 1. Unit type: *const () or *mut ()
    if (lower.contains("*const ()") || lower.contains("*mut ()")) && has_arithmetic {
        return true;
    }
    
    // 2. PhantomData (common marker types)
    if lower.contains("phantomdata") && has_arithmetic {
        return true;
    }
    
    // 3. PhantomPinned (another std marker type)
    if lower.contains("phantompinned") && has_arithmetic {
        return true;
    }
    
    // 4. Full paths to marker types
    if (lower.contains("std::marker::phantomdata") 
        || lower.contains("::marker::phantomdata")
        || lower.contains("core::marker::phantomdata")) && has_arithmetic {
        return true;
    }
    
    if (lower.contains("std::marker::phantompinned")
        || lower.contains("::marker::phantompinned") 
        || lower.contains("core::marker::phantompinned")) && has_arithmetic {
        return true;
    }
    
    // 5. Empty tuple/array patterns
    if (lower.contains("*const [(); 0]") || lower.contains("*mut [(); 0]")) && has_arithmetic {
        return true;
    }
    
    // 6. Check for explicit size annotations in comments or variable names
    // Sometimes ZST status is indicated in naming: ptr_zst, zst_ptr, etc.
    if (lower.contains("_zst") || lower.contains("zst_")) && has_arithmetic {
        return true;
    }
    
    // 7. Heuristic: Detect custom empty types by naming convention
    // Types with names like "EmptyStruct", "EmptyEnum", "UnitType", etc.
    // These are commonly user-defined ZSTs
    let empty_type_patterns = [
        "emptystruct", "emptyenum", "emptytype", "empty_struct", "empty_enum", "empty_type",
        "unitstruct", "unitenum", "unittype", "unit_struct", "unit_enum", "unit_type",
        "markerstruct", "markerenum", "markertype", "marker_struct", "marker_enum", "marker_type",
        "zststruct", "zstenum", "zsttype", "zst_struct", "zst_enum", "zst_type",
    ];
    if empty_type_patterns.iter().any(|p| lower.contains(p)) && has_arithmetic {
        return true;
    }
    
    // 8. Detect pointer types in impl blocks: <impl *const SomeType>::add(...)
    // Extract the type from the pattern and check if it looks like a ZST
    // Pattern: const_ptr::<impl *const TypeName>::method or const_ptr::<impl *mut TypeName>::method
    if let Some(impl_start) = lower.find("<impl *const ") {
        let type_start = impl_start + "<impl *const ".len();
        if let Some(impl_end) = lower[type_start..].find('>') {
            let type_name = &lower[type_start..type_start + impl_end];
            // Check if the extracted type name matches any ZST naming patterns
            if type_name.contains("empty") || type_name.contains("unit") || 
               type_name.contains("marker") || type_name.contains("zst") {
                return true;
            }
        }
    }
    if let Some(impl_start) = lower.find("<impl *mut ") {
        let type_start = impl_start + "<impl *mut ".len();
        if let Some(impl_end) = lower[type_start..].find('>') {
            let type_name = &lower[type_start..type_start + impl_end];
            if type_name.contains("empty") || type_name.contains("unit") || 
               type_name.contains("marker") || type_name.contains("zst") {
                return true;
            }
        }
    }
    
    false
}

#[allow(dead_code)]
fn looks_like_cleartext_env_var(line: &str) -> bool {
    let lower = line.to_lowercase();
    
    // Must contain set_var function call (various forms in MIR)
    if !lower.contains("set_var") {
        return false;
    }
    
    // Must look like an environment variable setting
    // In MIR this appears as: std::env::set_var::<&str, &str>
    if !lower.contains("std::env") && !lower.contains("::env::") {
        return false;
    }
    
    // Sensitive environment variable name patterns
    let sensitive_names = [
        "password",
        "passwd", 
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "auth",
        "private_key",
        "privatekey",
        "jwt",
        "access_token",
        "refresh_token",
        "bearer",
        "credential",
        "db_password",
        "database_password",
    ];
    
    // Check if any sensitive name appears in the line or nearby const string
    sensitive_names.iter().any(|name| lower.contains(name))
}

fn command_rule_should_skip(function: &MirFunction, package: &MirPackage) -> bool {
    if package.crate_name == "mir-extractor" {
        matches!(
            function.name.as_str(),
            "detect_rustc_version"
                | "run_cargo_rustc"
                | "discover_rustc_targets"
                | "detect_crate_name"
        )
    } else {
        false
    }
}

fn text_contains_word_case_insensitive(text: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }

    let target = needle.to_lowercase();
    text.to_lowercase()
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|token| token == target)
}

fn strip_comments(line: &str, in_block_comment: &mut bool) -> String {
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

#[derive(Debug, Clone, Deserialize)]
pub struct SuppressionRule {
    pub rule_id: String,
    pub file: Option<String>, // Glob pattern
    pub function: Option<String>, // Function name pattern
    pub reason: Option<String>,
}

pub struct RuleEngine {
    rules: Vec<Box<dyn Rule>>,
    pub suppressions: Vec<SuppressionRule>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new(), suppressions: Vec::new() }
    }

    pub fn with_builtin_rules() -> Self {
        let mut engine = RuleEngine::new();
        register_builtin_rules(&mut engine);
        engine
    }

    pub fn register_rule(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    pub fn run(&self, package: &MirPackage) -> AnalysisResult {
        let mut findings = Vec::new();
        let mut rules = Vec::new();

        memory_profiler::checkpoint_with_context("RuleEngine::run start", &package.crate_name);

        // Create shared interprocedural analysis once for all rules that need it.
        // This avoids creating 5+ separate instances (one per injection rule),
        // reducing memory usage significantly for large codebases.
        //
        // Memory usage is bounded by:
        // - MAX_PATHS (1000) per function for path enumeration
        // - MAX_FUNCTIONS threshold below
        // 
        // For crates exceeding the threshold, IPA is skipped but intra-procedural
        // analysis still runs for all rules.
        const MAX_FUNCTIONS_FOR_INTERPROCEDURAL: usize = 10000;
        
        let inter_analysis = if package.functions.len() <= MAX_FUNCTIONS_FOR_INTERPROCEDURAL {
            memory_profiler::checkpoint("IPA: Starting analysis");
            let _scope = memory_profiler::MemoryScope::new("IPA analysis");
            
            interprocedural::InterProceduralAnalysis::new(package)
                .and_then(|mut analysis| {
                    memory_profiler::checkpoint("IPA: Call graph built");
                    analysis.analyze(package)?;
                    memory_profiler::checkpoint("IPA: Analysis complete");
                    Ok(analysis)
                })
                .ok()
        } else {
            eprintln!(
                "Note: Skipping interprocedural analysis for {} ({} functions > {} threshold)",
                package.crate_name,
                package.functions.len(),
                MAX_FUNCTIONS_FOR_INTERPROCEDURAL
            );
            None
        };

        memory_profiler::checkpoint("Starting rule evaluation");
        
        for (i, rule) in self.rules.iter().enumerate() {
            let metadata = rule.metadata().clone();
            let rule_id = metadata.id.clone();
            rules.push(metadata.clone());
            
            if memory_profiler::is_enabled() && i % 5 == 0 {
                memory_profiler::checkpoint_with_context(
                    "Rule evaluation progress",
                    &format!("{}/{} - starting {}", i, self.rules.len(), rule_id)
                );
            }
            
            findings.extend(rule.evaluate(package, inter_analysis.as_ref()));
        }

        memory_profiler::checkpoint("RuleEngine::run complete");
        
        AnalysisResult { findings, rules }
    }

    pub fn rule_metadata(&self) -> Vec<RuleMetadata> {
        self.rules
            .iter()
            .map(|rule| rule.metadata().clone())
            .collect()
    }

    pub fn cache_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        for rule in &self.rules {
            hasher.update(rule.cache_key().as_bytes());
            hasher.update(&[0u8]);
        }
        hex::encode(hasher.finalize())
    }

    pub fn load_rulepack<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        let mut file =
            File::open(path).with_context(|| format!("open rulepack {}", path.display()))?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        self.load_rulepack_from_reader(&contents[..], &path.display().to_string())
    }

    pub fn load_rulepack_from_reader<R: Read>(
        &mut self,
        mut reader: R,
        origin: &str,
    ) -> Result<()> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let document: RulePackDocument =
            serde_yaml::from_slice(&buf).context("parse rulepack YAML")?;

        for rule_config in document.rules {
            let declarative = DeclarativeRule::new(rule_config, origin.to_string());
            self.register_rule(Box::new(declarative));
        }

        self.suppressions.extend(document.suppressions);

        Ok(())
    }

    pub fn load_wasm_module<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        fs::read(path).with_context(|| format!("read wasm module {}", path.display()))?;
        let module = path.to_string_lossy().to_string();
        self.register_rule(Box::new(WasmRulePlaceholder::from_path(path, module)));
        Ok(())
    }
}

#[derive(Debug, Deserialize, Default)]
struct RulePackDocument {
    #[serde(default)]
    rules: Vec<RulePackRuleConfig>,
    #[serde(default)]
    suppressions: Vec<SuppressionRule>,
}

#[derive(Debug, Deserialize)]
struct RulePackRuleConfig {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    short_description: Option<String>,
    #[serde(default)]
    full_description: Option<String>,
    #[serde(default)]
    help_uri: Option<String>,
    #[serde(default)]
    severity: Option<Severity>,
    #[serde(default)]
    severity_override: Option<Severity>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    function_name_contains_any: Vec<String>,
    #[serde(default)]
    function_name_contains_all: Vec<String>,
    #[serde(default)]
    body_contains_any: Vec<String>,
    #[serde(default)]
    body_contains_all: Vec<String>,
}

// =============================================================================
// Symbol constants for rule detection (used by tests)
// =============================================================================
const VEC_SET_LEN_SYMBOL: &str = concat!("Vec", "::", "set", "_len");
const MAYBE_UNINIT_TYPE_SYMBOL: &str = concat!("Maybe", "Uninit");
const MAYBE_UNINIT_ASSUME_INIT_SYMBOL: &str = concat!("assume", "_init");
const MEM_MODULE_SYMBOL: &str = concat!("mem");
const MEM_UNINITIALIZED_SYMBOL: &str = concat!("uninitialized");
const MEM_ZEROED_SYMBOL: &str = concat!("zeroed");
const DANGER_ACCEPT_INVALID_CERTS_SYMBOL: &str =
    concat!("danger", "_accept", "_invalid", "_certs");
const DANGER_ACCEPT_INVALID_HOSTNAMES_SYMBOL: &str =
    concat!("danger", "_accept", "_invalid", "_hostnames");

struct DeclarativeRule {
    metadata: RuleMetadata,
    message: Option<String>,
    severity_override: Option<Severity>,
    function_name_contains_any: Vec<String>,
    function_name_contains_all: Vec<String>,
    body_contains_any: Vec<String>,
    body_contains_all: Vec<String>,
}

impl DeclarativeRule {
    fn new(config: RulePackRuleConfig, origin: String) -> Self {
        let default_name = config.id.clone();
        let short_description = config
            .short_description
            .clone()
            .unwrap_or_else(|| config.id.clone());
        let full_description = config
            .full_description
            .clone()
            .unwrap_or_else(|| format!("Rule {} loaded from {}", config.id, origin));

        let metadata = RuleMetadata {
            id: config.id,
            name: config.name.unwrap_or(default_name),
            short_description,
            full_description,
            help_uri: config.help_uri,
            default_severity: config.severity.unwrap_or(Severity::Medium),
            origin: RuleOrigin::RulePack { source: origin },
            cwe_ids: Vec::new(),
            fix_suggestion: None,
        };

        Self {
            metadata,
            message: config.message,
            severity_override: config.severity_override,
            function_name_contains_any: config.function_name_contains_any,
            function_name_contains_all: config.function_name_contains_all,
            body_contains_any: config.body_contains_any,
            body_contains_all: config.body_contains_all,
        }
    }

    fn matches(&self, function: &MirFunction) -> bool {
        if !self.function_name_contains_any.is_empty()
            && !self
                .function_name_contains_any
                .iter()
                .any(|needle| function.name.contains(needle))
        {
            return false;
        }

        if !self.function_name_contains_all.is_empty()
            && !self
                .function_name_contains_all
                .iter()
                .all(|needle| function.name.contains(needle))
        {
            return false;
        }

        if !self.body_contains_any.is_empty()
            && !self
                .body_contains_any
                .iter()
                .any(|needle| function.body.iter().any(|line| line.contains(needle)))
        {
            return false;
        }

        if !self.body_contains_all.is_empty()
            && !self
                .body_contains_all
                .iter()
                .all(|needle| function.body.iter().any(|line| line.contains(needle)))
        {
            return false;
        }

        true
    }

    fn gather_evidence(&self, function: &MirFunction) -> Vec<String> {
        let mut evidence = Vec::new();

        for pattern in self
            .body_contains_any
            .iter()
            .chain(self.body_contains_all.iter())
        {
            if let Some(line) = function
                .body
                .iter()
                .find(|body_line| body_line.contains(pattern))
            {
                evidence.push(format!("matched `{pattern}`: {}", line.trim()));
            }
        }

        if evidence.is_empty() {
            evidence.push("Rule conditions satisfied".to_string());
        }

        evidence
    }
}

impl Rule for DeclarativeRule {
    fn cache_key(&self) -> String {
        let payload = json!({
            "metadata": &self.metadata,
            "message": &self.message,
            "severity_override": &self.severity_override,
            "function_name_contains_any": &self.function_name_contains_any,
            "function_name_contains_all": &self.function_name_contains_all,
            "body_contains_any": &self.body_contains_any,
            "body_contains_all": &self.body_contains_all,
        });
        serde_json::to_string(&payload).unwrap_or_default()
    }

    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        let mut findings = Vec::new();
        for function in &package.functions {
            if !self.matches(function) {
                continue;
            }

            let severity = self
                .severity_override
                .unwrap_or(self.metadata.default_severity);
            let message = self.message.clone().unwrap_or_else(|| {
                format!(
                    "Rule {} triggered for `{}`",
                    self.metadata.id, function.name
                )
            });
            let evidence = self.gather_evidence(function);

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity,
                confidence: Confidence::Medium,
                message,
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence,
                span: function.span.clone(),
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                code_snippet: None,
            });
        }

        findings
    }
}

struct WasmRulePlaceholder {
    metadata: RuleMetadata,
}

impl WasmRulePlaceholder {
    fn from_path(path: &Path, module_utf8: String) -> Self {
        let stem = path
            .file_stem()
            .and_then(|os| os.to_str())
            .unwrap_or("wasm-module");

        let sanitized = module_utf8
            .replace('\\', "::")
            .replace('/', "::")
            .replace(':', "-");

        let metadata = RuleMetadata {
            id: format!("WASM-STUB-{}", sanitized),
            name: format!("wasm::{stem}"),
            short_description: format!("Placeholder rule metadata for {stem}.wasm"),
            full_description: format!(
                "Rust-cola detected WASM module '{}' but execution is not implemented yet. This placeholder keeps metadata discoverable for future analysis runs.",
                module_utf8
            ),
            help_uri: None,
            default_severity: Severity::Low,
            origin: RuleOrigin::Wasm { module: module_utf8 },
            cwe_ids: Vec::new(),
            fix_suggestion: None,
        };

        Self { metadata }
    }
}

impl Rule for WasmRulePlaceholder {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, _package: &MirPackage, _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>) -> Vec<Finding> {
        Vec::new()
    }
}



// =============================================================================
// RUSTCOLA084: TLS verification disabled in custom clients
// =============================================================================

/// Detects disabled TLS certificate verification across multiple HTTP/TLS libraries.
/// This extends RUSTCOLA012 (reqwest) to cover native-tls, rustls, hyper-tls, and others.
///
/// Detects:
/// - native-tls: danger_accept_invalid_certs(true), danger_accept_invalid_hostnames(true)
/// - rustls: .dangerous() + custom verifier, DangerousClientConfigBuilder
/// - reqwest: danger_accept_invalid_certs(true), danger_accept_invalid_hostnames(true)
/// - hyper-tls: native-tls connector with verification disabled
fn register_builtin_rules(engine: &mut RuleEngine) {
    // Register rules from categorized modules
    rules::register_crypto_rules(engine);
    rules::register_memory_rules(engine);
    rules::register_concurrency_rules(engine);
    rules::register_ffi_rules(engine);
    rules::register_input_rules(engine);
    rules::register_resource_rules(engine);
    rules::register_code_quality_rules(engine);
    rules::register_web_rules(engine);
    rules::register_supply_chain_rules(engine);
    rules::register_injection_rules(engine);
    // All rules now registered via module registration functions
}


#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub enabled: bool,
    pub directory: PathBuf,
    pub clear: bool,
}

#[cfg(feature = "hir-driver")]
#[derive(Clone, Debug)]
pub struct HirOptions {
    pub capture: bool,
    pub cache: bool,
}

#[cfg(feature = "hir-driver")]
impl Default for HirOptions {
    fn default() -> Self {
        Self {
            capture: true,
            cache: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FunctionFingerprint {
    pub name: String,
    pub signature: String,
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hir_def_path_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CacheMetadata {
    pub crate_fingerprint: String,
    pub created_timestamp: u64,
    pub function_fingerprints: Vec<FunctionFingerprint>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct CachedAnalysisEntry {
    engine_fingerprint: String,
    findings: Vec<Finding>,
    rules: Vec<RuleMetadata>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum CacheMissReason {
    NotFound,
    Cleared,
    Invalid(String),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum CacheStatus {
    Hit(CacheMetadata),
    Miss {
        metadata: CacheMetadata,
        reason: CacheMissReason,
    },
    Disabled,
}

#[derive(Serialize, Deserialize)]
struct CacheEnvelope {
    version: u32,
    crate_fingerprint: String,
    rustc_version: String,
    created_timestamp: u64,
    function_fingerprints: Vec<FunctionFingerprint>,
    #[serde(default)]
    analysis_cache: Vec<CachedAnalysisEntry>,
    mir: MirPackage,
    #[cfg(feature = "hir-driver")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hir: Option<HirPackage>,
}

const CACHE_VERSION: u32 = 3;

pub fn extract_with_cache(
    crate_path: &Path,
    cache: &CacheConfig,
) -> Result<(MirPackage, CacheStatus)> {
    #[cfg(feature = "hir-driver")]
    let hir_options = HirOptions::default();

    let (artifacts, status) = extract_artifacts_with_cache(
        crate_path,
        cache,
        #[cfg(feature = "hir-driver")]
        &hir_options,
        || {
            extract_artifacts(
                crate_path,
                #[cfg(feature = "hir-driver")]
                &hir_options,
            )
        },
    )?;
    Ok((artifacts.mir, status))
}

#[cfg(feature = "hir-driver")]
pub fn extract_with_cache_full(
    crate_path: &Path,
    cache: &CacheConfig,
) -> Result<(ExtractionArtifacts, CacheStatus)> {
    let options = HirOptions::default();
    extract_with_cache_full_opts(crate_path, cache, &options)
}

#[cfg(feature = "hir-driver")]
pub fn extract_with_cache_full_opts(
    crate_path: &Path,
    cache: &CacheConfig,
    hir_options: &HirOptions,
) -> Result<(ExtractionArtifacts, CacheStatus)> {
    extract_artifacts_with_cache(crate_path, cache, hir_options, || {
        extract_artifacts(crate_path, hir_options)
    })
}

pub fn extract_artifacts_with_cache<F>(
    crate_path: &Path,
    cache: &CacheConfig,
    #[cfg(feature = "hir-driver")] hir_options: &HirOptions,
    extractor: F,
) -> Result<(ExtractionArtifacts, CacheStatus)>
where
    F: FnOnce() -> Result<ExtractionArtifacts>,
{
    if !cache.enabled {
        let package = extractor()?;
        return Ok((package, CacheStatus::Disabled));
    }

    fs::create_dir_all(&cache.directory).context("create cache directory")?;
    let canonical_crate =
        fs::canonicalize(crate_path).context("canonicalize crate path for cache")?;
    let rustc_version = detect_rustc_version();
    let crate_fingerprint = compute_crate_fingerprint(&canonical_crate, &rustc_version)?;
    let cache_file = cache
        .directory
        .join(format!("{crate_fingerprint}.cola-cache.json"));

    let mut miss_reason = CacheMissReason::NotFound;

    if cache.clear && cache_file.exists() {
        fs::remove_file(&cache_file).ok();
        miss_reason = CacheMissReason::Cleared;
    }

    if cache_file.exists() {
        match read_cache_envelope(&cache_file)? {
            Some(envelope) => {
                if envelope.version == CACHE_VERSION
                    && envelope.crate_fingerprint == crate_fingerprint
                    && envelope.rustc_version == rustc_version
                {
                    let metadata = CacheMetadata {
                        crate_fingerprint,
                        created_timestamp: envelope.created_timestamp,
                        function_fingerprints: envelope.function_fingerprints.clone(),
                    };
                    #[allow(unused_mut)]
                    let mut artifacts = ExtractionArtifacts {
                        mir: envelope.mir.clone(),
                        #[cfg(feature = "hir-driver")]
                        hir: if hir_options.cache && hir_options.capture {
                            envelope.hir.clone()
                        } else {
                            None
                        },
                    };

                    #[cfg(feature = "hir-driver")]
                    if hir_options.capture && (!hir_options.cache || artifacts.hir.is_none()) {
                        match hir::capture_hir(&canonical_crate) {
                            Ok(fresh_hir) => {
                                attach_hir_metadata_to_mir(&mut artifacts.mir, &fresh_hir);
                                artifacts.hir = Some(fresh_hir);
                            }
                            Err(err) => {
                                eprintln!(
                                    "rust-cola: failed to refresh HIR for {}: {err:?}",
                                    canonical_crate.display()
                                );
                            }
                        }
                    }

                    return Ok((artifacts, CacheStatus::Hit(metadata)));
                } else {
                    miss_reason = CacheMissReason::Invalid("fingerprint mismatch".to_string());
                    fs::remove_file(&cache_file).ok();
                }
            }
            None => {
                miss_reason = CacheMissReason::Invalid("corrupt cache entry".to_string());
                fs::remove_file(&cache_file).ok();
            }
        }
    }

    let artifacts = extractor()?;
    let function_fingerprints = compute_function_fingerprints(&artifacts.mir);
    let metadata = CacheMetadata {
        crate_fingerprint: crate_fingerprint.clone(),
        created_timestamp: current_timestamp(),
        function_fingerprints: function_fingerprints.clone(),
    };

    let envelope = CacheEnvelope {
        version: CACHE_VERSION,
        crate_fingerprint,
        rustc_version,
        created_timestamp: metadata.created_timestamp,
        function_fingerprints,
        analysis_cache: Vec::new(),
        mir: artifacts.mir.clone(),
        #[cfg(feature = "hir-driver")]
        hir: if hir_options.cache && hir_options.capture {
            artifacts.hir.clone()
        } else {
            None
        },
    };

    if let Err(err) = write_cache_envelope(&cache_file, &envelope) {
        eprintln!(
            "rust-cola: failed to persist cache at {}: {err}",
            cache_file.display()
        );
    }

    Ok((
        artifacts,
        CacheStatus::Miss {
            metadata,
            reason: miss_reason,
        },
    ))
}

fn read_cache_envelope(path: &Path) -> Result<Option<CacheEnvelope>> {
    let data = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("read cache file"),
    };

    let envelope: CacheEnvelope = match serde_json::from_slice(&data) {
        Ok(env) => env,
        Err(_) => return Ok(None),
    };

    Ok(Some(envelope))
}

fn write_cache_envelope(path: &Path, envelope: &CacheEnvelope) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create cache parent directory")?;
    }
    let mut file = File::create(path).context("create cache file")?;
    serde_json::to_writer_pretty(&mut file, envelope).context("write cache envelope")?;
    file.write_all(b"\n").ok();
    Ok(())
}

fn cache_entry_path_for(cache: &CacheConfig, fingerprint: &str) -> PathBuf {
    cache
        .directory
        .join(format!("{fingerprint}.cola-cache.json"))
}

fn cache_fingerprint_from_status(status: &CacheStatus) -> Option<&str> {
    match status {
        CacheStatus::Hit(meta) => Some(meta.crate_fingerprint.as_str()),
        CacheStatus::Miss { metadata, .. } => Some(metadata.crate_fingerprint.as_str()),
        CacheStatus::Disabled => None,
    }
}

pub fn load_cached_analysis(
    cache: &CacheConfig,
    status: &CacheStatus,
    engine: &RuleEngine,
) -> Result<Option<AnalysisResult>> {
    if !cache.enabled {
        return Ok(None);
    }

    let Some(fingerprint) = cache_fingerprint_from_status(status) else {
        return Ok(None);
    };

    load_cached_analysis_for_fingerprint(cache, fingerprint, engine)
}

pub fn store_cached_analysis(
    cache: &CacheConfig,
    status: &CacheStatus,
    engine: &RuleEngine,
    analysis: &AnalysisResult,
) -> Result<()> {
    if !cache.enabled {
        return Ok(());
    }

    let Some(fingerprint) = cache_fingerprint_from_status(status) else {
        return Ok(());
    };

    store_cached_analysis_for_fingerprint(cache, fingerprint, engine, analysis)
}

fn load_cached_analysis_for_fingerprint(
    cache: &CacheConfig,
    fingerprint: &str,
    engine: &RuleEngine,
) -> Result<Option<AnalysisResult>> {
    let path = cache_entry_path_for(cache, fingerprint);
    let envelope = match read_cache_envelope(&path)? {
        Some(env) => env,
        None => return Ok(None),
    };

    let engine_fp = engine.cache_fingerprint();
    if let Some(entry) = envelope
        .analysis_cache
        .iter()
        .find(|entry| entry.engine_fingerprint == engine_fp)
    {
        let expected_rules = engine.rule_metadata();
        if entry.rules != expected_rules {
            return Ok(None);
        }

        return Ok(Some(AnalysisResult {
            findings: entry.findings.clone(),
            rules: entry.rules.clone(),
        }));
    }

    Ok(None)
}

fn store_cached_analysis_for_fingerprint(
    cache: &CacheConfig,
    fingerprint: &str,
    engine: &RuleEngine,
    analysis: &AnalysisResult,
) -> Result<()> {
    let path = cache_entry_path_for(cache, fingerprint);
    let mut envelope = match read_cache_envelope(&path)? {
        Some(env) => env,
        None => return Ok(()),
    };

    let engine_fp = engine.cache_fingerprint();
    let entry = CachedAnalysisEntry {
        engine_fingerprint: engine_fp.clone(),
        findings: analysis.findings.clone(),
        rules: analysis.rules.clone(),
    };

    if let Some(existing) = envelope
        .analysis_cache
        .iter_mut()
        .find(|existing| existing.engine_fingerprint == engine_fp)
    {
        *existing = entry;
    } else {
        envelope.analysis_cache.push(entry);
    }

    write_cache_envelope(&path, &envelope)
}

fn compute_function_fingerprints(package: &MirPackage) -> Vec<FunctionFingerprint> {
    package
        .functions
        .iter()
        .map(|function| {
            let mut hasher = Sha256::new();
            hasher.update(function.name.as_bytes());
            hasher.update(&[0u8]);
            hasher.update(function.signature.as_bytes());
            hasher.update(&[0u8]);
            if let Some(hir) = &function.hir {
                hasher.update(hir.def_path_hash.as_bytes());
                hasher.update(&[0u8]);
            }
            for line in &function.body {
                hasher.update(line.as_bytes());
                hasher.update(&[0u8]);
            }
            FunctionFingerprint {
                name: function.name.clone(),
                signature: function.signature.clone(),
                hash: hex::encode(hasher.finalize()),
                hir_def_path_hash: function.hir.as_ref().map(|hir| hir.def_path_hash.clone()),
            }
        })
        .collect()
}

fn compute_crate_fingerprint(crate_path: &Path, rustc_version: &str) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(rustc_version.as_bytes());
    hasher.update(&[0u8]);

    let mut files_to_hash: Vec<PathBuf> = Vec::new();

    for entry in WalkDir::new(crate_path)
        .into_iter()
        .filter_entry(|e| filter_entry(e))
    {
        let entry = entry.context("walk crate directory")?;
        if !entry.file_type().is_file() {
            continue;
        }

        if should_hash_file(entry.path()) {
            files_to_hash.push(entry.into_path());
        }
    }

    files_to_hash.sort();

    for path in files_to_hash {
        let rel = path.strip_prefix(crate_path).unwrap_or(&path);
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(&[0u8]);
        let contents =
            fs::read(&path).with_context(|| format!("read source file {}", path.display()))?;
        hasher.update(&contents);
        hasher.update(&[0u8]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn filter_entry(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }

    let name = entry.file_name().to_string_lossy();
    if entry.file_type().is_dir()
        && matches!(
            name.as_ref(),
            "target" | ".git" | ".cola-cache" | "out" | "node_modules"
        )
    {
        return false;
    }
    true
}

fn should_hash_file(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(OsStr::to_str) {
        if ext == "rs" || ext == "toml" || ext == "lock" {
            return true;
        }
    }

    matches!(
        path.file_name().and_then(OsStr::to_str),
        Some("Cargo.toml") | Some("Cargo.lock")
    )
}

fn detect_rustc_version() -> String {
    match Command::new("rustc").arg("--version").output() {
        Ok(output) if output.status.success() => String::from_utf8(output.stdout)
            .unwrap_or_else(|_| "rustc version: utf8 error".to_string())
            .trim()
            .to_string(),
        Ok(output) => format!("rustc version: status {}", output.status),
        Err(err) => format!("rustc version: error {err}"),
    }
}

fn ensure_executable(path: PathBuf) -> Option<PathBuf> {
    if path.exists() {
        return Some(path);
    }

    if cfg!(windows) && path.extension().is_none() {
        let mut candidate = path.clone();
        candidate.set_extension("exe");
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

pub(crate) fn detect_cargo_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CARGO").map(PathBuf::from) {
        if let Some(resolved) = ensure_executable(path) {
            return Some(resolved);
        }
    }

    let rustup_home = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")));

    if let (Some(home), Some(toolchain)) = (rustup_home, std::env::var_os("RUSTUP_TOOLCHAIN")) {
        let candidate = PathBuf::from(&home)
            .join("toolchains")
            .join(toolchain)
            .join("bin")
            .join("cargo");
        if let Some(resolved) = ensure_executable(candidate) {
            return Some(resolved);
        }
    }

    if let Some(home) = std::env::var_os("CARGO_HOME").map(PathBuf::from) {
        let candidate = home.join("bin").join("cargo");
        if let Some(resolved) = ensure_executable(candidate) {
            return Some(resolved);
        }
    }

    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let candidate = home.join(".cargo").join("bin").join("cargo");
        if let Some(resolved) = ensure_executable(candidate) {
            return Some(resolved);
        }
    }

    if Command::new("cargo").arg("--version").output().is_ok() {
        return Some(PathBuf::from("cargo"));
    }

    None
}

#[allow(dead_code)]
fn detect_rustup_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("RUSTUP").map(PathBuf::from) {
        if let Some(resolved) = ensure_executable(path) {
            return Some(resolved);
        }
    }

    if let Some(home) = std::env::var_os("CARGO_HOME").map(PathBuf::from) {
        let candidate = home.join("bin").join("rustup");
        if let Some(resolved) = ensure_executable(candidate) {
            return Some(resolved);
        }
    }

    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let candidate = home.join(".cargo").join("bin").join("rustup");
        if let Some(resolved) = ensure_executable(candidate) {
            return Some(resolved);
        }
    }

    if Command::new("rustup").arg("--version").output().is_ok() {
        return Some(PathBuf::from("rustup"));
    }

    None
}

#[allow(dead_code)]
fn find_rust_toolchain_file() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        candidates.push(PathBuf::from(dir));
    }
    if let Ok(current) = std::env::current_dir() {
        candidates.push(current);
    }

    for mut dir in candidates {
        loop {
            let toml_candidate = dir.join("rust-toolchain.toml");
            if toml_candidate.exists() {
                return Some(toml_candidate);
            }

            let plain_candidate = dir.join("rust-toolchain");
            if plain_candidate.exists() {
                return Some(plain_candidate);
            }

            if !dir.pop() {
                break;
            }
        }
    }

    None
}

#[allow(dead_code)]
fn detect_toolchain() -> String {
    if let Ok(toolchain) = std::env::var("RUSTUP_TOOLCHAIN") {
        if !toolchain.is_empty() {
            return toolchain;
        }
    }

    if let Ok(toolchain) = std::env::var("RUST_TOOLCHAIN") {
        if !toolchain.is_empty() {
            return toolchain;
        }
    }

    if let Some(path) = find_rust_toolchain_file() {
        if let Ok(contents) = fs::read_to_string(&path) {
            if path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("toml"))
                .unwrap_or(false)
            {
                if let Ok(doc) = toml::from_str::<toml::Value>(&contents) {
                    if let Some(channel) = doc
                        .get("toolchain")
                        .and_then(|table| table.get("channel"))
                        .and_then(|val| val.as_str())
                    {
                        return channel.to_string();
                    }
                }
            } else {
                for line in contents.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        return trimmed.to_string();
                    }
                }
            }
        }
    }

    "nightly-2025-09-14".to_string()
}

/// The nightly toolchain version required for MIR extraction
const REQUIRED_NIGHTLY_TOOLCHAIN: &str = "nightly-2025-09-14";

fn build_cargo_command() -> Command {
    // Use cargo directly for metadata operations
    // Let the target project's toolchain handle basic cargo commands
    if let Some(cargo_path) = detect_cargo_binary() {
        Command::new(cargo_path)
    } else {
        Command::new("cargo")
    }
}

/// Build a cargo command that forces nightly toolchain for MIR extraction.
/// MIR extraction requires -Zunpretty=mir which is a nightly-only feature.
fn build_cargo_nightly_command() -> Command {
    // Use `rustup run <toolchain> cargo` to invoke cargo with a specific toolchain.
    // This is more reliable than `cargo +toolchain` which only works when cargo
    // is invoked through rustup's cargo shim (not a direct path to cargo binary).
    let mut cmd = Command::new("rustup");
    cmd.arg("run");
    cmd.arg(REQUIRED_NIGHTLY_TOOLCHAIN);
    cmd.arg("cargo");
    cmd
}

fn load_cargo_metadata(crate_path: &Path, no_deps: bool) -> Result<cargo_metadata::Metadata> {
    let canonical = fs::canonicalize(crate_path).unwrap_or_else(|_| crate_path.to_path_buf());
    let mut cmd = build_cargo_command();
    cmd.arg("metadata");
    cmd.args(["--format-version", "1"]);
    if no_deps {
        cmd.arg("--no-deps");
    }

    let debug_metadata = std::env::var_os("RUST_COLA_DEBUG_METADATA").is_some();

    if canonical.is_file() {
        if debug_metadata {
            eprintln!(
                "metadata canonical manifest {:?} (file?)",
                canonical.display()
            );
        }
        cmd.arg("--manifest-path");
        cmd.arg(&canonical);
    } else {
        let manifest_path = canonical.join("Cargo.toml");
        if debug_metadata {
            eprintln!(
                "metadata manifest candidate {:?} exists? {}",
                manifest_path.display(),
                manifest_path.exists()
            );
        }
        if manifest_path.exists() {
            cmd.arg("--manifest-path");
            cmd.arg(&manifest_path);
        } else {
            if debug_metadata {
                eprintln!(
                    "metadata falling back to current_dir {:?}",
                    canonical.display()
                );
            }
            cmd.current_dir(&canonical);
        }
    }

    if debug_metadata {
        let program = cmd.get_program().to_owned();
        let args: Vec<String> = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        eprintln!("cargo metadata command: {:?} {:?}", program, args);
    }

    let output = cmd
        .output()
        .with_context(|| format!("run cargo metadata for {}", canonical.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "cargo metadata failed for {}: {}",
            canonical.display(),
            stderr.trim()
        ));
    }

    serde_json::from_slice::<cargo_metadata::Metadata>(&output.stdout).with_context(|| {
        format!(
            "parse cargo metadata JSON produced for {}",
            canonical.display()
        )
    })
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug)]
pub(crate) enum RustcTarget {
    Lib,
    Bin(String),
}

impl RustcTarget {
    fn description(&self) -> String {
        match self {
            RustcTarget::Lib => "--lib".to_string(),
            RustcTarget::Bin(name) => format!("--bin {name}"),
        }
    }

    fn apply_to(&self, cmd: &mut Command) {
        match self {
            RustcTarget::Lib => {
                cmd.arg("--lib");
            }
            RustcTarget::Bin(name) => {
                cmd.args(["--bin", name]);
            }
        }
    }
}

pub(crate) fn discover_rustc_targets(crate_path: &Path) -> Result<Vec<RustcTarget>> {
    if std::env::var_os("RUST_COLA_DEBUG_METADATA").is_some() {
        eprintln!(
            "discover_rustc_targets crate_path {:?}",
            crate_path.display()
        );
    }
    let manifest_path = crate_path.join("Cargo.toml");
    let metadata = load_cargo_metadata(crate_path, true)
        .with_context(|| format!("query cargo metadata for {}", crate_path.display()))?;
    let manifest_canonical = fs::canonicalize(&manifest_path).unwrap_or(manifest_path.clone());
    let package = if let Some(pkg) = metadata.root_package() {
        pkg.clone()
    } else {
        metadata
            .packages
            .iter()
            .find(|pkg| {
                fs::canonicalize(pkg.manifest_path.as_std_path())
                    .map(|path| path == manifest_canonical)
                    .unwrap_or_else(|_| {
                        pkg.manifest_path.as_std_path() == manifest_canonical.as_path()
                    })
            })
            .cloned()
            .ok_or_else(|| anyhow!("no package metadata found for {}", crate_path.display()))?
    };

    let mut targets = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for target in &package.targets {
        if !target.required_features.is_empty() {
            skipped.push(target.name.clone());
            continue;
        }

        if target
            .kind
            .iter()
            .any(|kind| kind == "lib" || kind == "proc-macro")
        {
            targets.push(RustcTarget::Lib);
        }

        if target.kind.iter().any(|kind| kind == "bin") {
            targets.push(RustcTarget::Bin(target.name.clone()));
        }
    }

    if targets.is_empty() {
        if !skipped.is_empty() {
            return Err(anyhow!(
                "package {} has no lib or bin targets enabled without additional features (skipped targets: {})",
                package.name,
                skipped.join(", ")
            ));
        }

        return Err(anyhow!(
            "package {} has no lib or bin targets; cannot extract MIR",
            package.name
        ));
    }

    Ok(targets)
}

fn run_cargo_rustc(crate_path: &Path, target: &RustcTarget) -> Result<String> {
    // Use nightly toolchain for MIR extraction (-Zunpretty=mir is nightly-only)
    let mut cmd = build_cargo_nightly_command();
    cmd.current_dir(crate_path);
    cmd.arg("rustc");
    target.apply_to(&mut cmd);
    cmd.args(["--", "-Zunpretty=mir", "-Zmir-include-spans"]);

    let output = cmd
        .output()
        .with_context(|| format!("run `cargo rustc {}`", target.description()))?;

    if !output.status.success() {
        return Err(anyhow!(
            "cargo rustc failed for {}: {}",
            target.description(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout =
        String::from_utf8(output.stdout).context("decode MIR output to UTF-8 for target")?;
    Ok(stdout)
}

pub fn extract(crate_path: &Path) -> Result<MirPackage> {
    let canonical_crate_path = fs::canonicalize(crate_path).context("canonicalize crate path")?;
    let targets = discover_rustc_targets(&canonical_crate_path)?;
    let crate_root = canonical_crate_path
        .to_str()
        .ok_or_else(|| anyhow!("crate path is not valid UTF-8"))?
        .to_string();

    let crate_name = detect_crate_name(&canonical_crate_path).unwrap_or_else(|| {
        canonical_crate_path
            .file_name()
            .and_then(|os| os.to_str())
            .unwrap_or("unknown")
            .to_string()
    });

    let mut functions = Vec::new();
    let mut seen = HashSet::new();

    for target in targets {
        let stdout = run_cargo_rustc(&canonical_crate_path, &target)?;
        for function in parse_mir_dump(&stdout) {
            if seen.insert((function.name.clone(), function.signature.clone())) {
                functions.push(function);
            }
        }
    }

    Ok(MirPackage {
        crate_name,
        crate_root,
        functions,
    })
}

fn extract_artifacts(
    crate_path: &Path,
    #[cfg(feature = "hir-driver")] hir_options: &HirOptions,
) -> Result<ExtractionArtifacts> {
    #[allow(unused_mut)]
    let mut mir = extract(crate_path)?;

    #[cfg(feature = "hir-driver")]
    let hir = if hir_options.capture {
        match hir::capture_hir(crate_path) {
            Ok(hir) => Some(hir),
            Err(err) => {
                log_hir_capture_error(crate_path, &err);
                None
            }
        }
    } else {
        None
    };

    #[cfg(feature = "hir-driver")]
    if let Some(hir_package) = &hir {
        attach_hir_metadata_to_mir(&mut mir, hir_package);
    }

    Ok(ExtractionArtifacts {
        mir,
        #[cfg(feature = "hir-driver")]
        hir,
    })
}

#[cfg(feature = "hir-driver")]
fn attach_hir_metadata_to_mir(mir: &mut MirPackage, hir: &HirPackage) {
    let mut metadata_by_path = HashMap::with_capacity(hir.functions.len());
    let mut metadata_by_simple_name: HashMap<String, Vec<String>> = HashMap::new();
    let mut span_by_path = HashMap::new();

    for item in &hir.items {
        if let Some(span) = &item.span {
            span_by_path.insert(item.def_path.clone(), span.clone());
        }
    }

    for body in &hir.functions {
        metadata_by_path.insert(
            body.def_path.clone(),
            MirFunctionHirMetadata {
                def_path_hash: body.def_path_hash.clone(),
                signature: if body.signature.is_empty() {
                    None
                } else {
                    Some(body.signature.clone())
                },
            },
        );

        if let Some(simple) = body.def_path.rsplit("::").next() {
            metadata_by_simple_name
                .entry(simple.to_string())
                .or_default()
                .push(body.def_path.clone());
        }
    }

    for function in &mut mir.functions {
        if function.hir.is_some() {
            continue;
        }

        let mut matched_def_path = None;

        if let Some(def_path) = extract_def_path_from_signature(&function.signature) {
            if let Some(meta) = metadata_by_path.remove(&def_path) {
                function.hir = Some(meta);
                matched_def_path = Some(def_path.clone());
            }
        }

        if function.hir.is_none() {
            if let Some(candidates) = metadata_by_simple_name.get(function.name.as_str()) {
                if candidates.len() == 1 {
                    let def_path = candidates[0].clone();
                    if let Some(meta) = metadata_by_path.remove(&def_path) {
                        function.hir = Some(meta);
                        matched_def_path = Some(def_path.clone());
                    }
                }
            }
        }

        if let Some(def_path) = matched_def_path {
            if let Some(span) = span_by_path.get(&def_path) {
                function.span = Some(span.clone());
            }
        }
    }
}

#[cfg(feature = "hir-driver")]
fn log_hir_capture_error(crate_path: &Path, err: &anyhow::Error) {
    use crate::hir::{HirCaptureError, HirCaptureErrorKind};

    if let Some(hir_err) = err.downcast_ref::<HirCaptureError>() {
        match hir_err.kind() {
            HirCaptureErrorKind::RustcIce => {
                eprintln!(
                    "{} for {} (status {:?})",
                    HIR_CAPTURE_ICE_LOG_PREFIX,
                    crate_path.display(),
                    hir_err.status()
                );
                let diagnostic = hir_err.primary_diagnostic();
                if !diagnostic.is_empty() {
                    eprintln!(
                        "rust-cola: rustc ICE diagnostic: {}",
                        diagnostic
                    );
                }
                emit_truncated_rustc_stderr(hir_err.stderr());
            }
            HirCaptureErrorKind::CommandFailed => {
                eprintln!(
                    "rust-cola: cargo rustc failed while capturing HIR for {} (status {:?}): {}",
                    crate_path.display(),
                    hir_err.status(),
                    hir_err.primary_diagnostic()
                );
                emit_truncated_rustc_stderr(hir_err.stderr());
            }
        }
    } else {
        eprintln!(
            "rust-cola: failed to capture HIR for {}: {err:?}",
            crate_path.display()
        );
    }
}

#[cfg(feature = "hir-driver")]
fn emit_truncated_rustc_stderr(stderr: &str) {
    const MAX_LINES: usize = 20;
    if stderr.trim().is_empty() {
        return;
    }

    let lines: Vec<&str> = stderr.lines().collect();
    let display_count = lines.len().min(MAX_LINES);

    for (idx, line) in lines.iter().take(display_count).enumerate() {
        if line.trim().is_empty() {
            eprintln!("rust-cola: rustc stderr[{idx}]:");
        } else {
            eprintln!("rust-cola: rustc stderr[{idx}]: {}", line);
        }
    }

    if lines.len() > MAX_LINES {
        eprintln!(
            "rust-cola: rustc stderr truncated to {MAX_LINES} lines ({} total lines, {} bytes).",
            lines.len(),
            stderr.len()
        );
        eprintln!("rust-cola: rerun with `RUST_BACKTRACE=1` for more detail.");
    }
}

pub fn write_mir_json(path: impl AsRef<Path>, package: &MirPackage) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent).context("create parent directories for MIR JSON")?;
    }
    let mut file = File::create(path.as_ref()).context("create MIR JSON file")?;
    serde_json::to_writer_pretty(&mut file, package).context("serialize MIR package to JSON")?;
    file.write_all(b"\n").ok();
    Ok(())
}

#[cfg(feature = "hir-driver")]
pub fn write_hir_json(path: impl AsRef<Path>, package: &HirPackage) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent).context("create parent directories for HIR JSON")?;
    }
    let mut file = File::create(path.as_ref()).context("create HIR JSON file")?;
    serde_json::to_writer_pretty(&mut file, package).context("serialize HIR package to JSON")?;
    file.write_all(b"\n").ok();
    Ok(())
}

pub fn write_findings_json(path: impl AsRef<Path>, findings: &[Finding]) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent).context("create parent directories for findings JSON")?;
    }
    let mut file = File::create(path.as_ref()).context("create findings JSON file")?;
    serde_json::to_writer_pretty(&mut file, findings).context("serialize findings to JSON")?;
    file.write_all(b"\n").ok();
    Ok(())
}

pub fn write_sarif_json(path: impl AsRef<Path>, sarif: &serde_json::Value) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent).context("create parent directories for SARIF JSON")?;
    }
    let mut file = File::create(path.as_ref()).context("create SARIF file")?;
    serde_json::to_writer_pretty(&mut file, sarif).context("serialize SARIF report")?;
    file.write_all(b"\n").ok();
    Ok(())
}

pub fn analyze(package: &MirPackage) -> AnalysisResult {
    RuleEngine::with_builtin_rules().run(package)
}

pub fn analyze_with_engine(engine: &RuleEngine, package: &MirPackage) -> AnalysisResult {
    engine.run(package)
}

fn derive_relative_source_path(crate_name: &str, function_name: &str) -> Option<String> {
    let marker = " at ";
    let start = function_name.find(marker)? + marker.len();
    let rest = &function_name[start..];
    let end = rest.find("::")?;
    let location = &rest[..end];
    let path_part = location.split(':').next()?.trim();
    if path_part.is_empty() {
        return None;
    }

    let mut normalized = path_part.replace('\\', "/");
    let prefix = format!("{}/", crate_name);
    if let Some(stripped) = normalized.strip_prefix(&prefix) {
        normalized = stripped.to_string();
    }

    Some(normalized)
}

fn file_uri_from_path(path: &Path) -> String {
    #[cfg(windows)]
    {
        let mut owned = path.to_string_lossy().into_owned();

        if let Some(stripped) = owned.strip_prefix("\\\\?\\UNC\\") {
            let normalized = stripped.replace('\\', "/");
            return format!("file://{}", normalized);
        }

        if let Some(stripped) = owned.strip_prefix("\\\\?\\") {
            owned = stripped.to_string();
        }

        if let Some(stripped) = owned.strip_prefix("\\\\") {
            let normalized = stripped.replace('\\', "/");
            return format!("file://{}", normalized);
        }

        let mut normalized = owned.replace('\\', "/");
        if !normalized.starts_with('/') {
            normalized.insert(0, '/');
        }
        format!("file://{}", normalized)
    }
    #[cfg(not(windows))]
    {
        format!("file://{}", path.to_string_lossy())
    }
}

fn artifact_uri_for(package: &MirPackage, function_name: &str) -> String {
    let crate_root = PathBuf::from(&package.crate_root);
    if let Some(relative) = derive_relative_source_path(&package.crate_name, function_name) {
        let mut segments: Vec<&str> = relative
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();

        if let Some(first) = segments.first().copied() {
            let crate_dir = crate_root
                .file_name()
                .map(|os| os.to_string_lossy().to_string());
            let normalized_first = first.replace('_', "-").to_lowercase();
            let crate_name_normalized = package.crate_name.replace('_', "-").to_lowercase();
            let crate_dir_normalized = crate_dir
                .as_deref()
                .map(|dir| dir.replace('_', "-").to_lowercase());

            let drop_first = crate_dir_normalized
                .as_ref()
                .map(|dir| dir == &normalized_first)
                .unwrap_or(false)
                || normalized_first == crate_name_normalized
                || normalized_first == package.crate_name.replace('-', "_").to_lowercase();

            if drop_first {
                segments.remove(0);
            }
        }

        let mut path = crate_root.clone();
        for segment in segments {
            path.push(segment);
        }
        return file_uri_from_path(&path);
    }

    // Fallback: try to extract path from function name patterns like "src/lib.rs:15" or "build.rs:10"
    // This handles source-level rules that use location-style function names
    if function_name.contains(':') && !function_name.contains("::") {
        // Pattern: "file.rs:line" or "path/to/file.rs:line"
        if let Some(colon_pos) = function_name.rfind(':') {
            let path_part = &function_name[..colon_pos];
            if path_part.ends_with(".rs") {
                let file_path = crate_root.join(path_part);
                return file_uri_from_path(&file_path);
            }
        }
    }

    // Final fallback: use src/lib.rs if it exists, otherwise src/main.rs
    // GitHub Code Scanning requires a file path, not a directory
    let lib_rs = crate_root.join("src/lib.rs");
    if lib_rs.exists() {
        return file_uri_from_path(&lib_rs);
    }
    let main_rs = crate_root.join("src/main.rs");
    if main_rs.exists() {
        return file_uri_from_path(&main_rs);
    }

    // Last resort: append src/lib.rs even if it doesn't exist
    file_uri_from_path(&crate_root.join("src/lib.rs"))
}

pub fn sarif_report(package: &MirPackage, analysis: &AnalysisResult) -> serde_json::Value {
    let rule_index: HashMap<&str, &RuleMetadata> = analysis
        .rules
        .iter()
        .map(|meta| (meta.id.as_str(), meta))
        .collect();

    let results: Vec<_> = analysis
        .findings
        .iter()
        .map(|finding| {
            let rule_meta = rule_index.get(finding.rule_id.as_str());
            let origin = rule_meta
                .map(|meta| meta.origin.label())
                .unwrap_or_else(|| "unknown".to_string());

            let mut region = serde_json::Map::new();
            region.insert(
                "message".to_string(),
                json!({"text": finding.function_signature.clone()}),
            );

            let artifact_uri = if let Some(span) = &finding.span {
                region.insert("startLine".to_string(), json!(span.start_line));
                region.insert("startColumn".to_string(), json!(span.start_column));
                region.insert("endLine".to_string(), json!(span.end_line));
                region.insert("endColumn".to_string(), json!(span.end_column));

                let path = Path::new(&span.file);
                file_uri_from_path(path)
            } else {
                artifact_uri_for(package, &finding.function)
            };

            json!({
                "ruleId": finding.rule_id,
                "level": finding.severity.sarif_level(),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": artifact_uri,
                            },
                            "region": serde_json::Value::Object(region)
                        },
                        "logicalLocations": [
                            {
                                "fullyQualifiedName": finding.function,
                                "decoratedName": finding.function_signature,
                            }
                        ]
                    }
                ],
                "properties": {
                    "ruleName": finding.rule_name,
                    "origin": origin,
                    "evidence": finding.evidence,
                }
            })
        })
        .collect();

    let rules: Vec<_> = analysis
        .rules
        .iter()
        .map(|rule| {
            let mut value = json!({
                "id": rule.id,
                "name": rule.name,
                "shortDescription": {"text": rule.short_description},
                "fullDescription": {"text": rule.full_description},
                "helpUri": rule.help_uri,
                "defaultConfiguration": {
                    "level": rule.default_severity.sarif_level()
                },
                "properties": {
                    "origin": rule.origin.label()
                }
            });

            if rule.help_uri.is_none() {
                if let Some(obj) = value.as_object_mut() {
                    obj.remove("helpUri");
                }
            }

            value
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "rust-cola",
                        "informationUri": "https://github.com/your-org/rust-cola",
                        "version": env!("CARGO_PKG_VERSION"),
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "workingDirectory": {
                            "uri": file_uri_from_path(Path::new(&package.crate_root)),
                        },
                        "executionSuccessful": true
                    }
                ],
                "artifacts": [
                    {
                        "location": {
                            "uri": file_uri_from_path(Path::new(&package.crate_root))
                        },
                        "description": {
                            "text": format!("Crate {} analyzed via MIR", package.crate_name)
                        }
                    }
                ]
            }
        ]
    })
}

fn parse_mir_dump(input: &str) -> Vec<MirFunction> {
    let mut functions = Vec::new();
    let mut current_signature: Option<String> = None;
    let mut current_body: Vec<String> = Vec::new();

    for line in input.lines() {
        if line.trim_start().starts_with("fn ") {
            if let Some(sig) = current_signature.take() {
                functions.push(MirFunction::from_parts(
                    sig,
                    std::mem::take(&mut current_body),
                ));
            }
            current_signature = Some(line.trim().to_string());
        } else if current_signature.is_some() {
            current_body.push(line.to_string());
        }
    }

    if let Some(sig) = current_signature {
        functions.push(MirFunction::from_parts(sig, current_body));
    }

    functions
}

impl MirFunction {
    fn from_parts(signature: String, mut body: Vec<String>) -> MirFunction {
        trim_trailing_blanks(&mut body);
        let name = extract_name(&signature).unwrap_or_else(|| "unknown".to_string());
        let span = extract_span(&signature);
        MirFunction {
            name,
            signature,
            body,
            span,
            hir: None,
        }
    }
}

fn extract_name(signature: &str) -> Option<String> {
    let signature = signature.trim_start();
    signature
        .strip_prefix("fn ")
        .and_then(|rest| rest.split('(').next())
        .map(|s| s.trim().to_string())
}

#[cfg_attr(not(feature = "hir-driver"), allow(dead_code))]
fn extract_def_path_from_signature(signature: &str) -> Option<String> {
    let trimmed = signature.trim_start();
    let idx = trimmed.find("fn ")? + 3;
    let after_fn = &trimmed[idx..];
    let before_location = after_fn
        .split_once(" at ")
        .map(|(path, _)| path)
        .unwrap_or(after_fn);
    let path = before_location.split('(').next()?.trim();
    if path.is_empty() {
        return None;
    }
    Some(path.to_string())
}

pub fn extract_span_from_mir_line(line: &str) -> Option<SourceSpan> {
    // Example: ... // scope 0 at src/lib.rs:4:15: 4:35
    if let Some(idx) = line.rfind("// scope ") {
        let comment = &line[idx..];
        if let Some(at_idx) = comment.find(" at ") {
            let location = comment[at_idx + 4..].trim();
            // location is like "src/lib.rs:4:15: 4:35"
            
            // Parse backwards: end_column, end_line, start_column, start_line, file
            // Format: file:start_line:start_column: end_line:end_column
            
            if let Some((rest, end_column_str)) = location.rsplit_once(':') {
                if let Ok(end_column) = end_column_str.trim().parse::<u32>() {
                    if let Some((rest, end_line_str)) = rest.rsplit_once(':') {
                        if let Ok(end_line) = end_line_str.trim().parse::<u32>() {
                            if let Some((rest, start_column_str)) = rest.rsplit_once(':') {
                                if let Ok(start_column) = start_column_str.trim().parse::<u32>() {
                                    if let Some((file_path, start_line_str)) = rest.rsplit_once(':') {
                                        if let Ok(start_line) = start_line_str.trim().parse::<u32>() {
                                            return Some(SourceSpan {
                                                file: file_path.trim().replace('\\', "/"),
                                                start_line,
                                                start_column,
                                                end_line,
                                                end_column,
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
    }
    None
}

fn extract_span(signature: &str) -> Option<SourceSpan> {
    const MARKER: &str = " at ";
    let marker_idx = signature.find(MARKER)? + MARKER.len();
    let after_marker = &signature[marker_idx..];
    let location_end = after_marker.find('>')?;
    let location = after_marker[..location_end].trim();

    let (before_end_column, end_column_str) = location.rsplit_once(':')?;
    let end_column = end_column_str.trim().parse().ok()?;

    let (before_end_line, end_line_str) = before_end_column.rsplit_once(':')?;
    let end_line = end_line_str.trim().parse().ok()?;

    let (before_start_column, start_column_str) = before_end_line.rsplit_once(':')?;
    let start_column = start_column_str.trim().parse().ok()?;

    let (path_str, start_line_str) = before_start_column.rsplit_once(':')?;
    let start_line = start_line_str.trim().parse().ok()?;

    Some(SourceSpan {
        file: path_str.trim().replace('\\', "/"),
        start_line,
        start_column,
        end_line,
        end_column,
    })
}

fn trim_trailing_blanks(lines: &mut Vec<String>) {
    while matches!(lines.last(), Some(last) if last.trim().is_empty()) {
        lines.pop();
    }
}

pub(crate) fn detect_crate_name(crate_path: &Path) -> Option<String> {
    let canonical_crate = fs::canonicalize(crate_path)
        .ok()
        .unwrap_or_else(|| crate_path.to_path_buf());
    if std::env::var_os("RUST_COLA_DEBUG_METADATA").is_some() {
        eprintln!(
            "detect_crate_name crate_path {:?} canonical {:?}",
            crate_path.display(),
            canonical_crate.display()
        );
    }
    let manifest_path = if canonical_crate.is_file() {
        canonical_crate.clone()
    } else {
        canonical_crate.join("Cargo.toml")
    };

    let canonical_manifest = fs::canonicalize(&manifest_path).ok();

    let metadata = load_cargo_metadata(&canonical_crate, true).ok()?;

    if let Some(target_manifest) = canonical_manifest {
        if let Some(pkg) = metadata.packages.iter().find(|pkg| {
            let pkg_manifest = pkg.manifest_path.clone().into_std_path_buf();
            fs::canonicalize(pkg_manifest)
                .ok()
                .map(|path| path == target_manifest)
                .unwrap_or(false)
        }) {
            return Some(pkg.name.clone());
        }
    }

    metadata
        .packages
        .iter()
        .find(|pkg| {
            let parent = pkg
                .manifest_path
                .clone()
                .into_std_path_buf()
                .parent()
                .map(|p| p.to_path_buf());
            parent == Some(canonical_crate.clone())
        })
        .map(|pkg| pkg.name.clone())
        .or_else(|| metadata.root_package().map(|pkg| pkg.name.clone()))
        .or_else(|| metadata.packages.first().map(|pkg| pkg.name.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{CommandInjectionRiskRule, UntrustedEnvInputRule};
    use crate::rules::memory::{
        BoxIntoRawRule, MemForgetGuardRule, NonNullNewUncheckedRule, StaticMutGlobalRule,
    };
    use crate::rules::resource::{
        HardcodedHomePathRule, PermissionsSetReadonlyFalseRule, WorldWritableModeRule,
    };
    use crate::rules::utils::{StringLiteralState, strip_string_literals};
    use crate::rules::web::{NonHttpsUrlRule, OpensslVerifyNoneRule};
    use std::io::Cursor;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tempfile::tempdir;

    const LENGTH_TRUNCATION_CAST_INTTOINT_SYMBOL: &str = concat!("Int", "To", "Int");
    const LENGTH_TRUNCATION_CAST_WRITE_SYMBOL: &str = concat!("write", "_u16");
    const UNBOUNDED_ALLOCATION_WITH_CAPACITY_SYMBOL: &str = concat!("with", "_capacity");

    fn make_vec_set_len_line(indent: &str) -> String {
        let mut line = String::with_capacity(indent.len() + 48);
        line.push_str(indent);
        line.push_str("Vec::<i32>::");
        line.push_str("set_len");
        line.push_str("((*_1), const 4_usize);");
        line
    }

    fn make_maybe_uninit_assume_init_line(indent: &str) -> String {
        let mut line = String::with_capacity(indent.len() + 66);
        line.push_str(indent);
        line.push_str("_7 = core::mem::");
        line.push_str(MAYBE_UNINIT_TYPE_SYMBOL);
        line.push_str("::<i32>::");
        line.push_str(MAYBE_UNINIT_ASSUME_INIT_SYMBOL);
        line.push_str("(move _6);");
        line
    }

    fn make_mem_uninitialized_line(indent: &str) -> String {
        let mut line = String::with_capacity(indent.len() + 48);
        line.push_str(indent);
        line.push_str("_8 = std::");
        line.push_str(MEM_MODULE_SYMBOL);
        line.push_str("::");
        line.push_str(MEM_UNINITIALIZED_SYMBOL);
        line.push_str("::<i32>();");
        line
    }

    fn make_length_truncation_cast_lines(indent: &str) -> Vec<String> {
        let mut lines = Vec::with_capacity(4);

        let mut line = String::with_capacity(indent.len() + 24);
        line.push_str(indent);
        line.push_str("debug payload_len => _1;");
        lines.push(line);

        let mut line = String::with_capacity(indent.len() + 16);
        line.push_str(indent);
        line.push_str("_2 = copy _1;");
        lines.push(line);

        let mut line = String::with_capacity(indent.len() + 36);
        line.push_str(indent);
        line.push_str("_3 = move _2 as i32 (");
        line.push_str(LENGTH_TRUNCATION_CAST_INTTOINT_SYMBOL);
        line.push_str(");");
        lines.push(line);

        let mut line = String::with_capacity(indent.len() + 88);
        line.push_str(indent);
        line.push_str("_4 = byteorder::WriteBytesExt::");
        line.push_str(LENGTH_TRUNCATION_CAST_WRITE_SYMBOL);
        line.push_str("::<byteorder::BigEndian>(move _0, move _3);");
        lines.push(line);

        lines
    }

    fn make_unbounded_allocation_lines(indent: &str, debug_ident: &str) -> Vec<String> {
        let mut lines = Vec::with_capacity(3);

        let mut debug_line = String::with_capacity(indent.len() + debug_ident.len() + 16);
        debug_line.push_str(indent);
        debug_line.push_str("debug ");
        debug_line.push_str(debug_ident);
        debug_line.push_str(" => _1;");
        lines.push(debug_line);

        let mut copy_line = String::with_capacity(indent.len() + 16);
        copy_line.push_str(indent);
        copy_line.push_str("_2 = copy _1;");
        lines.push(copy_line);

        let mut alloc_line = String::with_capacity(indent.len() + 64);
        alloc_line.push_str(indent);
        alloc_line.push_str("_3 = Vec::<u8>::");
        alloc_line.push_str(UNBOUNDED_ALLOCATION_WITH_CAPACITY_SYMBOL);
        alloc_line.push_str("(move _2);");
        lines.push(alloc_line);

        lines
    }

    fn make_danger_accept_invalid_certs_line(indent: &str) -> String {
        let mut line = String::with_capacity(indent.len() + 86);
        line.push_str(indent);
        line.push_str("_10 = reqwest::ClientBuilder::");
        line.push_str(DANGER_ACCEPT_INVALID_CERTS_SYMBOL);
        line.push_str("(move _1, const true);");
        line
    }

    #[test]
    fn extracts_def_path_from_signature_examples() {
        assert_eq!(
            super::extract_def_path_from_signature("fn crate::module::demo(_1: i32)").as_deref(),
            Some("crate::module::demo")
        );

        assert_eq!(
            super::extract_def_path_from_signature(
                "unsafe extern \"C\" fn foo::bar::baz(_1: i32) -> i32",
            )
            .as_deref(),
            Some("foo::bar::baz")
        );

        assert_eq!(
            super::extract_def_path_from_signature("no function signature here"),
            None
        );
    }

    #[test]
    fn parse_extracts_functions() {
        let input = r#"
fn foo() -> () {
    bb0: {
        _0 = ();
        return;
    }
}

fn bar(_1: i32) -> i32 {
    bb0: {
        _0 = _1;
        return;
    }
}
"#;

        let functions = parse_mir_dump(input);
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "foo");
        assert_eq!(functions[1].name, "bar");
    }

    #[test]
    fn parse_extracts_function_spans() {
        let input = r#"
fn <impl at C:\\workspace\\demo\\src\\lib.rs:42:5: 42:27>::vec_set_len(_1: &mut Vec<u8>) -> () {
    bb0: {
        _0 = ();
        return;
    }
}
"#;

        let functions = parse_mir_dump(input);
        assert_eq!(functions.len(), 1);
        let span = functions[0].span.as_ref().expect("missing span");
        let normalized_path = span
            .file
            .split(|c| c == '/' || c == '\\')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        assert!(
            normalized_path.ends_with("workspace/demo/src/lib.rs"),
            "unexpected file: {}",
            span.file
        );
        assert_eq!(span.start_line, 42);
        assert_eq!(span.start_column, 5);
        assert_eq!(span.end_line, 42);
        assert_eq!(span.end_column, 27);
    }

    #[test]
    fn rule_finding_carries_function_span() {
        let input = r#"
fn <impl at C:\\workspace\\demo\\src\\lib.rs:40:1: 40:32>::vec_set_len(_1: &mut Vec<u8>) -> () {
    bb0: {
        _2 = Vec::<u8>::set_len(move _1, const 4_usize);
        return;
    }
}
"#;

        let functions = parse_mir_dump(input);
        assert_eq!(functions.len(), 1);

        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: "C:/workspace/demo".to_string(),
            functions,
        };

        let engine = RuleEngine::with_builtin_rules();
        let analysis = engine.run(&package);
        let finding = analysis
            .findings
            .iter()
            .find(|finding| finding.rule_id == "RUSTCOLA008")
            .expect("vec-set-len finding not emitted");

        let span = finding.span.as_ref().expect("finding missing span");
        let normalized_path = span
            .file
            .split(|c| c == '/' || c == '\\')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        assert!(
            normalized_path.ends_with("workspace/demo/src/lib.rs"),
            "unexpected file: {}",
            span.file
        );
        assert_eq!(span.start_line, 40);
        assert_eq!(span.start_column, 1);
        assert_eq!(span.end_line, 40);
        assert_eq!(span.end_column, 32);
    }

    #[test]
    fn sarif_report_includes_span_region() {
        let span = SourceSpan {
            file: "/workspace/demo/src/lib.rs".to_string(),
            start_line: 12,
            start_column: 5,
            end_line: 12,
            end_column: 18,
        };

        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: "/workspace/demo".to_string(),
            functions: Vec::new(),
        };

        let rule = RuleMetadata {
            id: "TEST001".to_string(),
            name: "demo-rule".to_string(),
            short_description: "demo description".to_string(),
            full_description: "demo full description".to_string(),
            help_uri: None,
            default_severity: Severity::Medium,
            origin: RuleOrigin::BuiltIn,
            cwe_ids: Vec::new(),
            fix_suggestion: None,
        };

        let finding = Finding {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            severity: rule.default_severity,
            confidence: Confidence::High,
            message: "Something happened".to_string(),
            function: "demo::example".to_string(),
            function_signature: "fn demo::example()".to_string(),
            evidence: vec![],
            span: Some(span.clone()),
            cwe_ids: Vec::new(),
            fix_suggestion: None,
            code_snippet: None,
        };

        let analysis = AnalysisResult {
            findings: vec![finding],
            rules: vec![rule],
        };

        let sarif = sarif_report(&package, &analysis);
        let result = &sarif["runs"][0]["results"][0];
        let region = &result["locations"][0]["physicalLocation"]["region"];

        assert_eq!(region["startLine"], json!(span.start_line));
        assert_eq!(region["startColumn"], json!(span.start_column));
        assert_eq!(region["endLine"], json!(span.end_line));
        assert_eq!(region["endColumn"], json!(span.end_column));

        let artifact_uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .expect("uri missing");
        let expected_uri = file_uri_from_path(Path::new(&span.file));
        assert_eq!(artifact_uri, expected_uri);
    }

    #[cfg(windows)]
    #[test]
    fn file_uri_from_path_strips_extended_prefix() {
        let uri =
            super::file_uri_from_path(Path::new(r"\\?\C:\workspace\mir-extractor\src\lib.rs"));
        assert!(
            uri.starts_with("file:///C:/workspace/mir-extractor/src/lib.rs"),
            "unexpected uri: {uri}"
        );
        assert!(!uri.contains("//?/"), "extended prefix remained: {uri}");
    }

    #[cfg(windows)]
    #[test]
    fn artifact_uri_for_avoids_duplicate_crate_folder() {
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: r"\\?\C:\workspace\mir-extractor".to_string(),
            functions: Vec::new(),
        };

        let uri = super::artifact_uri_for(
            &package,
            "fn <impl at mir-extractor\\src\\lib.rs:10:1: 10:2>::example()",
        );

        assert!(
            uri.starts_with("file:///C:/workspace/mir-extractor/src/lib.rs"),
            "unexpected uri: {uri}"
        );
        assert!(
            !uri.contains("mir-extractor/mir-extractor"),
            "duplicate crate segment detected: {uri}"
        );
    }

    #[test]
    fn rulepack_matches_body_contains() {
        let yaml = r#"
rules:
  - id: ORG001
    name: no-into-raw
    severity: high
    message: Detected into_raw usage
    body_contains_any:
      - "into_raw"
"#;

        let mut engine = RuleEngine::with_builtin_rules();
        engine
            .load_rulepack_from_reader(Cursor::new(yaml), "inline")
            .expect("load inline rulepack");

        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "ffi_create".to_string(),
                signature: "fn ffi_create()".to_string(),
                body: vec!["_0 = Box::into_raw(move _1);".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = engine.run(&package);
        assert!(analysis
            .findings
            .iter()
            .any(|f| f.rule_id == "ORG001" && f.severity == Severity::High));
        assert!(analysis.rules.iter().any(|meta| meta.id == "ORG001"));
    }

    #[test]
    fn builtin_security_rules_fire() {
        let engine = RuleEngine::with_builtin_rules();
        let package = MirPackage {
            crate_name: "security".to_string(),
            crate_root: ".".to_string(),
            functions: vec![
                MirFunction {
                    name: "unsafe_helper".to_string(),
                    signature: "unsafe fn unsafe_helper()".to_string(),
                    body: vec!["unsafe { core::ptr::read(_1); }".to_string()],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "md5_hash".to_string(),
                    signature: "fn md5_hash()".to_string(),
                    body: vec!["_2 = md5::Md5::new();".to_string()],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "sha1_hash".to_string(),
                    signature: "fn sha1_hash()".to_string(),
                    body: vec!["_3 = sha1::Sha1::new();".to_string()],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "env_usage".to_string(),
                    signature: "fn env_usage()".to_string(),
                    // Complete taint flow: env::var (source) -> Command::arg (sink)
                    body: vec![
                        "_4 = std::env::var(move _1) -> [return: bb1, unwind: bb2];".to_string(),
                        "_5 = Command::arg::<&str>(move _6, move _4) -> [return: bb3, unwind: bb4];".to_string(),
                    ],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "command_spawn".to_string(),
                    signature: "fn command_spawn()".to_string(),
                    body: vec!["_5 = std::process::Command::new(_1);".to_string()],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "vec_set_len".to_string(),
                    signature: "fn vec_set_len(v: &mut Vec<i32>)".to_string(),
                    body: vec![make_vec_set_len_line("")],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "maybe_uninit".to_string(),
                    signature: "fn maybe_uninit()".to_string(),
                    body: vec![make_maybe_uninit_assume_init_line("")],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "deprecated_mem".to_string(),
                    signature: "fn deprecated_mem()".to_string(),
                    body: vec![make_mem_uninitialized_line("")],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "http_url".to_string(),
                    signature: "fn http_url()".to_string(),
                    body: vec!["_9 = const \"http://example.com\";".to_string()],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "dangerous_tls".to_string(),
                    signature: "fn dangerous_tls(builder: reqwest::ClientBuilder)".to_string(),
                    body: vec![make_danger_accept_invalid_certs_line("")],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "openssl_none".to_string(),
                    signature: "fn openssl_none(ctx: &mut SslContextBuilder)".to_string(),
                    body: vec!["openssl::ssl::SslContextBuilder::set_verify((*_1), openssl::ssl::SslVerifyMode::NONE);".to_string()],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "home_path_literal".to_string(),
                    signature: "fn home_path_literal()".to_string(),
                    body: vec!["_11 = const \"/home/alice/.ssh/id_rsa\";".to_string()],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "static_mut_global".to_string(),
                    signature: "fn static_mut_global()".to_string(),
                    body: vec!["    static mut GLOBAL: i32 = 0;".to_string()],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "set_readonly_false".to_string(),
                    signature: "fn set_readonly_false(perm: &mut std::fs::Permissions)".to_string(),
                    body: vec!["    std::fs::Permissions::set_readonly(move _1, const false);".to_string()],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "world_writable_mode".to_string(),
                    signature: "fn world_writable_mode(opts: &mut std::fs::OpenOptions)".to_string(),
                    body: vec!["    std::os::unix::fs::OpenOptionsExt::mode(move _1, const 0o777);".to_string()],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "forget_guard".to_string(),
                    signature: "fn forget_guard(mutex: &std::sync::Mutex<i32>)".to_string(),
                    body: vec![
                        "    _1 = std::sync::Mutex::lock(move _0) -> [return: bb1, unwind: bb2];".to_string(),
                        "    _2 = core::result::Result::<std::sync::MutexGuard<'_, i32>, _>::unwrap(move _1);".to_string(),
                        "    std::mem::forget(move _2);".to_string(),
                    ],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "nonnull_unchecked".to_string(),
                    signature: "fn nonnull_unchecked(ptr: *mut u8)".to_string(),
                    body: vec!["    _0 = core::ptr::NonNull::<u8>::new_unchecked(_1);".to_string()],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "content_length_allocation".to_string(),
                    signature: "fn content_length_allocation(resp: reqwest::Response)".to_string(),
                    body: vec![
                        "    _1 = reqwest::Response::content_length(move _0);".to_string(),
                        "    _2 = copy _1;".to_string(),
                        "    _3 = Vec::<u8>::with_capacity(move _2);".to_string(),
                    ],
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "length_truncation_cast".to_string(),
                    signature: "fn length_truncation_cast(len: usize)".to_string(),
                    body: {
                        let mut body = Vec::with_capacity(6);
                        body.push("fn length_truncation_cast(len: usize) {".to_string());
                        body.extend(make_length_truncation_cast_lines("    "));
                        body.push("}".to_string());
                        body
                    },
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "unbounded_allocation".to_string(),
                    signature: "fn unbounded_allocation(len: usize)".to_string(),
                    body: make_unbounded_allocation_lines("    ", "len"),
                    span: None,
                ..Default::default()
                },
                MirFunction {
                    name: "broadcast_unsync".to_string(),
                    signature: "fn broadcast_unsync()".to_string(),
                    body: vec![
                        "    _5 = tokio::sync::broadcast::channel::<std::rc::Rc<String>>(const 16_usize);".to_string(),
                    ],
                    span: None,
                ..Default::default()
                },
            ],
        };

        let analysis = engine.run(&package);

        let triggered: Vec<_> = analysis
            .findings
            .iter()
            .map(|f| f.rule_id.as_str())
            .collect();
        assert!(
            triggered.contains(&"RUSTCOLA003"),
            "expected unsafe rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA004"),
            "expected md5 rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA005"),
            "expected sha1 rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA006"),
            "expected env rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA007"),
            "expected command rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA008"),
            "expected {} rule to fire",
            VEC_SET_LEN_SYMBOL
        );
        assert!(
            triggered.contains(&"RUSTCOLA009"),
            "expected MaybeUninit rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA010"),
            "expected {}::{} rule to fire",
            MEM_MODULE_SYMBOL,
            MEM_UNINITIALIZED_SYMBOL
        );
        assert!(
            triggered.contains(&"RUSTCOLA011"),
            "expected non-https rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA012"),
            "expected {} rule to fire",
            DANGER_ACCEPT_INVALID_CERTS_SYMBOL
        );
        assert!(
            triggered.contains(&"RUSTCOLA013"),
            "expected openssl verify none rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA014"),
            "expected hardcoded home path rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA025"),
            "expected static mut global rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA073"),
            "expected NonNull::new_unchecked rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA078"),
            "expected mem::forget guard rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA028"),
            "expected set_readonly(false) rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA029"),
            "expected world-writable mode rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA021"),
            "expected content-length allocation rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA022"),
            "expected length truncation cast rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA024"),
            "expected general unbounded allocation rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA023"),
            "expected broadcast unsync payload rule to fire"
        );
        let content_length_finding = analysis
            .findings
            .iter()
            .find(|f| f.rule_id == "RUSTCOLA021")
            .expect("content-length finding present");
        assert!(content_length_finding
            .evidence
            .iter()
            .any(|line| line.contains("with_capacity")));

        let truncation_finding = analysis
            .findings
            .iter()
            .find(|f| f.rule_id == "RUSTCOLA022")
            .expect("length truncation finding present");
        assert!(truncation_finding
            .evidence
            .iter()
            .any(|line| line.contains(LENGTH_TRUNCATION_CAST_INTTOINT_SYMBOL)));
        assert!(truncation_finding
            .evidence
            .iter()
            .any(|line| line.contains(LENGTH_TRUNCATION_CAST_WRITE_SYMBOL)));

        let broadcast_finding = analysis
            .findings
            .iter()
            .find(|f| f.rule_id == "RUSTCOLA023")
            .expect("broadcast finding present");
        assert!(broadcast_finding
            .evidence
            .iter()
            .any(|line| line.contains("broadcast::channel")));

        let unbounded_finding = analysis
            .findings
            .iter()
            .find(|f| f.rule_id == "RUSTCOLA024")
            .expect("unbounded allocation finding present");
        assert!(unbounded_finding
            .evidence
            .iter()
            .any(|line| line.contains(UNBOUNDED_ALLOCATION_WITH_CAPACITY_SYMBOL)));

        for id in &[
            "RUSTCOLA003",
            "RUSTCOLA004",
            "RUSTCOLA005",
            "RUSTCOLA006",
            "RUSTCOLA007",
            "RUSTCOLA008",
            "RUSTCOLA009",
            "RUSTCOLA010",
            "RUSTCOLA011",
            "RUSTCOLA012",
            "RUSTCOLA013",
            "RUSTCOLA014",
            "RUSTCOLA025",
            "RUSTCOLA073",
            "RUSTCOLA078",
            "RUSTCOLA028",
            "RUSTCOLA029",
            "RUSTCOLA021",
            "RUSTCOLA022",
            "RUSTCOLA024",
            "RUSTCOLA023",
        ] {
            assert!(analysis.rules.iter().any(|meta| meta.id == *id));
        }
    }

    #[test]
    fn box_into_raw_rule_detects_usage() {
        let rule = BoxIntoRawRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "ffi_bridge".to_string(),
                signature: "fn ffi_bridge()".to_string(),
                body: vec!["    _0 = Box::into_raw(move _1);".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|entry| entry.contains("Box::into_raw")));
    }

    #[test]
    fn box_into_raw_rule_skips_analyzer_crate() {
        let rule = BoxIntoRawRule::new();
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "ffi_bridge".to_string(),
                signature: "fn ffi_bridge()".to_string(),
                body: vec!["    _0 = Box::into_raw(move _1);".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn non_https_url_rule_detects_literal() {
        let rule = NonHttpsUrlRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "insecure_url".to_string(),
                signature: "fn insecure_url()".to_string(),
                body: vec!["    _1 = const \"http://example.com\";".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|entry| entry.contains("http://example.com")));
    }

    #[test]
    fn non_https_url_rule_skips_analyzer_crate() {
        let rule = NonHttpsUrlRule::new();
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "document_string".to_string(),
                signature: "fn document_string()".to_string(),
                body: vec!["    _1 = const \"http://docs\";".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn hardcoded_home_path_rule_detects_literal() {
        let rule = HardcodedHomePathRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "store_profile".to_string(),
                signature: "fn store_profile()".to_string(),
                body: vec!["    _1 = const \"/home/alice/.config\";".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|entry| entry.contains("/home/alice/.config")));
    }

    #[test]
    fn hardcoded_home_path_rule_skips_analyzer_crate() {
        let rule = HardcodedHomePathRule::new();
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "document_paths".to_string(),
                signature: "fn document_paths()".to_string(),
                body: vec!["    _1 = const \"/home/docs\";".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn static_mut_global_rule_detects_mutable_static() {
        let rule = StaticMutGlobalRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "global".to_string(),
                signature: "fn global()".to_string(),
                body: vec!["    static mut COUNTER: usize = 0;".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|entry| entry.contains("static mut")));
    }

    #[test]
    fn static_mut_global_rule_skips_analyzer_crate() {
        let rule = StaticMutGlobalRule::new();
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "global".to_string(),
                signature: "fn global()".to_string(),
                body: vec!["    static mut COUNTER: usize = 0;".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn permissions_set_readonly_rule_detects_false() {
        let rule = PermissionsSetReadonlyFalseRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "loosen_permissions".to_string(),
                signature: "fn loosen_permissions(perm: &mut std::fs::Permissions)".to_string(),
                body: vec![
                    "    std::fs::Permissions::set_readonly(move _1, const false);".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|entry| entry.contains("set_readonly")));
    }

    #[test]
    fn permissions_set_readonly_rule_skips_analyzer_crate() {
        let rule = PermissionsSetReadonlyFalseRule::new();
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "loosen_permissions".to_string(),
                signature: "fn loosen_permissions(perm: &mut std::fs::Permissions)".to_string(),
                body: vec![
                    "    std::fs::Permissions::set_readonly(move _1, const false);".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn permissions_set_readonly_rule_ignores_true() {
        let rule = PermissionsSetReadonlyFalseRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "harden_permissions".to_string(),
                signature: "fn harden_permissions(perm: &mut std::fs::Permissions)".to_string(),
                body: vec![
                    "    std::fs::Permissions::set_readonly(move _1, const true);".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn nonnull_rule_detects_new_unchecked() {
        let rule = NonNullNewUncheckedRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "make_nonnull".to_string(),
                signature: "fn make_nonnull(ptr: *mut u8)".to_string(),
                body: vec!["    _2 = core::ptr::NonNull::<u8>::new_unchecked(_1);".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|entry| entry.contains("NonNull")));
    }

    #[test]
    fn nonnull_rule_skips_analyzer_crate() {
        let rule = NonNullNewUncheckedRule::new();
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "make_nonnull".to_string(),
                signature: "fn make_nonnull(ptr: *mut u8)".to_string(),
                body: vec!["    _2 = core::ptr::NonNull::<u8>::new_unchecked(_1);".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn mem_forget_guard_rule_detects_guard_leak() {
        let rule = MemForgetGuardRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "forget_guard".to_string(),
                signature: "fn forget_guard(mutex: &std::sync::Mutex<i32>)".to_string(),
                body: vec![
                    "    _1 = std::sync::Mutex::lock(move _0) -> [return: bb1, unwind: bb2];".to_string(),
                    "    _2 = core::result::Result::<std::sync::MutexGuard<'_, i32>, _>::unwrap(move _1);".to_string(),
                    "    std::mem::forget(move _2);".to_string(),
                ],
                span: None,
            ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|entry| entry.contains("mem::forget")));
        assert!(findings[0]
            .evidence
            .iter()
            .any(|entry| entry.contains("MutexGuard")));
    }

    #[test]
    fn mem_forget_guard_rule_skips_analyzer_crate() {
        let rule = MemForgetGuardRule::new();
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "forget_guard".to_string(),
                signature: "fn forget_guard(mutex: &std::sync::Mutex<i32>)".to_string(),
                body: vec![
                    "    _1 = std::sync::Mutex::lock(move _0) -> [return: bb1, unwind: bb2];".to_string(),
                    "    _2 = core::result::Result::<std::sync::MutexGuard<'_, i32>, _>::unwrap(move _1);".to_string(),
                    "    std::mem::forget(move _2);".to_string(),
                ],
                span: None,
            ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn mem_forget_guard_rule_ignores_non_guard_forget() {
        let rule = MemForgetGuardRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "forget_vec".to_string(),
                signature: "fn forget_vec(buffer: Vec<u8>)".to_string(),
                body: vec!["    std::mem::forget(move _1);".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn world_writable_mode_rule_detects_set_mode() {
        let rule = WorldWritableModeRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "make_world_writable".to_string(),
                signature: "fn make_world_writable(perm: &mut std::os::unix::fs::PermissionsExt)"
                    .to_string(),
                body: vec![
                    "    std::os::unix::fs::PermissionsExt::set_mode(move _1, const 0o777);"
                        .to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|entry| entry.contains("0o777")));
    }

    #[test]
    fn world_writable_mode_rule_skips_analyzer_crate() {
        let rule = WorldWritableModeRule::new();
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "make_world_writable".to_string(),
                signature: "fn make_world_writable(perm: &mut std::os::unix::fs::PermissionsExt)"
                    .to_string(),
                body: vec![
                    "    std::os::unix::fs::PermissionsExt::set_mode(move _1, const 0o777);"
                        .to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn world_writable_mode_rule_ignores_safe_mask() {
        let rule = WorldWritableModeRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "make_restrictive".to_string(),
                signature: "fn make_restrictive(perm: &mut std::os::unix::fs::PermissionsExt)"
                    .to_string(),
                body: vec![
                    "    std::os::unix::fs::PermissionsExt::set_mode(move _1, const 0o755);"
                        .to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn command_rule_reports_tainted_arguments_with_high_severity() {
        let rule = CommandInjectionRiskRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "bad".to_string(),
                signature: "fn bad()".to_string(),
                body: vec![
                    "    _1 = std::env::var(const \"USER\");".to_string(),
                    "    _2 = std::process::Command::new(const \"/bin/sh\");".to_string(),
                    "    _3 = std::process::Command::arg(move _2, move _1);".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::High);
        assert!(finding
            .evidence
            .iter()
            .any(|entry| entry.contains("tainted arguments")));
        assert!(finding.message.contains("Potential command injection"));
    }

    #[test]
    fn command_rule_reports_tokio_process_usage() {
        let rule = CommandInjectionRiskRule::new();
        let package = MirPackage {
            crate_name: "tokio-demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "run_async".to_string(),
                signature: "fn run_async()".to_string(),
                body: vec![
                    "    _1 = std::env::var(const \"TARGET\");".to_string(),
                    "    _2 = tokio::process::Command::new(const \"/usr/bin/env\");".to_string(),
                    "    _3 = tokio::process::Command::arg(move _2, move _1);".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::High);
        assert!(finding
            .evidence
            .iter()
            .any(|entry| entry.contains("tokio::process::Command::new")));
    }

    #[test]
    fn command_rule_reports_constant_arguments_with_medium_severity() {
        let rule = CommandInjectionRiskRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "ok".to_string(),
                signature: "fn ok()".to_string(),
                body: vec![
                    "    _1 = std::process::Command::new(const \"git\");".to_string(),
                    "    _2 = std::process::Command::arg(move _1, const \"status\");".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.evidence.len(), 1);
        assert!(finding
            .message
            .contains("Process command execution detected"));
    }

    #[test]
    fn untrusted_env_rule_detects_env_call() {
        let rule = UntrustedEnvInputRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "read_env".to_string(),
                signature: "fn read_env()".to_string(),
                // Complete taint flow: env::var (source) -> Command::arg (sink)
                body: vec![
                    "_1 = std::env::var(move _2) -> [return: bb1, unwind: bb2];".to_string(),
                    "_3 = Command::arg::<&str>(move _4, move _1) -> [return: bb3, unwind: bb4];".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        // The finding should contain evidence about the taint flow
        assert!(findings[0].message.contains("Tainted data"));
    }

    #[test]
    fn untrusted_env_rule_ignores_string_literal() {
        let rule = UntrustedEnvInputRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "constant".to_string(),
                signature: "fn constant()".to_string(),
                body: vec!["    const _: &str = \"std::env::var\";".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn openssl_rule_reports_none_literal() {
        let rule = OpensslVerifyNoneRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "disable_verify".to_string(),
                signature: "fn disable_verify()".to_string(),
                body: vec![
                    "    _1 = openssl::ssl::SslContextBuilder::set_verify(move _0, openssl::ssl::SslVerifyMode::NONE);"
                        .to_string(),
                ],
                span: None,
            ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|line| line.contains("set_verify")));
    }

    #[test]
    fn openssl_rule_reports_empty_mode_variable() {
        let rule = OpensslVerifyNoneRule::new();
        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "disable_verify_var".to_string(),
                signature: "fn disable_verify_var()".to_string(),
                body: vec![
                    "    _1 = openssl::ssl::SslVerifyMode::empty();".to_string(),
                    "    _2 = openssl::ssl::SslContextBuilder::set_verify(move _0, move _1);"
                        .to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package, None);
        assert_eq!(findings.len(), 1);
        let evidence = &findings[0].evidence;
        assert_eq!(evidence.len(), 2);
        assert!(evidence
            .iter()
            .any(|line| line.contains("SslVerifyMode::empty")));
    }

    #[test]
    fn md5_rule_ignores_doc_only_matches() {
        let engine = RuleEngine::with_builtin_rules();
        let package = MirPackage {
            crate_name: "docs".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "doc_only".to_string(),
                signature: "fn doc_only()".to_string(),
                body: vec!["const _: &str = \"Detects use of MD5 hashing\";".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = engine.run(&package);

        assert!(
            !analysis
                .findings
                .iter()
                .any(|f| f.rule_id == "RUSTCOLA004" && f.function == "doc_only"),
            "md5 rule should not fire on doc-only strings"
        );
    }

    #[test]
    fn sha1_rule_ignores_doc_only_matches() {
        let engine = RuleEngine::with_builtin_rules();
        let package = MirPackage {
            crate_name: "docs".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "doc_only_sha".to_string(),
                signature: "fn doc_only_sha()".to_string(),
                body: vec!["const _: &str = \"Usage of SHA-1 hashing\";".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = engine.run(&package);

        assert!(
            !analysis
                .findings
                .iter()
                .any(|f| f.rule_id == "RUSTCOLA005" && f.function == "doc_only_sha"),
            "sha1 rule should not fire on doc-only strings"
        );
    }

    #[test]
    fn command_rule_ignores_rustc_detection() {
        let engine = RuleEngine::with_builtin_rules();
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "detect_rustc_version".to_string(),
                signature: "fn detect_rustc_version()".to_string(),
                body: vec!["_0 = std::process::Command::new(const \"rustc\");".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = engine.run(&package);

        assert!(
            !analysis
                .findings
                .iter()
                .any(|f| f.rule_id == "RUSTCOLA007" && f.function == "detect_rustc_version"),
            "command rule should ignore detect_rustc_version helper"
        );
    }

    #[test]
    fn command_rule_ignores_discover_targets() {
        let engine = RuleEngine::with_builtin_rules();
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "discover_rustc_targets".to_string(),
                signature: "fn discover_rustc_targets()".to_string(),
                body: vec!["_0 = std::process::Command::new(const \"cargo\");".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = engine.run(&package);

        assert!(
            !analysis
                .findings
                .iter()
                .any(|f| f.rule_id == "RUSTCOLA007" && f.function == "discover_rustc_targets"),
            "command rule should ignore discover_rustc_targets helper"
        );
    }

    #[test]
    fn command_rule_ignores_detect_crate_name() {
        let engine = RuleEngine::with_builtin_rules();
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "detect_crate_name".to_string(),
                signature: "fn detect_crate_name()".to_string(),
                body: vec!["_0 = MetadataCommand::new();".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = engine.run(&package);

        assert!(
            !analysis
                .findings
                .iter()
                .any(|f| f.rule_id == "RUSTCOLA007" && f.function == "detect_crate_name"),
            "command rule should ignore detect_crate_name helper"
        );
    }

    #[test]
    fn unsafe_send_sync_bounds_rule_detects_missing_generic_bounds() -> Result<()> {
        let temp = tempdir().expect("temp dir");
        let crate_root = temp.path();

        fs::create_dir_all(crate_root.join("src"))?;
        fs::write(
            crate_root.join("Cargo.toml"),
            r#"[package]
name = "unsafe-send-sync"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"#,
        )?;
        fs::write(
            crate_root.join("src/lib.rs"),
            r#"use std::marker::PhantomData;

pub struct Wrapper<T>(PhantomData<T>);

unsafe impl<T> Send for Wrapper<T> {}

        pub struct Pair<T, U>(PhantomData<(T, U)>);

        unsafe impl<T, U: Send> Send for Pair<T, U> {}

        pub struct SyncWrapper<T>(PhantomData<T>);

        unsafe impl<T> Sync for SyncWrapper<T> {}

pub struct SafeWrapper<T>(PhantomData<T>);

unsafe impl<T: Send> Send for SafeWrapper<T> {}

        pub struct SafePair<T, U>(PhantomData<(T, U)>);

        unsafe impl<T: Send, U: Send> Send for SafePair<T, U> {}

        pub struct QualifiedSafe<T>(PhantomData<T>);

        unsafe impl<T: std::marker::Send> Send for QualifiedSafe<T> {}

        pub struct PointerWrapper<T>(PhantomData<*const T>);

        unsafe impl<T: Sync> Send for PointerWrapper<T> {}

        pub struct WhereSync<T>(PhantomData<T>);

        unsafe impl<T> Sync for WhereSync<T>
        where
            T: Sync,
        {}

    pub struct SendBoundSync<T>(PhantomData<T>);

    unsafe impl<T: Send> Sync for SendBoundSync<T> {}
"#,
        )?;

        let package = MirPackage {
            crate_name: "unsafe-send-sync".to_string(),
            crate_root: crate_root.to_string_lossy().to_string(),
            functions: Vec::new(),
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);

        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA015")
            .collect();

        assert_eq!(matches.len(), 3, "expected three unsafe Send/Sync findings");

        let signatures: Vec<_> = matches
            .iter()
            .map(|finding| finding.function_signature.clone())
            .collect();

        assert!(
            signatures
                .iter()
                .any(|sig| sig.contains("unsafe impl<T> Send for Wrapper<T>")),
            "missing finding for Wrapper"
        );
        assert!(
            signatures
                .iter()
                .any(|sig| sig.contains("unsafe impl<T, U: Send> Send for Pair<T, U>")),
            "missing finding for Pair"
        );
        assert!(
            signatures
                .iter()
                .any(|sig| sig.contains("unsafe impl<T> Sync for SyncWrapper<T>")),
            "missing finding for SyncWrapper"
        );

        assert!(
            !signatures
                .iter()
                .any(|sig| sig.contains("unsafe impl<T: Send> Send for SafeWrapper<T>")),
            "safe Send impl should not be flagged"
        );
        assert!(
            !signatures
                .iter()
                .any(|sig| sig.contains("unsafe impl<T: Send, U: Send> Send for SafePair<T, U>")),
            "SafePair should not be flagged"
        );
        assert!(
            !signatures
                .iter()
                .any(|sig| sig.contains("unsafe impl<T> Sync for WhereSync<T>")),
            "WhereSync with where clause should not be flagged"
        );
        assert!(
            !signatures
                .iter()
                .any(|sig| sig
                    .contains("unsafe impl<T: std::marker::Send> Send for QualifiedSafe<T>")),
            "QualifiedSafe with fully qualified bound should not be flagged"
        );
        assert!(
            !signatures
                .iter()
                .any(|sig| sig.contains("unsafe impl<T: Sync> Send for PointerWrapper<T>")),
            "PointerWrapper requires Sync on T and should not be flagged"
        );
        assert!(
            !signatures
                .iter()
                .any(|sig| sig.contains("unsafe impl<T: Send> Sync for SendBoundSync<T>")),
            "SendBoundSync requires Send on T and should not be flagged"
        );

        Ok(())
    }

    #[test]
    fn unsafe_send_sync_bounds_rule_ignores_string_literals() -> Result<()> {
        let temp = tempdir().expect("temp dir");
        let crate_root = temp.path();

        fs::create_dir_all(crate_root.join("src"))?;
        fs::write(
            crate_root.join("Cargo.toml"),
            r#"[package]
name = "unsafe-send-sync-literals"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"#,
        )?;
        fs::write(
            crate_root.join("src/lib.rs"),
            r###"pub fn strings() {
    let _ = "unsafe impl<T> Send for Maybe<T> {}";
    let _ = r#"unsafe impl<T> Sync for Maybe<T> {}"#;
}
"###,
        )?;

        let package = MirPackage {
            crate_name: "unsafe-send-sync-literals".to_string(),
            crate_root: crate_root.to_string_lossy().to_string(),
            functions: Vec::new(),
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);

        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA015")
            .collect();

        assert!(
            matches.is_empty(),
            "string literals should not trigger unsafe send/sync findings",
        );

        Ok(())
    }

    #[test]
    fn strip_string_literals_preserves_lifetimes_and_length() -> Result<()> {
        let input = "fn demo<'a>(s: &'a str) -> &'a str { let c = 'x'; s }";
        let (sanitized, _) = strip_string_literals(StringLiteralState::default(), input);

        assert_eq!(sanitized.len(), input.len());
        assert!(sanitized.contains("&'a str"));
        assert!(!sanitized.contains("'x'"));

        Ok(())
    }

    #[test]
    fn ffi_buffer_leak_rule_flags_early_return() -> Result<()> {
        let temp = tempdir().expect("temp dir");
        let crate_root = temp.path();

        fs::create_dir_all(crate_root.join("src"))?;
        fs::write(
            crate_root.join("Cargo.toml"),
            r#"[package]
name = "ffi-buffer-leak"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"#,
        )?;
        fs::write(
            crate_root.join("src/lib.rs"),
            r#"#[no_mangle]
pub extern "C" fn ffi_allocate(target: *mut *mut u8, len: usize) -> Result<(), &'static str> {
    let mut buffer = Vec::with_capacity(len);
    let ptr = buffer.as_mut_ptr();

    unsafe {
        *target = ptr;
    }

    if len == 0 {
        return Err("len must be > 0");
    }

    std::mem::forget(buffer);
    Ok(())
}
"#,
        )?;

        let package = MirPackage {
            crate_name: "ffi-buffer-leak".to_string(),
            crate_root: crate_root.to_string_lossy().to_string(),
            functions: Vec::new(),
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let ffi_findings: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA016")
            .collect();

        assert_eq!(
            ffi_findings.len(),
            1,
            "expected single FFI buffer leak finding"
        );
        let finding = ffi_findings[0];
        assert!(finding.function.contains("src/lib.rs"));
        assert!(finding
            .evidence
            .iter()
            .any(|line| line.contains("Vec::with_capacity")));
        assert!(finding
            .evidence
            .iter()
            .any(|line| line.contains("return Err")));

        Ok(())
    }

    #[test]
    fn ffi_buffer_leak_rule_ignores_string_literals() -> Result<()> {
        let temp = tempdir().expect("temp dir");
        let crate_root = temp.path();

        fs::create_dir_all(crate_root.join("src"))?;
        fs::write(
            crate_root.join("Cargo.toml"),
            r#"[package]
name = "ffi-buffer-literal"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"#,
        )?;
        fs::write(
            crate_root.join("src/lib.rs"),
            r###"pub fn fixtures() {
    let _ = r#"
#[no_mangle]
pub extern "C" fn ffi_allocate(target: *mut *mut u8, len: usize) -> Result<(), &'static str> {
    let mut buffer = Vec::with_capacity(len);
    if len == 0 {
        return Err("len must be > 0");
    }
    std::mem::forget(buffer);
    Ok(())
}
"#;
}
"###,
        )?;

        let package = MirPackage {
            crate_name: "ffi-buffer-literal".to_string(),
            crate_root: crate_root.to_string_lossy().to_string(),
            functions: Vec::new(),
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA016")
            .collect();

        assert!(
            matches.is_empty(),
            "string literal containing FFI example should not trigger RUSTCOLA016",
        );

        Ok(())
    }

    #[test]
    fn allocator_mismatch_rule_ignores_string_literals() -> Result<()> {
        let temp = tempdir().expect("temp dir");
        let crate_root = temp.path();

        fs::create_dir_all(crate_root.join("src"))?;
        fs::write(
            crate_root.join("Cargo.toml"),
            r#"[package]
name = "allocator-mismatch-string-literals"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"#,
        )?;
        fs::write(
            crate_root.join("src/lib.rs"),
            r###"pub fn literal_patterns() {
    let message = "Box::into_raw should not trigger";
    let raw_literal = r#"libc::free mentioned here"#;
    let multiline = r#"Vec::from_raw_parts in documentation"#;
    let combined = format!("{} {}", message, raw_literal);
    drop((multiline, combined));
}
"###,
        )?;

        let package = MirPackage {
            crate_name: "allocator-mismatch-string-literals".to_string(),
            crate_root: crate_root.to_string_lossy().to_string(),
            functions: Vec::new(),
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let findings: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA017")
            .collect();

        assert!(
            findings.is_empty(),
            "string literals referencing allocator names should not trigger RUSTCOLA017"
        );

        Ok(())
    }

    #[test]
    fn unsafe_usage_rule_detects_unsafe_block() -> Result<()> {
        let package = MirPackage {
            crate_name: "unsafe-detect".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "danger".to_string(),
                signature: "fn danger()".to_string(),
                body: vec![
                    "fn danger() {".to_string(),
                    "    unsafe { core::ptr::read(_1); }".to_string(),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA003")
            .collect();

        assert_eq!(matches.len(), 1, "expected RUSTCOLA003 to fire");
        assert!(matches[0]
            .evidence
            .iter()
            .any(|line| line.contains("unsafe")));

        Ok(())
    }

    #[test]
    fn unsafe_usage_rule_ignores_string_literals() -> Result<()> {
        let package = MirPackage {
            crate_name: "unsafe-literal".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "doc_example".to_string(),
                signature: "fn doc_example()".to_string(),
                body: vec![
                    "fn doc_example() {".to_string(),
                    "    _1 = \"This string mentions unsafe code\";".to_string(),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA003")
            .collect();

        assert!(
            matches.is_empty(),
            "string literal mentioning unsafe should not trigger RUSTCOLA003"
        );

        Ok(())
    }

    #[test]
    fn vec_set_len_rule_detects_usage() -> Result<()> {
        let package = MirPackage {
            crate_name: "vec-set-len-detect".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "grow".to_string(),
                signature: "fn grow(vec: &mut Vec<i32>)".to_string(),
                body: vec![
                    "fn grow(vec: &mut Vec<i32>) {".to_string(),
                    make_vec_set_len_line("    "),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA008")
            .collect();

        assert_eq!(matches.len(), 1, "expected RUSTCOLA008 to fire");
        assert!(matches[0]
            .evidence
            .iter()
            .any(|line| line.contains("set_len")));

        Ok(())
    }

    #[test]
    fn vec_set_len_rule_ignores_string_literals() -> Result<()> {
        let package = MirPackage {
            crate_name: "vec-set-len-literal".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "doc_only".to_string(),
                signature: "fn doc_only()".to_string(),
                body: vec![
                    "fn doc_only() {".to_string(),
                    format!("    _1 = \"Documenting {} behavior\";", VEC_SET_LEN_SYMBOL),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA008")
            .collect();

        assert!(
            matches.is_empty(),
            "string literal mentioning {} should not trigger RUSTCOLA008",
            VEC_SET_LEN_SYMBOL
        );

        Ok(())
    }

    #[test]
    fn vec_set_len_rule_ignores_metadata_lines() -> Result<()> {
        let package = MirPackage {
            crate_name: "vec-set-len-metadata".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "meta".to_string(),
                signature: "fn meta()".to_string(),
                body: vec![
                    "fn meta() {".to_string(),
                    format!(
                        "    0x00 │ 56 65 63 3a 3a 73 65 74 5f 6c 65 6e │ {} used in metadata",
                        VEC_SET_LEN_SYMBOL
                    ),
                    "    0x10 │ 20 75 73 65 64 20 69 6e 20 6d 65 74 │  used in metadata"
                        .to_string(),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA008")
            .collect();

        assert!(
            matches.is_empty(),
            "metadata-style {} mention without call should not trigger RUSTCOLA008",
            VEC_SET_LEN_SYMBOL
        );

        Ok(())
    }

    #[test]
    fn maybe_uninit_rule_detects_usage() -> Result<()> {
        let package = MirPackage {
            crate_name: "maybe-uninit-detect".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "finalize".to_string(),
                signature: "fn finalize(buf: &mut core::mem::MaybeUninit<i32>)".to_string(),
                body: vec![
                    "fn finalize(buf: &mut core::mem::MaybeUninit<i32>) {".to_string(),
                    make_maybe_uninit_assume_init_line("    "),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA009")
            .collect();

        assert_eq!(matches.len(), 1, "expected RUSTCOLA009 to fire");
        assert!(matches[0]
            .evidence
            .iter()
            .any(|line| line.contains(MAYBE_UNINIT_ASSUME_INIT_SYMBOL)));

        Ok(())
    }

    #[test]
    fn maybe_uninit_rule_skips_analyzer_crate() -> Result<()> {
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "self_test".to_string(),
                signature: "fn self_test(vec: &mut Vec<i32>)".to_string(),
                body: vec![
                    "fn self_test(vec: &mut Vec<i32>) {".to_string(),
                    make_maybe_uninit_assume_init_line("    "),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let has_maybe_uninit = analysis
            .findings
            .iter()
            .any(|finding| finding.rule_id == "RUSTCOLA009");

        assert!(
            !has_maybe_uninit,
            "{}::{} rule should not flag mir-extractor crate",
            MAYBE_UNINIT_TYPE_SYMBOL, MAYBE_UNINIT_ASSUME_INIT_SYMBOL
        );

        Ok(())
    }

    #[test]
    fn mem_uninit_rule_detects_usage() -> Result<()> {
        let package = MirPackage {
            crate_name: "mem-uninit-detect".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "allocate".to_string(),
                signature: "fn allocate()".to_string(),
                body: vec![
                    "fn allocate() {".to_string(),
                    make_mem_uninitialized_line("    "),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA010")
            .collect();

        assert_eq!(matches.len(), 1, "expected RUSTCOLA010 to fire");
        assert!(matches[0]
            .evidence
            .iter()
            .any(|line| line.contains(MEM_UNINITIALIZED_SYMBOL)));

        Ok(())
    }

    #[test]
    fn mem_uninit_rule_skips_analyzer_crate() -> Result<()> {
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "self_test".to_string(),
                signature: "fn self_test()".to_string(),
                body: vec![
                    "fn self_test() {".to_string(),
                    make_mem_uninitialized_line("    "),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let has_mem_uninit = analysis
            .findings
            .iter()
            .any(|finding| finding.rule_id == "RUSTCOLA010");

        assert!(
            !has_mem_uninit,
            "{}::{} rule should not flag mir-extractor crate",
            MEM_MODULE_SYMBOL, MEM_UNINITIALIZED_SYMBOL
        );

        Ok(())
    }

    #[test]
    fn danger_accept_invalid_certs_rule_detects_usage() -> Result<()> {
        let package = MirPackage {
            crate_name: "danger-accept-invalid-certs-detect".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "configure".to_string(),
                signature: "fn configure(builder: reqwest::ClientBuilder)".to_string(),
                body: vec![
                    "fn configure(builder: reqwest::ClientBuilder) {".to_string(),
                    make_danger_accept_invalid_certs_line("    "),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA012")
            .collect();

        assert_eq!(matches.len(), 1, "expected RUSTCOLA012 to fire");
        assert!(matches[0]
            .evidence
            .iter()
            .any(|line| line.contains(DANGER_ACCEPT_INVALID_CERTS_SYMBOL)));

        Ok(())
    }

    #[test]
    fn danger_accept_invalid_certs_rule_detects_rustls_dangerous() -> Result<()> {
        let package = MirPackage {
            crate_name: "rustls-dangerous-client".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "dangerous_client".to_string(),
                signature: "fn dangerous_client(config: &mut rustls::ClientConfig)".to_string(),
                body: vec![
                    "fn dangerous_client(config: &mut rustls::ClientConfig) {".to_string(),
                    "    _3 = rustls::client::dangerous::DangerousClientConfig::set_certificate_verifier(move _2, move _1);".to_string(),
                    "}".to_string(),
                ],
                span: None,
            ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA012")
            .collect();

        assert_eq!(
            matches.len(),
            1,
            "expected RUSTCOLA012 to fire for rustls dangerous usage"
        );
        assert!(matches[0]
            .evidence
            .iter()
            .any(|line| line.contains("set_certificate_verifier")));

        Ok(())
    }

    #[test]
    fn danger_accept_invalid_certs_rule_skips_analyzer_crate() -> Result<()> {
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "self_test".to_string(),
                signature: "fn self_test(builder: reqwest::ClientBuilder)".to_string(),
                body: vec![
                    "fn self_test(builder: reqwest::ClientBuilder) {".to_string(),
                    make_danger_accept_invalid_certs_line("    "),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let has_danger_tls = analysis
            .findings
            .iter()
            .any(|finding| finding.rule_id == "RUSTCOLA012");

        assert!(
            !has_danger_tls,
            "{} rule should not flag mir-extractor crate",
            DANGER_ACCEPT_INVALID_CERTS_SYMBOL
        );

        Ok(())
    }

    #[test]
    fn length_truncation_cast_rule_detects_usage() -> Result<()> {
        let package = MirPackage {
            crate_name: "length-truncation-detect".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "encode".to_string(),
                signature: "fn encode(len: usize, writer: &mut byteorder::io::Write)".to_string(),
                body: {
                    let mut body = Vec::with_capacity(6);
                    body.push(
                        "fn encode(len: usize, writer: &mut byteorder::io::Write) {".to_string(),
                    );
                    body.extend(make_length_truncation_cast_lines("    "));
                    body.push("}".to_string());
                    body
                },
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA022")
            .collect();

        assert_eq!(matches.len(), 1, "expected RUSTCOLA022 to fire");
        let evidence = &matches[0].evidence;
        assert!(evidence
            .iter()
            .any(|line| line.contains(LENGTH_TRUNCATION_CAST_INTTOINT_SYMBOL)));
        assert!(evidence
            .iter()
            .any(|line| line.contains(LENGTH_TRUNCATION_CAST_WRITE_SYMBOL)));

        Ok(())
    }

    #[test]
    fn length_truncation_cast_rule_skips_analyzer_crate() -> Result<()> {
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "self_test".to_string(),
                signature: "fn self_test(len: usize)".to_string(),
                body: {
                    let mut body = Vec::with_capacity(6);
                    body.push("fn self_test(len: usize) {".to_string());
                    body.extend(make_length_truncation_cast_lines("    "));
                    body.push("}".to_string());
                    body
                },
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let has_truncation = analysis
            .findings
            .iter()
            .any(|finding| finding.rule_id == "RUSTCOLA022");

        assert!(
            !has_truncation,
            "{} rule should not flag mir-extractor crate",
            LENGTH_TRUNCATION_CAST_WRITE_SYMBOL
        );

        Ok(())
    }

    #[test]
    fn unbounded_allocation_rule_detects_usage() -> Result<()> {
        let package = MirPackage {
            crate_name: "unbounded-allocation-detect".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "allocate".to_string(),
                signature: "fn allocate(len: usize)".to_string(),
                body: {
                    let mut body = Vec::with_capacity(5);
                    body.push("fn allocate(len: usize) {".to_string());
                    body.extend(make_unbounded_allocation_lines("    ", "len"));
                    body.push("}".to_string());
                    body
                },
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA024")
            .collect();

        assert_eq!(matches.len(), 1, "expected RUSTCOLA024 to fire");
        let evidence = &matches[0].evidence;
        assert!(evidence
            .iter()
            .any(|line| line.contains(UNBOUNDED_ALLOCATION_WITH_CAPACITY_SYMBOL)));

        Ok(())
    }

    #[test]
    fn unbounded_allocation_rule_skips_analyzer_crate() -> Result<()> {
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "self_test".to_string(),
                signature: "fn self_test(len: usize)".to_string(),
                body: {
                    let mut body = Vec::with_capacity(5);
                    body.push("fn self_test(len: usize) {".to_string());
                    body.extend(make_unbounded_allocation_lines("    ", "len"));
                    body.push("}".to_string());
                    body
                },
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let has_unbounded = analysis
            .findings
            .iter()
            .any(|finding| finding.rule_id == "RUSTCOLA024");

        assert!(
            !has_unbounded,
            "{} rule should not flag mir-extractor crate",
            UNBOUNDED_ALLOCATION_WITH_CAPACITY_SYMBOL
        );

        Ok(())
    }

    #[test]
    fn transmute_rule_detects_usage() -> Result<()> {
        let package = MirPackage {
            crate_name: "transmute-detect".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "reinterpret".to_string(),
                signature: "unsafe fn reinterpret(value: u32) -> i32".to_string(),
                body: vec![
                    "unsafe fn reinterpret(value: u32) -> i32 {".to_string(),
                    "    std::mem::transmute(value)".to_string(),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA002")
            .collect();

        assert_eq!(matches.len(), 1, "expected single RUSTCOLA002 finding");
        assert!(matches[0]
            .evidence
            .iter()
            .any(|line| line.contains("std::mem::transmute")));

        Ok(())
    }

    #[test]
    fn transmute_rule_ignores_string_literals() -> Result<()> {
        let package = MirPackage {
            crate_name: "transmute-string".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "describe".to_string(),
                signature: "pub fn describe() -> &'static str".to_string(),
                body: vec![
                    "pub fn describe() -> &'static str {".to_string(),
                    "    \"std::mem::transmute should not trigger\"".to_string(),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA002")
            .collect();

        assert!(
            matches.is_empty(),
            "string literal should not trigger transmute rule"
        );

        Ok(())
    }

    #[test]
    fn allocator_mismatch_rule_detects_mixed_allocators() -> Result<()> {
        // Test using mock MIR that represents the allocator mismatch pattern
        // This simulates: CString::into_raw() followed by libc::free()
        // The free directly uses the variable from into_raw
        let package = MirPackage {
            crate_name: "allocator-mismatch".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "bad_mix".to_string(),
                signature: "unsafe extern \"C\" fn bad_mix()".to_string(),
                body: vec![
                    "_1 = CString::new::<&str>(const \"hello\") -> [return: bb1, unwind: bb5];".to_string(),
                    "_2 = Result::<CString, NulError>::unwrap(move _1) -> [return: bb2, unwind: bb5];".to_string(),
                    "_3 = CString::into_raw(move _2) -> [return: bb3, unwind: bb5];".to_string(),
                    "_4 = free(move _3) -> [return: bb4, unwind: bb5];".to_string(),
                ],
                span: Some(SourceSpan {
                    file: "src/lib.rs".to_string(),
                    start_line: 4,
                    start_column: 1,
                    end_line: 8,
                    end_column: 1,
                }),
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let findings: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA017")
            .collect();

        assert_eq!(
            findings.len(),
            1,
            "expected single allocator mismatch finding"
        );
        let finding = findings[0];
        assert!(finding.function.contains("bad_mix"));
        assert!(finding
            .evidence
            .iter()
            .any(|line| line.contains("into_raw")));
        assert!(finding
            .evidence
            .iter()
            .any(|line| line.contains("free")));

        Ok(())
    }

    #[test]
    fn rustsec_unsound_dependency_rule_flags_lockfile_matches() -> Result<()> {
        let temp = tempdir().expect("temp dir");
        let crate_root = temp.path();

        fs::create_dir_all(crate_root.join("src"))?;
        fs::write(
            crate_root.join("Cargo.toml"),
            r#"[package]
name = "rustsec-unsound"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"#,
        )?;
        fs::write(crate_root.join("src/lib.rs"), "pub fn noop() {}")?;
        fs::write(
            crate_root.join("Cargo.lock"),
            r#"# This file is automatically @generated by Cargo.
[[package]]
name = "arrayvec"
version = "0.4.10"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "rustsec-unsound"
version = "0.1.0"
"#,
        )?;

        let package = MirPackage {
            crate_name: "rustsec-unsound".to_string(),
            crate_root: crate_root.to_string_lossy().to_string(),
            functions: Vec::new(),
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let findings: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA018")
            .collect();

        assert_eq!(findings.len(), 1, "expected single RustSec unsound finding");
        let finding = findings[0];
        assert!(finding.function.ends_with("Cargo.lock"));
        assert!(finding.message.contains("arrayvec"));
        assert!(finding.message.contains("RUSTSEC-2018-0001"));

        Ok(())
    }

    #[test]
    fn yanked_crate_rule_flags_yanked_versions() -> Result<()> {
        let temp = tempdir().expect("temp dir");
        let crate_root = temp.path();

        fs::create_dir_all(crate_root.join("src"))?;
        fs::write(
            crate_root.join("Cargo.toml"),
            r#"[package]
name = "yanked-dep"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"#,
        )?;
        fs::write(crate_root.join("src/lib.rs"), "pub fn noop() {}")?;
        fs::write(
            crate_root.join("Cargo.lock"),
            r#"# autogenerated
[[package]]
name = "memoffset"
version = "0.5.6"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "yanked-dep"
version = "0.1.0"
"#,
        )?;

        let package = MirPackage {
            crate_name: "yanked-dep".to_string(),
            crate_root: crate_root.to_string_lossy().to_string(),
            functions: Vec::new(),
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let findings: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA019")
            .collect();

        assert_eq!(findings.len(), 1, "expected single yanked crate finding");
        let finding = findings[0];
        assert!(finding.message.contains("memoffset"));
        assert!(finding.message.contains("0.5.6"));

        Ok(())
    }

    #[test]
    fn cargo_auditable_rule_flags_missing_metadata() -> Result<()> {
        let temp = tempdir().expect("temp dir");
        let crate_root = temp.path();

        fs::create_dir_all(crate_root.join("src"))?;
        fs::write(
            crate_root.join("Cargo.toml"),
            r#"[package]
name = "auditable-missing"
version = "0.1.0"
edition = "2021"
"#,
        )?;
        fs::write(
            crate_root.join("src/main.rs"),
            "fn main() { println!(\"hi\"); }",
        )?;

        let package = MirPackage {
            crate_name: "auditable-missing".to_string(),
            crate_root: crate_root.to_string_lossy().to_string(),
            functions: Vec::new(),
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let findings: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA020")
            .collect();

        assert_eq!(findings.len(), 1, "expected missing auditable finding");
        let finding = findings[0];
        assert!(finding.function.contains("Cargo.toml"));
        assert!(finding.message.contains("auditable"));

        Ok(())
    }

    #[test]
    fn cargo_auditable_rule_respects_skip_metadata() -> Result<()> {
        let temp = tempdir().expect("temp dir");
        let crate_root = temp.path();

        fs::create_dir_all(crate_root.join("src"))?;
        fs::write(
            crate_root.join("Cargo.toml"),
            r#"[package]
name = "auditable-skip"
version = "0.1.0"
edition = "2021"

[package.metadata.rust-cola]
skip_auditable_check = true
"#,
        )?;
        fs::write(
            crate_root.join("src/main.rs"),
            "fn main() { println!(\"hi\"); }",
        )?;

        let package = MirPackage {
            crate_name: "auditable-skip".to_string(),
            crate_root: crate_root.to_string_lossy().to_string(),
            functions: Vec::new(),
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let finding_exists = analysis
            .findings
            .iter()
            .any(|finding| finding.rule_id == "RUSTCOLA020");

        assert!(!finding_exists, "skip metadata should suppress findings");

        Ok(())
    }

    #[test]
    fn cargo_auditable_rule_allows_marker_dependency() -> Result<()> {
        let temp = tempdir().expect("temp dir");
        let crate_root = temp.path();

        fs::create_dir_all(crate_root.join("src"))?;
        fs::write(
            crate_root.join("Cargo.toml"),
            r#"[package]
name = "auditable-marker"
version = "0.1.0"
edition = "2021"

[dependencies]
auditable = "0.1"
"#,
        )?;
        fs::write(
            crate_root.join("src/main.rs"),
            "fn main() { println!(\"hi\"); }",
        )?;

        let package = MirPackage {
            crate_name: "auditable-marker".to_string(),
            crate_root: crate_root.to_string_lossy().to_string(),
            functions: Vec::new(),
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let finding_exists = analysis
            .findings
            .iter()
            .any(|finding| finding.rule_id == "RUSTCOLA020");

        assert!(
            !finding_exists,
            "auditable dependency marker should suppress findings"
        );

        Ok(())
    }

    #[test]
    fn cargo_auditable_rule_detects_workspace_ci_markers() -> Result<()> {
        let temp = tempdir().expect("temp dir");
        let workspace_root = temp.path();

        fs::create_dir_all(workspace_root.join(".github/workflows"))?;
        fs::write(
            workspace_root.join(".github/workflows/ci.yml"),
            "run: cargo auditable build --release\n",
        )?;

        let crate_root = workspace_root.join("workspace-bin");
        fs::create_dir_all(crate_root.join("src"))?;
        fs::write(
            crate_root.join("Cargo.toml"),
            r#"[package]
name = "workspace-bin"
version = "0.1.0"
edition = "2021"
"#,
        )?;
        fs::write(
            crate_root.join("src/main.rs"),
            "fn main() { println!(\"hi\"); }",
        )?;

        let package = MirPackage {
            crate_name: "workspace-bin".to_string(),
            crate_root: crate_root.to_string_lossy().to_string(),
            functions: Vec::new(),
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let finding_exists = analysis
            .findings
            .iter()
            .any(|finding| finding.rule_id == "RUSTCOLA020");

        assert!(
            !finding_exists,
            "workspace CI markers should suppress cargo auditable warning"
        );

        Ok(())
    }

    #[test]
    fn wasm_stub_registers_metadata() -> Result<()> {
        let temp = tempdir().expect("temp dir");
        let wasm_path = temp.path().join("rust_cola_stub.wasm");
        fs::write(&wasm_path, b"\0asmstub")?;

        let mut engine = RuleEngine::new();
        engine.load_wasm_module(&wasm_path)?;

        let metadata = engine.rule_metadata();
        assert!(metadata
            .iter()
            .any(|meta| matches!(meta.origin, RuleOrigin::Wasm { .. })));

        let package = MirPackage {
            crate_name: "demo".to_string(),
            crate_root: ".".to_string(),
            functions: Vec::new(),
        };

        let analysis = engine.run(&package);
        assert!(analysis.findings.is_empty());

        Ok(())
    }

    #[test]
    fn cache_hit_skips_extractor() -> Result<()> {
        let temp = tempdir().expect("temp dir");
        let crate_root = temp.path();

        fs::create_dir_all(crate_root.join("src"))?;
        fs::write(
            crate_root.join("Cargo.toml"),
            r#"[package]
name = "cache-demo"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"#,
        )?;
        fs::write(
            crate_root.join("src/lib.rs"),
            "pub fn cached() -> i32 { 42 }",
        )?;

        let cache_temp = tempdir().expect("cache dir");
        let cache_config = CacheConfig {
            enabled: true,
            directory: cache_temp.path().to_path_buf(),
            clear: false,
        };

        let counter = Arc::new(AtomicUsize::new(0));
        let base_package = MirPackage {
            crate_name: "cache-demo".to_string(),
            crate_root: crate_root.to_string_lossy().to_string(),
            functions: vec![MirFunction {
                name: "cached".to_string(),
                signature: "fn cached() -> i32".to_string(),
                body: vec!["_0 = const 42_i32;".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let counter_clone = counter.clone();
        #[cfg(feature = "hir-driver")]
        let hir_options = HirOptions::default();

        let (first_artifacts, status1) = super::extract_artifacts_with_cache(
            crate_root,
            &cache_config,
            #[cfg(feature = "hir-driver")]
            &hir_options,
            move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                Ok(ExtractionArtifacts {
                    mir: base_package.clone(),
                    #[cfg(feature = "hir-driver")]
                    hir: None,
                })
            },
        )?;

        let first_package = first_artifacts.mir.clone();

        assert_eq!(counter.load(Ordering::SeqCst), 1);
        match status1 {
            CacheStatus::Miss { .. } => {}
            _ => panic!("expected first run to miss cache"),
        }

        let (second_artifacts, status2) = super::extract_artifacts_with_cache(
            crate_root,
            &cache_config,
            #[cfg(feature = "hir-driver")]
            &hir_options,
            || {
                panic!("extractor invoked during cache hit");
            },
        )?;

        let second_package = second_artifacts.mir;

        match status2 {
            CacheStatus::Hit(meta) => {
                assert_eq!(
                    meta.function_fingerprints.len(),
                    second_package.functions.len()
                );
            }
            _ => panic!("expected second run to hit cache"),
        }

        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(
            first_package.functions.len(),
            second_package.functions.len()
        );

        Ok(())
    }

    #[test]
    fn vec_set_len_rule_skips_analyzer_crate() -> Result<()> {
        let package = MirPackage {
            crate_name: "mir-extractor".to_string(),
            crate_root: ".".to_string(),
            functions: vec![MirFunction {
                name: "self_test".to_string(),
                signature: "fn self_test(vec: &mut Vec<i32>)".to_string(),
                body: vec![
                    "fn self_test(vec: &mut Vec<i32>) {".to_string(),
                    make_vec_set_len_line("    "),
                    "}".to_string(),
                ],
                span: None,
                ..Default::default()
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let has_vec_set_len = analysis
            .findings
            .iter()
            .any(|finding| finding.rule_id == "RUSTCOLA008");

        assert!(
            !has_vec_set_len,
            "Vec::set_len rule should not flag mir-extractor crate"
        );

        Ok(())
    }
}
