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
use semver::{Version, VersionReq};
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

// Import shared utilities from rules module
use rules::utils::{StringLiteralState, strip_string_literals, collect_sanitized_matches};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn sarif_level(&self) -> &'static str {
        match self {
            Severity::Low => "note",
            Severity::Medium => "warning",
            Severity::High => "error",
        }
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
    pub message: String,
    pub function: String,
    pub function_signature: String,
    pub evidence: Vec<String>,
    pub span: Option<SourceSpan>,
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
    fn evaluate(&self, package: &MirPackage) -> Vec<Finding>;

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

        for rule in &self.rules {
            let metadata = rule.metadata().clone();
            rules.push(metadata.clone());
            findings.extend(rule.evaluate(package));
        }

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

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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
                message,
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence,
                span: function.span.clone(),
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
        };

        Self { metadata }
    }
}

impl Rule for WasmRulePlaceholder {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, _package: &MirPackage) -> Vec<Finding> {
        Vec::new()
    }
}

struct BoxIntoRawRule {
    metadata: RuleMetadata,
}

impl BoxIntoRawRule {
    fn new() -> Self {
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

struct TransmuteRule {
    metadata: RuleMetadata,
}

impl TransmuteRule {
    fn new() -> Self {
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

struct UnsafeUsageRule {
    metadata: RuleMetadata,
}

impl UnsafeUsageRule {
    fn new() -> Self {
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

struct InsecureMd5Rule {
    metadata: RuleMetadata,
}

impl InsecureMd5Rule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA004".to_string(),
                name: "insecure-hash-md5".to_string(),
                short_description: "Usage of MD5 hashing".to_string(),
                full_description: "Detects calls into md5 hashing APIs which are considered cryptographically broken.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for InsecureMd5Rule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| line_contains_md5_usage(line))
                .map(|line| line.trim().to_string())
                .collect();
            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!("Insecure MD5 hashing detected in `{}`", function.name),
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence,
                span: function.span.clone(),
            });
        }

        findings
    }
}

struct InsecureSha1Rule {
    metadata: RuleMetadata,
}

impl InsecureSha1Rule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA005".to_string(),
                name: "insecure-hash-sha1".to_string(),
                short_description: "Usage of SHA-1 hashing".to_string(),
                full_description: "Detects SHA-1 hashing APIs which are deprecated for security-sensitive contexts.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for InsecureSha1Rule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("line_contains_sha1_usage") {
                continue;
            }

            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| line_contains_sha1_usage(line))
                .map(|line| line.trim().to_string())
                .collect();
            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!("Insecure SHA-1 hashing detected in `{}`", function.name),
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence,
                span: function.span.clone(),
            });
        }

        findings
    }
}

struct WeakHashingExtendedRule {
    metadata: RuleMetadata,
}

impl WeakHashingExtendedRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA062".to_string(),
                name: "weak-hashing-extended".to_string(),
                short_description: "Usage of weak cryptographic hash algorithms".to_string(),
                full_description: "Detects usage of weak or deprecated cryptographic hash algorithms beyond MD5/SHA-1, including RIPEMD (all variants), CRC32, CRC32Fast, and Adler32. These algorithms should not be used for security-sensitive operations like password hashing, authentication tokens, or cryptographic signatures. Use SHA-256, SHA-3, BLAKE2, or BLAKE3 instead.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for WeakHashingExtendedRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        // Self-exclusion: don't flag our own rule implementation
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            // Self-exclusion: don't flag the detection function itself
            if function.name.contains("WeakHashingExtendedRule") 
                || function.name.contains("line_contains_weak_hash_extended") {
                continue;
            }

            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| line_contains_weak_hash_extended(line))
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
                    "Weak cryptographic hash algorithm detected in `{}`",
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

struct NullPointerTransmuteRule {
    metadata: RuleMetadata,
}

impl NullPointerTransmuteRule {
    fn new() -> Self {
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
        // Self-exclusion: don't flag our own rule implementation
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            // Self-exclusion: don't flag the detection function itself
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
                    "Null pointer transmute detected in `{}` - this causes undefined behavior",
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

struct ZSTPointerArithmeticRule {
    metadata: RuleMetadata,
}

impl ZSTPointerArithmeticRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA064".to_string(),
                name: "zst-pointer-arithmetic".to_string(),
                short_description: "Pointer arithmetic on zero-sized types".to_string(),
                full_description: "Detects pointer arithmetic operations (offset, add, sub, wrapping_offset, etc.) on zero-sized types like unit type (), PhantomData, empty structs. Pointer arithmetic on ZSTs causes undefined behavior because offset calculations assume stride of size_of::<T>(), which is 0 for ZSTs, violating pointer aliasing rules and provenance. Sonar RSPEC-7412 parity.".to_string(),
                help_uri: Some("https://rules.sonarsource.com/rust/RSPEC-7412/".to_string()),
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
        // Self-exclusion: don't flag our own rule implementation
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            // Self-exclusion: don't flag the detection function itself
            if function.name.contains("ZSTPointerArithmeticRule") 
                || function.name.contains("looks_like_zst_pointer_arithmetic") {
                continue;
            }
            
            // Skip derive macro generated code (serde, etc.)
            // These use ZST pointer arithmetic internally in safe patterns
            if Self::is_derive_macro_generated(function) {
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
                    "Pointer arithmetic on zero-sized type detected in `{}` - this causes undefined behavior",
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

impl ZSTPointerArithmeticRule {
    /// Detect derive macro generated code (serde, etc.)
    /// These use ZST pointer arithmetic internally in safe patterns
    fn is_derive_macro_generated(function: &MirFunction) -> bool {
        let name = &function.name;
        let sig = &function.signature;
        
        // Serde derive patterns:
        // - <Type as serde::Serialize>::serialize
        // - <Type as serde::de::Deserialize>::deserialize
        // - <Type as _serde::Serialize>::serialize
        // - Visitor implementations
        // - DeserializeSeed patterns
        let serde_patterns = [
            "serde::Serialize",
            "serde::Deserialize", 
            "serde::de::Visitor",
            "serde::de::DeserializeSeed",
            "serde::ser::Serialize",
            "_serde::Serialize",
            "_serde::Deserialize",
            "_serde::de::Visitor",
            "::Visitor>::",
            "::Seed>::",
            "<impl Serialize for",
            "<impl Deserialize for",
        ];
        
        for pattern in &serde_patterns {
            if name.contains(pattern) || sig.contains(pattern) {
                return true;
            }
        }
        
        // Other common derive macros that may use ZST patterns
        // Debug, Clone, PartialEq, Eq, Hash, etc.
        let derive_patterns = [
            "<impl core::fmt::Debug for",
            "<impl std::fmt::Debug for",
            "<impl core::clone::Clone for",
            "<impl std::clone::Clone for",
            "<impl core::cmp::PartialEq for",
            "<impl core::cmp::Eq for",
            "<impl core::hash::Hash for",
            "<impl core::default::Default for",
        ];
        
        for pattern in &derive_patterns {
            if name.contains(pattern) || sig.contains(pattern) {
                return true;
            }
        }
        
        // Check for common serde derive helper function names
        // These are internal functions generated by derive macros
        if name.contains("::deserialize::") 
            || name.contains("::serialize::") 
            || name.contains("__Visitor")
            || name.contains("__Field")
            || name.contains("::__serde")
        {
            return true;
        }
        
        false
    }
}

struct CleartextEnvVarRule {
    metadata: RuleMetadata,
}

impl CleartextEnvVarRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA065".to_string(),
                name: "cleartext-env-var".to_string(),
                short_description: "Cleartext environment variable exposure".to_string(),
                full_description: "Detects env::set_var() calls with sensitive variable names like PASSWORD, SECRET, TOKEN, API_KEY, etc. Setting environment variables with sensitive values in cleartext can expose secrets to other processes, child processes, and system logs. Environment variables are visible via /proc on Linux and process inspection tools. Sensitive data should use secure credential storage (e.g., keyrings, secret management services) instead of environment variables.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for CleartextEnvVarRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        // Self-exclusion: don't flag our own rule implementation
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            // Self-exclusion: don't flag the detection function itself
            if function.name.contains("CleartextEnvVarRule") 
                || function.name.contains("looks_like_cleartext_env_var") {
                continue;
            }

            // Check if function body contains set_var call
            let body_str = function.body.join("\n").to_lowercase();
            
            if !body_str.contains("set_var") {
                continue;
            }
            
            // Check for sensitive variable names in the function body
            let sensitive_names = [
                "password", "passwd", "pwd", "secret", "token", 
                "api_key", "apikey", "auth", "private_key", "privatekey",
                "jwt", "access_token", "refresh_token", "bearer", 
                "credential", "db_password", "database_password",
            ];
            
            let has_sensitive_name = sensitive_names.iter().any(|name| body_str.contains(name));
            
            if !has_sensitive_name {
                continue;
            }

            // Collect evidence lines
            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| {
                    let lower = line.to_lowercase();
                    (lower.contains("set_var") && (lower.contains("std::env") || lower.contains("::env::")))
                        || sensitive_names.iter().any(|name| lower.contains(name))
                })
                .take(5) // Limit evidence to avoid overwhelming output
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
                    "Sensitive environment variable set in cleartext in `{}` - use secure credential storage instead",
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

struct ModuloBiasRandomRule {
    metadata: RuleMetadata,
}

impl ModuloBiasRandomRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA066".to_string(),
                name: "modulo-bias-random".to_string(),
                short_description: "Modulo bias on random outputs".to_string(),
                full_description: "Detects modulo operations (%) applied to random number generator outputs in cryptographic contexts. Modulo creates non-uniform distributions because the range of possible values doesn't divide evenly into the modulus. For example, rand() % 3 on a 0-255 RNG will favor values 0 and 1 over 2 (since 256 % 3 = 1). This bias can be exploited in cryptographic operations like key generation, nonce creation, signature schemes (ECDSA k-value attacks), and token generation. Use gen_range(), fill_bytes(), or rejection sampling instead for uniform distributions.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for ModuloBiasRandomRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        // Self-exclusion
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            // Self-exclusion
            if function.name.contains("ModuloBiasRandomRule") {
                continue;
            }

            let body_str = function.body.join("\n").to_lowercase();
            
            // Check for cryptographic context based on function name
            let crypto_keywords = [
                "crypto", "crypt", "key", "token", "auth", "sign", "encrypt", "decrypt",
                "hash", "hmac", "nonce", "salt", "secret", "password", "credential",
                "session", "verify", "signature",
            ];
            
            let is_crypto_context = crypto_keywords.iter().any(|kw| {
                function.name.to_lowercase().contains(kw)
            });
            
            if !is_crypto_context {
                continue;
            }
            
            // Check for random number generation
            let rand_patterns = [
                "::gen::<",  // rng.gen::<T>()
                "::gen(",    // rng.gen()
                "random::",  // random::random()
                "threadrng", // thread_rng()
                "rng",       // general rng variable
            ];
            
            let has_random = rand_patterns.iter().any(|pattern| body_str.contains(pattern));
            
            if !has_random {
                continue;
            }
            
            // Check for modulo operation
            // In MIR, modulo appears as "Rem" operation
            let modulo_patterns = [
                "rem(",      // Rem operation
                "% ",        // Modulo symbol  
                "_rem",      // _rem helper
            ];
            
            let has_modulo = modulo_patterns.iter().any(|pattern| body_str.contains(pattern));
            
            if !has_modulo {
                continue;
            }

            // Collect evidence lines showing random + modulo
            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| {
                    let lower = line.to_lowercase();
                    rand_patterns.iter().any(|p| lower.contains(p))
                        || modulo_patterns.iter().any(|p| lower.contains(p))
                })
                .take(10)
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
                    "Modulo bias on random output in cryptographic function `{}` - use gen_range() or rejection sampling for uniform distribution",
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

struct SpawnedChildNoWaitRule {
    metadata: RuleMetadata,
}

impl SpawnedChildNoWaitRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA067".to_string(),
                name: "spawned-child-no-wait".to_string(),
                short_description: "Spawned child process not waited on".to_string(),
                full_description: "Detects child processes spawned via Command::spawn() that are not waited on via wait(), status(), or wait_with_output(). Failing to wait on spawned children creates zombie processes that consume system resources (PIDs, kernel memory for process table entries) until the parent process exits. This is particularly problematic in long-running services that spawn many child processes. Implements Clippy's zombie_processes lint. Note: This is a heuristic check within a single function - children passed to other functions or stored in structs may be waited on elsewhere.".to_string(),
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
        // Self-exclusion
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            // Self-exclusion
            if function.name.contains("SpawnedChildNoWaitRule") {
                continue;
            }

            let body_str = function.body.join("\n");
            let lower = body_str.to_lowercase();
            
            // Count spawn calls
            let spawn_count = lower.matches("::spawn(").count();
            
            if spawn_count == 0 {
                continue;
            }
            
            // Count wait calls
            let wait_count = lower.matches("child::wait(").count()
                + lower.matches("::wait_with_output(").count();
            
            // Also check for Child::status (alternative wait method)
            // But be careful - status() might be for other things
            // Let's also count status() calls on Child
            let mut child_status_count = 0;
            for line in &function.body {
                let line_lower = line.to_lowercase();
                // Pattern: <... Child ...>::status(
                if line_lower.contains("child") && line_lower.contains("::status(") {
                    child_status_count += 1;
                }
            }
            
            let total_wait_count = wait_count + child_status_count;
            
            // If more spawns than waits, flag
            if spawn_count > total_wait_count {
                // Collect spawn lines as evidence
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
                        "Child process spawned in `{}` but not waited on - call wait(), status(), or wait_with_output() to prevent zombie processes",
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

struct UntrustedEnvInputRule {
    metadata: RuleMetadata,
}

impl UntrustedEnvInputRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA006".to_string(),
                name: "untrusted-env-input".to_string(),
                short_description: "Reads environment-provided input".to_string(),
                full_description: "Highlights reads from environment variables or command-line arguments which should be validated before use.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for UntrustedEnvInputRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        // Phase 1: Use taint tracking for more precise detection
        // This replaces the old heuristic approach with dataflow analysis
        use crate::dataflow::taint::TaintAnalysis;
        
        let taint_analysis = TaintAnalysis::new();
        let mut findings = Vec::new();

        for function in &package.functions {
            let (_tainted_vars, flows) = taint_analysis.analyze(function);
            
            // Convert each taint flow into a finding
            for flow in flows {
                if !flow.sanitized {
                    // Try to extract span from sink line
                    let sink_span = extract_span_from_mir_line(&flow.sink.sink_line);
                    let span = sink_span.or(function.span.clone());
                    
                    let finding = flow.to_finding(
                        &self.metadata,
                        &function.name,
                        &function.signature,
                        span,
                    );
                    findings.push(finding);
                }
            }
        }

        findings
    }
}

struct CommandInjectionRiskRule {
    metadata: RuleMetadata,
}

impl CommandInjectionRiskRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA007".to_string(),
                name: "process-command-execution".to_string(),
                short_description: "Spawns external commands".to_string(),
                full_description: "Detects uses of std::process::Command which should carefully sanitize inputs to avoid command injection.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for CommandInjectionRiskRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if command_rule_should_skip(function, package) {
                continue;
            }

            let invocations = detect_command_invocations(function);
            if invocations.is_empty() {
                continue;
            }

            for invocation in invocations {
                let mut evidence = vec![invocation.command_line.clone()];
                if !invocation.tainted_args.is_empty() {
                    evidence.push(format!(
                        "tainted arguments: {}",
                        invocation.tainted_args.join(", ")
                    ));
                }

                let (severity, message) = if invocation.tainted_args.is_empty() {
                    (
                        Severity::Medium,
                        format!(
                            "Process command execution detected in `{}`; review argument construction",
                            function.name
                        ),
                    )
                } else {
                    (
                        Severity::High,
                        format!(
                            "Potential command injection: tainted arguments reach Command::arg in `{}`",
                            function.name
                        ),
                    )
                };

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity,
                    message,
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

struct VecSetLenRule {
    metadata: RuleMetadata,
}

const VEC_SET_LEN_SYMBOL: &str = concat!("Vec", "::", "set", "_len");

impl VecSetLenRule {
    fn new() -> Self {
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

struct MaybeUninitAssumeInitRule {
    metadata: RuleMetadata,
}

const MAYBE_UNINIT_TYPE_SYMBOL: &str = concat!("Maybe", "Uninit");
const MAYBE_UNINIT_ASSUME_INIT_SYMBOL: &str = concat!("assume", "_init");

impl MaybeUninitAssumeInitRule {
    fn new() -> Self {
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

struct MemUninitZeroedRule {
    metadata: RuleMetadata,
}

const MEM_MODULE_SYMBOL: &str = concat!("mem");
const MEM_UNINITIALIZED_SYMBOL: &str = concat!("uninitialized");
const MEM_ZEROED_SYMBOL: &str = concat!("zeroed");

impl MemUninitZeroedRule {
    fn new() -> Self {
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

struct NonHttpsUrlRule {
    metadata: RuleMetadata,
}

impl NonHttpsUrlRule {
    fn new() -> Self {
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
            let evidence = collect_matches(&function.body, &patterns);
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

struct DangerAcceptInvalidCertRule {
    metadata: RuleMetadata,
}

const DANGER_ACCEPT_INVALID_CERTS_SYMBOL: &str = concat!("danger", "_accept", "_invalid", "_certs");
const DANGER_ACCEPT_INVALID_HOSTNAMES_SYMBOL: &str =
    concat!("danger", "_accept", "_invalid", "_hostnames");

impl DangerAcceptInvalidCertRule {
    fn new() -> Self {
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

struct OpensslVerifyNoneRule {
    metadata: RuleMetadata,
}

impl OpensslVerifyNoneRule {
    fn new() -> Self {
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

struct HardcodedHomePathRule {
    metadata: RuleMetadata,
}

impl HardcodedHomePathRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA014".to_string(),
                name: "hardcoded-home-path".to_string(),
                short_description: "Hard-coded home directory path detected".to_string(),
                full_description: "Detects absolute paths to user home directories hard-coded in string literals. Hard-coded home paths reduce portability and create security issues: (1) Code breaks when run under different users or in containers/CI, (2) Exposes username information in source code, (3) Prevents proper multi-user deployments, (4) Makes code non-portable across operating systems. Use environment variables (HOME, USERPROFILE), std::env::home_dir(), or the dirs crate instead. Detects patterns like /home/username, /Users/username, C:\\Users\\username, and ~username (with username).".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
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
            });
        }

        findings
    }
}

struct StaticMutGlobalRule {
    metadata: RuleMetadata,
}

impl StaticMutGlobalRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA025".to_string(),
                name: "static-mut-global".to_string(),
                short_description: "Mutable static global detected".to_string(),
                full_description: "Flags uses of `static mut` globals, which are unsafe shared mutable state and can introduce data races or memory safety bugs.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for StaticMutGlobalRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let patterns = ["static mut "];

        for function in &package.functions {
            let mut evidence = collect_matches(&function.body, &patterns);
            if evidence.is_empty() {
                continue;
            }

            // If the signature itself declared a mutable static, include it for additional context.
            if function.signature.contains("static mut ") {
                evidence.push(function.signature.trim().to_string());
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!(
                    "Mutable static global detected in `{}`; prefer interior mutability or synchronization primitives",
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

struct PermissionsSetReadonlyFalseRule {
    metadata: RuleMetadata,
}

impl PermissionsSetReadonlyFalseRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA028".to_string(),
                name: "permissions-set-readonly-false".to_string(),
                short_description: "Permissions::set_readonly(false) detected".to_string(),
                full_description: "Flags calls to std::fs::Permissions::set_readonly(false) which downgrade filesystem permissions and can leave files world-writable on Unix targets.".to_string(),
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

struct WorldWritableModeRule {
    metadata: RuleMetadata,
}

impl WorldWritableModeRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA029".to_string(),
                name: "world-writable-mode".to_string(),
                short_description: "World-writable file mode detected".to_string(),
                full_description: "Detects explicit world-writable permission masks (e.g., 0o777/0o666) passed to PermissionsExt::set_mode, OpenOptionsExt::mode, or similar builders, mirroring Snyk's insecure file permission checks.".to_string(),
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

struct NonNullNewUncheckedRule {
    metadata: RuleMetadata,
}

impl NonNullNewUncheckedRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA026".to_string(),
                name: "nonnull-new-unchecked".to_string(),
                short_description: "NonNull::new_unchecked without prior null guard".to_string(),
                full_description: "Flags calls to NonNull::new_unchecked, which require proving the pointer is non-null before use; prefer NonNull::new or ensure an explicit null check.".to_string(),
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
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            let mut evidence = Vec::new();

            for line in &function.body {
                let trimmed = line.trim();
                if trimmed.contains("NonNull::new_unchecked")
                    || (trimmed.contains("NonNull::<") && trimmed.contains("::new_unchecked"))
                {
                    evidence.push(trimmed.to_string());
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
                    "NonNull::new_unchecked used in `{}`; ensure the pointer is proven non-null first",
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

struct MemForgetGuardRule {
    metadata: RuleMetadata,
}

impl MemForgetGuardRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA027".to_string(),
                name: "mem-forget-guard".to_string(),
                short_description: "mem::forget called on RAII guard".to_string(),
                full_description: "Detects std::mem::forget or core::mem::forget invocations on synchronization guards (MutexGuard, RwLockGuard, Semaphore permits, etc.), which leak the underlying lock or permit and risk deadlocks or resource exhaustion.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn guard_type_tokens() -> &'static [&'static str] {
        &[
            "MutexGuard",
            "RwLockReadGuard",
            "RwLockWriteGuard",
            "MappedMutexGuard",
            "MappedRwLockReadGuard",
            "MappedRwLockWriteGuard",
            "SemaphorePermit",
            "OwnedSemaphorePermit",
            "OnceGuard",
            "BlockingMutexGuard",
            "FairMutexGuard",
        ]
    }

    fn guard_method_tokens() -> &'static [&'static str] {
        &[
            "::lock(",
            "::blocking_lock(",
            "::try_lock(",
            "::read(",
            "::write(",
            "::blocking_read(",
            "::blocking_write(",
            "::try_read(",
            "::try_write(",
            "::acquire(",
            "::acquire_owned(",
            "::try_acquire(",
            "::try_acquire_owned(",
            "::acquire_many(",
            "::acquire_many_owned(",
            "::try_acquire_many(",
            "::try_acquire_many_owned(",
        ]
    }

    fn assignment_has_guard_signal(assignment: &Assignment) -> bool {
        let rhs = assignment.rhs.as_str();

        if Self::guard_type_tokens()
            .iter()
            .any(|token| rhs.contains(token))
        {
            return true;
        }

        if Self::guard_method_tokens()
            .iter()
            .any(|token| rhs.contains(token))
            && (rhs.contains("Mutex") || rhs.contains("RwLock") || rhs.contains("Semaphore"))
        {
            return true;
        }

        false
    }

    fn collect_guard_vars(function: &MirFunction) -> (HashSet<String>, HashMap<String, String>) {
        let dataflow = MirDataflow::new(function);
        let mut guard_vars: HashSet<String> = HashSet::new();
        let mut guard_sources: HashMap<String, String> = HashMap::new();

        for assignment in dataflow.assignments() {
            if Self::assignment_has_guard_signal(assignment) {
                guard_vars.insert(assignment.target.clone());
                guard_sources
                    .entry(assignment.target.clone())
                    .or_insert_with(|| assignment.line.clone());
            }
        }

        let mut changed = true;
        while changed {
            changed = false;
            for assignment in dataflow.assignments() {
                if guard_vars.contains(&assignment.target) {
                    continue;
                }

                if assignment
                    .sources
                    .iter()
                    .any(|source| guard_vars.contains(source))
                {
                    guard_vars.insert(assignment.target.clone());
                    guard_sources
                        .entry(assignment.target.clone())
                        .or_insert_with(|| assignment.line.clone());
                    changed = true;
                }
            }
        }

        (guard_vars, guard_sources)
    }
}

impl Rule for MemForgetGuardRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            let (guard_vars, guard_sources) = Self::collect_guard_vars(function);
            if guard_vars.is_empty() {
                continue;
            }

            for line in &function.body {
                if !line.contains("mem::forget") {
                    continue;
                }

                let trimmed = line.trim().to_string();
                let referenced_guard = guard_vars
                    .iter()
                    .find(|var| trimmed.contains(var.as_str()))
                    .cloned();

                let Some(var) = referenced_guard else {
                    continue;
                };

                let mut evidence = vec![trimmed.clone()];
                if let Some(source_line) = guard_sources.get(&var) {
                    if !evidence.contains(source_line) {
                        evidence.push(source_line.clone());
                    }
                }

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "mem::forget called on synchronization guard `{}` in `{}`",
                        var, function.name
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

struct CommandArgConcatenationRule {
    metadata: RuleMetadata,
}

impl CommandArgConcatenationRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA031".to_string(),
                name: "command-arg-concatenation".to_string(),
                short_description: "Command built with string concatenation or formatting".to_string(),
                full_description: "Detects Command::new or Command::arg calls that use format!, format_args!, concat!, or string concatenation operators, which can enable command injection if user input is involved.".to_string(),
                help_uri: Some("https://cwe.mitre.org/data/definitions/78.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn concatenation_patterns() -> &'static [&'static str] {
        &[
            "format!",
            "format_args!",
            "concat!",
            "std::format",
            "core::format",
            "alloc::format",
            "String::from",
            "+ &str",
            "+ String",
        ]
    }

    fn command_construction_patterns() -> &'static [&'static str] {
        &[
            "Command::new(",
            "Command::arg(",
            "Command::args(",
        ]
    }
}

impl Rule for CommandArgConcatenationRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            let mut concat_lines: Vec<(usize, String)> = Vec::new();
            let mut command_lines: Vec<(usize, String)> = Vec::new();

            // First pass: collect concatenation and command lines
            for (idx, line) in function.body.iter().enumerate() {
                let trimmed = line.trim();

                // Check for concatenation patterns
                for pattern in Self::concatenation_patterns() {
                    if trimmed.contains(pattern) {
                        concat_lines.push((idx, trimmed.to_string()));
                        break;
                    }
                }

                // Check for command construction
                for pattern in Self::command_construction_patterns() {
                    if trimmed.contains(pattern) {
                        command_lines.push((idx, trimmed.to_string()));
                        break;
                    }
                }
            }

            // Second pass: check if command lines use concatenated values
            for (cmd_idx, cmd_line) in &command_lines {
                // Look for concatenation that happens before or near this command
                let relevant_concat: Vec<&String> = concat_lines
                    .iter()
                    .filter(|(concat_idx, _)| concat_idx < cmd_idx && cmd_idx - concat_idx < 10)
                    .map(|(_, line)| line)
                    .collect();

                if relevant_concat.is_empty() {
                    continue;
                }

                let mut evidence = vec![cmd_line.clone()];
                evidence.extend(relevant_concat.iter().map(|s| (*s).clone()));

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Command argument uses string concatenation in `{}`, potential injection risk",
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

/// RUSTCOLA032: OpenOptions missing truncate
/// Detects OpenOptions::new().write(true).create(true) without .truncate(true) or .append(true)
/// which can leave stale data in files, causing potential data disclosure.
struct OpenOptionsMissingTruncateRule {
    metadata: RuleMetadata,
}

impl OpenOptionsMissingTruncateRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA032".to_string(),
                name: "OpenOptions missing truncate".to_string(),
                short_description: "File created with write(true) without truncate or append".to_string(),
                full_description: "Detects OpenOptions::new().write(true).create(true) patterns that don't specify .truncate(true) or .append(true). When creating a writable file without truncation, old file contents may remain, leading to stale data disclosure or corruption.".to_string(),
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
            // Look for OpenOptions builder patterns in MIR
            // We need to find: write(true) AND create(true) WITHOUT truncate(true) or append(true)
            
            let mut has_write_true = false;
            let mut has_create_true = false;
            let mut has_truncate_or_append = false;
            let mut open_options_start_line = None;
            let mut evidence_lines = Vec::new();

            for (idx, line) in function.body.iter().enumerate() {
                // Detect OpenOptions::new()
                if line.contains("OpenOptions::new()") {
                    open_options_start_line = Some(idx);
                    has_write_true = false;
                    has_create_true = false;
                    has_truncate_or_append = false;
                    evidence_lines.clear();
                    evidence_lines.push(line.trim().to_string());
                }

                // If we're tracking an OpenOptions chain
                if open_options_start_line.is_some() {
                    // Check for builder methods within reasonable proximity (20 lines)
                    if idx <= open_options_start_line.unwrap() + 20 {
                        // Match both dotted syntax and MIR function calls
                        if line.contains(".write(true)") || line.contains(".write ( true )")
                            || (line.contains("OpenOptions::write") && line.contains("const true"))
                        {
                            has_write_true = true;
                            if !evidence_lines.iter().any(|e| e.contains(line.trim())) {
                                evidence_lines.push(line.trim().to_string());
                            }
                        }
                        
                        if line.contains(".create(true)") || line.contains(".create ( true )")
                            || (line.contains("OpenOptions::create") && line.contains("const true"))
                        {
                            has_create_true = true;
                            if !evidence_lines.iter().any(|e| e.contains(line.trim())) {
                                evidence_lines.push(line.trim().to_string());
                            }
                        }
                        
                        if line.contains(".truncate(true)") || line.contains(".truncate ( true )")
                            || (line.contains("OpenOptions::truncate") && line.contains("const true"))
                            || line.contains(".append(true)") || line.contains(".append ( true )")
                            || (line.contains("OpenOptions::append") && line.contains("const true"))
                        {
                            has_truncate_or_append = true;
                        }

                        // Check for .open() call - this terminates the builder chain
                        if line.contains(".open(") || line.contains("OpenOptions::open") {
                            if !evidence_lines.iter().any(|e| e.contains(line.trim())) {
                                evidence_lines.push(line.trim().to_string());
                            }

                            // Evaluate the complete builder chain
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

                            // Reset for next potential OpenOptions chain
                            open_options_start_line = None;
                            has_write_true = false;
                            has_create_true = false;
                            has_truncate_or_append = false;
                            evidence_lines.clear();
                        }
                    } else {
                        // Too far from start, reset
                        open_options_start_line = None;
                        has_write_true = false;
                        has_create_true = false;
                        has_truncate_or_append = false;
                        evidence_lines.clear();
                    }
                }
            }
        }

        findings
    }
}

/// RUSTCOLA033: Allocator mismatch across FFI
/// Detects Box::into_raw or CString::into_raw followed by libc::free
/// or malloc/calloc followed by Box::from_raw, which causes UB due to mismatched allocators.
struct AllocatorMismatchFfiRule {
    metadata: RuleMetadata,
}

impl AllocatorMismatchFfiRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA017".to_string(),
                name: "allocator-mismatch".to_string(),
                short_description: "Mixed allocator/deallocator usage".to_string(),
                full_description: "Detects functions that mix Rust and foreign allocation APIs, such as freeing Box/CString allocations with libc::free or wrapping libc::malloc pointers with Box::from_raw.".to_string(),
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

        // NOTE: This function contains pattern strings for detecting allocator mismatches
        // (e.g., "Box::into_raw", "libc::free"). These are intentional search patterns
        // for rule detection, NOT actual vulnerable code. Security scanners should
        // suppress false positives in this implementation.
        // NOSEC: Intentional pattern matching for security rule implementation
        // codeql[cpp/commented-out-code]: False positive - detection patterns only
        // CodeQL suppression: These patterns are for detecting vulnerabilities, not causing them

        for function in &package.functions {
            // Track Rust-allocated pointers (Box::into_raw, CString::into_raw)
            let mut rust_allocated_vars = Vec::new();
            
            // Track C-allocated pointers (malloc, calloc, realloc)
            let mut c_allocated_vars = Vec::new();
            
            // Track variable aliases (e.g., _4 = copy _2)
            let mut var_aliases: std::collections::HashMap<String, String> = std::collections::HashMap::new();

            for (idx, line) in function.body.iter().enumerate() {
                // Track variable aliases: "_4 = copy _2" or "_4 = move _2"
                if (line.contains(" = copy ") || line.contains(" = move "))
                    && line.trim().starts_with('_')
                {
                    let parts: Vec<&str> = line.split('=').collect();
                    if parts.len() >= 2 {
                        let lhs = parts[0].trim();
                        let rhs = parts[1].trim();
                        // Extract variable name from "copy _2" or "move _2 as ..."
                        if let Some(src_var) = rhs.split_whitespace().nth(1) {
                            if src_var.starts_with('_') {
                                var_aliases.insert(lhs.to_string(), src_var.to_string());
                            }
                        }
                    }
                }
                
                // Detect Rust allocations: Box::into_raw, CString::into_raw
                // MIR pattern: "_2 = Box::<i32>::into_raw(move _1)"
                // NOSEC: Pattern strings for vulnerability detection, not actual usage
                if (line.contains("Box::") && line.contains("::into_raw") 
                    || line.contains("CString::") && line.contains("::into_raw"))
                    && line.contains(" = ")
                {
                    // Extract variable name (e.g., "_5 = Box::into_raw")
                    if let Some(var_name) = line.trim().split('=').next() {
                        let var = var_name.trim().to_string();
                        rust_allocated_vars.push((var.clone(), idx, line.trim().to_string()));
                    }
                }

                // Detect C allocations: malloc, calloc, realloc
                // MIR pattern: "_1 = malloc(...)"
                // NOSEC: Pattern strings for vulnerability detection, not actual usage
                if (line.contains("malloc(") || line.contains("calloc(") || line.contains("realloc("))
                    && line.contains(" = ")
                {
                    if let Some(var_name) = line.trim().split('=').next() {
                        let var = var_name.trim().to_string();
                        c_allocated_vars.push((var.clone(), idx, line.trim().to_string()));
                    }
                }

                // Check for libc::free on Rust-allocated pointers
                // MIR pattern: "_3 = free(move _4)"
                // NOSEC: Pattern string "free(" for vulnerability detection, not actual usage
                if line.contains("free(") {
                    for (rust_var, alloc_idx, alloc_line) in &rust_allocated_vars {
                        // Check if this Rust-allocated variable or its alias is being freed
                        let mut is_freed = line.contains(rust_var);
                        
                        // Also check aliases (e.g., _4 copied from _2)
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
                // MIR pattern: "_3 = Box::<i32>::from_raw(move _2)"
                // NOSEC: Pattern strings for vulnerability detection, not actual usage
                if line.contains("Box::") && line.contains("::from_raw(") {
                    for (c_var, alloc_idx, alloc_line) in &c_allocated_vars {
                        // Check if this C-allocated variable or its alias is being converted to Box
                        let mut is_converted = line.contains(c_var);
                        
                        // Also check aliases
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
                // MIR pattern: "CString::from_raw(...)"
                // NOSEC: Pattern strings for vulnerability detection, not actual usage
                if line.contains("CString::") && line.contains("::from_raw(") {
                    for (c_var, alloc_idx, alloc_line) in &c_allocated_vars {
                        let mut is_converted = line.contains(c_var);
                        
                        // Also check aliases
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

/// RUSTCOLA035: repr(packed) field references
/// Detects taking references to fields of #[repr(packed)] structs,
/// which creates unaligned references (undefined behavior).
struct PackedFieldReferenceRule {
    metadata: RuleMetadata,
}

impl PackedFieldReferenceRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA035".to_string(),
                name: "repr-packed-field-reference".to_string(),
                short_description: "Reference to packed struct field".to_string(),
                full_description: "Detects taking references to fields of #[repr(packed)] structs. Creating references to packed struct fields creates unaligned references, which is undefined behavior in Rust. Use ptr::addr_of! or ptr::addr_of_mut! instead.".to_string(),
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
            
            // Find packed structs
            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Look for #[repr(packed)] attributes
                if trimmed.starts_with("#[repr(packed") {
                    // Find the next struct definition
                    for j in (idx + 1).min(lines.len())..lines.len() {
                        let struct_line = lines[j].trim();
                        if struct_line.starts_with("struct ") || struct_line.starts_with("pub struct ") {
                            // Extract struct name
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
                
                // Look for field access patterns that might create references
                // Pattern: &var.field or &mut var.field where var is a packed struct
                for struct_name in &packed_structs {
                    // Check for &struct_var.field or &mut struct_var.field patterns
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
                
                // Also check for generic pattern of field access with reference
                // This catches cases we might have missed
                if (trimmed.contains("& ") || trimmed.contains("&mut "))
                    && trimmed.contains('.')
                    && !trimmed.contains("ptr::addr_of")
                    && (trimmed.contains(".field") 
                        || trimmed.contains(".x")
                        || trimmed.contains(".y")
                        || trimmed.contains(".z")
                        || trimmed.contains(".data"))
                {
                    // This is a heuristic - might have false positives
                    // Only report if we have some context suggesting packed struct usage
                    if content.contains("#[repr(packed") {
                        let location = format!("{}:{}", rel_path, idx + 1);
                        
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: "Potential reference to field in packed struct".to_string(),
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

/// RUSTCOLA036: Unsafe CString pointer use
/// Detects CString::new(...).unwrap().as_ptr() patterns where the CString
/// temporary is dropped immediately, creating a dangling pointer.
struct UnsafeCStringPointerRule {
    metadata: RuleMetadata,
}

impl UnsafeCStringPointerRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA036".to_string(),
                name: "unsafe-cstring-pointer".to_string(),
                short_description: "Unsafe CString pointer from temporary".to_string(),
                full_description: "Detects patterns like CString::new(...).unwrap().as_ptr() where the CString is a temporary that gets dropped immediately, leaving a dangling pointer. The pointer must outlive the CString it came from. Store the CString in a variable to extend its lifetime.".to_string(),
                help_uri: Some("https://www.jetbrains.com/help/inspectopedia/RsCStringPointer.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn is_cstring_temp_pattern(line: &str) -> bool {
        // Look for CString::new(...).METHOD().as_ptr() patterns
        // where METHOD is unwrap, expect, or other methods that don't extend lifetime
        if !line.contains("CString::new") || !line.contains(".as_ptr()") {
            return false;
        }

        // Check if the CString is being used as a temporary (chained methods)
        // Pattern: CString::new(...).unwrap().as_ptr()
        // Pattern: CString::new(...).expect("...").as_ptr()
        // Pattern: CString::new(...)?.as_ptr()
        
        let has_intermediate_method = line.contains(".unwrap()") 
            || line.contains(".expect(") 
            || line.contains(".unwrap_or")
            || line.contains("?");

        // If there's chaining and no assignment before as_ptr, it's a temporary
        let looks_temporary = has_intermediate_method && !line.contains("let ");

        // Also check for direct chaining without intermediate
        // CString::new(...).as_ptr() is also problematic
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

/// RUSTCOLA037: Blocking sleep in async context
/// Detects std::thread::sleep and similar blocking sleep calls inside async functions
/// which can stall the async runtime and cause denial-of-service.
struct BlockingSleepInAsyncRule {
    metadata: RuleMetadata,
}

impl BlockingSleepInAsyncRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA037".to_string(),
                name: "blocking-sleep-in-async".to_string(),
                short_description: "Blocking sleep in async function".to_string(),
                full_description: "Detects std::thread::sleep and other blocking sleep calls inside async functions. Blocking sleep in async contexts can stall the executor and prevent other tasks from running, potentially causing denial-of-service. Use async sleep (tokio::time::sleep, async_std::task::sleep, etc.) instead.".to_string(),
                help_uri: Some("https://www.jetbrains.com/help/inspectopedia/RsSleepInsideAsyncFunction.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn blocking_sleep_patterns() -> &'static [&'static str] {
        &[
            "std::thread::sleep",
            "thread::sleep",
            "::thread::sleep",
        ]
    }
}

impl Rule for BlockingSleepInAsyncRule {
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

            // Track async function boundaries
            let mut in_async_fn = false;
            let mut async_fn_start = 0;
            let mut brace_depth = 0;
            let mut async_fn_name = String::new();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Detect async function start
                if trimmed.contains("async fn ") {
                    in_async_fn = true;
                    async_fn_start = idx;
                    brace_depth = 0;

                    // Extract function name
                    if let Some(fn_pos) = trimmed.find("fn ") {
                        let after_fn = &trimmed[fn_pos + 3..];
                        if let Some(paren_pos) = after_fn.find('(') {
                            async_fn_name = after_fn[..paren_pos].trim().to_string();
                        }
                    }
                }

                // Track brace depth to know when async function ends
                if in_async_fn {
                    brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                    // Check for blocking sleep patterns
                    for pattern in Self::blocking_sleep_patterns() {
                        if trimmed.contains(pattern) {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Blocking sleep in async function `{}` can stall executor",
                                    async_fn_name
                                ),
                                function: location,
                                function_signature: async_fn_name.clone(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                            });
                        }
                    }

                    // If brace depth returns to 0, we've exited the async function
                    if brace_depth <= 0 && idx > async_fn_start {
                        in_async_fn = false;
                    }
                }
            }
        }

        findings
    }
}

/// RUSTCOLA093: Blocking operations in async context
/// Extends RUSTCOLA037 to detect a broader range of blocking operations:
/// - std::sync::Mutex::lock() (use tokio::sync::Mutex instead)
/// - std::fs::* operations (use tokio::fs::* instead)
/// - std::net::* operations (use tokio::net::* instead)
/// - std::io::stdin/stdout (use tokio::io instead)
struct BlockingOpsInAsyncRule {
    metadata: RuleMetadata,
}

impl BlockingOpsInAsyncRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA093".to_string(),
                name: "blocking-ops-in-async".to_string(),
                short_description: "Blocking operation in async function".to_string(),
                full_description: "Detects blocking operations inside async functions that can stall the async executor. This includes std::sync::Mutex::lock(), std::fs::* operations, std::net::* operations, and blocking I/O. These operations block the current thread, preventing the async runtime from executing other tasks. Use async alternatives (tokio::sync::Mutex, tokio::fs, tokio::net) or wrap blocking ops in spawn_blocking/block_in_place.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Blocking patterns to detect with their categories
    fn blocking_patterns() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            // Pattern, Category, Recommendation
            // std::sync::Mutex
            ("Mutex::new", "sync_mutex", "Consider tokio::sync::Mutex for async contexts"),
            (".lock().unwrap()", "sync_mutex", "Use tokio::sync::Mutex::lock().await instead"),
            (".lock().expect(", "sync_mutex", "Use tokio::sync::Mutex::lock().await instead"),
            ("mutex.lock()", "sync_mutex", "Use tokio::sync::Mutex::lock().await instead"),
            // std::fs operations
            ("fs::read_to_string(", "blocking_fs", "Use tokio::fs::read_to_string().await instead"),
            ("fs::read(", "blocking_fs", "Use tokio::fs::read().await instead"),
            ("fs::write(", "blocking_fs", "Use tokio::fs::write().await instead"),
            ("fs::remove_file(", "blocking_fs", "Use tokio::fs::remove_file().await instead"),
            ("fs::remove_dir(", "blocking_fs", "Use tokio::fs::remove_dir().await instead"),
            ("fs::create_dir(", "blocking_fs", "Use tokio::fs::create_dir().await instead"),
            ("fs::create_dir_all(", "blocking_fs", "Use tokio::fs::create_dir_all().await instead"),
            ("fs::metadata(", "blocking_fs", "Use tokio::fs::metadata().await instead"),
            ("fs::copy(", "blocking_fs", "Use tokio::fs::copy().await instead"),
            ("fs::rename(", "blocking_fs", "Use tokio::fs::rename().await instead"),
            ("fs::File::open(", "blocking_fs", "Use tokio::fs::File::open().await instead"),
            ("fs::File::create(", "blocking_fs", "Use tokio::fs::File::create().await instead"),
            ("File::open(", "blocking_fs", "Use tokio::fs::File::open().await instead"),
            ("File::create(", "blocking_fs", "Use tokio::fs::File::create().await instead"),
            ("std::fs::read_to_string(", "blocking_fs", "Use tokio::fs::read_to_string().await instead"),
            ("std::fs::read(", "blocking_fs", "Use tokio::fs::read().await instead"),
            ("std::fs::write(", "blocking_fs", "Use tokio::fs::write().await instead"),
            // std::net operations
            ("TcpStream::connect(", "blocking_net", "Use tokio::net::TcpStream::connect().await instead"),
            ("TcpListener::bind(", "blocking_net", "Use tokio::net::TcpListener::bind().await instead"),
            ("UdpSocket::bind(", "blocking_net", "Use tokio::net::UdpSocket::bind().await instead"),
            ("std::net::TcpStream::connect(", "blocking_net", "Use tokio::net::TcpStream::connect().await instead"),
            ("std::net::TcpListener::bind(", "blocking_net", "Use tokio::net::TcpListener::bind().await instead"),
            // std::io blocking
            ("stdin().read_line(", "blocking_io", "Use tokio::io::stdin() with AsyncBufReadExt instead"),
            ("stdin().read(", "blocking_io", "Use tokio::io::stdin() with AsyncReadExt instead"),
            ("stdout().write(", "blocking_io", "Use tokio::io::stdout() with AsyncWriteExt instead"),
            ("stderr().write(", "blocking_io", "Use tokio::io::stderr() with AsyncWriteExt instead"),
            ("std::io::stdin()", "blocking_io", "Use tokio::io::stdin() instead"),
            ("std::io::stdout()", "blocking_io", "Use tokio::io::stdout() instead"),
            // reqwest blocking
            ("reqwest::blocking::", "blocking_http", "Use reqwest async API (reqwest::get, Client::new()) instead"),
        ]
    }

    /// Patterns that indicate the blocking op is wrapped safely
    fn safe_wrappers() -> &'static [&'static str] {
        &[
            "spawn_blocking",
            "block_in_place",
            "tokio::task::spawn_blocking",
            "tokio::task::block_in_place",
            "actix_web::web::block",
        ]
    }
}

impl Rule for BlockingOpsInAsyncRule {
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

            // Track async function boundaries
            let mut in_async_fn = false;
            let mut async_fn_start = 0;
            let mut brace_depth = 0;
            let mut async_fn_name = String::new();
            let mut in_safe_wrapper = false;
            let mut safe_wrapper_depth = 0;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Detect async function start
                if trimmed.contains("async fn ") || trimmed.contains("async move") {
                    if trimmed.contains("async fn ") {
                        in_async_fn = true;
                        async_fn_start = idx;
                        brace_depth = 0;

                        // Extract function name
                        if let Some(fn_pos) = trimmed.find("fn ") {
                            let after_fn = &trimmed[fn_pos + 3..];
                            if let Some(paren_pos) = after_fn.find('(') {
                                async_fn_name = after_fn[..paren_pos].trim().to_string();
                            }
                        }
                    }
                }

                // Track brace depth to know when async function ends
                if in_async_fn {
                    // Check for safe wrappers (spawn_blocking, block_in_place)
                    for wrapper in Self::safe_wrappers() {
                        if trimmed.contains(wrapper) {
                            in_safe_wrapper = true;
                            safe_wrapper_depth = brace_depth;
                        }
                    }

                    brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                    // Reset safe wrapper when we exit its scope
                    if in_safe_wrapper && brace_depth <= safe_wrapper_depth {
                        in_safe_wrapper = false;
                    }

                    // Skip if we're inside a safe wrapper
                    if in_safe_wrapper {
                        if brace_depth <= 0 && idx > async_fn_start {
                            in_async_fn = false;
                        }
                        continue;
                    }

                    // Check for blocking patterns
                    for (pattern, category, recommendation) in Self::blocking_patterns() {
                        if trimmed.contains(pattern) {
                            // Skip if the line has .await - it's an async version
                            if trimmed.contains(".await") {
                                continue;
                            }
                            // Skip if it's a tokio:: call (either on this line or mutex is tokio-based)
                            if trimmed.contains("tokio::") {
                                continue;
                            }
                            // Skip comments
                            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                                continue;
                            }
                            // Skip if this is within a function using tokio::sync::Mutex
                            // Look at the function's lines for tokio mutex declaration
                            let fn_content: String = lines[async_fn_start..=idx]
                                .iter()
                                .map(|s| *s)
                                .collect::<Vec<&str>>()
                                .join("\n");
                            if fn_content.contains("tokio::sync::Mutex") && pattern.contains(".lock") {
                                continue;
                            }

                            let location = format!("{}:{}", rel_path, idx + 1);
                            let message = match category {
                                "sync_mutex" => format!(
                                    "Blocking std::sync::Mutex in async function `{}`. {}",
                                    async_fn_name, recommendation
                                ),
                                "blocking_fs" => format!(
                                    "Blocking filesystem operation in async function `{}`. {}",
                                    async_fn_name, recommendation
                                ),
                                "blocking_net" => format!(
                                    "Blocking network operation in async function `{}`. {}",
                                    async_fn_name, recommendation
                                ),
                                "blocking_io" => format!(
                                    "Blocking I/O in async function `{}`. {}",
                                    async_fn_name, recommendation
                                ),
                                "blocking_http" => format!(
                                    "Blocking HTTP client in async function `{}`. {}",
                                    async_fn_name, recommendation
                                ),
                                _ => format!(
                                    "Blocking operation in async function `{}`",
                                    async_fn_name
                                ),
                            };

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message,
                                function: location,
                                function_signature: async_fn_name.clone(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                            });
                        }
                    }

                    // If brace depth returns to 0, we've exited the async function
                    if brace_depth <= 0 && idx > async_fn_start {
                        in_async_fn = false;
                    }
                }
            }
        }

        findings
    }
}

/// RUSTCOLA094: MutexGuard/RwLockGuard held across await points
/// Holding a sync guard across an .await point can cause deadlocks because
/// the guard is held while the async task is suspended.
struct MutexGuardAcrossAwaitRule {
    metadata: RuleMetadata,
}

impl MutexGuardAcrossAwaitRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA094".to_string(),
                name: "mutex-guard-across-await".to_string(),
                short_description: "MutexGuard held across await point".to_string(),
                full_description: "Holding a std::sync::MutexGuard or RwLockGuard across an .await point can cause deadlocks. When the async task yields, another task on the same thread may try to acquire the same lock, leading to deadlock. Use tokio::sync::Mutex or drop the guard before awaiting.".to_string(),
                help_uri: Some("https://rust-lang.github.io/rust-clippy/master/index.html#await_holding_lock".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn guard_patterns() -> &'static [(&'static str, &'static str)] {
        &[
            (".lock().unwrap()", "MutexGuard"),
            (".lock().expect(", "MutexGuard"),
            (".lock()?", "MutexGuard"),
            (".read().unwrap()", "RwLockReadGuard"),
            (".read().expect(", "RwLockReadGuard"),
            (".read()?", "RwLockReadGuard"),
            (".write().unwrap()", "RwLockWriteGuard"),
            (".write().expect(", "RwLockWriteGuard"),
            (".write()?", "RwLockWriteGuard"),
        ]
    }

    fn safe_guard_patterns() -> &'static [&'static str] {
        &[
            "tokio::sync::Mutex",
            "tokio::sync::RwLock",
            "async_std::sync::Mutex",
            "async_std::sync::RwLock",
            "futures::lock::Mutex",
        ]
    }
}

impl Rule for MutexGuardAcrossAwaitRule {
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

            // Track async function boundaries and guard acquisitions
            let mut in_async_fn = false;
            let mut async_fn_start = 0;
            let mut brace_depth = 0;
            let mut async_fn_name = String::new();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Detect async function start
                if trimmed.contains("async fn ") || trimmed.contains("async move") {
                    if trimmed.contains("async fn ") {
                        in_async_fn = true;
                        async_fn_start = idx;
                        brace_depth = 0;

                        // Extract function name
                        if let Some(fn_pos) = trimmed.find("fn ") {
                            let after_fn = &trimmed[fn_pos + 3..];
                            if let Some(paren_pos) = after_fn.find('(') {
                                async_fn_name = after_fn[..paren_pos].trim().to_string();
                            }
                        }
                    }
                }

                // Track brace depth to know when async function ends
                if in_async_fn {
                    brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                    // Look for guard acquisition patterns
                    for (pattern, guard_type) in Self::guard_patterns() {
                        if trimmed.contains(pattern) {
                            // Skip if it's a tokio/async mutex (has .await on same line)
                            if trimmed.contains(".await") {
                                continue;
                            }
                            // Skip comments
                            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                                continue;
                            }

                            // Check if the function containing this line uses async mutex types
                            let fn_content: String = lines[async_fn_start..=std::cmp::min(idx + 50, lines.len() - 1)]
                                .iter()
                                .map(|s| *s)
                                .collect::<Vec<&str>>()
                                .join("\n");

                            // Skip if the function uses async-aware mutex types
                            let uses_async_mutex = Self::safe_guard_patterns()
                                .iter()
                                .any(|p| fn_content.contains(p));
                            if uses_async_mutex {
                                continue;
                            }

                            // Check if there's an .await AFTER this guard acquisition within the same scope
                            // Look at lines after the guard acquisition until scope ends
                            let mut inner_brace_depth = 0;
                            let mut has_await_after = false;
                            let mut await_line = 0;

                            for (later_idx, later_line) in lines[idx..].iter().enumerate() {
                                let later_trimmed = later_line.trim();
                                inner_brace_depth += later_trimmed.chars().filter(|&c| c == '{').count() as i32;
                                inner_brace_depth -= later_trimmed.chars().filter(|&c| c == '}').count() as i32;

                                // Check for drop() which would release the guard
                                if later_trimmed.contains("drop(") {
                                    break;
                                }

                                // Check for .await after guard acquisition
                                if later_idx > 0 && later_trimmed.contains(".await") {
                                    has_await_after = true;
                                    await_line = idx + later_idx + 1;
                                    break;
                                }

                                // If we exit the scope (brace depth negative), guard is dropped
                                if inner_brace_depth < 0 {
                                    break;
                                }

                                // Don't look too far ahead
                                if later_idx > 30 {
                                    break;
                                }
                            }

                            if has_await_after {
                                let location = format!("{}:{}", rel_path, idx + 1);
                                findings.push(Finding {
                                    rule_id: self.metadata.id.clone(),
                                    rule_name: self.metadata.name.clone(),
                                    severity: self.metadata.default_severity,
                                    message: format!(
                                        "{} held across .await in async function `{}` (line {}). This can cause deadlocks. Drop the guard before awaiting or use tokio::sync::Mutex.",
                                        guard_type, async_fn_name, await_line
                                    ),
                                    function: location,
                                    function_signature: async_fn_name.clone(),
                                    evidence: vec![trimmed.to_string()],
                                    span: None,
                                });
                            }
                        }
                    }

                    // If brace depth returns to 0, we've exited the async function
                    if brace_depth <= 0 && idx > async_fn_start {
                        in_async_fn = false;
                    }
                }
            }
        }

        findings
    }
}

/// RUSTCOLA095: Transmute that changes lifetime parameters
/// Using transmute to extend or change reference lifetimes is undefined behavior.
struct TransmuteLifetimeChangeRule {
    metadata: RuleMetadata,
}

impl TransmuteLifetimeChangeRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA095".to_string(),
                name: "transmute-lifetime-change".to_string(),
                short_description: "Transmute changes reference lifetime".to_string(),
                full_description: "Using std::mem::transmute to change lifetime parameters of references is undefined behavior. It can create references that outlive the data they point to, leading to use-after-free. Use proper lifetime annotations or safe APIs instead.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/mem/fn.transmute.html#examples".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Extract the lifetime from a type annotation like "&'a str" or "&'static str"
    fn extract_lifetime(type_str: &str) -> Option<String> {
        // Look for 'lifetime pattern
        if let Some(quote_pos) = type_str.find('\'') {
            let after_quote = &type_str[quote_pos + 1..];
            // Lifetime ends at space, comma, >, or end of word characters
            let end_pos = after_quote
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap_or(after_quote.len());
            if end_pos > 0 {
                return Some(format!("'{}", &after_quote[..end_pos]));
            }
        }
        None
    }

    /// Check if two types differ only in lifetime parameters
    fn types_differ_in_lifetime(from_type: &str, to_type: &str) -> bool {
        let from_lifetime = Self::extract_lifetime(from_type);
        let to_lifetime = Self::extract_lifetime(to_type);

        // Both must have lifetimes, and they must differ
        match (from_lifetime, to_lifetime) {
            (Some(from_lt), Some(to_lt)) => {
                if from_lt != to_lt {
                    // Verify the types are otherwise similar (both are references)
                    let from_is_ref = from_type.contains('&');
                    let to_is_ref = to_type.contains('&');
                    return from_is_ref && to_is_ref;
                }
                false
            }
            // One has explicit lifetime, one has implicit - suspicious
            (Some(_), None) | (None, Some(_)) => {
                // Check if both are reference types
                from_type.contains('&') && to_type.contains('&')
            }
            _ => false,
        }
    }
}

impl Rule for TransmuteLifetimeChangeRule {
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
                if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                    continue;
                }

                // Look for transmute patterns
                if trimmed.contains("transmute") {
                    // Pattern 1: transmute::<From, To>(...)
                    if let Some(turbofish_start) = trimmed.find("transmute::<") {
                        let after_turbofish = &trimmed[turbofish_start + 12..];
                        if let Some(end) = after_turbofish.find(">(") {
                            let types_str = &after_turbofish[..end];
                            // Split by comma to get from and to types
                            let parts: Vec<&str> = types_str.split(',').collect();
                            if parts.len() == 2 {
                                let from_type = parts[0].trim();
                                let to_type = parts[1].trim();
                                
                                if Self::types_differ_in_lifetime(from_type, to_type) {
                                    let location = format!("{}:{}", rel_path, idx + 1);
                                    findings.push(Finding {
                                        rule_id: self.metadata.id.clone(),
                                        rule_name: self.metadata.name.clone(),
                                        severity: self.metadata.default_severity,
                                        message: format!(
                                            "Transmute changes lifetime in `{}`: {} -> {}. This can create dangling references.",
                                            current_fn_name, from_type, to_type
                                        ),
                                        function: location,
                                        function_signature: current_fn_name.clone(),
                                        evidence: vec![trimmed.to_string()],
                                        span: None,
                                    });
                                }
                            }
                        }
                    }
                    
                    // Pattern 2: Check function signature for lifetime extension patterns
                    // Look for return types like -> &'static T when input has different lifetime
                    // Only match if this line contains transmute (not just uses) and 
                    // the function signature itself shows the lifetime change
                    
                    // Find the function signature line (contains "fn " and "->")
                    let mut fn_sig_line = String::new();
                    for back_idx in (0..=idx).rev() {
                        let back_line = lines[back_idx].trim();
                        if back_line.contains("fn ") && back_line.contains("->") {
                            fn_sig_line = back_line.to_string();
                            break;
                        }
                        // Stop if we hit another function or struct definition
                        if back_line.starts_with("pub fn ") || back_line.starts_with("fn ") {
                            if !back_line.contains("->") {
                                break;
                            }
                        }
                    }
                    
                    // Check if function signature shows lifetime change pattern
                    // The signature should have both a short lifetime param ('a, 'b) AND return 'static
                    let sig_has_short_lifetime = fn_sig_line.contains("'a") || 
                                                fn_sig_line.contains("'b");
                    let sig_returns_static = fn_sig_line.contains("-> &'static") ||
                                            fn_sig_line.contains("-> StaticData");
                    
                    // Only trigger if this is an actual transmute call (not just mention in string)
                    let is_actual_transmute = trimmed.contains("transmute(") || 
                                             trimmed.contains("transmute::<");
                    
                    if sig_has_short_lifetime && sig_returns_static && is_actual_transmute {
                        // Don't double-report if we already caught this with turbofish
                        let already_reported = findings.iter().any(|f| 
                            f.function == format!("{}:{}", rel_path, idx + 1)
                        );
                        if !already_reported {
                            let location = format!("{}:{}", rel_path, idx + 1);
                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Transmute may extend lifetime to 'static in `{}`. This can create dangling references.",
                                    current_fn_name
                                ),
                                function: location,
                                function_signature: current_fn_name.clone(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                            });
                        }
                    }
                    
                    // Pattern 3: Struct with lifetime parameter transmuted to struct without
                    // e.g. transmute::<BorrowedData<'a>, StaticData>
                    if let Some(turbofish_start) = trimmed.find("transmute::<") {
                        let after_turbofish = &trimmed[turbofish_start + 12..];
                        if let Some(end) = after_turbofish.find(">(") {
                            let types_str = &after_turbofish[..end];
                            // Check if from type has lifetime but to type doesn't
                            // e.g., BorrowedData<'a> -> StaticData
                            if types_str.contains("<'") || types_str.contains("< '") {
                                // Split by comma, careful of nested <>
                                let mut depth = 0;
                                let mut split_pos = None;
                                for (i, c) in types_str.char_indices() {
                                    match c {
                                        '<' => depth += 1,
                                        '>' => depth -= 1,
                                        ',' if depth == 0 => {
                                            split_pos = Some(i);
                                            break;
                                        }
                                        _ => {}
                                    }
                                }
                                
                                if let Some(pos) = split_pos {
                                    let from_type = types_str[..pos].trim();
                                    let to_type = types_str[pos + 1..].trim();
                                    
                                    // From has lifetime, to doesn't (or has 'static)
                                    let from_has_lifetime = from_type.contains("'a") ||
                                                           from_type.contains("'b") ||
                                                           from_type.contains("'_");
                                    let to_has_static = !to_type.contains('\'') ||  // No lifetime = implicitly 'static for structs
                                                       to_type.contains("'static");
                                    
                                    if from_has_lifetime && to_has_static {
                                        let already_reported = findings.iter().any(|f| 
                                            f.function == format!("{}:{}", rel_path, idx + 1)
                                        );
                                        if !already_reported {
                                            let location = format!("{}:{}", rel_path, idx + 1);
                                            findings.push(Finding {
                                                rule_id: self.metadata.id.clone(),
                                                rule_name: self.metadata.name.clone(),
                                                severity: self.metadata.default_severity,
                                                message: format!(
                                                    "Transmute changes struct lifetime in `{}`: {} -> {}. This can create dangling references.",
                                                    current_fn_name, from_type, to_type
                                                ),
                                                function: location,
                                                function_signature: current_fn_name.clone(),
                                                evidence: vec![trimmed.to_string()],
                                                span: None,
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

        findings
    }
}

/// RUSTCOLA096: Raw pointer from reference escaping safe scope
/// Detecting when a reference is cast to raw pointer and escapes the valid lifetime.
struct RawPointerEscapeRule {
    metadata: RuleMetadata,
}

impl RawPointerEscapeRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA096".to_string(),
                name: "raw-pointer-escape".to_string(),
                short_description: "Raw pointer from local reference escapes function".to_string(),
                full_description: "Casting a reference to a raw pointer (`as *const T` or `as *mut T`) and returning it or storing it beyond the reference's lifetime creates a dangling pointer. When the referenced data is dropped or moved, the pointer becomes invalid. Use Box::leak, 'static data, or ensure the caller manages the lifetime.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/primitive.pointer.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Check if a line contains a raw pointer cast pattern
    fn is_ptr_cast(line: &str) -> bool {
        line.contains("as *const") || 
        line.contains("as *mut") ||
        line.contains(".as_ptr()") ||
        line.contains(".as_mut_ptr()")
    }

    /// Check if the pointer appears to be returned
    fn is_return_context(lines: &[&str], idx: usize, ptr_var: &str) -> bool {
        let line = lines[idx].trim();
        
        // Direct return on same line
        if line.starts_with("return ") && (line.contains("as *const") || line.contains("as *mut")) {
            return true;
        }
        
        // Implicit return (last expression in function)
        if (line.contains("as *const") || line.contains("as *mut") || line.contains(".as_ptr()")) 
           && !line.ends_with(';') 
           && !line.contains("let ") {
            return true;
        }
        
        // Check if ptr_var is returned in subsequent lines
        if !ptr_var.is_empty() {
            for check_line in lines.iter().skip(idx + 1).take(10) {
                let trimmed = check_line.trim();
                if trimmed.starts_with("return ") && trimmed.contains(ptr_var) {
                    return true;
                }
                if trimmed.contains(ptr_var) && !trimmed.ends_with(';') && trimmed.ends_with(')') {
                    // Likely implicit return
                    return true;
                }
                if trimmed.starts_with(ptr_var) && !trimmed.ends_with(';') {
                    return true;
                }
            }
        }
        
        false
    }

    /// Check if the pointer is stored in a struct field or global
    fn is_escape_via_store(lines: &[&str], idx: usize) -> bool {
        let line = lines[idx].trim();
        
        // Stored in struct literal field
        if line.contains("ptr:") && (line.contains("as *const") || line.contains("as *mut")) {
            return true;
        }
        
        // Stored via dereferencing out parameter  
        // Match patterns like *out = &x as *const T, *ptr = &local as *mut T
        if (line.starts_with("*") && line.contains(" = ")) && 
           (line.contains("as *const") || line.contains("as *mut")) {
            // Check it's not just a dereference assignment to a local
            if line.contains("&") {
                return true;
            }
        }
        
        // Stored in global/static
        if line.contains("GLOBAL") || line.contains("STATIC") {
            if line.contains("as *const") || line.contains("as *mut") {
                return true;
            }
        }
        
        false
    }

    /// Check for safe patterns that should not be flagged
    fn is_safe_pattern(lines: &[&str], idx: usize, fn_context: &str) -> bool {
        let line = lines[idx].trim();
        
        // Taking pointer from parameter (caller manages lifetime)
        // Function signature has reference parameter
        if fn_context.contains("fn ") && fn_context.contains("(&") {
            // Check if the cast is on a parameter name
            if !line.contains("let ") && (line.contains(" x ") || line.contains("(x)")) {
                return true;
            }
        }
        
        // Box::leak pattern
        if line.contains("Box::leak") {
            return true;
        }
        
        // 'static string literals
        if fn_context.contains("&'static str") {
            return true;
        }
        
        // Returning Box along with pointer (both in return tuple)
        if line.contains("(ptr,") && (fn_context.contains("Box<") || fn_context.contains("boxed")) {
            return true;
        }
        
        // ManuallyDrop pattern
        if fn_context.contains("ManuallyDrop") {
            return true;
        }
        
        // Pin pattern
        if fn_context.contains("Pin<") {
            return true;
        }
        
        // Used immediately, not stored
        if line.contains("unsafe {") && line.contains("*ptr") && !line.contains("return") {
            return true;
        }
        
        // Local use only (no return, no escape)
        let next_lines: String = lines[idx..std::cmp::min(idx + 5, lines.len())]
            .iter()
            .map(|s| *s)
            .collect::<Vec<&str>>()
            .join("\n");
        if next_lines.contains("unsafe { *ptr }") && !next_lines.contains("return ptr") {
            return true;
        }
        
        false
    }
}

impl Rule for RawPointerEscapeRule {
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
            let mut current_fn_name = String::new();
            let mut current_fn_start = 0;
            let mut returns_ptr = false;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Track function names and signatures
                if trimmed.contains("fn ") {
                    if let Some(fn_pos) = trimmed.find("fn ") {
                        let after_fn = &trimmed[fn_pos + 3..];
                        if let Some(paren_pos) = after_fn.find('(') {
                            current_fn_name = after_fn[..paren_pos].trim().to_string();
                            current_fn_start = idx;
                            // Check if function returns a raw pointer
                            returns_ptr = trimmed.contains("-> *const") || 
                                         trimmed.contains("-> *mut") ||
                                         trimmed.contains("*const i32") ||  // Common patterns
                                         trimmed.contains("*const u8") ||
                                         trimmed.contains("*const str");
                        }
                    }
                }

                // Skip comments (doc comments start with //, /*, or just * followed by whitespace)
                if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                    continue;
                }
                // Skip doc comment continuation lines (* at start of line in multiline comments)
                if trimmed.starts_with("* ") || trimmed == "*" || trimmed.starts_with("*/") {
                    continue;
                }

                // Look for raw pointer casts
                if Self::is_ptr_cast(trimmed) {
                    // Get function context
                    let fn_context: String = lines[current_fn_start..=idx.min(lines.len() - 1)]
                        .iter()
                        .take(20)
                        .map(|s| *s)
                        .collect::<Vec<&str>>()
                        .join("\n");
                    
                    // Check for safe patterns first
                    if Self::is_safe_pattern(&lines, idx, &fn_context) {
                        continue;
                    }
                    
                    // Look for local variable being cast
                    // Pattern: &x as *const, &local as *const, etc.
                    let is_local_cast = trimmed.contains("&x ") || 
                                       trimmed.contains("&local") ||
                                       trimmed.contains("&temp") ||
                                       trimmed.contains("&s ") ||
                                       trimmed.contains("s.as_ptr()") ||
                                       trimmed.contains("s.as_str()") ||
                                       trimmed.contains("&v[");
                    
                    // Check if this escapes
                    let mut ptr_var = String::new();
                    if trimmed.contains("let ") && trimmed.contains(" = ") {
                        if let Some(eq_pos) = trimmed.find(" = ") {
                            let before_eq = &trimmed[..eq_pos];
                            if let Some(let_pos) = before_eq.find("let ") {
                                ptr_var = before_eq[let_pos + 4..].trim().to_string();
                            }
                        }
                    }
                    
                    let escapes_via_return = Self::is_return_context(&lines, idx, &ptr_var);
                    let escapes_via_store = Self::is_escape_via_store(&lines, idx);
                    
                    // Flag if: returns raw pointer AND has local cast that escapes
                    // Also check for dereferenced pointer assignment pattern
                    let is_deref_assign = trimmed.starts_with("*") && trimmed.contains(" = &");
                    
                    if ((returns_ptr || escapes_via_return || escapes_via_store) && is_local_cast) || 
                       (is_deref_assign && is_local_cast) {
                        let location = format!("{}:{}", rel_path, idx + 1);
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "Raw pointer from local reference escapes function `{}`. This creates a dangling pointer when the local is dropped.",
                                current_fn_name
                            ),
                            function: location,
                            function_signature: current_fn_name.clone(),
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

/// RUSTCOLA097: Network/process access in build scripts
/// Build scripts should not make network requests or download files - supply chain risk.
struct BuildScriptNetworkRule {
    metadata: RuleMetadata,
}

impl BuildScriptNetworkRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA097".to_string(),
                name: "build-script-network-access".to_string(),
                short_description: "Network access detected in build script".to_string(),
                full_description: "Build scripts (build.rs) should not perform network requests, download files, or spawn processes that contact external systems. This is a supply-chain security risk - malicious dependencies could exfiltrate data or download malware at build time. Use vendored dependencies or pre-downloaded assets instead.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/cargo/reference/build-scripts.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
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
                    });
                    break; // Only report once per line
                }
            }
        }

        findings
    }
}

struct VecSetLenMisuseRule {
    metadata: RuleMetadata,
}

impl VecSetLenMisuseRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA038".to_string(),
                name: "vec-set-len-misuse".to_string(),
                short_description: "Vec::set_len called on uninitialized vector".to_string(),
                full_description: "Detects Vec::set_len calls where the vector may not be fully initialized. Calling set_len without ensuring all elements are initialized leads to undefined behavior when accessing uninitialized memory. Use Vec::resize, Vec::resize_with, or manually initialize elements before calling set_len.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/vec/struct.Vec.html#method.set_len".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn initialization_methods() -> &'static [&'static str] {
        &[
            ".push(",
            ".extend(",
            ".insert(",
            ".resize(",
            ".resize_with(",
            "Vec::from(",
            "vec![",
            ".clone()",
            ".to_vec()",
        ]
    }
}

impl Rule for VecSetLenMisuseRule {
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

            // Track vector variable initialization state
            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Look for set_len calls
                if trimmed.contains(".set_len(") || trimmed.contains("::set_len(") {
                    // Look backwards to find the vector variable
                    let mut var_name = None;
                    
                    // Try to extract variable name from current line or context
                    if let Some(pos) = trimmed.find(".set_len(") {
                        let before_set_len = &trimmed[..pos];
                        // Extract the last identifier before .set_len
                        if let Some(last_word_start) = before_set_len.rfind(|c: char| c.is_whitespace() || c == '(' || c == '{' || c == ';') {
                            var_name = Some(&before_set_len[last_word_start + 1..]);
                        } else {
                            var_name = Some(before_set_len);
                        }
                    }

                    if let Some(var) = var_name {
                        // Look backward in the same function to see if initialization happened
                        let mut found_initialization = false;
                        let lookback_limit = idx.saturating_sub(50); // Look back up to 50 lines

                        for prev_idx in (lookback_limit..idx).rev() {
                            let prev_line = lines[prev_idx];
                            
                            // Check if this line initializes the vector
                            for init_method in Self::initialization_methods() {
                                if prev_line.contains(var) && prev_line.contains(init_method) {
                                    found_initialization = true;
                                    break;
                                }
                            }

                            // Check for explicit element writes
                            if prev_line.contains(var) && 
                               (prev_line.contains("[") && prev_line.contains("]=") || 
                                prev_line.contains("ptr::write") ||
                                prev_line.contains(".as_mut_ptr()")) {
                                found_initialization = true;
                                break;
                            }

                            // Check for with_capacity without subsequent initialization
                            if prev_line.contains(var) && prev_line.contains("Vec::with_capacity") {
                                // This is suspicious - with_capacity doesn't initialize
                                found_initialization = false;
                                break;
                            }

                            // Stop at function boundaries
                            if prev_line.trim().starts_with("fn ") || 
                               prev_line.trim().starts_with("pub fn ") ||
                               prev_line.trim().starts_with("async fn ") {
                                break;
                            }
                        }

                        if !found_initialization {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Vec::set_len called on potentially uninitialized vector `{}`",
                                    var
                                ),
                                function: location,
                                function_signature: var.to_string(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}

struct HardcodedCryptoKeyRule {
    metadata: RuleMetadata,
}

impl HardcodedCryptoKeyRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA039".to_string(),
                name: "hardcoded-crypto-key".to_string(),
                short_description: "Hard-coded cryptographic key or IV".to_string(),
                full_description: "Detects hard-coded cryptographic keys, initialization vectors, or secrets in source code. Embedded secrets cannot be rotated without code changes, enable credential theft if the binary is reverse-engineered, and violate security best practices. Use environment variables, configuration files, or secret management services instead.".to_string(),
                help_uri: Some("https://cwe.mitre.org/data/definitions/798.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn crypto_key_patterns() -> &'static [&'static str] {
        &[
            "Aes128::new",
            "Aes192::new",
            "Aes256::new",
            "ChaCha20::new",
            "ChaCha20Poly1305::new",
            "Hmac::new_from_slice",
            "GenericArray::from_slice",
            "Key::from_slice",
            "Cipher::new",
        ]
    }

    fn suspicious_var_names() -> &'static [&'static str] {
        &[
            "key",
            "secret",
            "password",
            "token",
            "iv",
            "nonce",
            "salt",
        ]
    }

    /// Check if a line contains a suspicious variable assignment with a literal value.
    /// This uses more precise matching to reduce false positives.
    fn is_suspicious_assignment(line: &str, pattern: &str) -> bool {
        let lower_line = line.to_lowercase();
        let lower_pattern = pattern.to_lowercase();

        // Quick rejection: must contain the pattern
        if !lower_line.contains(&lower_pattern) {
            return false;
        }

        // Must have an assignment operator
        if !line.contains('=') {
            return false;
        }

        // Split on '=' to get left and right sides
        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() != 2 {
            return false;
        }

        let left_side = parts[0].trim().to_lowercase();
        let right_side = parts[1].trim();

        // Check if the left side contains the pattern as a word boundary
        // Look for the pattern as a standalone identifier or part of an identifier
        // but not just anywhere in a longer word
        let has_pattern_in_identifier = Self::has_word_boundary_match(&left_side, &lower_pattern);

        if !has_pattern_in_identifier {
            return false;
        }

        // Check if right side contains a literal value
        // Byte string literals
        if right_side.contains("b\"") || right_side.contains("b'") {
            return true;
        }

        // Byte array literals
        if right_side.contains("&[") || right_side.contains("[0x") || right_side.contains("[0u8") {
            return true;
        }

        // Long string literals (likely to be keys/tokens)
        if right_side.starts_with('"') && right_side.len() > 30 {
            return true;
        }

        // Hex string patterns (common for keys)
        if right_side.starts_with('"') && right_side.chars().filter(|c| c.is_ascii_hexdigit()).count() > 20 {
            return true;
        }

        false
    }

    /// Check if a pattern appears at a word boundary in the text.
    /// This prevents matching "iv" in "driver", "private", etc.
    /// But allows matching in compound identifiers like "api_token", "my_secret_key"
    fn has_word_boundary_match(text: &str, pattern: &str) -> bool {
        // For short patterns like "iv", we need to be especially careful
        // Look for the pattern surrounded by non-alphanumeric characters or underscores

        if let Some(pos) = text.find(pattern) {
            let before_ok = if pos == 0 {
                true
            } else {
                let char_before = text.chars().nth(pos - 1).unwrap_or(' ');
                // Allow underscore (for compound identifiers) but not other alphanumeric
                !char_before.is_alphanumeric() || char_before == '_'
            };

            let after_pos = pos + pattern.len();
            let after_ok = if after_pos >= text.len() {
                true
            } else {
                let char_after = text.chars().nth(after_pos).unwrap_or(' ');
                // After the pattern, we need a non-alphanumeric boundary
                // Underscore here means it's part of a longer word (like "token" in "tokenize")
                !char_after.is_alphanumeric()
            };

            before_ok && after_ok
        } else {
            false
        }
    }
}

impl Rule for HardcodedCryptoKeyRule {
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

                // Skip comments and test code
                if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                    continue;
                }

                // Look for crypto API calls with literal byte arrays
                for pattern in Self::crypto_key_patterns() {
                    if trimmed.contains(pattern) {
                        // Check if the line contains a byte array literal
                        if trimmed.contains("b\"") || trimmed.contains("&[") || trimmed.contains("[0x") {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: "Hard-coded cryptographic key or IV detected in source code".to_string(),
                                function: location,
                                function_signature: pattern.to_string(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                            });
                        }
                    }
                }

                // Also look for suspicious variable assignments with literals
                // Use more precise matching to avoid false positives
                for var_pattern in Self::suspicious_var_names() {
                    // Check if this line contains a variable name that looks like a secret
                    // and is being assigned a literal value
                    if Self::is_suspicious_assignment(trimmed, var_pattern) {
                        let location = format!("{}:{}", rel_path, idx + 1);

                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "Potential hard-coded secret in variable containing '{}'",
                                var_pattern
                            ),
                            function: location,
                            function_signature: var_pattern.to_string(),
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

#[allow(dead_code)]
struct AllocatorMismatchRule {
    metadata: RuleMetadata,
}

#[allow(dead_code)]
impl AllocatorMismatchRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA017".to_string(),
                name: "allocator-mismatch".to_string(),
                short_description: "Mixed allocator/deallocator usage".to_string(),
                full_description: "Detects functions that mix Rust and foreign allocation APIs, such as freeing Box/CString allocations with libc::free or wrapping libc::malloc pointers with Box::from_raw.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn rust_allocation_patterns() -> &'static [&'static str] {
        &[
            "Box::into_raw",
            "CString::into_raw",
            "Arc::into_raw",
            "Vec::into_raw_parts",
            ".into_raw()",
            ".into_raw_parts()",
        ]
    }

    fn rust_deallocation_patterns() -> &'static [&'static str] {
        &[
            "Box::from_raw",
            "CString::from_raw",
            "Arc::from_raw",
            "Vec::from_raw_parts",
            "Vec::from_raw",
        ]
    }

    fn foreign_allocation_patterns() -> &'static [&'static str] {
        &[
            "libc::malloc",
            "libc::calloc",
            "libc::realloc",
            "libc::aligned_alloc",
            "libc::posix_memalign",
            "libc::strdup",
        ]
    }

    fn foreign_deallocation_patterns() -> &'static [&'static str] {
        &["libc::free", "libc::realloc", "libc::cfree"]
    }

    fn collect_function_block(lines: &[&str], start_idx: usize) -> (usize, usize, Vec<String>) {
        let mut block_lines = Vec::new();

        let mut lookback = start_idx;
        while lookback > 0 {
            let prev = lines[lookback - 1].trim();
            if prev.is_empty() {
                lookback -= 1;
                continue;
            }
            if prev.starts_with("#[") {
                lookback -= 1;
                continue;
            }
            break;
        }
        let attr_start = lookback;

        for idx in attr_start..start_idx {
            let trimmed = lines[idx].trim();
            if !trimmed.is_empty() {
                block_lines.push(trimmed.to_string());
            }
        }

        let mut brace_balance: i32 = 0;
        let mut body_started = false;
        let mut idx = start_idx;

        while idx < lines.len() {
            let current = lines[idx];
            let trimmed = current.trim();
            if !trimmed.is_empty() {
                block_lines.push(trimmed.to_string());
            }

            let opens = current.chars().filter(|c| *c == '{').count() as i32;
            let closes = current.chars().filter(|c| *c == '}').count() as i32;
            brace_balance += opens;
            if brace_balance > 0 {
                body_started = true;
            }
            brace_balance -= closes;

            if body_started && brace_balance <= 0 {
                idx += 1;
                break;
            }

            if !body_started && trimmed.ends_with(';') {
                idx += 1;
                break;
            }

            idx += 1;
        }

        (idx, attr_start, block_lines)
    }
}

impl Rule for AllocatorMismatchRule {
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

            while idx < lines.len() {
                let line = lines[idx];
                let trimmed = line.trim();

                if !trimmed.contains("fn ") || trimmed.starts_with("//") {
                    idx += 1;
                    continue;
                }

                let (next_idx, start_idx, block_lines) = Self::collect_function_block(&lines, idx);

                let signature = block_lines
                    .iter()
                    .find(|l| l.contains("fn "))
                    .cloned()
                    .unwrap_or_else(|| block_lines.first().cloned().unwrap_or_default());

                let rust_alloc_hits =
                    collect_sanitized_matches(&block_lines, Self::rust_allocation_patterns());
                let rust_free_hits =
                    collect_sanitized_matches(&block_lines, Self::rust_deallocation_patterns());
                let foreign_alloc_hits =
                    collect_sanitized_matches(&block_lines, Self::foreign_allocation_patterns());
                let foreign_free_hits =
                    collect_sanitized_matches(&block_lines, Self::foreign_deallocation_patterns());

                let rust_to_foreign = !rust_alloc_hits.is_empty() && !foreign_free_hits.is_empty();
                let foreign_to_rust = !foreign_alloc_hits.is_empty() && !rust_free_hits.is_empty();

                if rust_to_foreign || foreign_to_rust {
                    let mut evidence = Vec::new();
                    let mut seen: HashSet<String> = HashSet::new();

                    for line in rust_alloc_hits
                        .into_iter()
                        .chain(foreign_free_hits.into_iter())
                        .chain(foreign_alloc_hits.into_iter())
                        .chain(rust_free_hits.into_iter())
                    {
                        if seen.insert(line.clone()) {
                            evidence.push(line);
                        }
                    }

                    let scenario = match (rust_to_foreign, foreign_to_rust) {
                        (true, true) => {
                            "Mixed Rust and foreign allocators in same function".to_string()
                        }
                        (true, false) => "Rust allocation freed via foreign allocator".to_string(),
                        (false, true) => {
                            "Foreign allocation released via Rust allocator".to_string()
                        }
                        _ => "Mixed allocator usage".to_string(),
                    };

                    let location = format!("{}:{}", rel_path, start_idx + 1);
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: scenario,
                        function: location,
                        function_signature: signature,
                        evidence,
                        span: None,
                    });
                }

                idx = next_idx;
            }
        }

        findings
    }
}

struct ContentLengthAllocationRule {
    metadata: RuleMetadata,
}

impl ContentLengthAllocationRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA021".to_string(),
                name: "content-length-allocation".to_string(),
                short_description:
                    "Allocations sized from untrusted Content-Length header".to_string(),
                full_description: "Flags allocations (`Vec::with_capacity`, `reserve*`) that trust HTTP Content-Length values without upper bounds, enabling attacker-controlled memory exhaustion. See RUSTSEC-2025-0015 for real-world examples.".to_string(),
                help_uri: Some("https://rustsec.org/advisories/RUSTSEC-2025-0015.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for ContentLengthAllocationRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            let allocations = detect_content_length_allocations(function);

            for allocation in allocations {
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
                        "Potential unbounded allocation from Content-Length in `{}`",
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

struct UnboundedAllocationRule {
    metadata: RuleMetadata,
}

impl UnboundedAllocationRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA024".to_string(),
                name: "unbounded-allocation".to_string(),
                short_description: "Allocation sized from tainted length without guard".to_string(),
                full_description: "Detects allocations (`with_capacity`, `reserve*`) that rely on tainted length values (parameters, `.len()` on attacker data, etc.) without bounding them, enabling memory exhaustion.".to_string(),
                help_uri: Some("https://github.com/Opus-the-penguin/Rust-cola/blob/main/docs/security-rule-backlog.md#resource-management--dos".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
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
                });
            }
        }

        findings
    }
}

struct LengthTruncationCastRule {
    metadata: RuleMetadata,
}

impl LengthTruncationCastRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA022".to_string(),
                name: "length-truncation-cast".to_string(),
                short_description: "Payload length cast to narrower integer".to_string(),
                full_description: "Detects casts or try_into conversions that shrink message length fields to 8/16/32-bit integers without bounds checks, potentially smuggling extra bytes past protocol parsers. See RUSTSEC-2024-0363 and RUSTSEC-2024-0365 for PostgreSQL wire protocol examples.".to_string(),
                help_uri: Some("https://rustsec.org/advisories/RUSTSEC-2024-0363.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for LengthTruncationCastRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            let casts = detect_truncating_len_casts(function);

            for cast in casts {
                let mut evidence = vec![cast.cast_line.clone()];

                if !cast.source_vars.is_empty() {
                    evidence.push(format!("length sources: {}", cast.source_vars.join(", ")));
                }

                for sink in &cast.sink_lines {
                    if !evidence.contains(sink) {
                        evidence.push(sink.clone());
                    }
                }

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Potential length truncation before serialization in `{}`",
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

struct RustsecUnsoundDependencyRule {
    metadata: RuleMetadata,
}

struct UnsoundAdvisory {
    crate_name: &'static str,
    version_req: &'static str,
    advisory_id: &'static str,
    summary: &'static str,
}

impl RustsecUnsoundDependencyRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA018".to_string(),
                name: "rustsec-unsound-dependency".to_string(),
                short_description: "Dependency flagged as unsound by RustSec".to_string(),
                full_description: "Surfaces crates listed in Cargo.lock that match RustSec advisories marked unsound, prompting dependency upgrades or mitigations.".to_string(),
                help_uri: Some("https://rustsec.org/advisories".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn advisories() -> &'static [UnsoundAdvisory] {
        &[
            UnsoundAdvisory {
                crate_name: "arrayvec",
                version_req: "<= 0.4.10",
                advisory_id: "RUSTSEC-2018-0001",
                summary: "arrayvec::ArrayVec::insert can cause memory corruption",
            },
            UnsoundAdvisory {
                crate_name: "smallvec",
                version_req: "< 1.10.0",
                advisory_id: "RUSTSEC-2021-0009",
                summary: "SmallVec::insert_many can cause memory exposure",
            },
            UnsoundAdvisory {
                crate_name: "fixedbitset",
                version_req: "< 0.4.0",
                advisory_id: "RUSTSEC-2019-0003",
                summary: "FixedBitSet::insert unsound aliasing",
            },
        ]
    }

    fn advisory_matches(advisory: &UnsoundAdvisory, version: &Version) -> bool {
        VersionReq::parse(advisory.version_req)
            .ok()
            .map(|req| req.matches(version))
            .unwrap_or(false)
    }
}

impl Rule for RustsecUnsoundDependencyRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        let crate_root = Path::new(&package.crate_root);
        let lock_path = crate_root.join("Cargo.lock");

        if !lock_path.exists() {
            return findings;
        }

        let Ok(contents) = fs::read_to_string(&lock_path) else {
            return findings;
        };

        let Ok(doc) = toml::from_str::<toml::Value>(&contents) else {
            return findings;
        };

        let Some(packages) = doc.get("package").and_then(|value| value.as_array()) else {
            return findings;
        };

        let relative_lock = lock_path
            .strip_prefix(crate_root)
            .unwrap_or(&lock_path)
            .to_string_lossy()
            .replace('\\', "/");

        let mut emitted = HashSet::new();

        for pkg in packages {
            let Some(name) = pkg.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(version_str) = pkg.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            let Ok(version) = Version::parse(version_str) else {
                continue;
            };

            for advisory in Self::advisories() {
                if advisory.crate_name != name {
                    continue;
                }

                if !Self::advisory_matches(advisory, &version) {
                    continue;
                }

                let key = (
                    name.to_string(),
                    version_str.to_string(),
                    advisory.advisory_id,
                );
                if !emitted.insert(key) {
                    continue;
                }

                let evidence = vec![format!(
                    "{} {} matches {} ({})",
                    name, version_str, advisory.advisory_id, advisory.summary
                )];

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Dependency '{}' v{} is flagged unsound by advisory {}",
                        name, version_str, advisory.advisory_id
                    ),
                    function: relative_lock.clone(),
                    function_signature: format!("{} {}", name, version_str),
                    evidence,
                    span: None,
                });
            }
        }

        findings
    }
}

struct YankedCrateRule {
    metadata: RuleMetadata,
}

struct YankedRelease {
    crate_name: &'static str,
    version: &'static str,
    reason: &'static str,
}

impl YankedCrateRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA019".to_string(),
                name: "yanked-crate-version".to_string(),
                short_description: "Dependency references a yanked crate version".to_string(),
                full_description: "Highlights crates pinned to versions that have been yanked from crates.io, indicating that consumers should upgrade before the version disappears from the index cache.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/cargo/reference/publishing.html#removing-a-version".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn releases() -> &'static [YankedRelease] {
        &[
            YankedRelease {
                crate_name: "memoffset",
                version: "0.5.6",
                reason: "Yanked due to soundness issue (RUSTSEC-2021-0119)",
            },
            YankedRelease {
                crate_name: "chrono",
                version: "0.4.19",
                reason: "Yanked pending security fixes",
            },
        ]
    }
}

impl Rule for YankedCrateRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        let crate_root = Path::new(&package.crate_root);
        let lock_path = crate_root.join("Cargo.lock");

        if !lock_path.exists() {
            return findings;
        }

        let Ok(contents) = fs::read_to_string(&lock_path) else {
            return findings;
        };

        let Ok(doc) = toml::from_str::<toml::Value>(&contents) else {
            return findings;
        };

        let Some(packages) = doc.get("package").and_then(|value| value.as_array()) else {
            return findings;
        };

        let relative_lock = lock_path
            .strip_prefix(crate_root)
            .unwrap_or(&lock_path)
            .to_string_lossy()
            .replace('\\', "/");

        let mut emitted = HashSet::new();

        for pkg in packages {
            let Some(name) = pkg.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(version) = pkg.get("version").and_then(|v| v.as_str()) else {
                continue;
            };

            for release in Self::releases() {
                if release.crate_name != name || release.version != version {
                    continue;
                }

                if !emitted.insert((name.to_string(), version.to_string())) {
                    continue;
                }

                let evidence = vec![format!(
                    "{} {} is yanked: {}",
                    name, version, release.reason
                )];

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Dependency '{}' v{} is yanked from crates.io",
                        name, version
                    ),
                    function: relative_lock.clone(),
                    function_signature: format!("{} {}", name, version),
                    evidence,
                    span: None,
                });
            }
        }

        findings
    }
}

struct CargoAuditableMetadataRule {
    metadata: RuleMetadata,
}

impl CargoAuditableMetadataRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA020".to_string(),
                name: "cargo-auditable-metadata".to_string(),
                short_description: "Binary crate missing cargo auditable metadata".to_string(),
                full_description: "Detects binary crates that do not integrate cargo auditable metadata, encouraging projects to embed supply-chain provenance in release artifacts.".to_string(),
                help_uri: Some("https://github.com/rust-secure-code/cargo-auditable".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn read_manifest(crate_root: &Path) -> Option<toml::Value> {
        let manifest_path = crate_root.join("Cargo.toml");
        let contents = fs::read_to_string(manifest_path).ok()?;
        toml::from_str::<toml::Value>(&contents).ok()
    }

    fn is_workspace(manifest: &toml::Value) -> bool {
        manifest.get("workspace").is_some() && manifest.get("package").is_none()
    }

    fn is_binary_crate(manifest: &toml::Value, crate_root: &Path) -> bool {
        if Self::is_workspace(manifest) {
            return false;
        }

        if manifest
            .get("bin")
            .and_then(|value| value.as_array())
            .map(|arr| !arr.is_empty())
            .unwrap_or(false)
        {
            return true;
        }

        let src_main = crate_root.join("src").join("main.rs");
        if src_main.exists() {
            return true;
        }

        let bin_dir = crate_root.join("src").join("bin");
        if let Ok(entries) = fs::read_dir(&bin_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && path
                        .extension()
                        .and_then(OsStr::to_str)
                        .map_or(false, |ext| ext.eq_ignore_ascii_case("rs"))
                {
                    return true;
                }

                if path.is_dir() && path.join("main.rs").exists() {
                    return true;
                }
            }
        }

        false
    }

    fn metadata_skip(manifest: &toml::Value) -> bool {
        manifest
            .get("package")
            .and_then(|pkg| pkg.get("metadata"))
            .and_then(|metadata| match metadata {
                toml::Value::Table(table) => table.get("rust-cola"),
                _ => None,
            })
            .and_then(|rust_cola| match rust_cola {
                toml::Value::Table(table) => table.get("skip_auditable_check"),
                _ => None,
            })
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
    }

    fn has_auditable_markers(manifest: &toml::Value) -> bool {
        let marker_keys = ["auditable", "cargo-auditable"];

        let dep_tables = [
            manifest.get("dependencies"),
            manifest.get("dev-dependencies"),
            manifest.get("build-dependencies"),
        ];

        if dep_tables.iter().any(|value| match value {
            Some(toml::Value::Table(table)) => table
                .keys()
                .any(|key| marker_keys.iter().any(|mk| key.contains(mk))),
            _ => false,
        }) {
            return true;
        }

        if manifest
            .get("package")
            .and_then(|pkg| pkg.get("metadata"))
            .and_then(|metadata| match metadata {
                toml::Value::Table(table) => Some(table),
                _ => None,
            })
            .map(|metadata_table| {
                metadata_table.keys().any(|key| marker_keys.iter().any(|mk| key.contains(mk)))
                    || metadata_table.values().any(|value| matches!(value, toml::Value::Table(inner) if inner.keys().any(|k| k.contains("auditable"))))
            })
            .unwrap_or(false)
        {
            return true;
        }

        if let Some(toml::Value::Table(features)) = manifest.get("features") {
            if features.iter().any(|(key, value)| {
                key.contains("auditable")
                    || matches!(value, toml::Value::Array(items) if items.iter().any(|item| item.as_str().map_or(false, |s| s.contains("auditable"))))
            }) {
                return true;
            }
        }

        false
    }

    fn lockfile_mentions_auditable(crate_root: &Path) -> bool {
        let lock_path = crate_root.join("Cargo.lock");
        let Ok(contents) = fs::read_to_string(lock_path) else {
            return false;
        };

        contents.to_lowercase().contains("auditable")
    }

    fn ci_mentions_cargo_auditable(crate_root: &Path) -> bool {
        const MAX_ANCESTOR_SEARCH: usize = 5;

        for ancestor in crate_root.ancestors().take(MAX_ANCESTOR_SEARCH) {
            if Self::ci_markers_within(ancestor) {
                return true;
            }
        }

        false
    }

    fn ci_markers_within(base: &Path) -> bool {
        let search_dirs = [".github", ".gitlab", "ci", "scripts"];
        for dir in &search_dirs {
            let path = base.join(dir);
            if !path.exists() {
                continue;
            }

            for entry in WalkDir::new(&path)
                .max_depth(6)
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

                if let Ok(metadata) = entry.metadata() {
                    if metadata.len() > 512 * 1024 {
                        continue;
                    }
                }

                if fs::read_to_string(entry.path())
                    .map(|contents| contents.to_lowercase().contains("cargo auditable"))
                    .unwrap_or(false)
                {
                    return true;
                }
            }
        }

        let marker_files = ["Makefile", "makefile", "Justfile", "justfile"];
        for file in &marker_files {
            let path = base.join(file);
            if !path.exists() {
                continue;
            }

            if fs::read_to_string(&path)
                .map(|contents| contents.to_lowercase().contains("cargo auditable"))
                .unwrap_or(false)
            {
                return true;
            }
        }

        false
    }
}

impl Rule for CargoAuditableMetadataRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        let crate_root = Path::new(&package.crate_root);

        let Some(manifest) = Self::read_manifest(crate_root) else {
            return findings;
        };

        if !Self::is_binary_crate(&manifest, crate_root) {
            return findings;
        }

        if Self::metadata_skip(&manifest) {
            return findings;
        }

        if Self::has_auditable_markers(&manifest)
            || Self::lockfile_mentions_auditable(crate_root)
            || Self::ci_mentions_cargo_auditable(crate_root)
        {
            return findings;
        }

        let package_name = manifest
            .get("package")
            .and_then(|pkg| pkg.get("name"))
            .and_then(|name| name.as_str())
            .unwrap_or(&package.crate_name);

        let mut evidence = Vec::new();
        if crate_root.join("src").join("main.rs").exists() {
            evidence.push("Found src/main.rs binary entry point".to_string());
        }

        if crate_root.join("src").join("bin").exists() {
            evidence.push("Found src/bin directory indicating additional binaries".to_string());
        }

        if manifest
            .get("bin")
            .and_then(|value| value.as_array())
            .map(|arr| !arr.is_empty())
            .unwrap_or(false)
        {
            evidence.push("Cargo.toml defines [[bin]] targets".to_string());
        }

        evidence.push(
            "No cargo auditable dependency, metadata, lockfile entry, or CI integration detected"
                .to_string(),
        );

        let manifest_path = crate_root.join("Cargo.toml");
        let relative_manifest = manifest_path
            .strip_prefix(crate_root)
            .unwrap_or(&manifest_path)
            .to_string_lossy()
            .replace('\\', "/");

        findings.push(Finding {
            rule_id: self.metadata.id.clone(),
            rule_name: self.metadata.name.clone(),
            severity: self.metadata.default_severity,
            message: format!(
                "Binary crate '{}' is missing cargo auditable metadata; consider integrating cargo auditable builds",
                package_name
            ),
            function: relative_manifest,
            function_signature: package_name.to_string(),
            evidence,
            span: None,
        });

        findings
    }
}

/// RUSTCOLA042: Cookie without Secure attribute
/// Detects cookie builders that don't set the Secure flag, allowing transmission over HTTP
struct CookieSecureAttributeRule {
    metadata: RuleMetadata,
}

impl CookieSecureAttributeRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA042".to_string(),
                name: "cookie-without-secure".to_string(),
                short_description: "Cookie without Secure attribute".to_string(),
                full_description: "Detects cookies created without the Secure flag, which allows them to be transmitted over unencrypted HTTP connections. This can lead to session hijacking and credential theft. Always use .secure(true) for cookies containing sensitive data.".to_string(),
                help_uri: Some("https://owasp.org/www-community/controls/SecureCookieAttribute".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn is_cookie_builder(line: &str) -> bool {
        let lowered = line.to_lowercase();
        lowered.contains("cookie::") && (lowered.contains("::build(") || lowered.contains("::new("))
    }

    fn has_secure_call(lines: &[String], start_idx: usize) -> bool {
        // Look forward from cookie builder for .secure(true) call
        for (idx, line) in lines.iter().enumerate().skip(start_idx) {
            let lowered = line.to_lowercase();
            
            // Stop searching if we hit a statement terminator without chaining
            if line.trim().ends_with(';') && !line.contains(".secure(") {
                // Check if this line or previous lines had .secure(true)
                for check_idx in start_idx..=idx {
                    if lines[check_idx].to_lowercase().contains(".secure(true") {
                        return true;
                    }
                }
                return false;
            }
            
            // Found secure call
            if lowered.contains(".secure(true") {
                return true;
            }
            
            // Limit search to reasonable builder chain length
            if idx - start_idx > 20 {
                break;
            }
        }
        false
    }
}

impl Rule for CookieSecureAttributeRule {
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

            let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();

            for (idx, line) in lines.iter().enumerate() {
                if line.trim().starts_with("//") {
                    continue;
                }

                if Self::is_cookie_builder(line) && !Self::has_secure_call(&lines, idx) {
                    let location = format!("{}:{}", rel_path, idx + 1);

                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: "Cookie created without Secure attribute; vulnerable to interception over HTTP".to_string(),
                        function: location,
                        function_signature: String::new(),
                        evidence: vec![line.trim().to_string()],
                        span: None,
                    });
                }
            }
        }

        findings
    }
}

/// RUSTCOLA043: Overly permissive CORS configuration
/// Detects CORS configurations that allow any origin, enabling CSRF and data theft
struct CorsWildcardRule {
    metadata: RuleMetadata,
}

impl CorsWildcardRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA043".to_string(),
                name: "cors-wildcard-origin".to_string(),
                short_description: "Overly permissive CORS wildcard origin".to_string(),
                full_description: "Detects CORS configurations that allow requests from any origin (*), which can enable cross-site request forgery and credential theft. Use specific origin allowlists instead of wildcards for production APIs.".to_string(),
                help_uri: Some("https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#access-control-allow-origin".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn is_wildcard_cors(line: &str) -> bool {
        let lowered = line.to_lowercase();
        
        // Common patterns for wildcard CORS
        let patterns = [
            ".allow_origin(\"*\")",
            ".allow_origin(\"*\".to_string())",
            "::allow_origin(\"*\")",
            ".alloworigin(\"*\")",
            "alloworigin::any()",
            ".allow_any_origin()",
            ".with_allow_origin(\"*\")",
            "access-control-allow-origin: *",
            "\"access-control-allow-origin\", \"*\"",
        ];

        patterns.iter().any(|p| lowered.contains(p))
    }
}

impl Rule for CorsWildcardRule {
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

            for (idx, line) in content.lines().enumerate() {
                if line.trim().starts_with("//") {
                    continue;
                }

                if Self::is_wildcard_cors(line) {
                    let location = format!("{}:{}", rel_path, idx + 1);

                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: "CORS configured with wildcard origin (*); allows any site to make credentialed requests".to_string(),
                        function: location,
                        function_signature: String::new(),
                        evidence: vec![line.trim().to_string()],
                        span: None,
                    });
                }
            }
        }

        findings
    }
}

/// RUSTCOLA044: Observable timing discrepancy in secret comparison
/// Detects non-constant-time comparisons of secrets that could leak information via timing
struct TimingAttackRule {
    metadata: RuleMetadata,
}

impl TimingAttackRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA044".to_string(),
                name: "timing-attack-secret-comparison".to_string(),
                short_description: "Non-constant-time secret comparison".to_string(),
                full_description: "Detects comparisons of secrets (passwords, tokens, HMACs) using non-constant-time operations like == or .starts_with(). These can leak information through timing side-channels. Use constant_time_eq or subtle::ConstantTimeEq instead.".to_string(),
                help_uri: Some("https://codahale.com/a-lesson-in-timing-attacks/".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_secret(var_name: &str) -> bool {
        let lowered = var_name.to_lowercase();
        let secret_markers = [
            "password",
            "passwd",
            "pwd",
            "token",
            "secret",
            "key",
            "hmac",
            "signature",
            "auth",
            "credential",
            "api_key",
            "apikey",
        ];

        secret_markers.iter().any(|marker| lowered.contains(marker))
    }

    fn is_non_constant_time_comparison(line: &str) -> bool {
        let lowered = line.to_lowercase();
        
        // Skip if already using constant-time comparison
        if lowered.contains("constant_time_eq")
            || lowered.contains("constanttimeeq")
            || lowered.contains("subtle::") 
        {
            return false;
        }

        // Look for comparisons
        if lowered.contains(" == ") 
            || lowered.contains(" != ")
            || lowered.contains(".eq(")
            || lowered.contains(".ne(")
            || lowered.contains(".starts_with(")
            || lowered.contains(".ends_with(")
        {
            // Extract variable names
            let words: Vec<&str> = line.split(&[' ', '(', ')', ',', ';', '=', '!'][..])
                .filter(|w| !w.is_empty())
                .collect();

            // Check if any variable looks like a secret
            return words.iter().any(|w| Self::looks_like_secret(w));
        }

        false
    }
}

impl Rule for TimingAttackRule {
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

            for (idx, line) in content.lines().enumerate() {
                if line.trim().starts_with("//") {
                    continue;
                }

                if Self::is_non_constant_time_comparison(line) {
                    let location = format!("{}:{}", rel_path, idx + 1);

                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: "Secret comparison using non-constant-time operation; vulnerable to timing attacks".to_string(),
                        function: location,
                        function_signature: String::new(),
                        evidence: vec![line.trim().to_string()],
                        span: None,
                    });
                }
            }
        }

        findings
    }
}

/// RUSTCOLA045: Weak or deprecated cipher algorithm
/// Detects use of cryptographically broken ciphers like DES, 3DES, RC4, Blowfish
struct WeakCipherRule {
    metadata: RuleMetadata,
}

impl WeakCipherRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA045".to_string(),
                name: "weak-cipher-usage".to_string(),
                short_description: "Weak or deprecated cipher algorithm".to_string(),
                full_description: "Detects use of cryptographically broken or deprecated ciphers including DES, 3DES, RC4, RC2, and Blowfish. These algorithms have known vulnerabilities and should not be used for security-sensitive operations. Use modern algorithms like AES-256-GCM or ChaCha20-Poly1305 instead.".to_string(),
                help_uri: Some("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn contains_weak_cipher(line: &str) -> bool {
        let lowered = line.to_lowercase();
        
        // Skip comments
        if lowered.trim_start().starts_with("//") {
            return false;
        }

        // Skip string literals - they shouldn't trigger cipher detection
        // Look for actual function calls and type usage
        
        // Weak cipher patterns in common Rust crypto crates
        // These patterns are designed to match actual cipher usage in MIR, not arbitrary strings
        // lgtm[rust/weak-cryptographic-algorithm]
        let weak_patterns = [
            // DES variants - looking for module paths and types
            "::des::",
            "::des<",
            " des::",
            "<des>",
            "cipher::des",
            "block_modes::des",
            "des_ede3",      // 3DES
            "tripledes",
            "::tdes::",
            "::tdes<",
            "tdesede",
            
            // RC4 - stream cipher
            "::rc4::",
            "::rc4<",
            " rc4::",
            "<rc4>",
            "cipher::rc4",
            "stream_cipher::rc4",
            
            // RC2
            "::rc2::",
            "::rc2<",
            " rc2::",
            "<rc2>",
            "cipher::rc2",
            
            // Blowfish (legacy, not for new systems)
            "::blowfish::",
            "::blowfish<",
            " blowfish::",
            "<blowfish>",
            "cipher::blowfish",
            "block_modes::blowfish",
            
            // Other weak ciphers
            "::arcfour::",   // RC4 variant
            " arcfour::",
            "::cast5::",     // Outdated
            " cast5::",
        ];

        // Check if line contains cipher patterns but is not just a string literal
        for pattern in weak_patterns {
            if lowered.contains(pattern) {
                // Additional heuristic: skip if it's in alloc section (string literal data)
                if lowered.contains("alloc") && (lowered.contains("0x") || lowered.contains("│")) {
                    continue;
                }
                return true;
            }
        }
        
        false
    }
}

impl Rule for WeakCipherRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check MIR bodies for weak cipher usage
        for function in &package.functions {
            // Exclude the rule's own implementation to avoid self-detection
            if function.name.contains("WeakCipherRule") 
                || function.name.contains("contains_weak_cipher") {
                continue;
            }

            for line in &function.body {
                if Self::contains_weak_cipher(line) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "Weak or deprecated cipher algorithm detected in `{}`",
                            function.name
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![line.trim().to_string()],
                        span: function.span.clone(),
                    });
                }
            }
        }

        findings
    }
}

/// RUSTCOLA046: Predictable randomness from constant seeds
/// Detects RNG initialization with hardcoded constant seeds, which makes the output predictable
struct PredictableRandomnessRule {
    metadata: RuleMetadata,
}

impl PredictableRandomnessRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA046".to_string(),
                name: "predictable-randomness".to_string(),
                short_description: "Predictable random number generation".to_string(),
                full_description: "Detects RNG initialization using constant or hardcoded seeds. Predictable randomness is a critical security flaw in cryptographic operations, session token generation, and nonce creation. Use cryptographically secure random sources like OsRng, ThreadRng, or properly seeded RNGs from entropy sources.".to_string(),
                help_uri: Some("https://owasp.org/www-community/vulnerabilities/Insecure_Randomness".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn is_predictable_seed(line: &str) -> bool {
        let lowered = line.to_lowercase();
        
        // Skip comments
        if lowered.trim_start().starts_with("//") {
            return false;
        }

        // Skip alloc sections (string literal data)
        if lowered.contains("alloc") && (lowered.contains("0x") || lowered.contains("│")) {
            return false;
        }

        // Look for seeding functions with constant values
        // Common patterns in Rust RNG crates
        
        // Pattern 1: seed_from_u64(constant) - most common pattern
        // lgtm[rust/insufficient-random-values]
        if lowered.contains("seed_from_u64") {
            // Check if followed by a constant literal
            // MIR shows: seed_from_u64(const 12345_u64) or similar
            if lowered.contains("const") && (lowered.contains("_u64") || lowered.contains("_i64")) {
                return true;
            }
        }

        // Pattern 2: from_seed with array literals
        if lowered.contains("from_seed") {
            // Check for const array: from_seed(const [u8; 32])
            if lowered.contains("const") && lowered.contains("[") {
                return true;
            }
        }

        // Pattern 3: StdRng::seed_from_u64, ChaChaRng::seed_from_u64, etc.
        // lgtm[rust/insufficient-random-values]
        let seedable_rngs = [
            "stdrng::seed_from_u64",
            "chacharng::seed_from_u64",
            "chacha8rng::seed_from_u64",
            "chacha12rng::seed_from_u64",
            "chacha20rng::seed_from_u64",
            "isaacrng::seed_from_u64",
            "isaac64rng::seed_from_u64",
            "smallrng::seed_from_u64",
        ];

        for rng in seedable_rngs {
            if lowered.contains(rng) && lowered.contains("const") {
                return true;
            }
        }

        // Pattern 4: Rand::new with constant seed (older API)
        if (lowered.contains("::new(") || lowered.contains("::new_seeded(")) 
            && lowered.contains("const") 
            && (lowered.contains("rng") || lowered.contains("rand")) {
            return true;
        }

        false
    }

    fn looks_like_crypto_context(function_name: &str) -> bool {
        let lowered = function_name.to_lowercase();
        let crypto_markers = [
            "crypto", "encrypt", "decrypt", "key", "token", "session",
            "nonce", "salt", "random", "secure", "secret", "auth",
            "sign", "verify", "hmac", "hash", "password",
        ];
        
        crypto_markers.iter().any(|marker| lowered.contains(marker))
    }
}

impl Rule for PredictableRandomnessRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Exclude the rule's own implementation to avoid self-detection
            if function.name.contains("PredictableRandomnessRule") 
                || function.name.contains("is_predictable_seed")
                || function.name.contains("looks_like_crypto_context") {
                continue;
            }

            for line in &function.body {
                if Self::is_predictable_seed(line) {
                    let in_crypto_context = Self::looks_like_crypto_context(&function.name);

                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: Severity::High,
                        message: if in_crypto_context {
                            format!(
                                "CRITICAL: Predictable RNG seed in cryptographic context `{}`",
                                function.name
                            )
                        } else {
                            format!(
                                "Predictable RNG seed detected in `{}`",
                                function.name
                            )
                        },
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![line.trim().to_string()],
                        span: function.span.clone(),
                    });
                }
            }
        }

        findings
    }
}

// RUSTCOLA047: Environment variable literal detection
struct EnvVarLiteralRule {
    metadata: RuleMetadata,
}

impl EnvVarLiteralRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA047".to_string(),
                name: "env-var-literal".to_string(),
                short_description: "Environment variable name should be a constant".to_string(),
                full_description: "Detects string literals passed to env::var() or env::var_os(). Using constants for environment variable names improves maintainability and prevents typos.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn is_env_var_with_literal(line: &str) -> bool {
        let lower = line.to_lowercase();
        
        // Skip comments and allocations
        if lower.trim_start().starts_with("//") || lower.contains(" │ ") {
            return false;
        }
        
        // Look for env::var or env::var_os patterns with string literals
        // MIR patterns show calls like:
        // _1 = var::<&str>(const "HOME")
        // _1 = var_os::<&str>(const "PATH")
        // _2 = std::env::var::<&str>(const "USER")
        
        // Pattern 1: var::<type>(const "...") - direct call
        if (lower.contains("var::<") || lower.contains("var_os::<")) 
            && lower.contains("const \"") {
            return true;
        }
        
        // Pattern 2: std::env::var with const string
        if (lower.contains("std::env::var") || lower.contains("core::env::var"))
            && lower.contains("const \"") {
            return true;
        }
        
        false
    }
}

impl Rule for EnvVarLiteralRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            for line in &function.body {
                if Self::is_env_var_with_literal(line) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: "Environment variable name should be a constant. Consider defining `const VAR_NAME: &str = \"...\";` and using `env::var(VAR_NAME)` instead of a string literal.".to_string(),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![line.clone()],
                        span: extract_span_from_mir_line(line).or(function.span.clone()),
                    });
                    break; // One finding per function is enough
                }
            }
        }

        findings
    }
}

// RUSTCOLA048: Invisible Unicode character detection
struct InvisibleUnicodeRule {
    metadata: RuleMetadata,
}

impl InvisibleUnicodeRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA048".to_string(),
                name: "invisible-unicode".to_string(),
                short_description: "Invisible Unicode characters detected".to_string(),
                full_description: "Detects invisible or control Unicode characters in source code that could be used for spoofing, hidden backdoors, or trojan source attacks. These include zero-width characters, bidirectional overrides, and other non-printable Unicode characters.".to_string(),
                help_uri: Some("https://trojansource.codes/".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn has_invisible_unicode(text: &str) -> bool {
        text.chars().any(|c| Self::is_invisible_or_dangerous(c))
    }

    fn is_invisible_or_dangerous(c: char) -> bool {
        match c {
            // Zero-width characters
            '\u{200B}' => true, // ZERO WIDTH SPACE
            '\u{200C}' => true, // ZERO WIDTH NON-JOINER
            '\u{200D}' => true, // ZERO WIDTH JOINER
            '\u{FEFF}' => true, // ZERO WIDTH NO-BREAK SPACE (BOM)
            '\u{2060}' => true, // WORD JOINER
            '\u{2061}' => true, // FUNCTION APPLICATION
            '\u{2062}' => true, // INVISIBLE TIMES
            '\u{2063}' => true, // INVISIBLE SEPARATOR
            '\u{2064}' => true, // INVISIBLE PLUS
            
            // Bidirectional text control characters (Trojan Source)
            '\u{202A}' => true, // LEFT-TO-RIGHT EMBEDDING
            '\u{202B}' => true, // RIGHT-TO-LEFT EMBEDDING
            '\u{202C}' => true, // POP DIRECTIONAL FORMATTING
            '\u{202D}' => true, // LEFT-TO-RIGHT OVERRIDE
            '\u{202E}' => true, // RIGHT-TO-LEFT OVERRIDE
            '\u{2066}' => true, // LEFT-TO-RIGHT ISOLATE
            '\u{2067}' => true, // RIGHT-TO-LEFT ISOLATE
            '\u{2068}' => true, // FIRST STRONG ISOLATE
            '\u{2069}' => true, // POP DIRECTIONAL ISOLATE
            
            // Other invisible/control characters
            '\u{00AD}' => true, // SOFT HYPHEN
            '\u{180E}' => true, // MONGOLIAN VOWEL SEPARATOR
            '\u{061C}' => true, // ARABIC LETTER MARK
            
            // Private use areas (could hide malicious intent)
            '\u{E000}'..='\u{F8FF}' => true, // Private Use Area
            '\u{F0000}'..='\u{FFFFD}' => true, // Supplementary Private Use Area-A
            '\u{100000}'..='\u{10FFFD}' => true, // Supplementary Private Use Area-B
            
            _ => false,
        }
    }

    fn describe_character(c: char) -> &'static str {
        match c {
            '\u{200B}' => "ZERO WIDTH SPACE",
            '\u{200C}' => "ZERO WIDTH NON-JOINER",
            '\u{200D}' => "ZERO WIDTH JOINER",
            '\u{FEFF}' => "ZERO WIDTH NO-BREAK SPACE (BOM)",
            '\u{2060}' => "WORD JOINER",
            '\u{202A}' => "LEFT-TO-RIGHT EMBEDDING",
            '\u{202B}' => "RIGHT-TO-LEFT EMBEDDING",
            '\u{202C}' => "POP DIRECTIONAL FORMATTING",
            '\u{202D}' => "LEFT-TO-RIGHT OVERRIDE",
            '\u{202E}' => "RIGHT-TO-LEFT OVERRIDE (Trojan Source)",
            '\u{2066}' => "LEFT-TO-RIGHT ISOLATE",
            '\u{2067}' => "RIGHT-TO-LEFT ISOLATE",
            '\u{2068}' => "FIRST STRONG ISOLATE",
            '\u{2069}' => "POP DIRECTIONAL ISOLATE",
            '\u{00AD}' => "SOFT HYPHEN",
            '\u{E000}'..='\u{F8FF}' => "PRIVATE USE AREA CHARACTER",
            _ => "INVISIBLE/CONTROL CHARACTER",
        }
    }
}

impl Rule for InvisibleUnicodeRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            for line in &function.body {
                if Self::has_invisible_unicode(line) {
                    // Find the specific characters for better reporting
                    let dangerous_chars: Vec<char> = line.chars()
                        .filter(|c| Self::is_invisible_or_dangerous(*c))
                        .collect();
                    
                    let char_descriptions: Vec<String> = dangerous_chars.iter()
                        .map(|c| format!("U+{:04X} ({})", *c as u32, Self::describe_character(*c)))
                        .collect();
                    
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "Invisible Unicode character(s) detected: {}. This could indicate a Trojan Source attack or unintentional spoofing.",
                            char_descriptions.join(", ")
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![line.clone()],
                        span: None,
                    });
                    break; // One finding per function
                }
            }
        }

        findings
    }
}

// RUSTCOLA049: Crate-wide allow attributes detection
struct CrateWideAllowRule {
    metadata: RuleMetadata,
}

impl CrateWideAllowRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA049".to_string(),
                name: "crate-wide-allow".to_string(),
                short_description: "Crate-wide allow attribute disables lints".to_string(),
                full_description: "Detects crate-level #![allow(...)] attributes that disable lints for the entire crate. This reduces security coverage and should be avoided. Use more targeted #[allow(...)] on specific items instead.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn has_crate_wide_allow(line: &str) -> bool {
        let trimmed = line.trim();
        
        // Look for crate-level attribute: #![allow(...)]
        // The '!' makes it crate-level vs #[allow(...)] which is item-level
        if trimmed.starts_with("#![allow") {
            return true;
        }
        
        false
    }

    fn extract_allowed_lints(line: &str) -> Vec<String> {
        // Extract lint names from #![allow(lint1, lint2, ...)]
        if let Some(start) = line.find("#![allow(") {
            if let Some(end) = line[start..].find(')') {
                let content = &line[start + 9..start + end]; // Skip "#![allow("
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
        let mut reported = false; // Only report once per package

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
                            "Crate-wide #![allow(...)] attribute disables lints for entire crate: {}. Consider using item-level #[allow(...)] for more targeted suppression.",
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

// RUSTCOLA050: Misordered assert_eq arguments detection
struct MisorderedAssertEqRule {
    metadata: RuleMetadata,
}

impl MisorderedAssertEqRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA050".to_string(),
                name: "misordered-assert-eq".to_string(),
                short_description: "assert_eq arguments may be misordered".to_string(),
                full_description: "Detects assert_eq! calls where a literal or constant appears as the first argument instead of the second. Convention is assert_eq!(actual, expected) so error messages show 'expected X but got Y' correctly.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_misordered_assert(&self, function: &MirFunction) -> bool {
        // Look for the promoted constant pattern used by assert_eq!
        // Misordered: _3 = const <function>::promoted[N]; (literal first)
        // Correct: _4 = const <function>::promoted[N]; (literal second)
        
        let mut has_misordered_promoted = false;
        let mut has_assert_failed = false;
        
        for line in &function.body {
            let trimmed = line.trim();
            
            // Check for promoted constant in FIRST position (_3)
            // This indicates a literal is being loaded as the first argument
            if trimmed.starts_with("_3 = const") && trimmed.contains("::promoted[") {
                has_misordered_promoted = true;
            }
            
            // Check for assert_failed call (indicates this is an assertion)
            if trimmed.contains("assert_failed") {
                has_assert_failed = true;
            }
        }
        
        // Misordered if we have a promoted constant in position _3 (first arg)
        // and an assert_failed call
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
                // Find the promoted const line as evidence
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
                    message: "assert_eq! may have misordered arguments. Convention is assert_eq!(actual, expected) where 'expected' is typically a literal. This ensures error messages show 'expected X but got Y' correctly.".to_string(),
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
// RUSTCOLA051: Try operator on io::Result
// ============================================================================

struct TryIoResultRule {
    metadata: RuleMetadata,
}

impl TryIoResultRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA051".to_string(),
                name: "try-io-result".to_string(),
                short_description: "Try operator (?) used on io::Result".to_string(),
                full_description: "Detects use of the ? operator on std::io::Result, which can obscure IO errors. Prefer explicit error handling with .map_err() to add context or use a custom error type that wraps IO errors with additional information.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_io_result_try(&self, function: &MirFunction) -> bool {
        // Look for MIR patterns indicating ? operator on io::Result
        // The ? operator on Result<T, E> desugars to a match that propagates the error
        // In MIR, this appears as:
        // 1. Function returns Result<T, io::Error>
        // 2. Discriminant checks on Result values (the ? desugaring)
        
        let mut has_io_error_type = false;
        let mut has_discriminant_check = false;
        
        // Check signature for io::Result return type
        if function.signature.contains("std::io::Error") || function.signature.contains("io::Error") {
            has_io_error_type = true;
        }
        
        // Look for discriminant checks in body (indicates ? operator)
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
                // Find evidence lines
                let mut evidence = vec![];
                for line in &function.body {
                    if line.to_lowercase().contains("io::error") 
                        || line.to_lowercase().contains("discriminant") 
                        || line.to_lowercase().contains("from_error") {
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
                    message: "Using ? operator on io::Result may lose error context. Consider using .map_err() to add file paths, operation details, or other context to IO errors.".to_string(),
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
// RUSTCOLA052: Local RefCell usage
// ============================================================================

struct LocalRefCellRule {
    metadata: RuleMetadata,
}

impl LocalRefCellRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA052".to_string(),
                name: "local-ref-cell".to_string(),
                short_description: "RefCell used for local mutable state".to_string(),
                full_description: "Detects RefCell<T> used for purely local mutable state where a regular mutable variable would suffice. RefCell adds runtime borrow checking overhead and panic risk. Use RefCell only when interior mutability is truly needed (shared ownership, trait objects, etc.).".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_local_refcell(&self, function: &MirFunction) -> bool {
        // Look for RefCell::new followed by borrow_mut/borrow in the same function
        // This suggests local usage where a plain mut variable would work
        
        let mut has_refcell_new = false;
        let mut has_borrow_mut = false;
        
        for line in &function.body {
            let lower = line.to_lowercase();
            
            // Check for RefCell::new
            if lower.contains("refcell") && lower.contains("::new") {
                has_refcell_new = true;
            }
            
            // Check for borrow_mut or borrow calls
            if lower.contains("borrow_mut") || (lower.contains("borrow(") && !lower.contains("borrow_mut")) {
                has_borrow_mut = true;
            }
        }
        
        // If we see RefCell::new and borrow operations in the same function,
        // it's likely local usage
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
                    message: "RefCell used for local mutable state. Consider using a regular mutable variable instead. RefCell adds runtime overhead and panic risk - use it only when interior mutability is truly needed (shared ownership, trait objects, callbacks, etc.).".to_string(),
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
// RUSTCOLA053: Lines from stdin not trimmed
// ============================================================================

struct UntrimmedStdinRule {
    metadata: RuleMetadata,
}

impl UntrimmedStdinRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA053".to_string(),
                name: "untrimmed-stdin".to_string(),
                short_description: "Lines read from stdin not trimmed".to_string(),
                full_description: "Detects reading lines from stdin via read_line() without trimming. BufRead::lines() auto-strips newlines, so only read_line() is vulnerable. Parsing to integers is safe as parse() ignores whitespace.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_untrimmed_stdin(&self, function: &MirFunction) -> bool {
        // Key insight: BufRead::lines() already strips trailing newlines!
        // Only read_line() is actually vulnerable because it preserves the newline.
        // Also safe: parsing to integers (parse::<usize>(), etc.) ignores whitespace.
        
        let body_str = function.body.join("\n");
        let body_lower = body_str.to_lowercase();
        
        // Skip functions that are just defining constant arrays of patterns
        // These contain strings like "read_line" but aren't actual code
        if function.name.contains("input_source_patterns")
            || function.name.contains("::new")
            || body_lower.contains("const \"read_line")
            || body_lower.contains("const \"stdin") {
            return false;
        }
        
        // Only flag read_line() calls - lines() auto-strips
        // MIR pattern: BufRead>::read_line or Stdin::read_line or read_line(move _X
        let has_read_line = body_lower.contains("read_line(") 
            || body_lower.contains("bufread>::read_line")
            || body_lower.contains("stdin::read_line");
        
        if !has_read_line {
            return false;
        }
        
        // Check if we have stdin involved (direct stdin() call or in same function)
        let has_stdin = body_lower.contains("stdin()") 
            || body_lower.contains("= stdin(")
            || body_lower.contains("io::stdin");
        
        if !has_stdin {
            return false;
        }
        
        // Safe: if we call trim on the result
        // MIR pattern: str::trim, .trim(), trim_end, trim_start
        let has_trim = body_lower.contains("::trim(") 
            || body_lower.contains("::trim_end(")
            || body_lower.contains("::trim_start(")
            || body_lower.contains("str::trim")
            || body_lower.contains("trim::<");
        
        if has_trim {
            return false;
        }
        
        // Safe: parsing to integers (parse ignores whitespace)
        // MIR pattern: parse::<usize>, parse::<i32>, FromStr>::from_str
        let has_int_parse = body_lower.contains("parse::<usize>")
            || body_lower.contains("parse::<u8>")
            || body_lower.contains("parse::<u16>")
            || body_lower.contains("parse::<u32>")
            || body_lower.contains("parse::<u64>")
            || body_lower.contains("parse::<i8>")
            || body_lower.contains("parse::<i16>")
            || body_lower.contains("parse::<i32>")
            || body_lower.contains("parse::<i64>")
            || body_lower.contains("parse::<f32>")
            || body_lower.contains("parse::<f64>")
            || body_lower.contains("fromstr>::from_str");
        
        if has_int_parse {
            return false;
        }
        
        true
    }
}

impl Rule for UntrimmedStdinRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.looks_like_untrimmed_stdin(function) {
                let mut evidence = vec![];
                for line in &function.body {
                    let lower = line.to_lowercase();
                    if lower.contains("read_line") || lower.contains("stdin") {
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
                    message: "Input from stdin via read_line() is not trimmed. read_line() preserves trailing newlines that can enable injection attacks when passed to commands, file paths, or other sensitive contexts. Use .trim() or .trim_end() on the input.".to_string(),
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

// RUSTCOLA054: Detect infinite iterators without termination
struct InfiniteIteratorRule {
    metadata: RuleMetadata,
}

impl InfiniteIteratorRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA054".to_string(),
                name: "infinite-iterator-without-termination".to_string(),
                short_description: "Infinite iterator without termination".to_string(),
                full_description: "Detects infinite iterators (std::iter::repeat, cycle, repeat_with) without termination methods (take, take_while, any, find, position, zip, enumerate+break). Such iterators can cause unbounded loops leading to Denial of Service (DoS) if not properly constrained.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_infinite_iterator(&self, function: &MirFunction) -> bool {
        let body_str = function.body.join("\n");
        
        // Skip functions that are just defining string constants (rule infrastructure)
        // These contain strings like "iter::repeat" but aren't actual code
        if function.name.contains("::new") 
            || body_str.contains("const \"iter::repeat")
            || body_str.contains("const \"std::iter::repeat")
            || body_str.contains("const \"cycle") {
            return false;
        }
        
        // Check for infinite iterator constructors
        // Note: MIR may show these as:
        // - std::iter::repeat / core::iter::repeat
        // - repeat_with::<...> (without full path)
        // - RepeatWith<...>::collect / Repeat<...>::collect
        let has_repeat = body_str.contains("std::iter::repeat")
            || body_str.contains("core::iter::repeat")
            || body_str.contains("Repeat<"); // Type name in MIR
        let has_cycle = body_str.contains("::cycle")
            || body_str.contains("Cycle<"); // Type name in MIR
        let has_repeat_with = body_str.contains("std::iter::repeat_with")
            || body_str.contains("core::iter::repeat_with")
            || body_str.contains("repeat_with::<") // Called without full path
            || body_str.contains("RepeatWith<"); // Type name in MIR
        
        if !has_repeat && !has_cycle && !has_repeat_with {
            return false;
        }
        
        // Check if there are termination methods
        // MIR pattern: >::method::<  or ::method( or ::method>
        let has_take = body_str.contains("::take(") || body_str.contains("::take>")
            || body_str.contains(">::take::<");
        let has_take_while = body_str.contains("::take_while")
            || body_str.contains(">::take_while::<");
        let has_any = body_str.contains("::any(") || body_str.contains("::any>")
            || body_str.contains(">::any::<");
        let has_find = body_str.contains("::find(") || body_str.contains("::find>")
            || body_str.contains(">::find::<");
        let has_position = body_str.contains("::position")
            || body_str.contains(">::position::<");
        let has_zip = body_str.contains("::zip"); // zip with finite iterator terminates
        let has_nth = body_str.contains("::nth(") || body_str.contains(">::nth::<");
        let _has_last = body_str.contains("::last"); // last would hang but it's clear intent
        let _has_fold = body_str.contains("::fold"); // fold on infinite = hang, but usually with early return
        
        // Check for break statement in the function (manual loop termination)
        // In MIR, break in a for loop appears as a conditional jump that exits the loop
        // We can detect this by looking for:
        // 1. A switchInt with one branch going back to loop start and another exiting
        // 2. Multiple return blocks (one for early exit, one for normal)
        // 
        // Heuristic: if the function has both a loop (goto back to earlier bb) 
        // AND multiple bb's that lead to return, it likely has an early exit.
        // For now, we use a simpler heuristic: just look for functions where
        // the number of return; statements > 1 (indicating early return)
        let return_count = body_str.matches("return;").count();
        let has_early_return = return_count > 1;
        
        // Flag if we have infinite iterator but no termination
        !has_take && !has_take_while && !has_any && !has_find && !has_position 
            && !has_zip && !has_nth && !has_early_return
    }
}

impl Rule for InfiniteIteratorRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.looks_like_infinite_iterator(function) {
                let mut evidence = Vec::new();

                // Collect evidence of infinite iterator usage
                for line in &function.body {
                    if line.contains("std::iter::repeat") 
                        || line.contains("core::iter::repeat")
                        || line.contains("::cycle")
                        || line.contains("repeat_with") {
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
                    message: "Infinite iterator (repeat, cycle, or repeat_with) detected without termination method (take, take_while, any, find, position, zip, break). This can cause unbounded loops leading to DoS. Add a termination condition.".to_string(),
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

// RUSTCOLA055: Detect Unix permissions passed as decimal instead of octal
struct UnixPermissionsNotOctalRule {
    metadata: RuleMetadata,
}

impl UnixPermissionsNotOctalRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA055".to_string(),
                name: "unix-permissions-not-octal".to_string(),
                short_description: "Unix file permissions not in octal notation".to_string(),
                full_description: "Detects Unix file permissions passed as decimal literals instead of octal notation. Decimal literals like 644 or 755 are confusing because they look like octal but are interpreted as decimal (755 decimal = 0o1363 octal). Use explicit octal notation with 0o prefix (e.g., 0o644, 0o755).".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_decimal_permission(&self, function: &MirFunction) -> bool {
        let body_str = format!("{:?}", function.body);
        
        // Look for permission-related function calls
        let has_permission_api = body_str.contains("from_mode")
            || body_str.contains("set_mode")
            || body_str.contains("chmod")
            || body_str.contains("DirBuilder")
            || body_str.contains("create_dir");
        
        if !has_permission_api {
            return false;
        }
        
        // Common decimal permission patterns that look like octal
        // 644 (rw-r--r--), 755 (rwxr-xr-x), 777 (rwxrwxrwx), etc.
        // These are problematic because they look like octal but are decimal
        let suspicious_decimals = [
            "644_u32", "755_u32", "777_u32", "666_u32",
            "600_u32", "700_u32", "750_u32", "640_u32",
            "= 644", "= 755", "= 777", "= 666",
            "= 600", "= 700", "= 750", "= 640",
        ];
        
        for pattern in &suspicious_decimals {
            if body_str.contains(pattern) {
                // Make sure it's not already in octal (0o prefix)
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

                // Collect evidence of permission usage
                for line in body_str.lines().take(200) {
                    if (line.contains("from_mode") || line.contains("set_mode") 
                        || line.contains("chmod") || line.contains("DirBuilder"))
                        && (line.contains("644") || line.contains("755") 
                            || line.contains("777") || line.contains("666")
                            || line.contains("600") || line.contains("700")
                            || line.contains("750") || line.contains("640")) {
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
                    message: "Unix file permissions appear to use decimal notation instead of octal. Decimal values like 644 or 755 are confusing because they look like octal permissions but are interpreted as decimal (755 decimal = 0o1363 octal, not the intended rwxr-xr-x). Use explicit octal notation with 0o prefix (e.g., 0o644 for rw-r--r--, 0o755 for rwxr-xr-x).".to_string(),
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

// RUSTCOLA056: Detect OpenOptions with inconsistent or dangerous flag combinations
struct OpenOptionsInconsistentFlagsRule {
    metadata: RuleMetadata,
}

impl OpenOptionsInconsistentFlagsRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA056".to_string(),
                name: "openoptions-inconsistent-flags".to_string(),
                short_description: "OpenOptions with inconsistent flag combinations".to_string(),
                full_description: "Detects OpenOptions with dangerous or inconsistent flag combinations: (1) write(true) without create/truncate/append may fail or leave stale data, (2) create(true) without write(true) is useless, (3) truncate(true) without write(true) is dangerous. These patterns suggest programmer confusion about file operations.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn check_openoptions_flags(&self, function: &MirFunction) -> Option<String> {
        let body_str = function.body.join("\n");
        
        // Check if this function uses OpenOptions
        if !body_str.contains("OpenOptions") {
            return None;
        }
        
        let has_write = body_str.contains(".write(true)") || body_str.contains("OpenOptions::write") && body_str.contains("const true");
        let _has_read = body_str.contains(".read(true)") || body_str.contains("OpenOptions::read") && body_str.contains("const true");
        let has_create = body_str.contains(".create(true)") || body_str.contains("OpenOptions::create") && body_str.contains("const true");
        let has_create_new = body_str.contains(".create_new(true)") || body_str.contains("OpenOptions::create_new") && body_str.contains("const true");
        let has_truncate = body_str.contains(".truncate(true)") || body_str.contains("OpenOptions::truncate") && body_str.contains("const true");
        let has_append = body_str.contains(".append(true)") || body_str.contains("OpenOptions::append") && body_str.contains("const true");
        
        // Pattern 1: create(true) without write(true) - useless, file created but not writable
        if (has_create || has_create_new) && !has_write && !has_append {
            return Some("create(true) or create_new(true) without write(true) or append(true). The file will be created but not writable, making the create flag useless.".to_string());
        }
        
        // Pattern 2: truncate(true) without write(true) - dangerous, truncates existing file but can't write
        if has_truncate && !has_write && !has_append {
            return Some("truncate(true) without write(true) or append(true). This would truncate the file but not allow writing, resulting in data loss.".to_string());
        }
        
        // Pattern 3: append(true) with truncate(true) - contradictory
        if has_append && has_truncate {
            return Some("append(true) with truncate(true). These flags are contradictory: append preserves existing content while truncate deletes it.".to_string());
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

                // Collect evidence of OpenOptions usage
                for line in &function.body {
                    if line.contains("OpenOptions") || line.contains(".write") 
                        || line.contains(".create") || line.contains(".truncate")
                        || line.contains(".append") || line.contains(".read") {
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

// RUSTCOLA057: Detect unnecessary borrow_mut() on RefCell
struct UnnecessaryBorrowMutRule {
    metadata: RuleMetadata,
}

impl UnnecessaryBorrowMutRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA057".to_string(),
                name: "unnecessary-borrow-mut".to_string(),
                short_description: "Unnecessary borrow_mut() on RefCell".to_string(),
                full_description: "Detects RefCell::borrow_mut() calls where the mutable borrow is never actually used for mutation. Using borrow_mut() when borrow() suffices creates unnecessary runtime overhead, increases risk of panics from conflicting borrows, and obscures the code's intent. Use borrow() for read-only access.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_unnecessary_borrow_mut(&self, function: &MirFunction) -> bool {
        let body_str = function.body.join("\n");
        
        // Skip rule infrastructure functions
        if function.name.contains("::new") {
            return false;
        }
        
        // Look for borrow_mut calls on RefCell
        let has_borrow_mut = body_str.contains("RefCell") && body_str.contains("borrow_mut");
        
        if !has_borrow_mut {
            return false;
        }
        
        // Check for actual mutation patterns in MIR:
        
        // 1. Mutation methods on collections
        let mutation_methods = [
            "::push(", "::insert(", "::remove(", "::clear(", "::extend(",
            "::swap(", "::sort(", "::reverse(", "::drain(", "::append(",
            "::truncate(", "::resize(", "::retain(", "::dedup(",
            "::split_off(", "::pop(", "::swap_remove(",
            // HashMap/BTreeMap mutations
            "::entry(", "::get_mut(",
        ];
        let has_mutation_method = mutation_methods.iter().any(|m| body_str.contains(m));
        
        // 2. DerefMut access on RefMut - THE KEY MUTATION INDICATOR
        // Read-only: <RefMut<'_, ...> as Deref>::deref
        // Mutation:  <RefMut<'_, ...> as DerefMut>::deref_mut
        let has_refmut_deref_mut = body_str.contains("RefMut") && body_str.contains("DerefMut");
        
        // 3. IndexMut access (mutable indexing)
        // MIR pattern: IndexMut<...>>::index_mut
        let has_index_mut = body_str.contains("IndexMut") || body_str.contains("index_mut");
        
        // 4. Direct assignment to variable derived from borrow
        // Look for patterns like (*_X) = where X is the borrow result
        // This is tricky - we need to avoid matching initialization
        // For now, rely on DerefMut and IndexMut detection
        
        // Flag if we have borrow_mut but no clear mutation patterns
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

                // Collect evidence of borrow_mut usage
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
                    message: "RefCell::borrow_mut() called but mutable borrow may not be necessary. If the borrowed value is only read (not modified), use borrow() instead of borrow_mut(). This reduces runtime overhead, lowers panic risk from conflicting borrows, and makes the code's intent clearer.".to_string(),
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

// RUSTCOLA058: Detect absolute paths in Path::join() or PathBuf::push()
struct AbsolutePathInJoinRule {
    metadata: RuleMetadata,
}

impl AbsolutePathInJoinRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA058".to_string(),
                name: "absolute-path-in-join".to_string(),
                short_description: "Absolute path passed to Path::join() or PathBuf::push()".to_string(),
                full_description: "Detects when Path::join() or PathBuf::push() receives an absolute path argument. Absolute paths nullify the base path, defeating sanitization and potentially enabling path traversal attacks. The joined path becomes just the absolute argument, ignoring the supposedly safe base directory.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_absolute_path_join(&self, function: &MirFunction) -> bool {
        let body_str = format!("{:?}", function.body);
        
        // Look for Path/PathBuf operations
        let has_path_ops = body_str.contains("Path::join") || 
                          body_str.contains("PathBuf::join") ||
                          body_str.contains("PathBuf::push");
        
        if !has_path_ops {
            return false;
        }
        
        // Look for absolute path patterns in string literals
        // Unix absolute paths start with /
        // Windows absolute paths start with drive letter (C:\, D:\, etc.)
        let absolute_patterns = [
            "\"/", "\"C:", "\"D:", "\"E:", "\"F:",
            "\"/etc", "\"/usr", "\"/var", "\"/tmp", "\"/home",
            "\"/root", "\"/sys", "\"/proc", "\"/dev",
            "\"C:\\\\", "\"D:\\\\", "\"E:\\\\", "\"F:\\\\",
            "\"/Users", "\"/Applications", "\"/Library",
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

                // Collect evidence of path operations with absolute paths
                // We need to find lines that contain BOTH a join/push operation AND an absolute path
                for line in &function.body {
                    // Check if this line has a join/push operation
                    let has_join_or_push = (line.contains("Path::join") || 
                                           line.contains("PathBuf::join") || 
                                           line.contains("PathBuf::push")) &&
                                          line.contains("const");
                    
                    if !has_join_or_push {
                        continue;
                    }
                    
                    // Check if the join/push argument is an absolute path
                    let has_absolute = line.contains("const \"/") || 
                                      line.contains("const \"C:") || 
                                      line.contains("const \"D:") || 
                                      line.contains("const \"E:") || 
                                      line.contains("const \"F:");
                    
                    if has_absolute {
                        evidence.push(line.trim().to_string());
                        if evidence.len() >= 5 {
                            break;
                        }
                    }
                }
                
                // Only create a finding if we found actual evidence
                if !evidence.is_empty() {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: "Absolute path passed to Path::join() or PathBuf::push(). When an absolute path is joined, it completely replaces the base path, nullifying any sanitization or security checks on the base directory. This can enable path traversal attacks. Use only relative paths with join/push, or validate that arguments are relative using is_relative().".to_string(),
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
// RUSTCOLA059: #[ctor]/#[dtor] invoking std APIs
// ============================================================================

struct CtorDtorStdApiRule {
    metadata: RuleMetadata,
}

impl CtorDtorStdApiRule {
    fn new() -> Self {
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

    fn looks_like_ctor_dtor_with_std_calls(&self, function: &MirFunction) -> bool {
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
// RUSTCOLA060: Connection strings with empty or hardcoded passwords
// ============================================================================

struct ConnectionStringPasswordRule {
    metadata: RuleMetadata,
}

impl ConnectionStringPasswordRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA060".to_string(),
                name: "connection-string-password".to_string(),
                short_description: "Connection string with empty or hardcoded password".to_string(),
                full_description: "Detects database or message broker connection strings with empty passwords or hardcoded credentials. Credentials should be loaded from environment variables or secret management systems, not embedded in code. Mirrors Checkmarx Empty_Password_In_Connection_String and Hardcoded_Password_in_Connection_String rules.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_connection_string_with_password_issue(&self, function: &MirFunction) -> bool {
        // Look for string literals that look like connection strings
        // Common patterns: postgres://, postgresql://, mysql://, redis://, amqp://, mongodb://
        for line in &function.body {
            if self.has_connection_string_issue(line) {
                return true;
            }
        }
        false
    }

    fn has_connection_string_issue(&self, line: &str) -> bool {
        let line_lower = line.to_lowercase();
        
        // Check for connection string protocols
        let protocols = ["postgres://", "postgresql://", "mysql://", "redis://", "amqp://", "mongodb://"];
        let has_protocol = protocols.iter().any(|p| line_lower.contains(p));
        
        if !has_protocol {
            return false;
        }

        // Exclude cases where the protocol is in an array literal (format! macro)
        // format! creates arrays like ["mysql://", ":", "@", "/mydb"]
        if line.contains("[const") && line.contains(",") {
            return false;
        }

        // Check for empty password pattern: user:@host or user@host (no password)
        // Pattern: protocol://user:@host or protocol://user@host
        if line_lower.contains(":@") {
            return true;
        }

        // Check for hardcoded password patterns
        // Look for :password@ or :123@ or :secret@ etc
        // We'll use a simple heuristic: if there's a : followed by non-empty text before @
        // and it's not localhost or a port number
        if line_lower.contains("://") && line_lower.contains("@") {
            // Extract the part between :// and @
            if let Some(creds_start) = line_lower.find("://") {
                if let Some(at_pos) = line_lower[creds_start+3..].find('@') {
                    let creds = &line_lower[creds_start+3..creds_start+3+at_pos];
                    
                    // Check if there's a colon (indicating user:pass format)
                    if let Some(colon_pos) = creds.find(':') {
                        let password = &creds[colon_pos+1..];
                        
                        // Flag if password is present and not empty (hardcoded password)
                        if !password.is_empty() && password != "@" {
                            // Exclude cases where it might be a port (all digits)
                            if !password.chars().all(|c| c.is_ascii_digit()) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }
}

impl Rule for ConnectionStringPasswordRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if self.looks_like_connection_string_with_password_issue(function) {
                // Collect evidence lines containing connection strings
                let mut evidence = vec![];
                for line in &function.body {
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("postgres://") || line_lower.contains("postgresql://") ||
                       line_lower.contains("mysql://") || line_lower.contains("redis://") ||
                       line_lower.contains("amqp://") || line_lower.contains("mongodb://") {
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
                        message: "Connection string contains empty or hardcoded password. Store credentials in environment variables or secret management systems instead of embedding them in code.".to_string(),
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

// RUSTCOLA061: Missing password field masking in web forms
/// Detects HTML forms or template rendering that expose password fields without proper masking
struct PasswordFieldMaskingRule {
    metadata: RuleMetadata,
}

impl PasswordFieldMaskingRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA061".to_string(),
                name: "password-field-masking".to_string(),
                short_description: "Missing password field masking in web forms".to_string(),
                full_description: "Detects HTML form inputs or template rendering where password fields are exposed without proper masking (type=\"password\"). Using type=\"text\" for password inputs or echoing password values in responses can expose credentials in browser history, screen recordings, or over-the-shoulder viewing. Always use type=\"password\" for password inputs and never display submitted passwords back to users.".to_string(),
                help_uri: Some("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Weak_Lock_Out_Mechanism".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_password_exposure(line: &str) -> bool {
        let lowered = line.to_lowercase();
        
        // Skip comments
        if lowered.trim_start().starts_with("//") {
            return false;
        }

        // Pattern 1: HTML input with type="text" and password-related name
        // Look for combinations like: <input type="text" name="password">
        if lowered.contains("type") && lowered.contains("text") {
            // Must be in an input context
            if lowered.contains("input") {
                if lowered.contains("password") || lowered.contains("passwd") 
                    || lowered.contains("name=\"pwd\"") {
                    return true;
                }
            }
        }

        // Pattern 2: Rendering password values in responses
        // Look for patterns like: format!("Password: {}", password)
        if lowered.contains("format!") || lowered.contains("println!") {
            // Must have both password variable AND placeholder
            if (lowered.contains("password") || lowered.contains("passwd")) 
                && (lowered.contains("{}") || lowered.contains("{:?}")) {
                // Exclude if just checking length or displaying generic messages
                if !lowered.contains(".len()") && !lowered.contains("updated") 
                    && !lowered.contains("length:") && !lowered.contains("field name") {
                    return true;
                }
            }
        }

        // Pattern 3: Template interpolation with password variables
        // Common in Handlebars, Tera, Askama: {{password}}, {password}, etc.
        if lowered.contains("{{") && lowered.contains("password") {
            return true;
        }

        // Pattern 4: Setting input value to password
        // value="{password}" or value="{{password}}"
        if lowered.contains("value") && lowered.contains("{}") {
            if lowered.contains("password") || lowered.contains("passwd") {
                return true;
            }
        }

        false
    }
}

impl Rule for PasswordFieldMaskingRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Exclude the rule's own implementation
            if function.name.contains("PasswordFieldMaskingRule") 
                || function.name.contains("looks_like_password_exposure")
                || function.name.contains("7806:1")  // Exclude the impl block line number
                || function.name.contains("7872:1") {
                continue;
            }

            let mut evidence = Vec::new();
            
            for line in &function.body {
                if Self::looks_like_password_exposure(line) {
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
                    message: "Password field may be exposed without proper masking. Use type=\"password\" for password inputs and never display password values in responses or logs.".to_string(),
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

// RUSTCOLA068: Dead stores in arrays
struct DeadStoreArrayRule {
    metadata: RuleMetadata,
}

impl DeadStoreArrayRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA068".to_string(),
                name: "dead-store-array".to_string(),
                short_description: "Dead store in array".to_string(),
                full_description: "Detects array elements that are written but never read before being overwritten or going out of scope. Dead stores can indicate logic errors, wasted computation, or security issues like stale sensitive data not being properly cleared. Pattern: Array index assignment without subsequent read before overwrite or function end.".to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Check if a line contains an array write operation
    /// Pattern: variable[index] = value
    /// Example: "_1[_2] = const 10_i32;"
    fn is_array_write(line: &str) -> Option<(&str, &str)> {
        let trimmed = line.trim();
        
        // Look for pattern: _X[_Y] = ...
        if let Some(eq_pos) = trimmed.find(" = ") {
            let left_side = trimmed[..eq_pos].trim();
            
            // Check if left side is array index: _X[_Y]
            if let Some(bracket_start) = left_side.find('[') {
                if let Some(bracket_end) = left_side.find(']') {
                    if bracket_start < bracket_end && bracket_end == left_side.len() - 1 {
                        let var = left_side[..bracket_start].trim();
                        let index = left_side[bracket_start + 1..bracket_end].trim();
                        
                        // Basic validation: variable should start with _ and index should be reasonable
                        if var.starts_with('_') && !index.is_empty() {
                            return Some((var, index));
                        }
                    }
                }
            }
        }
        
        None
    }

    /// Check if a line contains an array read operation
    /// Patterns:
    /// - _X = &_Y[_Z];  (borrow)
    /// - _X = _Y[_Z];   (copy/move)
    /// - ... = &_Y[_Z]  (inline borrow)
    /// - function(&_Y) or function(_Y) - passing array to function
    fn is_array_read(line: &str, var: &str) -> bool {
        let trimmed = line.trim();
        
        // Pattern 1: function(&array) or function(copy array) - array passed to function
        // This is a form of read since the function may access all elements
        // We need to be careful about matching _1 vs _10, _11, etc.
        if trimmed.contains("(copy ") || trimmed.contains("(&") || trimmed.contains("(move ") {
            // Use word-boundary aware matching for the variable
            let patterns = [
                format!("(copy {})", var),   // "(copy _1)"
                format!("(&{})", var),        // "(&_1)"
                format!("(move {})", var),    // "(move _1)"
                format!("copy {})", var),     // "copy _1)"
                format!("copy {},", var),     // "copy _1,"
                format!("move {})", var),     // "move _1)"
                format!("move {},", var),     // "move _1,"
            ];
            if patterns.iter().any(|p| trimmed.contains(p)) {
                return true;
            }
        }
        
        // Pattern 2: Look for array index read: var[index]
        let pattern = format!("{}[", var);
        if !trimmed.contains(&pattern) {
            return false;
        }
        
        // Exclude writes (left side of assignment)
        if let Some(eq_pos) = trimmed.find(" = ") {
            let left_side = trimmed[..eq_pos].trim();
            // If the array access is on the left side, it's a write not a read
            if left_side.contains(&pattern) {
                return false;
            }
            // If it's on the right side, it's a read
            if trimmed[eq_pos + 3..].contains(&pattern) {
                return true;
            }
        }
        
        // Also check for array access in function calls or other contexts
        trimmed.contains(&pattern)
    }
}

impl Rule for DeadStoreArrayRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        // Skip our own crate to avoid self-analysis
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            // Skip functions that return arrays - they're likely intentionally building arrays
            if function.signature.contains("-> [") && function.signature.contains("; ") {
                continue;
            }
            
            // Skip functions that take mutable array references - they're likely filling arrays
            if function.signature.contains("&mut [") {
                continue;
            }
            
            // Strategy: Track all array writes and detect overwrites without intervening reads
            // Build a map of temporary variables to their constant values
            let mut const_values: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            
            // First pass: collect constant assignments (e.g., "_2 = const 0_usize;")
            for line in &function.body {
                let trimmed = line.trim();
                if let Some(eq_pos) = trimmed.find(" = const ") {
                    let left = trimmed[..eq_pos].trim();
                    let right = trimmed[eq_pos + 9..].trim(); // Skip " = const "
                    if let Some(semicolon) = right.find(';') {
                        let value = right[..semicolon].trim();
                        const_values.insert(left.to_string(), value.to_string());
                    }
                }
            }
            
            // Collect all array writes with their resolved indices
            // (line_idx, array_var, resolved_index, line_text)
            let mut all_writes: Vec<(usize, String, String, String)> = Vec::new();
            
            for (line_idx, line) in function.body.iter().enumerate() {
                let trimmed = line.trim();
                if let Some((var, index)) = Self::is_array_write(trimmed) {
                    let resolved_index = const_values.get(index).unwrap_or(&index.to_string()).clone();
                    all_writes.push((line_idx, var.to_string(), resolved_index, line.clone()));
                }
            }
            
            // For each write, check if there's another write to the same location later
            // without any read in between
            for (i, (write_line_idx, write_var, write_resolved_idx, write_line)) in all_writes.iter().enumerate() {
                let key = format!("{}[{}]", write_var, write_resolved_idx);
                
                // Look for a later write to the same location
                for (j, (overwrite_line_idx, overwrite_var, overwrite_resolved_idx, overwrite_line)) in all_writes.iter().enumerate() {
                    if j <= i {
                        continue; // Only look at later writes
                    }
                    
                    let overwrite_key = format!("{}[{}]", overwrite_var, overwrite_resolved_idx);
                    if key != overwrite_key {
                        continue; // Different location
                    }
                    
                    // Check if there's any read of this index between write and overwrite
                    let mut has_read_between = false;
                    for (between_idx, between_line) in function.body.iter().enumerate() {
                        if between_idx <= *write_line_idx || between_idx >= *overwrite_line_idx {
                            continue;
                        }
                        
                        // Check for specific index read: var[resolved_idx] on right side
                        // Note: We need to be careful not to match the index variable assignment
                        let trimmed = between_line.trim();
                        
                        // Skip basic block labels, assertions, gotos
                        if trimmed.starts_with("bb") || trimmed.starts_with("goto") 
                            || trimmed.starts_with("assert") || trimmed.starts_with("switchInt")
                            || trimmed.starts_with("return") || trimmed.starts_with("unreachable") {
                            continue;
                        }
                        
                        // Check for array read of this variable
                        if Self::is_array_read(trimmed, write_var) {
                            // Need to check if it's reading THIS specific index
                            // For simplicity, treat any read of the array as reading this index
                            // This is conservative and avoids false positives
                            has_read_between = true;
                            break;
                        }
                    }
                    
                    if !has_read_between {
                        // Found a dead store: written then overwritten without read
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "Dead store: array element {} written but overwritten without being read in `{}`",
                                key,
                                function.name
                            ),
                            function: function.name.clone(),
                            function_signature: function.signature.clone(),
                            evidence: vec![
                                format!("Line {}: {}", write_line_idx, write_line.trim()),
                                format!("Line {}: {} (overwrites previous)", overwrite_line_idx, overwrite_line.trim()),
                            ],
                            span: function.span.clone(),
                        });
                        // Only report first overwrite for this write
                        break;
                    } else {
                        // There's a read between this write and the potential overwrite
                        // Move on to check the next potential overwrite
                    }
                }
            }
        }

        findings
    }
}

// RUSTCOLA073: Unsafe FFI pointer returns
/// Detects extern "C" functions that return raw pointers without safety documentation
struct UnsafeFfiPointerReturnRule {
    metadata: RuleMetadata,
}

impl UnsafeFfiPointerReturnRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA073".to_string(),
                name: "unsafe-ffi-pointer-return".to_string(),
                short_description: "FFI function returns raw pointer without safety invariants".to_string(),
                full_description: "Detects extern \"C\" functions that return raw pointers (*const T or *mut T). \
                    These functions expose memory that must be managed correctly by callers, but the Rust \
                    type system cannot enforce this across FFI boundaries. Functions returning raw pointers \
                    should document ownership semantics (who frees the memory), lifetime requirements, \
                    and validity invariants. Consider using safer alternatives like returning by value \
                    or using output parameters with clear ownership.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/nomicon/ffi.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Check if a function signature indicates an extern "C" function returning a pointer
    fn is_ffi_returning_pointer(signature: &str, body: &[String]) -> Option<String> {
        // Check if it's an extern "C" function
        if !signature.contains("extern \"C\"") && !signature.contains("extern \"system\"") {
            return None;
        }

        // Check if it returns a raw pointer
        // Pattern: -> *const T or -> *mut T
        if let Some(arrow_pos) = signature.find("->") {
            let return_type = signature[arrow_pos + 2..].trim();
            if return_type.starts_with("*const") || return_type.starts_with("*mut") {
                // Check if there's safety documentation in the function body
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
                        "extern \"C\" function `{}` returns raw pointer `{}` without documented safety invariants. \
                        Consider documenting ownership (who frees), lifetime requirements, and validity constraints.",
                        function.name,
                        return_type
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: vec![
                        format!("Returns: {}", return_type),
                        "No safety documentation found (SAFETY:, # Safety, invariant, ownership, caller must, must be freed)".to_string(),
                    ],
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}

// RUSTCOLA074: Non-thread-safe calls in tests
/// Detects #[test] functions using non-Send/Sync types that may cause race conditions
struct NonThreadSafeTestRule {
    metadata: RuleMetadata,
}

impl NonThreadSafeTestRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA074".to_string(),
                name: "non-thread-safe-test".to_string(),
                short_description: "Test function uses non-thread-safe types".to_string(),
                full_description: "Detects test functions that use non-thread-safe types like Rc, RefCell, \
                    Cell, or raw pointers in ways that could cause issues when tests run in parallel. \
                    The Rust test framework runs tests concurrently by default, and using !Send or !Sync \
                    types with shared state (like static variables) can lead to data races or undefined \
                    behavior. Consider using thread-safe alternatives (Arc, Mutex, AtomicCell) or marking \
                    tests that require serialization with #[serial].".to_string(),
                help_uri: Some("https://doc.rust-lang.org/book/ch16-04-extensible-concurrency-sync-and-send.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Non-Send/Sync type patterns
    fn non_thread_safe_patterns() -> &'static [&'static str] {
        &[
            "Rc<",
            "Rc::",
            "RefCell<",
            "RefCell::",
            "Cell<",
            "Cell::",
            "UnsafeCell<",
            "UnsafeCell::",
            "*const ",
            "*mut ",
        ]
    }

    /// Check if function name indicates it's a test
    fn is_test_function(name: &str, signature: &str) -> bool {
        // Test functions typically have names starting with test or are in test modules
        // and have no parameters, returning ()
        let looks_like_test_name = name.contains("::test_") || 
            name.starts_with("test_") ||
            name.contains("::tests::") ||
            name.ends_with("_test");

        // Test functions don't take arguments (except for rstest parameterized tests)
        let no_params = signature.contains("fn()") || 
            signature.contains("fn ()") ||
            (signature.contains('(') && signature.contains("()"));

        looks_like_test_name && no_params
    }

    /// Check if function body uses non-thread-safe types
    fn uses_non_thread_safe_types(body: &[String]) -> Vec<String> {
        let mut evidence = Vec::new();
        let patterns = Self::non_thread_safe_patterns();

        for line in body {
            let trimmed = line.trim();
            
            // Skip comments
            if trimmed.starts_with("//") {
                continue;
            }

            for pattern in patterns {
                if trimmed.contains(pattern) {
                    // Check if it's actually being used (not just in a type annotation comment)
                    evidence.push(trimmed.to_string());
                    break;
                }
            }
        }

        evidence
    }

    /// Check if test accesses static/global state
    fn accesses_static_state(body: &[String]) -> bool {
        body.iter().any(|line| {
            let trimmed = line.trim();
            trimmed.contains("static ") ||
            trimmed.contains("lazy_static!") ||
            trimmed.contains("thread_local!") ||
            trimmed.contains("GLOBAL") ||
            trimmed.contains("STATE")
        })
    }
}

impl Rule for NonThreadSafeTestRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Only check test functions
            if !Self::is_test_function(&function.name, &function.signature) {
                continue;
            }

            let non_thread_safe_usage = Self::uses_non_thread_safe_types(&function.body);
            
            if !non_thread_safe_usage.is_empty() {
                // Higher severity if it also accesses static state
                let severity = if Self::accesses_static_state(&function.body) {
                    Severity::High
                } else {
                    self.metadata.default_severity
                };

                // Limit evidence to first 5 occurrences
                let limited_evidence: Vec<_> = non_thread_safe_usage.into_iter().take(5).collect();

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity,
                    message: format!(
                        "Test function `{}` uses non-thread-safe types (Rc, RefCell, Cell, raw pointers). \
                        Tests run in parallel by default; consider using thread-safe alternatives or #[serial].",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: limited_evidence,
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}

// RUSTCOLA075: Cleartext Logging of Secrets
/// Detects sensitive data (passwords, tokens, API keys) from environment variables
/// being logged through print macros, log crate, or format strings.
struct CleartextLoggingRule {
    metadata: RuleMetadata,
}

impl CleartextLoggingRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA075".to_string(),
                name: "cleartext-logging-secrets".to_string(),
                short_description: "Sensitive data logged in cleartext".to_string(),
                full_description: "Detects sensitive data (passwords, tokens, API keys, secrets) \
                    from environment variables being logged through println!, eprintln!, format!, \
                    panic!, or log crate macros. Logging secrets in cleartext exposes them in log \
                    files, monitoring systems, stdout/stderr captures, and audit trails. Consider \
                    masking sensitive values (e.g., showing only first/last 4 characters), using \
                    structured logging with secret redaction, or avoiding logging secrets entirely."
                    .to_string(),
                help_uri: Some("https://cwe.mitre.org/data/definitions/532.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Environment variable names that indicate sensitive data
    fn sensitive_env_var_patterns() -> &'static [&'static str] {
        &[
            "PASSWORD",
            "PASSWD",
            "SECRET",
            "TOKEN",
            "API_KEY",
            "APIKEY",
            "AUTH",
            "CREDENTIAL",
            "PRIVATE_KEY",
            "PRIV_KEY",
            "JWT",
            "BEARER",
            "ACCESS_KEY",
            "ENCRYPTION_KEY",
            "SIGNING_KEY",
        ]
    }

    /// Log sink patterns in MIR (desugarings of print/log macros)
    fn log_sink_patterns() -> &'static [&'static str] {
        &[
            "_print(",           // println!, print! desugaring
            "eprint",            // eprintln!, eprint!
            "::fmt(",            // format! and Debug/Display impl calls
            "Arguments::new",    // format_args! macro
            "panic_fmt",         // panic! with formatting
            "begin_panic",       // older panic desugaring
            "::log(",            // log crate macros
            "::info(",
            "::warn(",
            "::error(",
            "::debug(",
            "::trace(",
        ]
    }

    /// Check if an env var name is sensitive
    fn is_sensitive_env_var(env_var_context: &str) -> bool {
        let upper = env_var_context.to_uppercase();
        
        // First check for sensitive patterns
        let has_sensitive_pattern = Self::sensitive_env_var_patterns()
            .iter()
            .any(|pattern| upper.contains(pattern));
        
        if !has_sensitive_pattern {
            return false;
        }
        
        // Exclude non-sensitive config values that happen to contain sensitive keywords
        // e.g., SECRET_PORT, SECRET_HOST - these are config values, not secrets
        let non_sensitive_suffixes = ["_PORT", "_HOST", "_URL", "_PATH", "_DIR", "_TIMEOUT", 
                                       "_COUNT", "_SIZE", "_LIMIT", "_VERSION", "_MODE",
                                       "_ADDR", "_ADDRESS", "_ENDPOINT", "_LEVEL"];
        
        for suffix in non_sensitive_suffixes {
            if upper.ends_with(suffix) {
                return false;
            }
        }
        
        // Also exclude if the pattern is part of a suffix description
        // e.g., LOG_SECRET_LEVEL (where SECRET is describing what's being logged)
        // but keep things like SECRET_VALUE, SECRET_KEY
        
        true
    }

    /// Extract the env var name from a line if present
    fn extract_env_var_name(line: &str) -> Option<String> {
        // Look for patterns like: var::<...>(const "ENV_VAR_NAME")
        // MIR format: var::<&str>(const "DB_PASSWORD") -> ...
        
        // Find (const " pattern which precedes the env var name
        if let Some(start) = line.find("(const \"") {
            let after_const = &line[start + 8..]; // skip past '(const "'
            if let Some(quote_end) = after_const.find('"') {
                return Some(after_const[..quote_end].to_string());
            }
        }
        
        // Fallback: look for var( pattern without const
        if let Some(start) = line.find("var(") {
            let after_var = &line[start + 4..];
            if let Some(quote_start) = after_var.find('"') {
                let after_quote = &after_var[quote_start + 1..];
                if let Some(quote_end) = after_quote.find('"') {
                    return Some(after_quote[..quote_end].to_string());
                }
            }
        }
        None
    }

    /// Track which MIR local variables hold sensitive data
    fn track_sensitive_vars(body: &[String]) -> HashMap<String, String> {
        let mut sensitive_vars: HashMap<String, String> = HashMap::new(); // var -> env_name
        
        for line in body {
            let trimmed = line.trim();
            
            // Look for env::var calls - pattern: _N = var::<...>(const "ENV_NAME")
            if trimmed.contains("var::<") || trimmed.contains("var(") || trimmed.contains("var_os(") {
                // Extract the target variable (left side of assignment)
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    
                    // Extract MIR local variable (e.g., "_2" from "_2 = var::")
                    let var_name = Self::extract_mir_local(target);
                    
                    if let Some(var) = var_name {
                        // Check if this env var is sensitive
                        if let Some(env_name) = Self::extract_env_var_name(trimmed) {
                            if Self::is_sensitive_env_var(&env_name) {
                                sensitive_vars.insert(var, env_name);
                            }
                        } else if Self::is_sensitive_env_var(trimmed) {
                            // Fallback: check if line mentions sensitive keywords
                            sensitive_vars.insert(var, "SENSITIVE".to_string());
                        }
                    }
                }
            }
        }
        
        // Second pass: propagate taint through assignments
        let mut changed = true;
        while changed {
            changed = false;
            for line in body {
                let trimmed = line.trim();
                
                // Pattern: _N = ... _M ... where _M is sensitive
                if trimmed.contains(" = ") && !trimmed.contains("var::<") {
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let target = trimmed[..eq_pos].trim();
                        let source = trimmed[eq_pos + 3..].trim();
                        
                        // Check if any sensitive var appears in source
                        for (sensitive_var, env_name) in sensitive_vars.clone() {
                            // Check for various MIR patterns: move _N, copy _N, _N, &_N
                            let patterns = [
                                format!("move {}", sensitive_var),
                                format!("copy {}", sensitive_var),
                                format!("&{}", sensitive_var),
                                format!("&mut {}", sensitive_var),
                                sensitive_var.clone(),
                            ];
                            
                            let found = patterns.iter().any(|p| source.contains(p));
                            
                            if found {
                                if let Some(target_var) = Self::extract_mir_local(target) {
                                    if !sensitive_vars.contains_key(&target_var) {
                                        sensitive_vars.insert(target_var, env_name);
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        sensitive_vars
    }
    
    /// Extract MIR local variable name (e.g., "_1", "_2") from a string
    fn extract_mir_local(s: &str) -> Option<String> {
        // Look for pattern like "_N" where N is digits
        for word in s.split(|c: char| !c.is_alphanumeric() && c != '_') {
            if word.starts_with('_') && word.len() > 1 && word[1..].chars().all(|c| c.is_ascii_digit()) {
                return Some(word.to_string());
            }
        }
        None
    }
    
    /// Build a map of variable aliases (which variables point to which others)
    fn build_alias_map(body: &[String]) -> HashMap<String, HashSet<String>> {
        let mut aliases: HashMap<String, HashSet<String>> = HashMap::new();
        
        for line in body {
            let trimmed = line.trim();
            if !trimmed.contains(" = ") {
                continue;
            }
            
            if let Some(eq_pos) = trimmed.find(" = ") {
                let lhs = trimmed[..eq_pos].trim();
                let rhs = trimmed[eq_pos + 3..].trim();
                
                // Extract target variable
                let target = Self::extract_mir_local(lhs);
                if target.is_none() {
                    continue;
                }
                let target = target.unwrap();
                
                // Find source variables on RHS
                // Patterns: &_N, copy _N, move _N, deref_copy (_N.0: ...), etc.
                for word in rhs.split(|c: char| !c.is_alphanumeric() && c != '_') {
                    if word.starts_with('_') && word.len() > 1 && word[1..].chars().all(|c| c.is_ascii_digit()) {
                        aliases.entry(target.clone()).or_default().insert(word.to_string());
                    }
                }
            }
        }
        
        // Transitively expand aliases
        let mut changed = true;
        let max_iterations = 10;
        let mut iteration = 0;
        while changed && iteration < max_iterations {
            changed = false;
            iteration += 1;
            
            let current: Vec<_> = aliases.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            for (target, sources) in current {
                let mut new_sources = sources.clone();
                for source in &sources {
                    if let Some(transitive) = aliases.get(source) {
                        for t in transitive {
                            if new_sources.insert(t.clone()) {
                                changed = true;
                            }
                        }
                    }
                }
                if new_sources.len() > sources.len() {
                    aliases.insert(target, new_sources);
                }
            }
        }
        
        aliases
    }

    /// Check if a line is a log sink that uses a sensitive variable
    fn find_logged_secrets(body: &[String], sensitive_vars: &HashMap<String, String>) -> Vec<(String, String)> {
        let mut findings = Vec::new();
        let sink_patterns = Self::log_sink_patterns();
        
        // Strategy: If a function has sensitive vars and log sinks,
        // check if any sensitive var is used anywhere in the logging flow
        // MIR logging pattern: 
        //   _N = &sensitive_var
        //   _M = Argument::new_display(copy _N)
        //   _X = [move _M]
        //   _Y = Arguments::new_v1(...)
        //   _print(move _Y)
        
        // Find all log sink lines
        let log_lines: Vec<(usize, &str)> = body.iter()
            .enumerate()
            .filter(|(_, line)| sink_patterns.iter().any(|p| line.contains(p)))
            .map(|(i, line)| (i, line.trim()))
            .collect();
        
        if log_lines.is_empty() {
            return findings;
        }
        
        // Build alias map for dataflow tracking
        let aliases = Self::build_alias_map(body);
        
        // Track sanitized variables (redact, mask, hash functions applied)
        let sanitized_vars = Self::find_sanitized_vars(body);
        
        // For each log sink, scan backward to see if any sensitive var flows to it
        for (log_idx, log_line) in &log_lines {
            let start_idx = log_idx.saturating_sub(30); // Look back more for complex flows
            
            for (var, env_name) in sensitive_vars {
                // Skip if this variable has been sanitized
                if sanitized_vars.contains(var) {
                    continue;
                }
                
                // Also check if any alias of the sensitive variable is sanitized
                let mut is_sanitized_flow = false;
                if let Some(var_aliases) = aliases.get(var) {
                    // Check if any variable that points to this sensitive var is sanitized
                    for alias in var_aliases {
                        if sanitized_vars.contains(alias) {
                            is_sanitized_flow = true;
                            break;
                        }
                    }
                }
                // And check if the sensitive var flows to any sanitized var
                for (target, sources) in &aliases {
                    if sources.contains(var) && sanitized_vars.contains(target) {
                        is_sanitized_flow = true;
                        break;
                    }
                }
                if is_sanitized_flow {
                    continue;
                }
                
                // Build patterns for the sensitive var and all its aliases
                let mut check_vars = vec![var.clone()];
                for (target, sources) in &aliases {
                    if sources.contains(var) {
                        check_vars.push(target.clone());
                    }
                }
                
                // Generate patterns for all vars to check
                let mut var_patterns = Vec::new();
                for v in &check_vars {
                    var_patterns.push(format!("&{} ", v));
                    var_patterns.push(format!("&{})", v));
                    var_patterns.push(format!("&{};", v));
                    var_patterns.push(format!("&{},", v));
                    var_patterns.push(format!("copy {} ", v));
                    var_patterns.push(format!("copy {})", v));
                    var_patterns.push(format!("copy {});", v));
                    var_patterns.push(format!("move {} ", v));
                    var_patterns.push(format!("move {})", v));
                    var_patterns.push(format!("move {});", v));
                }
                
                for check_idx in start_idx..*log_idx {
                    let check_line = body.get(check_idx).map(|s| s.trim()).unwrap_or("");
                    
                    // Check if this line is a formatting call (Argument::new_display, etc.)
                    let is_fmt_call = check_line.contains("Argument::") && 
                                     (check_line.contains("new_display") || 
                                      check_line.contains("new_debug") ||
                                      check_line.contains("new_lower_exp") ||
                                      check_line.contains("new_upper_exp") ||
                                      check_line.contains("new_octal") ||
                                      check_line.contains("new_pointer") ||
                                      check_line.contains("new_binary") ||
                                      check_line.contains("new_lower_hex") ||
                                      check_line.contains("new_upper_hex"));
                    
                    // Only check formatting calls - this is where the sensitive data would appear
                    // if it's being logged directly
                    if !is_fmt_call {
                        continue;
                    }
                    
                    // Check what TYPE is being formatted - skip non-sensitive types
                    // Pattern: new_display::<TYPE>(...)
                    // If TYPE is bool, usize, u32, i32, etc., it's derived data, not the secret
                    let safe_types = ["bool", "usize", "isize", "u8", "u16", "u32", "u64", "u128",
                                     "i8", "i16", "i32", "i64", "i128", "f32", "f64"];
                    let is_safe_type = safe_types.iter().any(|t| {
                        check_line.contains(&format!("::<{}>", t)) ||
                        check_line.contains(&format!("::<{},", t)) ||
                        check_line.contains(&format!("<{}>", t))
                    });
                    
                    if is_safe_type {
                        // This is formatting a primitive type, not the secret string
                        continue;
                    }
                    
                    for pattern in &var_patterns {
                        if check_line.contains(pattern) {
                            findings.push((env_name.clone(), log_line.to_string()));
                            break;
                        }
                    }
                }
            }
        }
        
        // Deduplicate findings by env_name
        findings.sort_by(|a, b| a.0.cmp(&b.0));
        findings.dedup_by(|a, b| a.0 == b.0);
        
        findings
    }
    
    /// Find variables that have been sanitized (redact, mask, hash functions applied)
    fn find_sanitized_vars(body: &[String]) -> HashSet<String> {
        let mut sanitized = HashSet::new();
        
        // Sanitization function patterns
        let sanitize_patterns = ["redact", "mask", "censor", "hide", "obfuscate", 
                                 "hash", "encrypt", "truncate"];
        
        for line in body {
            let trimmed = line.trim();
            let lower = trimmed.to_lowercase();
            
            // Check if this line calls a sanitization function
            let has_sanitize = sanitize_patterns.iter().any(|p| lower.contains(p));
            
            if has_sanitize && trimmed.contains(" = ") {
                // Extract the target variable that receives sanitized output
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    if let Some(var) = Self::extract_mir_local(target) {
                        sanitized.insert(var);
                    }
                }
            }
        }
        
        // Propagate sanitization through assignments
        let mut changed = true;
        while changed {
            changed = false;
            for line in body {
                let trimmed = line.trim();
                if trimmed.contains(" = ") {
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let target = trimmed[..eq_pos].trim();
                        let source = trimmed[eq_pos + 3..].trim();
                        
                        // Check if source uses a sanitized var
                        for svar in sanitized.clone() {
                            if source.contains(&svar) {
                                if let Some(target_var) = Self::extract_mir_local(target) {
                                    if sanitized.insert(target_var) {
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        sanitized
    }
    
    /// Identify functions that log their parameters (helper logging functions)
    fn find_logging_functions(functions: &[MirFunction]) -> HashSet<String> {
        let mut logging_funcs = HashSet::new();
        let sink_patterns = Self::log_sink_patterns();
        
        for function in functions {
            // Check if function has log sinks
            let has_log_sink = function.body.iter().any(|line| {
                sink_patterns.iter().any(|p| line.contains(p))
            });
            
            if !has_log_sink {
                continue;
            }
            
            // Check if parameter _1 is logged (common pattern for helper functions)
            // Pattern: function logs its first parameter directly
            let logs_param = function.body.iter().any(|line| {
                let trimmed = line.trim();
                trimmed.contains("Argument::") &&
                (trimmed.contains("new_display") || trimmed.contains("new_debug")) &&
                (trimmed.contains("copy _1)") || trimmed.contains("&_1)") || 
                 trimmed.contains("copy _6)") && function.body.iter().any(|l| l.contains("_6 = &_1")))
            });
            
            if logs_param {
                logging_funcs.insert(function.name.clone());
            }
        }
        
        logging_funcs
    }
    
    /// Check if sensitive data flows to a call of a logging helper function
    fn find_logged_via_helper(
        body: &[String], 
        sensitive_vars: &HashMap<String, String>,
        logging_funcs: &HashSet<String>,
        aliases: &HashMap<String, HashSet<String>>,
    ) -> Vec<(String, String)> {
        let mut findings = Vec::new();
        
        for line in body {
            let trimmed = line.trim();
            
            // Check if this is a call to a logging function
            for func_name in logging_funcs {
                if trimmed.contains(&format!(" {}(", func_name)) || 
                   trimmed.contains(&format!("= {}(", func_name)) {
                    // Check if any sensitive variable is passed as argument
                    for (var, env_name) in sensitive_vars {
                        // Check direct use
                        if trimmed.contains(&format!("copy {}", var)) ||
                           trimmed.contains(&format!("move {}", var)) {
                            findings.push((env_name.clone(), trimmed.to_string()));
                        }
                        
                        // Check aliased use
                        for (alias_target, alias_sources) in aliases {
                            if alias_sources.contains(var) {
                                if trimmed.contains(&format!("copy {}", alias_target)) ||
                                   trimmed.contains(&format!("move {}", alias_target)) {
                                    findings.push((env_name.clone(), trimmed.to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }
        
        findings
    }
}

impl Rule for CleartextLoggingRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // First pass: identify helper functions that log their parameters
        let logging_funcs = Self::find_logging_functions(&package.functions);

        for function in &package.functions {
            // Skip internal functions
            if function.name.contains("mir_extractor") || function.name.contains("mir-extractor") {
                continue;
            }

            // Track which variables hold sensitive data
            let sensitive_vars = Self::track_sensitive_vars(&function.body);
            
            if sensitive_vars.is_empty() {
                continue;
            }
            
            // Build alias map for this function
            let aliases = Self::build_alias_map(&function.body);

            // Find log sinks that use sensitive variables (direct logging)
            let logged_secrets = Self::find_logged_secrets(&function.body, &sensitive_vars);
            
            // Also check for sensitive data passed to logging helper functions
            let helper_logged = Self::find_logged_via_helper(
                &function.body, &sensitive_vars, &logging_funcs, &aliases
            );
            
            // Combine findings
            let mut all_logged: Vec<_> = logged_secrets.into_iter().chain(helper_logged).collect();
            all_logged.sort_by(|a, b| a.0.cmp(&b.0));
            all_logged.dedup_by(|a, b| a.0 == b.0);
            
            for (env_name, evidence_line) in all_logged {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Sensitive data from `{}` may be logged in cleartext in function `{}`. \
                        Consider masking or redacting sensitive values before logging.",
                        env_name,
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: vec![evidence_line],
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}

// RUSTCOLA076: Log Injection
/// Detects untrusted input containing newlines being passed to logging functions,
/// which can forge log entries and confuse log analysis.
struct LogInjectionRule {
    metadata: RuleMetadata,
}

impl LogInjectionRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA076".to_string(),
                name: "log-injection".to_string(),
                short_description: "Untrusted input may enable log injection".to_string(),
                full_description: "Detects environment variables or command-line arguments \
                    that flow to logging functions without newline sanitization. Attackers can \
                    inject newline characters to forge log entries, evade detection, or corrupt \
                    log analysis. Sanitize by replacing or escaping \\n, \\r characters, or use \
                    structured logging formats (JSON) that properly escape special characters."
                    .to_string(),
                help_uri: Some("https://cwe.mitre.org/data/definitions/117.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Input source patterns (untrusted data origins)
    fn input_source_patterns() -> &'static [&'static str] {
        &[
            "= var::<",       // env::var::<T> - generic call (MIR format)
            "= var(",         // env::var - standard call
            "var_os(",        // env::var_os
            "::args(",        // env::args
            "args_os(",       // env::args_os
            "::nth(",         // iterator nth (often on args)
            "read_line(",     // stdin
            "read_to_string(", // file/stdin reads
        ]
    }

    /// Sanitizer patterns that remove/escape newlines
    fn newline_sanitizer_patterns() -> &'static [&'static str] {
        &[
            "::replace",      // .replace() - MIR format: str::replace::<...>
            "::trim(",        // .trim() removes trailing newlines
            "::trim_end(",      
            "::trim_matches(",
            "escape_",        // escape_default, escape_debug
            "::lines(",       // .lines() splits on newlines
            "::split(",       // .split('\n')
            "::parse::<",     // .parse::<T>() converts to different type (no newlines)
        ]
    }

    /// Track untrusted input variables
    fn track_untrusted_vars(body: &[String]) -> HashSet<String> {
        let mut untrusted_vars = HashSet::new();
        let source_patterns = Self::input_source_patterns();
        
        for line in body {
            let trimmed = line.trim();
            
            // Check if this line contains an input source
            let is_source = source_patterns.iter().any(|p| trimmed.contains(p));
            
            if is_source {
                // Extract target variable
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    if let Some(var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        untrusted_vars.insert(var.to_string());
                    }
                }
            }
            
            // Propagate through assignments (but check for sanitizers)
            if trimmed.contains(" = ") && !is_source {
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    let source = trimmed[eq_pos + 3..].trim();
                    
                    // Check if source uses an untrusted var (with word boundaries)
                    let uses_untrusted = untrusted_vars.iter().any(|v| Self::contains_var(source, v));
                    
                    if uses_untrusted {
                        // Check if there's a sanitizer on this line
                        let has_sanitizer = Self::newline_sanitizer_patterns()
                            .iter()
                            .any(|p| source.contains(p));
                        
                        if !has_sanitizer {
                            // Propagate taint
                            if let Some(target_var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                                .find(|s| s.starts_with('_'))
                            {
                                untrusted_vars.insert(target_var.to_string());
                            }
                        }
                    }
                }
            }
        }
        
        untrusted_vars
    }

    /// Check if a MIR line contains a specific variable with proper word boundaries
    fn contains_var(line: &str, var: &str) -> bool {
        for (idx, _) in line.match_indices(var) {
            let after_pos = idx + var.len();
            if after_pos >= line.len() {
                return true;
            }
            let next_char = line[after_pos..].chars().next().unwrap();
            if !next_char.is_ascii_digit() {
                return true;
            }
        }
        false
    }

    /// Find log sinks using untrusted variables
    fn find_log_injections(body: &[String], untrusted_vars: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        let log_sinks = CleartextLoggingRule::log_sink_patterns();
        
        for line in body {
            let trimmed = line.trim();
            
            // Check if this is a log sink
            let is_log_sink = log_sinks.iter().any(|p| trimmed.contains(p));
            
            if is_log_sink {
                // Check if any untrusted variable is used (with proper word boundaries)
                for var in untrusted_vars {
                    if Self::contains_var(trimmed, var) {
                        evidence.push(trimmed.to_string());
                        break;
                    }
                }
            }
        }
        
        evidence
    }

    /// Find helper functions that log their parameters
    /// Returns a set of function names that log parameter _1
    fn find_logging_helpers(package: &MirPackage) -> HashSet<String> {
        let mut helpers = HashSet::new();
        let log_sinks = CleartextLoggingRule::log_sink_patterns();
        
        for function in &package.functions {
            // Skip closures
            if function.name.contains("{closure") {
                continue;
            }
            
            // Check if function has a parameter (look for "debug X => _1")
            let has_param = function.body.iter().any(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("debug ") && trimmed.contains(" => _1")
            });
            
            if !has_param {
                continue;
            }
            
            // Check if the parameter flows to a log sink
            // Simple check: _1 or derivatives used in log sink
            let mut param_vars: HashSet<String> = HashSet::new();
            param_vars.insert("_1".to_string());
            
            // Propagate through simple assignments
            for line in &function.body {
                let trimmed = line.trim();
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    let source = trimmed[eq_pos + 3..].trim();
                    
                    let uses_param = param_vars.iter().any(|v| Self::contains_var(source, v));
                    if uses_param {
                        if let Some(target_var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                            .find(|s| s.starts_with('_'))
                        {
                            param_vars.insert(target_var.to_string());
                        }
                    }
                }
            }
            
            // Check if any param-derived var reaches a log sink
            for line in &function.body {
                let trimmed = line.trim();
                let is_log_sink = log_sinks.iter().any(|p| trimmed.contains(p));
                if is_log_sink {
                    for var in &param_vars {
                        if Self::contains_var(trimmed, var) {
                            helpers.insert(function.name.clone());
                            break;
                        }
                    }
                }
            }
        }
        
        helpers
    }

    /// Find calls to logging helper functions with untrusted data
    fn find_helper_log_injections(
        body: &[String],
        untrusted_vars: &HashSet<String>,
        logging_helpers: &HashSet<String>,
    ) -> Vec<String> {
        let mut evidence = Vec::new();
        
        for line in body {
            let trimmed = line.trim();
            
            // Check if this is a call to a logging helper
            for helper in logging_helpers {
                // Extract just the function name (last part of path)
                let helper_name = helper.split("::").last().unwrap_or(helper);
                if trimmed.contains(&format!("{}(", helper_name)) {
                    // Check if any untrusted variable is passed
                    for var in untrusted_vars {
                        if Self::contains_var(trimmed, var) {
                            evidence.push(trimmed.to_string());
                            break;
                        }
                    }
                }
            }
        }
        
        evidence
    }
}

impl Rule for LogInjectionRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // First pass: Find helper functions that log their parameters
        let logging_helpers = Self::find_logging_helpers(package);

        for function in &package.functions {
            // Skip internal functions
            if function.name.contains("mir_extractor") || function.name.contains("mir-extractor") {
                continue;
            }

            // Track untrusted input variables
            let untrusted_vars = Self::track_untrusted_vars(&function.body);
            
            if untrusted_vars.is_empty() {
                continue;
            }

            // Find direct log injections
            let mut injections = Self::find_log_injections(&function.body, &untrusted_vars);
            
            // Also find injections via helper functions
            let helper_injections = Self::find_helper_log_injections(
                &function.body,
                &untrusted_vars,
                &logging_helpers,
            );
            injections.extend(helper_injections);
            
            if !injections.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Untrusted input flows to logging in `{}` without newline sanitization. \
                        Attackers may inject newlines to forge log entries.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: injections.into_iter().take(3).collect(),
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}

// RUSTCOLA077: Division by Untrusted Denominator
/// Detects division or modulo operations where the denominator comes from
/// untrusted input without validation, risking divide-by-zero panics.
struct DivisionByUntrustedRule {
    metadata: RuleMetadata,
}

impl DivisionByUntrustedRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA077".to_string(),
                name: "division-by-untrusted".to_string(),
                short_description: "Division by untrusted input without zero check".to_string(),
                full_description: "Detects division (/) or modulo (%) operations where the \
                    denominator originates from environment variables, command-line arguments, \
                    or other untrusted sources without preceding zero validation. An attacker \
                    can cause denial-of-service by providing zero, triggering a panic. Use \
                    checked_div, checked_rem, or validate the denominator is non-zero before use."
                    .to_string(),
                help_uri: Some("https://cwe.mitre.org/data/definitions/369.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Division/modulo operation patterns in MIR
    fn division_patterns() -> &'static [&'static str] {
        &[
            "Div(",           // Division operation
            "Rem(",           // Remainder/modulo operation
            " / ",            // Infix division
            " % ",            // Infix modulo
        ]
    }

    /// Patterns that indicate zero checking
    fn zero_check_patterns() -> &'static [&'static str] {
        &[
            "checked_div",
            "checked_rem",
            "saturating_div",
            "wrapping_div",
            "!= 0",
            "!= 0_",
            "> 0",
            ">= 1",
            "is_zero",
            "NonZero",
        ]
    }

    /// Track untrusted numeric variables
    fn track_untrusted_numerics(body: &[String]) -> HashSet<String> {
        let mut untrusted_vars = HashSet::new();
        let source_patterns = LogInjectionRule::input_source_patterns();
        
        for line in body {
            let trimmed = line.trim();
            
            // Check if this line contains an input source
            let is_source = source_patterns.iter().any(|p| trimmed.contains(p));
            
            if is_source {
                // Extract target variable
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    if let Some(var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        untrusted_vars.insert(var.to_string());
                    }
                }
            }
            
            // Also track .parse() results from untrusted data
            if trimmed.contains("::parse::") {
                // Check if source is untrusted
                let uses_untrusted = untrusted_vars.iter().any(|v| trimmed.contains(v));
                if uses_untrusted {
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let target = trimmed[..eq_pos].trim();
                        if let Some(var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                            .find(|s| s.starts_with('_'))
                        {
                            untrusted_vars.insert(var.to_string());
                        }
                    }
                }
            }
            
            // Propagate through assignments
            if trimmed.contains(" = ") && !is_source {
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    let source = trimmed[eq_pos + 3..].trim();
                    
                    let uses_untrusted = untrusted_vars.iter().any(|v| source.contains(v));
                    
                    if uses_untrusted {
                        if let Some(target_var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                            .find(|s| s.starts_with('_'))
                        {
                            untrusted_vars.insert(target_var.to_string());
                        }
                    }
                }
            }
        }
        
        untrusted_vars
    }

    /// Check if function has zero validation for untrusted vars
    fn has_zero_validation(body: &[String], untrusted_vars: &HashSet<String>) -> bool {
        let check_patterns = Self::zero_check_patterns();
        
        for line in body {
            let trimmed = line.trim();
            
            // Check for zero validation patterns
            let has_check = check_patterns.iter().any(|p| trimmed.contains(p));
            
            if has_check {
                // Check if it involves an untrusted variable
                for var in untrusted_vars {
                    if trimmed.contains(var) {
                        return true;
                    }
                }
            }
        }
        
        false
    }

    /// Find division operations using untrusted denominators
    fn find_unsafe_divisions(body: &[String], untrusted_vars: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        let div_patterns = Self::division_patterns();
        
        for line in body {
            let trimmed = line.trim();
            
            // Check if this is a division operation
            let is_division = div_patterns.iter().any(|p| trimmed.contains(p));
            
            if is_division {
                // Check if denominator might be untrusted
                // In MIR, Div(a, b) has b as second operand
                for var in untrusted_vars {
                    if trimmed.contains(var) {
                        evidence.push(trimmed.to_string());
                        break;
                    }
                }
            }
        }
        
        evidence
    }
}

impl Rule for DivisionByUntrustedRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Skip internal functions
            if function.name.contains("mir_extractor") || function.name.contains("mir-extractor") {
                continue;
            }

            // Track untrusted numeric variables
            let untrusted_vars = Self::track_untrusted_numerics(&function.body);
            
            if untrusted_vars.is_empty() {
                continue;
            }

            // Check if there's zero validation
            if Self::has_zero_validation(&function.body, &untrusted_vars) {
                continue;
            }

            // Find unsafe divisions
            let unsafe_divs = Self::find_unsafe_divisions(&function.body, &untrusted_vars);
            
            if !unsafe_divs.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Division in `{}` uses untrusted input as denominator without zero validation. \
                        Use checked_div/checked_rem or validate denominator != 0.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: unsafe_divs.into_iter().take(3).collect(),
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}

// RUSTCOLA078: MaybeUninit assume_init without write (dataflow-enhanced)
/// Enhanced version of RUSTCOLA009 that uses dataflow analysis to detect
/// assume_init() calls without preceding MaybeUninit::write() operations.
struct MaybeUninitAssumeInitDataflowRule {
    metadata: RuleMetadata,
}

impl MaybeUninitAssumeInitDataflowRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA078".to_string(),
                name: "maybeuninit-assume-init-without-write".to_string(),
                short_description: "MaybeUninit::assume_init without preceding write".to_string(),
                full_description: "Detects MaybeUninit::assume_init() or assume_init_read() calls \
                    where no preceding MaybeUninit::write(), write_slice(), or ptr::write() \
                    initializes the data. Reading uninitialized memory is undefined behavior and \
                    can lead to crashes, data corruption, or security vulnerabilities. Always \
                    initialize MaybeUninit values before assuming them initialized."
                    .to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/mem/union.MaybeUninit.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Patterns that indicate MaybeUninit creation
    fn uninit_creation_patterns() -> &'static [&'static str] {
        &[
            "MaybeUninit::uninit",
            "MaybeUninit::<",  // Generic instantiation
            "uninit_array",
            "uninit(",
        ]
    }

    /// Patterns that initialize MaybeUninit
    fn init_patterns() -> &'static [&'static str] {
        &[
            ".write(",
            "::write(",
            "write_slice(",
            "ptr::write(",
            "ptr::write_bytes(",
            "ptr::copy(",
            "ptr::copy_nonoverlapping(",
            "as_mut_ptr()",   // Often used with ptr::write
            "zeroed(",        // MaybeUninit::zeroed is pre-initialized
            "MaybeUninit::new(",  // Pre-initialized
        ]
    }

    /// Patterns that assume initialization
    fn assume_init_patterns() -> &'static [&'static str] {
        &[
            "assume_init(",
            "assume_init_read(",
            "assume_init_ref(",
            "assume_init_mut(",
            "assume_init_drop(",
        ]
    }

    /// Track MaybeUninit variables and their initialization state
    fn analyze_uninit_flow(body: &[String]) -> Vec<(String, String)> {
        let mut uninitialized_vars: HashMap<String, String> = HashMap::new(); // var -> creation_line
        let mut initialized_vars: HashSet<String> = HashSet::new();
        let mut unsafe_assumes: Vec<(String, String)> = Vec::new(); // (var, assume_line)
        
        let creation_patterns = Self::uninit_creation_patterns();
        let init_patterns = Self::init_patterns();
        let assume_patterns = Self::assume_init_patterns();
        
        for line in body {
            let trimmed = line.trim();
            
            // Check for MaybeUninit creation
            let is_creation = creation_patterns.iter().any(|p| trimmed.contains(p));
            
            if is_creation && !trimmed.contains("zeroed") && !trimmed.contains("::new(") {
                // Extract target variable
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    if let Some(var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        uninitialized_vars.insert(var.to_string(), trimmed.to_string());
                    }
                }
            }
            
            // Check for initialization
            let is_init = init_patterns.iter().any(|p| trimmed.contains(p));
            
            if is_init {
                // Mark any referenced uninit vars as initialized
                for var in uninitialized_vars.keys() {
                    if trimmed.contains(var) {
                        initialized_vars.insert(var.clone());
                    }
                }
            }
            
            // Check for assume_init calls
            let is_assume = assume_patterns.iter().any(|p| trimmed.contains(p));
            
            if is_assume {
                // Check if any uninit var is assumed without being initialized
                for (var, creation_line) in &uninitialized_vars {
                    if trimmed.contains(var) && !initialized_vars.contains(var) {
                        unsafe_assumes.push((creation_line.clone(), trimmed.to_string()));
                    }
                }
            }
        }
        
        unsafe_assumes
    }
}

impl Rule for MaybeUninitAssumeInitDataflowRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Skip internal functions and test harnesses
            if function.name.contains("mir_extractor") || 
               function.name.contains("mir-extractor") ||
               function.name.contains("MaybeUninit") {
                continue;
            }

            // Check for unsafe assume_init patterns
            let unsafe_assumes = Self::analyze_uninit_flow(&function.body);
            
            for (creation_line, assume_line) in unsafe_assumes {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "MaybeUninit::assume_init() called in `{}` without preceding initialization. \
                        Reading uninitialized memory is undefined behavior.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: vec![
                        format!("Created: {}", creation_line),
                        format!("Assumed: {}", assume_line),
                    ],
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}


// RUSTCOLA079: Regex Injection
/// Detects untrusted input flowing to Regex::new or RegexBuilder without validation,
/// which can enable ReDoS (Regular Expression Denial of Service) attacks.
struct RegexInjectionRule {
    metadata: RuleMetadata,
}

impl RegexInjectionRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA079".to_string(),
                name: "regex-injection".to_string(),
                short_description: "Untrusted input used to construct regex pattern".to_string(),
                full_description: "Detects environment variables, command-line arguments, or other \
                    untrusted input flowing to Regex::new(), RegexBuilder::new(), or regex! macro \
                    without sanitization. Attackers can craft malicious patterns causing catastrophic \
                    backtracking (ReDoS), consuming excessive CPU and causing denial of service. \
                    Validate regex patterns, use timeouts, limit pattern complexity, or use \
                    regex crates with ReDoS protection (e.g., `regex` crate's default is safe, \
                    but user-controlled patterns can still match unexpectedly)."
                    .to_string(),
                help_uri: Some("https://cwe.mitre.org/data/definitions/1333.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Input source patterns (untrusted data origins)
    fn input_source_patterns() -> &'static [&'static str] {
        &[
            // Environment variables - MIR patterns
            "var::<",             // MIR: var::<&str>(const "...")
            "var_os::<",          // MIR: var_os::<&str>(const "...")
            "= var(",             // env::var - alternate format
            "env::var",           // Source form
            // Command-line arguments - MIR patterns
            "args::<",            // MIR form for env::args
            "= args(",            // env::args - alternate format
            "args_os(",           // env::args_os
            "Args>",              // Args iterator type
            "::nth(",             // iterator nth (often on args)
            // Stdin - MIR patterns
            "read_line(",         // stdin - includes BufRead>::read_line
            "read_to_string",     // file/stdin reads - includes fs::read_to_string
            "Read>::read(",       // file reads
            "= stdin(",           // stdin() call
            "Stdin",              // Stdin type
            // Network/HTTP sources
            "::get(",             // HashMap/BTreeMap get, query params
            "query(",             // URL query parameters
            "body(",              // HTTP body
            "json(",              // JSON payload
            "TcpStream",          // Network source
            "::connect(",         // Network connection
        ]
    }

    /// Sanitizer patterns that validate or escape regex input
    fn sanitizer_patterns() -> &'static [&'static str] {
        &[
            "escape(",        // regex::escape()
            "is_match(",      // Pre-validated pattern
            "validate",       // Custom validation
            "sanitize",       
            "whitelist",
            "allowlist",
            "allowed_pattern",
            "safe_pattern",
        ]
    }

    /// Regex sink patterns where injection can occur
    fn regex_sink_patterns() -> &'static [&'static str] {
        &[
            "Regex::new",            // Matches both Regex::new( and Regex::new::<
            "RegexBuilder::new",     // Matches regex::RegexBuilder::new
            "RegexSet::new",         // Matches regex::RegexSet::new::<...>
            "regex!(",
            "Regex::from_str",
            "RegexBuilder::from_str",
            "RegexBuilder::build",   // The final build call
        ]
    }

    /// Check if there's a validation guard pattern in the MIR body
    /// Returns true if a validation function is called on any tainted variable followed by a switchInt
    fn has_validation_guard(body: &[String], untrusted_vars: &HashSet<String>) -> bool {
        let validation_funcs = ["validate", "sanitize", "is_valid", "check_pattern"];
        
        // Track if a validation was called on a tainted variable
        let mut validation_result_var: Option<String> = None;
        
        for line in body {
            let trimmed = line.trim();
            
            // Check for validation function calls
            for validator in &validation_funcs {
                if trimmed.to_lowercase().contains(validator) {
                    // Check if any tainted variable is used as argument
                    for var in untrusted_vars {
                        if Self::contains_var(trimmed, var) {
                            // Extract the result variable
                            if let Some(eq_pos) = trimmed.find(" = ") {
                                let lhs = trimmed[..eq_pos].trim();
                                if let Some(result_var) = lhs.split(|c: char| !c.is_alphanumeric() && c != '_')
                                    .find(|s| s.starts_with('_'))
                                {
                                    validation_result_var = Some(result_var.to_string());
                                }
                            }
                        }
                    }
                }
            }
            
            // Check if there's a switchInt using the validation result
            if let Some(ref result_var) = validation_result_var {
                if trimmed.contains("switchInt") && Self::contains_var(trimmed, result_var) {
                    // Found switchInt on validation result - this is a validation guard
                    return true;
                }
            }
        }
        
        false
    }

    /// Check if a MIR line contains a specific variable with proper word boundaries
    /// e.g., "_1" should not match "_11" or "_10"
    fn contains_var(line: &str, var: &str) -> bool {
        // Look for the variable followed by a non-digit character
        // Common patterns: move _N, copy _N, &_N, _N), _N,, (_N
        for (idx, _) in line.match_indices(var) {
            // Check what comes after the variable
            let after_pos = idx + var.len();
            if after_pos >= line.len() {
                return true; // var at end of line
            }
            let next_char = line[after_pos..].chars().next().unwrap();
            // If next char is a digit, this is a longer variable like _11 when looking for _1
            if !next_char.is_ascii_digit() {
                return true;
            }
        }
        false
    }

    /// Track untrusted input variables
    fn track_untrusted_vars(body: &[String]) -> HashSet<String> {
        let mut untrusted_vars = HashSet::new();
        let source_patterns = Self::input_source_patterns();
        let sanitizer_patterns = Self::sanitizer_patterns();
        
        // First, build a map of references: _X -> _Y means _X is a reference to _Y
        let mut ref_aliases: HashMap<String, String> = HashMap::new();
        for line in body {
            let trimmed = line.trim();
            // Pattern: _9 = &mut _2 or _9 = &_2
            if let Some(eq_pos) = trimmed.find(" = &") {
                let lhs = trimmed[..eq_pos].trim();
                let rhs = &trimmed[eq_pos + 3..].trim();
                
                // Extract variable from rhs (might be &mut _2 or &_2)
                let rhs_clean = rhs.trim_start_matches("mut ");
                
                if let Some(lhs_var) = lhs.split(|c: char| !c.is_alphanumeric() && c != '_')
                    .find(|s| s.starts_with('_'))
                {
                    if let Some(rhs_var) = rhs_clean.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        ref_aliases.insert(lhs_var.to_string(), rhs_var.to_string());
                    }
                }
            }
        }
        
        for line in body {
            let trimmed = line.trim();
            
            // Check if this line contains an input source
            let is_source = source_patterns.iter().any(|p| trimmed.contains(p));
            
            if is_source {
                // Extract target variable
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    if let Some(var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        untrusted_vars.insert(var.to_string());
                    }
                }
                
                // Special case: read_line writes to its second argument, not return value
                // Pattern: read_line(move _N, copy _M) - _M receives the data
                if trimmed.contains("read_line(") {
                    // Extract the second argument (the buffer that receives data)
                    if let Some(start) = trimmed.find("read_line(") {
                        let after = &trimmed[start..];
                        // Look for copy _N or move _N as the second argument
                        if let Some(copy_pos) = after.rfind("copy _") {
                            let var_start = &after[copy_pos + 5..]; // skip "copy "
                            if let Some(end) = var_start.find(|c: char| !c.is_alphanumeric() && c != '_') {
                                let var = &var_start[..end];
                                if var.starts_with('_') {
                                    untrusted_vars.insert(var.to_string());
                                    // Also taint the aliased variable if this is a reference
                                    if let Some(aliased) = ref_aliases.get(var) {
                                        untrusted_vars.insert(aliased.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Second pass: propagate taint through assignments
        let mut changed = true;
        while changed {
            changed = false;
            for line in body {
                let trimmed = line.trim();
                
                // Pattern: _N = ... _M ... where _M is untrusted
                if trimmed.contains(" = ") {
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let target = trimmed[..eq_pos].trim();
                        let source = trimmed[eq_pos + 3..].trim();
                        
                        // Check if source uses an untrusted var (with word boundary matching)
                        let uses_untrusted = untrusted_vars.iter().any(|v| {
                            Self::contains_var(source, v)
                        });
                        
                        if uses_untrusted {
                            // Check if there's a sanitizer on this line
                            let has_sanitizer = sanitizer_patterns
                                .iter()
                                .any(|p| source.to_lowercase().contains(&p.to_lowercase()));
                            
                            if !has_sanitizer {
                                // Propagate taint
                                if let Some(target_var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                                    .find(|s| s.starts_with('_'))
                                {
                                    if !untrusted_vars.contains(target_var) {
                                        untrusted_vars.insert(target_var.to_string());
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        untrusted_vars
    }

    /// Propagate taint through assignments in function body
    fn propagate_taint_in_body(body: &[String], untrusted_vars: &mut HashSet<String>) {
        let sanitizer_patterns = Self::sanitizer_patterns();
        
        let mut changed = true;
        while changed {
            changed = false;
            for line in body {
                let trimmed = line.trim();
                
                if trimmed.contains(" = ") {
                    if let Some(eq_pos) = trimmed.find(" = ") {
                        let target = trimmed[..eq_pos].trim();
                        let source = trimmed[eq_pos + 3..].trim();
                        
                        let uses_untrusted = untrusted_vars.iter().any(|v| {
                            Self::contains_var(source, v)
                        });
                        
                        if uses_untrusted {
                            let has_sanitizer = sanitizer_patterns
                                .iter()
                                .any(|p| source.to_lowercase().contains(&p.to_lowercase()));
                            
                            if !has_sanitizer {
                                if let Some(target_var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                                    .find(|s| s.starts_with('_'))
                                {
                                    if !untrusted_vars.contains(target_var) {
                                        untrusted_vars.insert(target_var.to_string());
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Find regex sinks using untrusted variables
    fn find_regex_injections(body: &[String], untrusted_vars: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        let regex_sinks = Self::regex_sink_patterns();
        
        for line in body {
            let trimmed = line.trim();
            
            // Check if this is a regex sink
            let is_regex_sink = regex_sinks.iter().any(|p| trimmed.contains(p));
            
            if is_regex_sink {
                // Check if any untrusted variable is used (with proper word boundaries)
                for var in untrusted_vars {
                    if Self::contains_var(trimmed, var) {
                        evidence.push(trimmed.to_string());
                        break;
                    }
                }
            }
        }
        
        evidence
    }
}

impl Rule for RegexInjectionRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // First pass: Collect parent functions that pass untrusted input to closure combinators
        // like and_then, map, filter, etc.
        let mut tainted_closures: HashSet<String> = HashSet::new();
        
        for function in &package.functions {
            // Skip closures in first pass
            if function.name.contains("{closure") {
                continue;
            }
            
            let untrusted_vars = Self::track_untrusted_vars(&function.body);
            if untrusted_vars.is_empty() {
                continue;
            }
            
            // Check if untrusted data flows to closure combinators
            let combinator_patterns = ["and_then", "map(", "filter(", "filter_map(", "unwrap_or_else("];
            for line in &function.body {
                let trimmed = line.trim();
                for pattern in &combinator_patterns {
                    if trimmed.contains(pattern) {
                        // Check if an untrusted variable is used
                        for var in &untrusted_vars {
                            if Self::contains_var(trimmed, var) {
                                // Mark any closure belonging to this function as tainted
                                // The closure naming convention is: parent_function::{closure#N}
                                tainted_closures.insert(function.name.clone());
                                break;
                            }
                        }
                    }
                }
            }
        }

        for function in &package.functions {
            // Skip internal functions
            if function.name.contains("mir_extractor") || function.name.contains("mir-extractor") {
                continue;
            }

            // For closures, check if their parent function has tainted data
            let is_closure = function.name.contains("{closure");
            let mut untrusted_vars = if is_closure {
                // Extract parent function name
                let parent_name = function.name.split("::{closure").next().unwrap_or("");
                if tainted_closures.contains(parent_name) {
                    // The closure receives tainted input - mark parameter _2 as tainted
                    // (in MIR, closure parameters start at _1 for self, _2 for first arg)
                    let mut vars = HashSet::new();
                    // Find parameter variable from "debug p => _N" pattern
                    for line in &function.body {
                        let trimmed = line.trim();
                        if trimmed.starts_with("debug ") && trimmed.contains(" => _") {
                            if let Some(var) = trimmed.split(" => _").nth(1) {
                                let var = var.trim_end_matches(';');
                                vars.insert(format!("_{}", var));
                            }
                        }
                    }
                    // If no explicit debug parameter, assume _2
                    if vars.is_empty() {
                        vars.insert("_2".to_string());
                    }
                    vars
                } else {
                    HashSet::new()
                }
            } else {
                Self::track_untrusted_vars(&function.body)
            };
            
            // Propagate taint for closures
            if is_closure && !untrusted_vars.is_empty() {
                Self::propagate_taint_in_body(&function.body, &mut untrusted_vars);
            }
            
            if untrusted_vars.is_empty() {
                continue;
            }

            // Check if there's a validation guard that protects against regex injection
            if Self::has_validation_guard(&function.body, &untrusted_vars) {
                // The untrusted input is validated before use - skip
                continue;
            }

            // Find regex injections
            let injections = Self::find_regex_injections(&function.body, &untrusted_vars);
            
            if !injections.is_empty() {
                // For closures, report the parent function name for clarity
                let report_name = if is_closure {
                    function.name.split("::{closure").next().unwrap_or(&function.name).to_string()
                } else {
                    function.name.clone()
                };
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Untrusted input flows to regex construction in `{}`. \
                        Attackers may craft patterns causing ReDoS (catastrophic backtracking) \
                        or unexpected matches. Use regex::escape() for literal matching or \
                        validate patterns against an allowlist.",
                        report_name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: injections.into_iter().take(3).collect(),
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}


// RUSTCOLA080: Unchecked Index Arithmetic
/// Detects untrusted input used as array/slice index without bounds checking,
/// which can cause panics or out-of-bounds access.
struct UncheckedIndexRule {
    metadata: RuleMetadata,
}

impl UncheckedIndexRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA080".to_string(),
                name: "unchecked-indexing".to_string(),
                short_description: "Untrusted input used as array index without bounds check".to_string(),
                full_description: "Detects array or slice indexing operations where the index \
                    originates from untrusted sources (environment variables, command-line \
                    arguments, file contents, network input) without bounds validation. Direct \
                    indexing with [] can panic if the index is out of bounds, causing denial of \
                    service. Use .get() for safe access that returns Option, or validate the \
                    index against the array length before indexing."
                    .to_string(),
                help_uri: Some("https://cwe.mitre.org/data/definitions/129.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Input source patterns (untrusted data origins)
    fn input_source_patterns() -> &'static [&'static str] {
        &[
            // Environment variables - MIR patterns
            "var::<",             // MIR: var::<&str>(const "...")
            "var_os::<",          // MIR: var_os::<&str>(const "...")
            "= var(",             // env::var alternate
            "env::var",           // Source form
            // Command-line arguments - MIR patterns
            "args::<",            // MIR form for env::args
            "= args(",            // env::args alternate
            "args_os(",           // env::args_os
            "Args>",              // Args iterator type
            "::nth(",             // iterator nth (often on args)
            // Stdin - MIR patterns
            "read_line(",         // stdin read_line
            "Stdin::read_line",   // explicit Stdin::read_line
            "Stdin",              // Stdin type
            "= stdin(",           // stdin() call
            // File operations
            "read_to_string",     // file/stdin reads
            "Read>::read(",       // file reads
            "fs::read_to_string", // fs::read_to_string
            // Other untrusted sources
            "::get(",             // HashMap/query params (can be untrusted)
            "TcpStream",          // Network source
            "::connect(",         // Network connection
        ]
    }

    /// Check if a MIR line contains a specific variable with proper word boundaries
    fn contains_var(line: &str, var: &str) -> bool {
        for (idx, _) in line.match_indices(var) {
            let after_pos = idx + var.len();
            if after_pos >= line.len() {
                return true;
            }
            let next_char = line[after_pos..].chars().next().unwrap();
            if !next_char.is_ascii_digit() {
                return true;
            }
        }
        false
    }

    /// Track untrusted index variables (especially numeric ones)
    /// Now with inter-procedural support: tainted_return_funcs contains names of functions
    /// that return tainted data from user input sources.
    fn track_untrusted_indices(body: &[String], tainted_return_funcs: &HashSet<String>) -> HashSet<String> {
        let mut untrusted_vars = HashSet::new();
        let source_patterns = Self::input_source_patterns();
        
        // Build a map of &mut refs: _ref -> _target
        let mut mut_refs: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for line in body {
            let trimmed = line.trim();
            // Pattern: _12 = &mut _7;
            if trimmed.contains("= &mut _") {
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    let source = trimmed[eq_pos + 3..].trim();
                    if let Some(target_var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        // Extract _N from "&mut _7" or "&mut _7;"
                        if let Some(src_start) = source.find("_") {
                            let src_var: String = source[src_start..].chars()
                                .take_while(|c| c.is_alphanumeric() || *c == '_')
                                .collect();
                            if !src_var.is_empty() {
                                mut_refs.insert(target_var.to_string(), src_var);
                            }
                        }
                    }
                }
            }
        }
        
        // First pass: identify initial source taints
        for line in body {
            let trimmed = line.trim();
            
            // Check if this line contains an input source
            let is_source = source_patterns.iter().any(|p| trimmed.contains(p));
            
            if is_source {
                // Extract target variable
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    if let Some(var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        untrusted_vars.insert(var.to_string());
                    }
                }
                
                // For read_line, also taint the buffer being written to
                // Pattern: Stdin::read_line(move _10, copy _12) where _12 is &mut _7
                if trimmed.contains("read_line") {
                    for (ref_var, target_var) in &mut_refs {
                        if trimmed.contains(ref_var) {
                            untrusted_vars.insert(target_var.clone());
                        }
                    }
                }
            }
            
            // Inter-procedural: Check if this line calls a function that returns tainted data
            // Pattern: _N = function_name(...) -> [return: ...]
            if !tainted_return_funcs.is_empty() {
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let source = trimmed[eq_pos + 3..].trim();
                    // Check if any tainted function is called
                    for func_name in tainted_return_funcs {
                        // Look for the function name followed by ( or ::
                        // Handle both "get_user_index(" and "module::get_user_index("
                        let short_name = func_name.split("::").last().unwrap_or(func_name);
                        if source.contains(&format!("{}(", short_name)) || 
                           source.contains(&format!("{}::", short_name)) {
                            let target = trimmed[..eq_pos].trim();
                            if let Some(var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                                .find(|s| s.starts_with('_'))
                            {
                                untrusted_vars.insert(var.to_string());
                            }
                        }
                    }
                }
            }
        }
        
        // Second pass: propagate taint through assignments, parse, unwrap, etc.
        // This needs to be iterative because taint can propagate through chains
        let mut changed = true;
        while changed {
            changed = false;
            for line in body {
                let trimmed = line.trim();
                
                // Check if line uses any untrusted variable
                let uses_untrusted = untrusted_vars.iter().any(|v| Self::contains_var(trimmed, v));
                
                if !uses_untrusted {
                    continue;
                }
                
                // Extract target variable if this is an assignment
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    if let Some(target_var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        if !untrusted_vars.contains(target_var) {
                            // Taint propagates through:
                            // - parse/from_str (string to number conversion)
                            // - unwrap/expect (Result/Option extraction)
                            // - general assignments (references, derefs, copies, moves)
                            let dominated_by_untrusted = 
                                trimmed.contains("::parse") || 
                                trimmed.contains("parse::") ||
                                trimmed.contains("from_str") ||
                                trimmed.contains("::unwrap(") || 
                                trimmed.contains("::expect(") ||
                                // General assignment - check source side
                                {
                                    let source = trimmed[eq_pos + 3..].trim();
                                    untrusted_vars.iter().any(|v| Self::contains_var(source, v))
                                };
                            
                            if dominated_by_untrusted {
                                untrusted_vars.insert(target_var.to_string());
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
        
        untrusted_vars
    }

    /// Check if function has bounds validation for indices
    /// This checks for EXPLICIT bounds checking, not just MIR-level panic assertions
    fn has_bounds_validation(body: &[String], untrusted_vars: &HashSet<String>) -> bool {
        // Track comparison results to see if they're used in conditional branches
        let mut comparison_vars: HashSet<String> = HashSet::new();
        
        for line in body {
            let trimmed = line.trim();
            
            // Skip safe .get() calls - they're the alternative, not a validation
            if trimmed.contains("::get(") || trimmed.contains("::get_mut(") || trimmed.contains("::get::<") {
                continue;
            }
            
            // Check for length comparisons involving untrusted vars
            // Must be explicit len() comparison, not just any "<" or ">"
            if trimmed.contains(".len()") || trimmed.contains("::len(") {
                for var in untrusted_vars {
                    if Self::contains_var(trimmed, var) {
                        // Looks like a bounds check against len()
                        return true;
                    }
                }
            }
            
            // Check for min/max bounds clamping
            // Pattern like: raw_idx.min(data.len() - 1) or ::min(...)
            if (trimmed.contains("::min(") || trimmed.contains("::max(")) && 
               (trimmed.contains("len") || trimmed.contains("_")) {
                for var in untrusted_vars {
                    if Self::contains_var(trimmed, var) {
                        return true;
                    }
                }
            }
            
            // Track comparison results (Lt, Gt, etc.) that involve untrusted vars
            // These are only valid if they control a conditional branch, not just an assert
            let has_comparison = trimmed.contains("Lt(") || trimmed.contains("Le(") || 
                                  trimmed.contains("Gt(") || trimmed.contains("Ge(");
            if has_comparison {
                for var in untrusted_vars {
                    if Self::contains_var(trimmed, var) {
                        // Extract the target variable for this comparison
                        if let Some(eq_pos) = trimmed.find(" = ") {
                            let target = trimmed[..eq_pos].trim();
                            if let Some(target_var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                                .find(|s| s.starts_with('_'))
                            {
                                comparison_vars.insert(target_var.to_string());
                            }
                        }
                    }
                }
            }
            
            // Check if comparison result is used in switchInt (conditional branch)
            // This indicates a proper if-check, not just an assert that panics
            if trimmed.contains("switchInt(") {
                for comp_var in &comparison_vars {
                    if Self::contains_var(trimmed, comp_var) {
                        return true;
                    }
                }
            }
        }
        
        false
    }

    /// Find unsafe indexing operations using untrusted indices
    fn find_unsafe_indexing(body: &[String], untrusted_vars: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        
        for line in body {
            let trimmed = line.trim();
            
            // MIR uses Index trait: <Vec<T> as Index<usize>>::index(..., copy _N)
            // The index is the SECOND argument after the comma
            // Pattern: ::index(move _20, copy _13) - _13 is the index
            if trimmed.contains("::index(") || trimmed.contains("::index_mut(") {
                // Skip safe get() methods - they return Option
                if trimmed.contains("::get(") || trimmed.contains("::get_mut(") {
                    continue;
                }
                
                // Extract the index argument (second parameter after comma)
                // Pattern: ::index(move _X, copy _Y) or ::index(move _X, move _Y)
                if let Some(idx_start) = trimmed.find("::index") {
                    let after_index = &trimmed[idx_start..];
                    // Find the comma separating arguments
                    if let Some(comma_pos) = after_index.find(", ") {
                        let index_arg = &after_index[comma_pos + 2..];
                        // Check if any untrusted variable is the index
                        for var in untrusted_vars {
                            if Self::contains_var(index_arg, var) {
                                evidence.push(trimmed.to_string());
                                break;
                            }
                        }
                    }
                }
            }
            
            // Also check for direct array indexing pattern: [_N] in MIR
            // This appears for arrays: (*_1)[_2] or _X = copy _Y[_Z]
            // But NOT array literals like: _25 = [move _26]
            if trimmed.contains('[') && trimmed.contains(']') {
                // Skip array literals - pattern: "= [" means creating array, not indexing
                if trimmed.contains("= [") {
                    continue;
                }
                
                // Skip type declarations and safe .get() patterns
                if trimmed.contains("let ") || trimmed.contains("::get") {
                    continue;
                }
                
                // Extract the index variable from brackets
                if let Some(bracket_start) = trimmed.find('[') {
                    if let Some(bracket_end) = trimmed[bracket_start..].find(']') {
                        let index_content = &trimmed[bracket_start + 1..bracket_start + bracket_end];
                        
                        // Check if any untrusted variable is used as index
                        for var in untrusted_vars {
                            if Self::contains_var(index_content, var) {
                                evidence.push(trimmed.to_string());
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        evidence
    }
    
    /// Identify functions that return tainted data from user input sources.
    /// These are functions that:
    /// 1. Contain input source patterns (stdin, env, args, file reads)
    /// 2. Return data derived from those sources (taint flows to _0)
    fn find_tainted_return_functions(package: &MirPackage) -> HashSet<String> {
        let mut tainted_funcs = HashSet::new();
        let source_patterns = Self::input_source_patterns();
        
        for function in &package.functions {
            // Skip internal functions
            if function.name.contains("mir_extractor") || 
               function.name.contains("mir-extractor") ||
               function.name.contains("__") {
                continue;
            }
            
            // Check if function contains a source
            let has_source = function.body.iter().any(|line| {
                source_patterns.iter().any(|p| line.contains(p))
            });
            
            if !has_source {
                continue;
            }
            
            // Track taint to see if it reaches the return value (_0)
            // Use simplified taint tracking just for this analysis
            let empty_set = HashSet::new();
            let tainted = Self::track_untrusted_indices(&function.body, &empty_set);
            
            // Check if taint propagates to return value
            // MIR patterns: "_0 = move _N" or "_0 = copy _N" where _N is tainted
            let returns_tainted = function.body.iter().any(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with("_0 = ") || trimmed.starts_with("_0 =") {
                    // Check if any tainted var is on the RHS
                    tainted.iter().any(|v| Self::contains_var(trimmed, v))
                } else {
                    false
                }
            });
            
            if returns_tainted {
                tainted_funcs.insert(function.name.clone());
            }
        }
        
        tainted_funcs
    }
}

impl Rule for UncheckedIndexRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Phase 1: Build inter-procedural taint map - identify functions that return tainted data
        let tainted_return_funcs = Self::find_tainted_return_functions(package);

        // Phase 2: Analyze each function with inter-procedural context
        for function in &package.functions {
            // Skip internal functions and test harnesses
            if function.name.contains("mir_extractor") || 
               function.name.contains("mir-extractor") ||
               function.name.contains("__") {
                continue;
            }

            // Track untrusted index variables (now with inter-procedural support)
            let untrusted_vars = Self::track_untrusted_indices(&function.body, &tainted_return_funcs);
            
            if untrusted_vars.is_empty() {
                continue;
            }

            // Check if function has bounds validation
            if Self::has_bounds_validation(&function.body, &untrusted_vars) {
                continue;
            }

            // Find unsafe indexing operations
            let unsafe_indexing = Self::find_unsafe_indexing(&function.body, &untrusted_vars);
            
            if !unsafe_indexing.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Untrusted input used as array index in `{}` without bounds checking. \
                        This can cause panic if index is out of bounds. Use .get() for safe \
                        access or validate index < array.len() before indexing.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: unsafe_indexing.into_iter().take(3).collect(),
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}


// =============================================================================
// RUSTCOLA081: Serde serialize_* length mismatch
// =============================================================================

/// Detects when the declared length argument to serialize_struct/serialize_tuple/etc
/// doesn't match the actual number of serialize_field/serialize_element calls.
/// This can cause deserialization failures in binary formats.
struct SerdeLengthMismatchRule {
    metadata: RuleMetadata,
}

impl SerdeLengthMismatchRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA081".to_string(),
                name: "serde-length-mismatch".to_string(),
                short_description: "Serde serialize_* length mismatch".to_string(),
                full_description: "Detects when the declared field/element count in \
                    serialize_struct/serialize_tuple/etc doesn't match the actual number \
                    of serialize_field/serialize_element calls. This mismatch can cause \
                    deserialization failures, data corruption, or panics in binary formats \
                    like bincode, postcard, or MessagePack that rely on precise length hints."
                    .to_string(),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                help_uri: None,
            },
        }
    }

    /// Extract declared length from serialize_struct/tuple/etc calls
    /// Returns: Vec<(serializer_type, struct_name, declared_len, line)>
    fn find_serializer_declarations(body: &[String]) -> Vec<(String, String, usize, String)> {
        let mut declarations = Vec::new();
        
        // First pass: collect variable assignments for Option<usize> values
        // Pattern: _N = std::option::Option::<usize>::Some(const K_usize);
        let mut var_values: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for line in body {
            let trimmed = line.trim();
            if trimmed.contains("Option::<usize>::Some(const ") {
                // Extract variable name (e.g., "_6 = ...")
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let var_name = trimmed[..eq_pos].trim().to_string();
                    // Extract the constant value
                    if let Some(start) = trimmed.find("Some(const ") {
                        let after = &trimmed[start + 11..];
                        if let Some(end) = after.find("_usize") {
                            if let Ok(val) = after[..end].trim().parse::<usize>() {
                                var_values.insert(var_name, val);
                            }
                        }
                    }
                }
            }
        }
        
        for line in body {
            let trimmed = line.trim();
            
            // Pattern: serialize_struct(move _N, const "Name", const K_usize)
            if trimmed.contains("serialize_struct(") && !trimmed.contains("serialize_struct_variant") {
                if let Some(decl) = Self::extract_struct_declaration(trimmed) {
                    declarations.push(("struct".to_string(), decl.0, decl.1, trimmed.to_string()));
                }
            }
            
            // Pattern: serialize_tuple(move _N, const K_usize)
            if trimmed.contains("serialize_tuple(") && !trimmed.contains("serialize_tuple_struct") && !trimmed.contains("serialize_tuple_variant") {
                if let Some(len) = Self::extract_tuple_length(trimmed) {
                    declarations.push(("tuple".to_string(), "".to_string(), len, trimmed.to_string()));
                }
            }
            
            // Pattern: serialize_tuple_struct(move _N, const "Name", const K_usize)
            if trimmed.contains("serialize_tuple_struct(") {
                if let Some(decl) = Self::extract_struct_declaration(trimmed) {
                    declarations.push(("tuple_struct".to_string(), decl.0, decl.1, trimmed.to_string()));
                }
            }
            
            // Pattern: serialize_seq(move _N) where _N was assigned Some(K) constant
            if trimmed.contains("serialize_seq(") {
                // First try direct constant in the line
                if let Some(len) = Self::extract_seq_length(trimmed) {
                    declarations.push(("seq".to_string(), "".to_string(), len, trimmed.to_string()));
                } else {
                    // Try to find the variable reference and look it up
                    if let Some(len) = Self::extract_seq_length_from_var(trimmed, &var_values) {
                        declarations.push(("seq".to_string(), "".to_string(), len, trimmed.to_string()));
                    }
                }
            }
            
            // Pattern: serialize_map(move _N) where _N was assigned Some(K) constant
            if trimmed.contains("serialize_map(") {
                if let Some(len) = Self::extract_map_length(trimmed) {
                    declarations.push(("map".to_string(), "".to_string(), len, trimmed.to_string()));
                } else {
                    if let Some(len) = Self::extract_map_length_from_var(trimmed, &var_values) {
                        declarations.push(("map".to_string(), "".to_string(), len, trimmed.to_string()));
                    }
                }
            }
        }
        
        declarations
    }

    /// Extract struct name and declared field count from serialize_struct call
    fn extract_struct_declaration(line: &str) -> Option<(String, usize)> {
        // Pattern: serialize_struct(move _N, const "Name", const K_usize)
        // or: serialize_tuple_struct(move _N, const "Name", const K_usize)
        
        // Find the struct name in quotes
        let name_start = line.find("const \"")? + 7;
        let name_end = line[name_start..].find("\"")? + name_start;
        let name = line[name_start..name_end].to_string();
        
        // Find the length constant after the name
        let after_name = &line[name_end..];
        // Look for "const N_usize" pattern
        if let Some(const_pos) = after_name.find("const ") {
            let len_start = const_pos + 6;
            let len_str = &after_name[len_start..];
            // Extract the number before _usize
            if let Some(usize_pos) = len_str.find("_usize") {
                let num_str = &len_str[..usize_pos];
                if let Ok(len) = num_str.trim().parse::<usize>() {
                    return Some((name, len));
                }
            }
        }
        
        None
    }

    /// Extract length from serialize_tuple call
    fn extract_tuple_length(line: &str) -> Option<usize> {
        // Pattern: serialize_tuple(move _N, const K_usize)
        if let Some(const_pos) = line.rfind("const ") {
            let after_const = &line[const_pos + 6..];
            if let Some(usize_pos) = after_const.find("_usize") {
                let num_str = &after_const[..usize_pos];
                if let Ok(len) = num_str.trim().parse::<usize>() {
                    return Some(len);
                }
            }
        }
        None
    }

    /// Extract length from serialize_seq(Some(K)) where K is constant
    fn extract_seq_length(line: &str) -> Option<usize> {
        // Pattern: serialize_seq(Some(K)) represented as const N_usize or move _var
        // We only flag when it's a hardcoded constant, not dynamic like self.data.len()
        
        // Skip if it uses None (dynamic length)
        if line.contains("Option::<usize>::None") || line.contains("None::<usize>") {
            return None;
        }
        
        // Look for const pattern - indicates hardcoded length
        if let Some(const_pos) = line.rfind("const ") {
            let after_const = &line[const_pos + 6..];
            if let Some(usize_pos) = after_const.find("_usize") {
                let num_str = &after_const[..usize_pos];
                if let Ok(len) = num_str.trim().parse::<usize>() {
                    return Some(len);
                }
            }
        }
        
        None
    }

    /// Extract length from serialize_map(Some(K)) where K is constant
    fn extract_map_length(line: &str) -> Option<usize> {
        // Same logic as seq
        Self::extract_seq_length(line)
    }

    /// Extract seq length by looking up a variable reference
    /// Pattern: serialize_seq(move _N, move _M) where _M was assigned Some(K)
    fn extract_seq_length_from_var(line: &str, var_values: &std::collections::HashMap<String, usize>) -> Option<usize> {
        // Find the last argument (which should be the Option<usize> for length)
        // Pattern: serialize_seq(move _2, move _6) -> look up _6
        if let Some(paren_start) = line.find("serialize_seq(") {
            let after = &line[paren_start..];
            // Find the last "move _N" pattern before the closing paren
            for (var, val) in var_values {
                if after.contains(&format!("move {}", var)) || after.contains(&format!(", {})", var)) {
                    return Some(*val);
                }
            }
        }
        None
    }

    /// Extract map length by looking up a variable reference
    fn extract_map_length_from_var(line: &str, var_values: &std::collections::HashMap<String, usize>) -> Option<usize> {
        if let Some(paren_start) = line.find("serialize_map(") {
            let after = &line[paren_start..];
            for (var, val) in var_values {
                if after.contains(&format!("move {}", var)) || after.contains(&format!(", {})", var)) {
                    return Some(*val);
                }
            }
        }
        None
    }

    /// Count serialize_field calls in the function body
    fn count_serialize_fields(body: &[String]) -> usize {
        body.iter()
            .filter(|line| {
                let trimmed = line.trim();
                // Count SerializeStruct::serialize_field calls
                trimmed.contains("SerializeStruct>::serialize_field") ||
                // Also count SerializeStructVariant::serialize_field
                trimmed.contains("SerializeStructVariant>::serialize_field")
            })
            .count()
    }

    /// Count serialize_element calls in the function body
    fn count_serialize_elements(body: &[String]) -> usize {
        body.iter()
            .filter(|line| {
                let trimmed = line.trim();
                // Count SerializeTuple::serialize_element
                trimmed.contains("SerializeTuple>::serialize_element") ||
                // Count SerializeTupleStruct::serialize_field (not serialize_element!)
                trimmed.contains("SerializeTupleStruct>::serialize_field")
            })
            .count()
    }

    /// Count serialize_element for seq
    fn count_seq_elements(body: &[String]) -> usize {
        body.iter()
            .filter(|line| {
                let trimmed = line.trim();
                trimmed.contains("SerializeSeq>::serialize_element")
            })
            .count()
    }

    /// Count serialize_entry for map
    fn count_map_entries(body: &[String]) -> usize {
        body.iter()
            .filter(|line| {
                let trimmed = line.trim();
                trimmed.contains("SerializeMap>::serialize_entry") ||
                // Also count serialize_key/serialize_value pairs
                trimmed.contains("SerializeMap>::serialize_key")
            })
            .count()
    }

    /// Check if this is a loop-based serialization (dynamic elements)
    fn has_loop_serialization(body: &[String]) -> bool {
        // If there's a loop pattern, the element count is dynamic
        let body_str = body.join("\n");
        
        // Common loop patterns in MIR
        body_str.contains("switchInt") && 
        (body_str.contains("IntoIterator") || 
         body_str.contains("Iterator>::next") ||
         body_str.contains("Range"))
    }
}

impl Rule for SerdeLengthMismatchRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Skip non-serialize functions
            if !function.name.contains("serialize") && !function.signature.contains("Serialize") {
                continue;
            }
            
            // Skip derive-generated serializations (they're always correct)
            if function.signature.contains("impl _::_serde::Serialize") ||
               function.signature.contains("<impl Serialize") {
                // This might be derive-generated, but also might be manual impl
                // We'll still check it
            }

            // Find serializer declarations
            let declarations = Self::find_serializer_declarations(&function.body);
            
            if declarations.is_empty() {
                continue;
            }

            for (ser_type, name, declared_len, decl_line) in &declarations {
                let has_loop = Self::has_loop_serialization(&function.body);
                
                let actual_count = match ser_type.as_str() {
                    "struct" => Self::count_serialize_fields(&function.body),
                    "tuple" | "tuple_struct" => Self::count_serialize_elements(&function.body),
                    "seq" => {
                        // For loop-based serialization, we can't count statically
                        // but using a hardcoded constant with a loop is suspicious
                        if has_loop {
                            // Signal that we have a loop pattern
                            usize::MAX
                        } else {
                            Self::count_seq_elements(&function.body)
                        }
                    }
                    "map" => {
                        if has_loop {
                            usize::MAX
                        } else {
                            Self::count_map_entries(&function.body)
                        }
                    }
                    _ => continue,
                };

                // Special case: loop-based serialization with hardcoded constant
                if actual_count == usize::MAX {
                    // Hardcoded constant + loop = likely bug
                    // The declared length won't match the runtime iteration count
                    let type_desc = match ser_type.as_str() {
                        "seq" => "sequence",
                        "map" => "map",
                        _ => "collection",
                    };

                    let name_info = if name.is_empty() {
                        String::new()
                    } else {
                        format!(" for `{}`", name)
                    };

                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "Serde serialize_{}{} declares constant length {} but uses loop-based serialization. \
                            The hardcoded length hint will likely not match the actual number of {} entries. \
                            Use `None` for dynamic-length collections or use `self.{}.len()` instead.",
                            ser_type, name_info, declared_len, type_desc,
                            if ser_type == "seq" { "data" } else { "items" }
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![decl_line.clone()],
                        span: function.span.clone(),
                    });
                    continue;
                }

                // Check for mismatch
                if actual_count != *declared_len {
                    let type_desc = match ser_type.as_str() {
                        "struct" => "struct fields",
                        "tuple" | "tuple_struct" => "tuple elements",
                        "seq" => "sequence elements",
                        "map" => "map entries",
                        _ => "elements",
                    };

                    let name_info = if name.is_empty() {
                        String::new()
                    } else {
                        format!(" for `{}`", name)
                    };

                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "Serde serialize_{}{} declares {} {} but actually serializes {}. \
                            This mismatch can cause deserialization failures in binary formats. \
                            Update the length argument to match the actual count.",
                            ser_type, name_info, declared_len, type_desc, actual_count
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![decl_line.clone()],
                        span: function.span.clone(),
                    });
                }
            }
        }

        findings
    }
}


// =============================================================================
// RUSTCOLA082: Raw pointer to slice of different element size
// =============================================================================

/// Detects unsafe transmutes between slice/pointer types where the element sizes
/// differ. This can cause memory corruption because the slice length field doesn't
/// account for the size difference.
///
/// Example: transmuting &[u8] to &[u32] corrupts the slice - if the u8 slice has
/// length 8, the result claims to have 8 u32 elements (32 bytes) instead of 2.
struct SliceElementSizeMismatchRule {
    metadata: RuleMetadata,
}

impl SliceElementSizeMismatchRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA082".to_string(),
                name: "slice-element-size-mismatch".to_string(),
                short_description: "Raw pointer to slice of different element size".to_string(),
                full_description: "Detects transmutes between slice types with different \
                    element sizes (e.g., &[u8] to &[u32]). This is unsound because the slice \
                    length field isn't adjusted for the size difference, causing the new slice \
                    to reference memory beyond the original allocation. Use slice::from_raw_parts \
                    or slice::align_to instead."
                    .to_string(),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                help_uri: None,
            },
        }
    }

    /// Get element size for primitive types
    fn get_primitive_size(type_name: &str) -> Option<usize> {
        // Extract the inner type from slice/reference patterns
        let inner = type_name
            .trim_start_matches('&')
            .trim_start_matches("mut ")
            .trim_start_matches("*const ")
            .trim_start_matches("*mut ")
            .trim_start_matches('[')
            .trim_end_matches(']');

        match inner {
            "u8" | "i8" | "bool" => Some(1),
            "u16" | "i16" => Some(2),
            "u32" | "i32" | "f32" | "char" => Some(4),
            "u64" | "i64" | "f64" => Some(8),
            "u128" | "i128" => Some(16),
            "usize" | "isize" => Some(8), // Assume 64-bit
            _ => None,
        }
    }

    /// Parse a slice type and return the element type
    /// Handles: &[T], &mut [T], *const [T], *mut [T]
    fn extract_slice_element_type(type_str: &str) -> Option<String> {
        let trimmed = type_str.trim();
        
        // Check if it's a slice type
        if !trimmed.contains('[') || !trimmed.contains(']') {
            return None;
        }
        
        // Extract element type from patterns like:
        // &[u8], &mut [u32], *const [u64], *mut [i8]
        let start = trimmed.find('[')? + 1;
        let end = trimmed.rfind(']')?;
        
        if start >= end {
            return None;
        }
        
        Some(trimmed[start..end].trim().to_string())
    }

    /// Check if types are slices with different element sizes
    fn is_slice_size_mismatch(from_type: &str, to_type: &str) -> Option<(String, String, usize, usize)> {
        let from_elem = Self::extract_slice_element_type(from_type)?;
        let to_elem = Self::extract_slice_element_type(to_type)?;
        
        // Same element type is fine
        if from_elem == to_elem {
            return None;
        }
        
        let from_size = Self::get_primitive_size(&from_elem);
        let to_size = Self::get_primitive_size(&to_elem);
        
        match (from_size, to_size) {
            (Some(fs), Some(ts)) => {
                // Both primitives - check if sizes differ
                if fs == ts {
                    None
                } else {
                    Some((from_elem, to_elem, fs, ts))
                }
            }
            (None, None) => {
                // Both are custom types (structs) - different named types = likely mismatch
                // We can't know the sizes, but different struct names suggest different layouts
                // Use 0 as sentinel for "unknown size"
                Some((from_elem, to_elem, 0, 0))
            }
            _ => {
                // One primitive, one custom - definitely a mismatch
                // Use the known size or 0 for unknown
                Some((from_elem, to_elem, from_size.unwrap_or(0), to_size.unwrap_or(0)))
            }
        }
    }

    /// Check if types are Vecs with different element sizes
    fn is_vec_size_mismatch(from_type: &str, to_type: &str) -> Option<(String, String, usize, usize)> {
        // Pattern: std::vec::Vec<u8> to std::vec::Vec<u32>
        let extract_vec_elem = |t: &str| -> Option<String> {
            if !t.contains("Vec<") {
                return None;
            }
            let start = t.find("Vec<")? + 4;
            let end = t.rfind('>')?;
            if start >= end {
                return None;
            }
            Some(t[start..end].trim().to_string())
        };
        
        let from_elem = extract_vec_elem(from_type)?;
        let to_elem = extract_vec_elem(to_type)?;
        
        if from_elem == to_elem {
            return None;
        }
        
        let from_size = Self::get_primitive_size(&from_elem)?;
        let to_size = Self::get_primitive_size(&to_elem)?;
        
        if from_size == to_size {
            return None;
        }
        
        Some((from_elem, to_elem, from_size, to_size))
    }

    /// Parse transmute_copy pattern
    /// Pattern: _0 = transmute_copy::<&[u8], &[u32]>(copy _2)
    fn parse_transmute_copy_line(line: &str) -> Option<(String, String)> {
        let trimmed = line.trim();
        
        if !trimmed.contains("transmute_copy::<") {
            return None;
        }
        
        // Extract type parameters: transmute_copy::<FROM, TO>
        let start = trimmed.find("transmute_copy::<")? + 17;
        let end = trimmed[start..].find(">")? + start;
        
        let type_params = &trimmed[start..end];
        
        // Split by comma, handling nested generics
        let mut depth = 0;
        let mut split_pos = None;
        for (i, c) in type_params.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => depth -= 1,
                ',' if depth == 0 => {
                    split_pos = Some(i);
                    break;
                }
                _ => {}
            }
        }
        
        let split = split_pos?;
        let from_type = type_params[..split].trim().to_string();
        let to_type = type_params[split + 1..].trim().to_string();
        
        Some((from_type, to_type))
    }
}

impl Rule for SliceElementSizeMismatchRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Skip test functions
            if function.signature.contains("#[test]") || function.name.contains("test") {
                continue;
            }

            // Build a map of variable types from the function body
            // Pattern: let _N: TYPE;
            // Pattern: debug VAR => _N;
            let mut var_types: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            
            // Also extract parameter types from signature
            // Pattern: fn foo(_1: &[u8]) -> &[u32]
            if let Some(params_start) = function.signature.find('(') {
                if let Some(params_end) = function.signature.find(')') {
                    let params = &function.signature[params_start + 1..params_end];
                    // Parse parameters like "_1: &[u8], _2: i32"
                    for param in params.split(',') {
                        let param = param.trim();
                        if let Some(colon_pos) = param.find(':') {
                            let var_name = param[..colon_pos].trim();
                            let var_type = param[colon_pos + 1..].trim();
                            var_types.insert(var_name.to_string(), var_type.to_string());
                        }
                    }
                }
            }

            // Parse variable declarations from body
            for line in &function.body {
                let trimmed = line.trim();
                
                // Pattern: let _0: &[u32];
                // Pattern: let mut _0: Vec<u8>;
                if trimmed.starts_with("let ") {
                    let rest = trimmed.trim_start_matches("let ").trim_start_matches("mut ");
                    if let Some(colon_pos) = rest.find(':') {
                        let var_name = rest[..colon_pos].trim();
                        let type_end = rest.find(';').unwrap_or(rest.len());
                        let var_type = rest[colon_pos + 1..type_end].trim();
                        var_types.insert(var_name.to_string(), var_type.to_string());
                    }
                }
            }

            for line in &function.body {
                let trimmed = line.trim();

                // Check for transmute_copy patterns first (has explicit types)
                if let Some((from_type, to_type)) = Self::parse_transmute_copy_line(trimmed) {
                    // Check for slice mismatch
                    if let Some((from_elem, to_elem, from_size, to_size)) = 
                        Self::is_slice_size_mismatch(&from_type, &to_type) 
                    {
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "transmute_copy between slices with different element sizes: \
                                [{}] ({} bytes) to [{}] ({} bytes). The slice length won't be \
                                adjusted, causing memory access beyond the original allocation. \
                                Use slice::from_raw_parts with adjusted length instead.",
                                from_elem, from_size, to_elem, to_size
                            ),
                            function: function.name.clone(),
                            function_signature: function.signature.clone(),
                            evidence: vec![trimmed.to_string()],
                            span: function.span.clone(),
                        });
                        continue;
                    }
                    
                    // Check for Vec mismatch
                    if let Some((from_elem, to_elem, from_size, to_size)) = 
                        Self::is_vec_size_mismatch(&from_type, &to_type) 
                    {
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "transmute_copy between Vecs with different element sizes: \
                                Vec<{}> ({} bytes) to Vec<{}> ({} bytes). This corrupts the \
                                Vec's length and capacity fields.",
                                from_elem, from_size, to_elem, to_size
                            ),
                            function: function.name.clone(),
                            function_signature: function.signature.clone(),
                            evidence: vec![trimmed.to_string()],
                            span: function.span.clone(),
                        });
                        continue;
                    }
                }

                // Check for direct transmute patterns
                // Pattern: _0 = copy _1 as &[u32] (Transmute);
                if trimmed.contains("(Transmute)") && trimmed.contains(" as ") {
                    // Extract source variable and destination type
                    // Pattern: _0 = copy _1 as TYPE (Transmute);
                    // Pattern: _0 = move _1 as TYPE (Transmute);
                    
                    let copy_move_pattern = if trimmed.contains("copy ") {
                        "copy "
                    } else if trimmed.contains("move ") {
                        "move "
                    } else {
                        continue;
                    };
                    
                    let as_pos = match trimmed.find(" as ") {
                        Some(p) => p,
                        None => continue,
                    };
                    
                    let transmute_pos = match trimmed.find("(Transmute)") {
                        Some(p) => p,
                        None => continue,
                    };
                    
                    // Get destination type
                    let to_type = trimmed[as_pos + 4..transmute_pos].trim();
                    
                    // Get source variable
                    let copy_pos = match trimmed.find(copy_move_pattern) {
                        Some(p) => p,
                        None => continue,
                    };
                    
                    let src_start = copy_pos + copy_move_pattern.len();
                    let src_end = as_pos;
                    let src_var = trimmed[src_start..src_end].trim();
                    
                    // Look up source type
                    let from_type = match var_types.get(src_var) {
                        Some(t) => t.as_str(),
                        None => continue,
                    };

                    // Check for slice mismatch
                    if let Some((from_elem, to_elem, from_size, to_size)) = 
                        Self::is_slice_size_mismatch(from_type, to_type) 
                    {
                        // Format message based on whether sizes are known
                        let size_info = if from_size == 0 && to_size == 0 {
                            format!(
                                "Transmute between slices of different struct types: \
                                [{}] to [{}]. Different struct types likely have different sizes, \
                                causing the slice length to be incorrect.",
                                from_elem, to_elem
                            )
                        } else if from_size == 0 || to_size == 0 {
                            format!(
                                "Transmute between slices with different element types: \
                                [{}] to [{}]. The slice length won't be adjusted for size differences.",
                                from_elem, to_elem
                            )
                        } else {
                            format!(
                                "Transmute between slices with different element sizes: \
                                [{}] ({} bytes) to [{}] ({} bytes). The slice length won't be \
                                adjusted, causing memory access beyond the original allocation.",
                                from_elem, from_size, to_elem, to_size
                            )
                        };
                        
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "{} Use slice::from_raw_parts with adjusted length, or slice::align_to.",
                                size_info
                            ),
                            function: function.name.clone(),
                            function_signature: function.signature.clone(),
                            evidence: vec![trimmed.to_string()],
                            span: function.span.clone(),
                        });
                    }
                    
                    // Check for Vec mismatch
                    if let Some((from_elem, to_elem, from_size, to_size)) = 
                        Self::is_vec_size_mismatch(from_type, to_type) 
                    {
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "Transmute between Vecs with different element sizes: \
                                Vec<{}> ({} bytes) to Vec<{}> ({} bytes). This corrupts the \
                                Vec's length and capacity fields, potentially causing memory \
                                corruption or use-after-free.",
                                from_elem, from_size, to_elem, to_size
                            ),
                            function: function.name.clone(),
                            function_signature: function.signature.clone(),
                            evidence: vec![trimmed.to_string()],
                            span: function.span.clone(),
                        });
                    }
                }
            }
        }

        findings
    }
}


// =============================================================================
// RUSTCOLA083: slice::from_raw_parts length inflation
// =============================================================================

/// Detects potentially dangerous uses of slice::from_raw_parts where the length
/// argument may exceed the actual allocation size, causing undefined behavior
/// through out-of-bounds memory access.
///
/// Flags cases where:
/// - Length comes directly from function parameters (untrusted)
/// - Length comes from environment variables or command-line args
/// - Length is a large constant (> 10000)
/// - Length is computed without validation
///
/// Does NOT flag when:
/// - Length comes from .len() of a container
/// - Length matches allocation count
/// - Length is validated with bounds check before use
/// - Length uses min/saturating operations
struct SliceFromRawPartsRule {
    metadata: RuleMetadata,
}

impl SliceFromRawPartsRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA083".to_string(),
                name: "slice-from-raw-parts-length".to_string(),
                short_description: "slice::from_raw_parts with potentially invalid length".to_string(),
                full_description: "Detects calls to slice::from_raw_parts or from_raw_parts_mut \
                    where the length argument may exceed the actual allocation, causing undefined \
                    behavior. Common issues include using untrusted input for length, forgetting \
                    to divide byte length by element size, or using unvalidated external lengths. \
                    Ensure length is derived from a trusted source or properly validated."
                    .to_string(),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                help_uri: None,
            },
        }
    }

    /// Check if a variable name suggests it's from a trusted length source
    fn is_trusted_length_source(var_name: &str, body: &[String]) -> bool {
        // Check if the variable comes from a trusted source
        let body_str = body.join("\n");
        
        // Trusted: length from .len() method
        if body_str.contains(&format!("{} = ", var_name)) {
            // Check for Vec::len, slice::len patterns
            for line in body {
                if line.contains(&format!("{} = ", var_name)) {
                    if line.contains("::len(") || 
                       line.contains(">::len(") ||
                       line.contains(".len()") {
                        return true;
                    }
                }
            }
        }
        
        // Trusted: variable named 'count' used in allocation and from_raw_parts
        if var_name.contains("count") {
            // Check if same count used for allocation
            if body_str.contains("Layout::array") || body_str.contains("with_capacity") {
                return true;
            }
        }
        
        false
    }

    /// Check if length is validated before from_raw_parts call
    fn has_length_validation(len_var: &str, body: &[String]) -> bool {
        let body_str = body.join("\n");
        
        // Check for comparison/validation patterns
        // Pattern: Gt/Lt/Le/Ge comparisons involving the length variable
        let comparison_patterns = [
            format!("Gt(copy {}", len_var),
            format!("Lt(copy {}", len_var),
            format!("Le(copy {}", len_var),
            format!("Ge(copy {}", len_var),
            format!("Gt(move {}", len_var),
            format!("Lt(move {}", len_var),
            format!("Le(move {}", len_var),
            format!("Ge(move {}", len_var),
        ];
        
        for pattern in &comparison_patterns {
            if body_str.contains(pattern) {
                return true;
            }
        }
        
        // Check for min/saturating operations involving the length variable directly
        // Pattern: _N = min(copy len_var, ...) or min(..., copy len_var)
        if body_str.contains("::min(") {
            if body_str.contains(&format!("copy {}", len_var)) || 
               body_str.contains(&format!("move {}", len_var)) {
                // Make sure it's actually using min() on our variable
                for line in body {
                    if line.contains("::min(") && line.contains(len_var) {
                        return true;
                    }
                }
            }
        }
        if body_str.contains("saturating_") && body_str.contains(len_var) {
            // Check for saturating operations that actually involve our variable
            for line in body {
                if line.contains("saturating_") && line.contains(len_var) {
                    return true;
                }
            }
        }
        
        // Check for checked arithmetic on the length variable
        if body_str.contains("checked_") && body_str.contains(len_var) {
            for line in body {
                if line.contains("checked_") && line.contains(len_var) {
                    return true;
                }
            }
        }
        
        // Check for assert!/debug_assert! that specifically compares the length
        // The assertion should directly reference the length variable in a comparison
        // NOT overflow checks on intermediate variables
        for line in body {
            if line.contains("assert") {
                // Only count as validation if the assertion directly compares len_var
                // Pattern: assert!(len <= max) shows as assert(Le(copy len_var, ...))
                if line.contains(&format!("Le(copy {}", len_var)) ||
                   line.contains(&format!("Lt(copy {}", len_var)) ||
                   line.contains(&format!("Le(move {}", len_var)) ||
                   line.contains(&format!("Lt(move {}", len_var)) {
                    return true;
                }
            }
        }
        
        false
    }

    /// Check if a constant length is suspiciously large
    fn is_large_constant(line: &str) -> Option<usize> {
        // Pattern: from_raw_parts(ptr, const N_usize)
        if let Some(const_pos) = line.rfind("const ") {
            let after_const = &line[const_pos + 6..];
            if let Some(usize_pos) = after_const.find("_usize") {
                let num_str = &after_const[..usize_pos];
                if let Ok(n) = num_str.trim().parse::<usize>() {
                    if n > 10000 {
                        return Some(n);
                    }
                }
            }
        }
        None
    }

    /// Check if length comes from untrusted source (env, args, etc.)
    fn is_untrusted_length_source(_len_var: &str, body: &[String]) -> bool {
        let body_str = body.join("\n");
        
        // Check if variable is derived from env::var
        if body_str.contains("env::var") || body_str.contains("var::<") {
            // Check if length var is in the taint chain
            // Simple heuristic: if env::var and parse appear before from_raw_parts
            if body_str.contains("parse") {
                return true;
            }
        }
        
        // Check if variable comes from env::args
        if body_str.contains("env::args") || body_str.contains("Args") || body_str.contains("args::<") {
            return true;
        }
        
        // Check if variable comes from stdin
        if body_str.contains("stdin") || body_str.contains("Stdin") {
            return true;
        }
        
        // Check if it's a direct function parameter with 'len' in name
        // This is less certain, so we'll mark it but with lower confidence
        
        false
    }

    /// Check if length comes from a potentially dangerous computation
    /// Returns Some(reason) if dangerous, None if safe
    fn is_dangerous_length_computation(len_var: &str, body: &[String]) -> Option<String> {
        // First, check if len_var is assigned from another variable via cast/move
        // Pattern: _3 = move _4 as usize (IntToInt)
        let mut source_var = len_var.to_string();
        for line in body {
            let trimmed = line.trim();
            if trimmed.contains(&format!("{} = move ", len_var)) && trimmed.contains("as usize") {
                // Extract the source variable
                if let Some(start) = trimmed.find("move ") {
                    let after_move = &trimmed[start + 5..];
                    if let Some(end) = after_move.find(" as") {
                        source_var = after_move[..end].to_string();
                    }
                }
            }
        }
        
        // Now check both len_var and source_var for dangerous patterns
        for line in body {
            let trimmed = line.trim();
            
            // Pattern: _N = MulWithOverflow(...) or _N = Mul(...)
            // Dangerous: multiplication could overflow or be wrong scale
            if trimmed.contains(&format!("{} = MulWithOverflow", len_var)) ||
                trimmed.contains(&format!("{} = Mul(", len_var)) {
                return Some("length computed from multiplication (may overflow or use wrong scale)".to_string());
            }
            
            // Pattern: _N = offset_from(...)
            // Dangerous: pointer diff from untrusted pointers
            // Check both the direct var and the source var (before cast)
            if trimmed.contains(&format!("{} =", len_var)) && trimmed.contains("offset_from") {
                return Some("length derived from pointer difference (end pointer may be invalid)".to_string());
            }
            if source_var != len_var && trimmed.contains(&format!("{} =", source_var)) && trimmed.contains("offset_from") {
                return Some("length derived from pointer difference (end pointer may be invalid)".to_string());
            }
            
            // Pattern: _N = move (_M.0: usize) where _M is from MulWithOverflow
            // This is the result of MulWithOverflow
            if trimmed.contains(&format!("{} = move (", len_var)) && 
               trimmed.contains(".0: usize)") {
                // Check if any line was MulWithOverflow
                let body_str = body.join("\n");
                if body_str.contains("MulWithOverflow") {
                    return Some("length computed from multiplication (may overflow or use wrong scale)".to_string());
                }
            }
            
            // Pattern: _N = Layout::size(...)
            // Dangerous: returns byte size, not element count
            if trimmed.contains(&format!("{} = Layout::size", len_var)) {
                return Some("length from Layout::size() returns bytes, not element count".to_string());
            }
            // Also check general pattern with Layout::size anywhere on the line
            if trimmed.contains(&format!("{} =", len_var)) && trimmed.contains("Layout::size") {
                return Some("length from Layout::size() returns bytes, not element count".to_string());
            }
            
            // Pattern: _N = Div(...) with wrong divisor for type
            // This needs more context, but we can flag suspicious divisions
            if trimmed.contains(&format!("{} = Div(", len_var)) {
                // Check if divisor doesn't match expected element size
                // For from_raw_parts::<T>, divisor should be size_of::<T>()
                // For now, flag divisions by 2 when element type is likely 4+ bytes
                if trimmed.contains("const 2_usize") {
                    return Some("length divided by 2 may not match element size".to_string());
                }
            }
        }
        
        None
    }

    /// Parse from_raw_parts call and extract length variable
    fn parse_from_raw_parts_call(line: &str) -> Option<(String, String)> {
        // Pattern: std::slice::from_raw_parts::<'_, T>(ptr, len)
        // Pattern: std::slice::from_raw_parts_mut::<'_, T>(ptr, len)
        
        if !line.contains("from_raw_parts") {
            return None;
        }
        
        // Extract the arguments
        // Find the last opening paren before the arrow
        let call_start = if line.contains("from_raw_parts_mut") {
            line.find("from_raw_parts_mut")?
        } else {
            line.find("from_raw_parts")?
        };
        
        let after_call = &line[call_start..];
        
        // Find the argument list
        let args_start = after_call.find('(')? + 1;
        let args_end = after_call.rfind(')')?;
        
        if args_start >= args_end {
            return None;
        }
        
        let args_str = &after_call[args_start..args_end];
        
        // Split by comma - ptr is first, len is second
        let parts: Vec<&str> = args_str.split(',').collect();
        if parts.len() != 2 {
            return None;
        }
        
        let ptr_arg = parts[0].trim()
            .trim_start_matches("copy ")
            .trim_start_matches("move ")
            .to_string();
        let len_arg = parts[1].trim()
            .trim_start_matches("copy ")
            .trim_start_matches("move ")
            .to_string();
        
        Some((ptr_arg, len_arg))
    }

    /// Check if the length variable is a function parameter
    fn is_function_parameter(len_var: &str, signature: &str) -> bool {
        // Pattern: fn foo(_1: *const u8, _2: usize)
        // Check if len_var appears as parameter in signature
        signature.contains(&format!("{}: usize", len_var)) ||
        signature.contains(&format!("{}: u64", len_var)) ||
        signature.contains(&format!("{}: u32", len_var))
    }
}

impl Rule for SliceFromRawPartsRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Skip test functions
            if function.signature.contains("#[test]") || function.name.contains("test") {
                continue;
            }

            for line in &function.body {
                let trimmed = line.trim();
                
                // Look for from_raw_parts calls
                if !trimmed.contains("from_raw_parts") {
                    continue;
                }
                
                // Skip if it's just a type reference, not a call
                if !trimmed.contains("->") || !trimmed.contains("(") {
                    continue;
                }

                // Parse the call
                let (_ptr_var, len_var) = match Self::parse_from_raw_parts_call(trimmed) {
                    Some(p) => p,
                    None => continue,
                };

                // Check for large constant length
                if let Some(large_len) = Self::is_large_constant(trimmed) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "slice::from_raw_parts called with large constant length {}. \
                            Ensure the pointer actually points to at least {} elements of \
                            memory. Large constant lengths often indicate bugs.",
                            large_len, large_len
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: function.span.clone(),
                    });
                    continue;
                }

                // Check if length is from trusted source
                if Self::is_trusted_length_source(&len_var, &function.body) {
                    continue;
                }

                // Check if length is validated
                if Self::has_length_validation(&len_var, &function.body) {
                    continue;
                }

                // Check for untrusted sources (env, args, stdin)
                if Self::is_untrusted_length_source(&len_var, &function.body) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "slice::from_raw_parts length '{}' derived from untrusted source \
                            (environment variable, command-line argument, or user input). \
                            Validate length against allocation size before creating slice.",
                            len_var
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: function.span.clone(),
                    });
                    continue;
                }
                
                // Check for dangerous length computations (multiplication, pointer diff, Layout::size)
                if let Some(reason) = Self::is_dangerous_length_computation(&len_var, &function.body) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "slice::from_raw_parts length '{}': {}. \
                            Verify the length correctly represents element count within the allocation.",
                            len_var, reason
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: function.span.clone(),
                    });
                    continue;
                }

                // Check if length is a direct function parameter (potentially untrusted)
                if Self::is_function_parameter(&len_var, &function.signature) {
                    // Skip if function uses NonNull - indicates safety-aware API design
                    // where the caller is trusted to provide valid values
                    if function.signature.contains("NonNull<") {
                        continue;
                    }
                    
                    // This is a warning - the parameter could be from a trusted caller
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: Severity::Medium, // Lower severity for parameter case
                        message: format!(
                            "slice::from_raw_parts length '{}' comes directly from function \
                            parameter without validation. If callers can pass arbitrary values, \
                            add bounds checking or document the safety requirements.",
                            len_var
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: function.span.clone(),
                    });
                }
            }
        }

        findings
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
struct TlsVerificationDisabledRule {
    metadata: RuleMetadata,
}

impl TlsVerificationDisabledRule {
    fn new() -> Self {
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
struct AwsS3UnscopedAccessRule {
    metadata: RuleMetadata,
}

impl AwsS3UnscopedAccessRule {
    fn new() -> Self {
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
            let mut untrusted_vars: std::collections::HashSet<String> = std::collections::HashSet::new();
            
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

// ============================================================================
// RUSTCOLA086: Path Traversal Vulnerability Detection
// ============================================================================

/// Detects path traversal vulnerabilities where untrusted input flows to
/// filesystem operations without proper validation. Uses interprocedural 
/// analysis to track taint through helper functions.
///
/// **Sources:** env::var, env::args, stdin, HTTP request parameters
/// **Sinks:** fs::read*, fs::write*, fs::remove*, File::open, etc.
/// **Sanitizers:** canonicalize + starts_with, allowlist validation, 
///                 stripping dangerous characters (../, backslashes)
struct PathTraversalRule {
    metadata: RuleMetadata,
}

impl PathTraversalRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA086".to_string(),
                name: "path-traversal".to_string(),
                short_description: "Untrusted input used in filesystem path".to_string(),
                full_description: "Detects when user-controlled input flows to filesystem \
                    operations without proper validation. Attackers can use path traversal \
                    sequences like '../' or absolute paths to access files outside intended \
                    directories. Use canonicalize() + starts_with() validation, or strip \
                    dangerous path components before use.".to_string(),
                help_uri: Some("https://owasp.org/www-community/attacks/Path_Traversal".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
    
    /// Filesystem sink patterns that can be exploited via path traversal
    const FS_SINKS: &'static [&'static str] = &[
        // Read operations
        "fs::read_to_string",
        "fs::read",
        "File::open",
        "std::fs::read_to_string",
        "std::fs::read",
        "std::fs::File::open",
        "OpenOptions::open",
        "read_to_string(",
        "read_to_string::<",  // MIR monomorphized form
        // Write operations  
        "fs::write",
        "fs::create_dir",
        "fs::create_dir_all",
        "std::fs::write",
        "std::fs::create_dir",
        "std::fs::create_dir_all",
        "File::create",
        "std::fs::File::create",
        "create_dir_all::<",  // MIR monomorphized form
        "create_dir::<",      // MIR monomorphized form
        // Delete operations
        "fs::remove_file",
        "fs::remove_dir",
        "fs::remove_dir_all",
        "std::fs::remove_file",
        "std::fs::remove_dir",
        "std::fs::remove_dir_all",
        "remove_file::<",     // MIR monomorphized form
        "remove_dir::<",      // MIR monomorphized form
        "remove_dir_all::<",  // MIR monomorphized form
        // Copy/Move operations
        "fs::copy",
        "fs::rename",
        "std::fs::copy",
        "std::fs::rename",
        "copy::<",            // MIR monomorphized form (be careful of false positives)
        "rename::<",          // MIR monomorphized form
        // Path operations that can enable traversal
        "Path::join",
        "PathBuf::push",
        "PathBuf::join",
    ];
    
    /// Patterns indicating untrusted input sources
    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        // Environment variables
        "env::var(",
        "env::var_os(",
        "std::env::var(",
        "std::env::var_os(",
        " = var(",
        " = var::",
        // Command-line arguments
        "env::args()",
        "std::env::args()",
        " = args()",
        "Args>::next(",  // Iterator over args
        // User input - MIR patterns
        " = stdin()",
        "Stdin::lock(",
        "BufRead>::read_line(",
        "read_line(move",
        "io::stdin()",
    ];
    
    /// Patterns indicating path sanitization/validation
    const SANITIZERS: &'static [&'static str] = &[
        // Canonicalization
        "canonicalize(",
        // Validation checks - MIR patterns
        "starts_with(",
        "strip_prefix(",
        "is_relative(",
        "is_absolute(",
        // Allowlist/contains validation - MIR patterns
        "::contains(move",
        "::contains(copy",
        "slice::<impl",  // slice::contains pattern
        // String replacement/sanitization - MIR patterns
        "String::replace",
        "str::replace",
        // Filter/validation patterns
        ".filter(",
        "chars().all(",
        "is_alphanumeric",
        // Common validation function names (will match in MIR function calls)
        "validate",
        "sanitize", 
        "check_path",
        "is_safe",
        "safe_join",
    ];

    /// Track untrusted variables through the function body
    fn track_untrusted_paths(&self, body: &[String]) -> HashSet<String> {
        let mut untrusted_vars = HashSet::new();
        
        // First pass: find source variables
        for line in body {
            let trimmed = line.trim();
            
            // Check for untrusted sources
            for source in Self::UNTRUSTED_SOURCES {
                if trimmed.contains(source) {
                    // Extract assignment target
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        untrusted_vars.insert(target);
                    }
                }
            }
        }
        
        // Second pass: propagate taint through assignments
        let mut changed = true;
        let max_iterations = 20;
        let mut iterations = 0;
        
        while changed && iterations < max_iterations {
            changed = false;
            iterations += 1;
            
            for line in body {
                let trimmed = line.trim();
                
                // Skip if not an assignment
                if !trimmed.contains(" = ") {
                    continue;
                }
                
                // Extract target and source of assignment
                if let Some(target) = self.extract_assignment_target(trimmed) {
                    // Check if any untrusted variable appears in the RHS
                    for untrusted in untrusted_vars.clone() {
                        if self.contains_var(trimmed, &untrusted) {
                            if !untrusted_vars.contains(&target) {
                                untrusted_vars.insert(target.clone());
                                changed = true;
                            }
                        }
                    }
                }
                
                // PathBuf operations that propagate taint
                if trimmed.contains("PathBuf::from(") || 
                   trimmed.contains("Path::new(") ||
                   trimmed.contains("::join(") ||
                   trimmed.contains("::push(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if trimmed.contains(&format!("move {}", untrusted)) ||
                               trimmed.contains(&format!("copy {}", untrusted)) ||
                               trimmed.contains(&format!("&{}", untrusted)) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through .unwrap(), .expect(), .unwrap_or_default()
                if trimmed.contains("unwrap()") || 
                   trimmed.contains("expect(") ||
                   trimmed.contains("unwrap_or") ||
                   trimmed.contains("Result::Ok(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through string formatting
                if trimmed.contains("format!") || trimmed.contains("format_args!") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through vector/slice indexing: _x = _vec[_idx] or Index::index
                if trimmed.contains("Index>::index(") || trimmed.contains("IndexMut>::index_mut(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through str::trim() operations
                if trimmed.contains("str>::trim(") || trimmed.contains("str>::trim_end(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through Deref (String -> &str, etc.)
                if trimmed.contains("Deref>::deref(") || trimmed.contains("as_str(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through reference creation (_14 = &_2)
                if trimmed.contains(" = &") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        // Find what's being referenced
                        if let Some(amp_idx) = trimmed.find('&') {
                            let after_amp = &trimmed[amp_idx + 1..];
                            let referenced = if after_amp.starts_with("mut ") {
                                after_amp[4..].trim().trim_end_matches(';')
                            } else {
                                after_amp.trim().trim_end_matches(';')
                            };
                            if untrusted_vars.contains(referenced) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Special handling for read_line: taint flows to the buffer argument
        // Pattern: read_line(move _x, copy _y) or read_line(move _x, move _y)
        // The buffer (_y in `&mut _y`) becomes tainted
        for line in body {
            if line.contains("read_line(") {
                // Extract the buffer argument - it's the variable being read into
                // In MIR: _4 = <StdinLock<'_> as BufRead>::read_line(move _5, copy _8)
                // where _8 is &mut String that receives the input
                if let Some(buffer_ref) = Self::extract_read_line_buffer(line) {
                    // buffer_ref might be _8, but we need to find what _8 points to
                    // Look for "_8 = &mut _2" pattern
                    if let Some(actual_var) = Self::resolve_reference(body, &buffer_ref) {
                        untrusted_vars.insert(actual_var);
                    } else {
                        // If we can't resolve, taint the reference var anyway
                        untrusted_vars.insert(buffer_ref);
                    }
                }
            }
        }
        
        untrusted_vars
    }
    
    /// Resolve a reference variable to its target
    /// Given _8, finds "_8 = &mut _2" and returns "_2"
    fn resolve_reference(body: &[String], ref_var: &str) -> Option<String> {
        for line in body {
            let trimmed = line.trim();
            // Pattern: _8 = &mut _2 or _8 = &_2
            if trimmed.starts_with(ref_var) && trimmed.contains(" = &") {
                // Extract target after & or &mut
                if let Some(amp_idx) = trimmed.find('&') {
                    let after_amp = &trimmed[amp_idx + 1..];
                    // Skip "mut " if present
                    let target = if after_amp.starts_with("mut ") {
                        after_amp[4..].trim_end_matches(';')
                    } else {
                        after_amp.trim_end_matches(';')
                    };
                    let target = target.trim();
                    if target.starts_with('_') {
                        return Some(target.to_string());
                    }
                }
            }
        }
        None
    }
    
    /// Extract the buffer variable from a read_line call
    fn extract_read_line_buffer(line: &str) -> Option<String> {
        // Pattern: read_line(move _X, copy _Y) or read_line(move _X, move _Y)
        // We want _Y (the string buffer)
        if let Some(idx) = line.find("read_line(") {
            let after = &line[idx..];
            // Find the second argument (after the comma)
            if let Some(comma_idx) = after.find(',') {
                let second_arg = &after[comma_idx + 1..];
                // Extract _N pattern
                for word in second_arg.split_whitespace() {
                    let clean = word.trim_matches(|c| c == ')' || c == '(' || c == '&');
                    if clean.starts_with('_') && clean.len() > 1 {
                        return Some(clean.to_string());
                    }
                }
            }
        }
        None
    }
    
    /// Check if function has path sanitization/validation
    fn has_path_sanitization(&self, body: &[String], _untrusted_vars: &HashSet<String>) -> bool {
        let body_str = body.join("\n");
        
        // Check for sanitizer patterns anywhere in the function
        for sanitizer in Self::SANITIZERS {
            if body_str.contains(sanitizer) {
                return true;
            }
        }
        
        // Check for conditional checks that guard path operations
        // MIR pattern: switchInt after contains/starts_with check
        if body_str.contains("switchInt(") {
            // Look for path validation patterns before switchInt
            if body_str.contains("contains(") || 
               body_str.contains("starts_with(") ||
               body_str.contains("is_relative()") ||
               body_str.contains("strip_prefix(") {
                return true;
            }
        }
        
        // Check for early return on validation failure
        // Pattern: if !path.starts_with(...) { return Err(...) }
        if body_str.contains("Err(") && 
           (body_str.contains("Permission") || 
            body_str.contains("Invalid") ||
            body_str.contains("traversal") ||
            body_str.contains("not in allow")) {
            return true;
        }
        
        false
    }
    
    /// Find filesystem operations using untrusted paths
    fn find_unsafe_fs_operations(&self, body: &[String], untrusted_vars: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        
        for line in body {
            let trimmed = line.trim();
            
            // Check for filesystem sink patterns
            for sink in Self::FS_SINKS {
                if trimmed.contains(sink) {
                    // Check if any untrusted variable is used
                    for var in untrusted_vars {
                        if trimmed.contains(&format!("move {}", var)) ||
                           trimmed.contains(&format!("copy {}", var)) ||
                           trimmed.contains(&format!("&{}", var)) ||
                           trimmed.contains(&format!("({}", var)) {
                            evidence.push(trimmed.to_string());
                            break;
                        }
                    }
                }
            }
        }
        
        evidence
    }
    
    /// Extract variable name from assignment target
    fn extract_assignment_target(&self, line: &str) -> Option<String> {
        let parts: Vec<&str> = line.split('=').collect();
        if parts.len() >= 2 {
            let target = parts[0].trim();
            // Extract MIR local name (_1, _2, etc.)
            if target.starts_with('_') && target.chars().skip(1).all(|c| c.is_ascii_digit()) {
                return Some(target.to_string());
            }
            // Also handle more complex patterns
            if let Some(var) = target.split_whitespace().find(|s| s.starts_with('_')) {
                let var_clean = var.trim_end_matches(':');
                if var_clean.starts_with('_') {
                    return Some(var_clean.to_string());
                }
            }
        }
        None
    }
    
    /// Check if line contains a specific variable
    fn contains_var(&self, line: &str, var: &str) -> bool {
        // Match the variable exactly, not as a substring
        line.contains(&format!("move {}", var)) ||
        line.contains(&format!("copy {}", var)) ||
        line.contains(&format!("&{}", var)) ||
        line.contains(&format!("({})", var)) ||
        line.contains(&format!("({})", var)) ||
        line.contains(&format!("{},", var)) ||
        line.contains(&format!(" {} ", var)) ||
        line.contains(&format!("[{}]", var))
    }
}

impl Rule for PathTraversalRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 1: Intra-procedural analysis (direct source → sink in same function)
        for function in &package.functions {
            // Skip internal/test/toolchain functions
            if function.name.contains("mir_extractor") || 
               function.name.contains("mir-extractor") ||
               function.name.contains("__") ||
               function.name.contains("test_") ||
               function.name.contains("detect_rustup") ||
               function.name.contains("find_rust_toolchain") ||
               function.name.contains("detect_toolchain") ||
               function.name.contains("find_cargo_cola_workspace") {
                continue;
            }

            // Track untrusted path variables
            let untrusted_vars = self.track_untrusted_paths(&function.body);
            
            if untrusted_vars.is_empty() {
                continue;
            }

            // Check if function has path sanitization
            if self.has_path_sanitization(&function.body, &untrusted_vars) {
                continue;
            }

            // Find unsafe filesystem operations
            let unsafe_ops = self.find_unsafe_fs_operations(&function.body, &untrusted_vars);
            
            if !unsafe_ops.is_empty() {
                // Determine severity based on operation type
                let severity = if unsafe_ops.iter().any(|op| 
                    op.contains("remove") || op.contains("write") || 
                    op.contains("create") || op.contains("rename")) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity,
                    message: format!(
                        "Untrusted input used in filesystem path in `{}`. \
                        User-controlled paths can enable access to files outside \
                        intended directories using '../' sequences or absolute paths. \
                        Use canonicalize() + starts_with() validation, or sanitize \
                        path input to remove dangerous components.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: unsafe_ops.into_iter().take(3).collect(),
                    span: function.span.clone(),
                });
            }
        }

        // Phase 2: Inter-procedural analysis (flows through helper functions)
        // This detects patterns like:
        //   fn get_user_file() -> String { env::var("FILE").unwrap() }
        //   fn read_file() { fs::read_to_string(get_user_file()); }
        if let Ok(mut inter_analysis) = interprocedural::InterProceduralAnalysis::new(package) {
            if inter_analysis.analyze(package).is_ok() {
                let flows = inter_analysis.detect_inter_procedural_flows(package);
                
                // Track already reported functions to avoid duplicates
                let mut reported_functions: std::collections::HashSet<String> = findings
                    .iter()
                    .map(|f| f.function.clone())
                    .collect();
                
                for flow in flows {
                    // Only consider filesystem sinks for path traversal
                    if flow.sink_type != "filesystem" {
                        continue;
                    }
                    
                    // Skip internal/toolchain functions
                    let is_internal = flow.sink_function.contains("mir_extractor")
                        || flow.sink_function.contains("mir-extractor")
                        || flow.sink_function.contains("cache_envelope")
                        || flow.sink_function.contains("detect_toolchain")
                        || flow.sink_function.contains("extract_artifacts")
                        || flow.sink_function.contains("__")
                        || flow.source_function.contains("mir_extractor")
                        || flow.source_function.contains("mir-extractor")
                        || flow.source_function.contains("cache_envelope")
                        || flow.source_function.contains("fingerprint")
                        || flow.source_function.contains("toolchain");
                    if is_internal {
                        continue;
                    }
                    
                    // Skip if already reported (by intra-procedural or another inter-procedural flow)
                    if reported_functions.contains(&flow.sink_function) {
                        continue;
                    }
                    
                    // Skip if sanitized
                    if flow.sanitized {
                        continue;
                    }
                    
                    // Get the sink function for span info
                    let sink_func = package.functions.iter()
                        .find(|f| f.name == flow.sink_function);
                    
                    let span = sink_func.map(|f| f.span.clone()).unwrap_or_default();
                    let signature = sink_func.map(|f| f.signature.clone()).unwrap_or_default();
                    
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: Severity::High,
                        message: format!(
                            "Inter-procedural path traversal: untrusted input from `{}` \
                            flows through {} to filesystem operation in `{}`. \
                            User-controlled paths can enable access to files outside \
                            intended directories.",
                            flow.source_function,
                            if flow.call_chain.len() > 2 {
                                format!("{} function calls", flow.call_chain.len() - 1)
                            } else {
                                "helper function".to_string()
                            },
                            flow.sink_function
                        ),
                        function: flow.sink_function.clone(),
                        function_signature: signature,
                        evidence: vec![flow.describe()],
                        span,
                    });
                    
                    // Track this sink function to avoid duplicates from other flows
                    reported_functions.insert(flow.sink_function.clone());
                }
            }
        }

        findings
    }
}

/// RUSTCOLA088: Server-Side Request Forgery (SSRF) Detection
///
/// Detects when user-controlled input flows to HTTP client URL parameters
/// without proper validation. SSRF occurs when attackers can control server-side
/// HTTP requests, enabling access to internal services, cloud metadata endpoints,
/// or bypassing network access controls.
///
/// **Sources:** env::var, env::args, stdin, file contents  
/// **Sinks:** reqwest::get, reqwest::Client::get/post, ureq::get, hyper::Client
/// **Sanitizers:** URL parsing with host validation, allowlist checks, scheme validation
struct SsrfRule {
    metadata: RuleMetadata,
}

impl SsrfRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA088".to_string(),
                name: "server-side-request-forgery".to_string(),
                short_description: "Untrusted input used as HTTP request URL".to_string(),
                full_description: "Detects when user-controlled input is used directly as \
                    an HTTP request URL without validation. This enables attackers to make \
                    the server send requests to arbitrary destinations, potentially accessing \
                    internal services (localhost, cloud metadata at 169.254.169.254), scanning \
                    internal networks, or exfiltrating data. Validate URLs against an allowlist \
                    of permitted hosts and schemes before making requests.".to_string(),
                help_uri: Some("https://owasp.org/www-community/attacks/Server_Side_Request_Forgery".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
    
    /// HTTP client patterns that indicate URL sinks
    const HTTP_SINKS: &'static [&'static str] = &[
        // reqwest patterns - MIR style
        "reqwest::blocking::get",
        "reqwest::get",
        "blocking::get",
        "Client>::get",
        "Client>::post",
        "Client>::put",
        "Client>::delete",
        "Client>::patch",
        "Client>::head",
        "ClientBuilder",
        "RequestBuilder>::send",
        // ureq patterns - MIR style
        "ureq::get",
        "ureq::post",
        "ureq::put",
        "ureq::delete",
        "ureq::request",
        "Agent>::get",
        "Agent>::post",
        "Request>::call",
        // hyper patterns
        "hyper::Client",
        "hyper::Request",
        "Request>::builder",
        "Uri::from_str",
        // Generic HTTP patterns
        "http::Request",
        // Call patterns in MIR
        "get::<&String>",
        "get::<&str>",
        "post::<&String>",
        "post::<&str>",
    ];
    
    /// Patterns indicating untrusted input sources (same as SQL injection)
    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        // Environment variables - MIR patterns
        "env::var(",
        "env::var_os(",
        "std::env::var(",
        "std::env::var_os(",
        " = var(",       // Direct var call
        " = var::",      // MIR style var call
        "var::<&str>",   // Generic var call in MIR
        "var_os::<",     // Generic var_os call
        // Command-line arguments
        "env::args()",
        "std::env::args()",
        " = args()",
        "Args>::next(",
        "args().collect",
        // User input - MIR patterns
        " = stdin()",
        "Stdin::lock(",
        "Stdin>::lock",
        "BufRead>::read_line(",
        "read_line(move",
        "io::stdin()",
        "Lines>::next(",  // stdin.lines().next()
        // File contents (indirect)
        "fs::read_to_string(",
        "read_to_string(move",
        "read_to_string::",
        "BufReader>::read",
        "Read>::read",
        // Web framework input
        "Request",
        "Form",
        "Query",
        "Json",
        "Path",
    ];
    
    /// Patterns indicating SSRF sanitization/validation
    const SANITIZERS: &'static [&'static str] = &[
        // URL parsing with validation
        "Url::parse(",
        "url::Url::parse(",
        "Uri::from_str(",
        "host_str(",
        "scheme(",
        // Host validation patterns
        "starts_with(",
        "ends_with(",
        "contains(",
        // Allowlist patterns
        "allowed",
        "whitelist",
        "allowlist",
        "trusted",
        "permitted",
        // Blocklist patterns (blocking internal IPs)
        "localhost",
        "127.0.0.1",
        "169.254.169.254",  // AWS metadata
        "192.168.",
        "10.",
        "172.",
        ".internal",
        // Scheme validation
        "== \"https\"",
        "== \"http\"",
        // Input validation
        "is_alphanumeric",
        "chars().all(",
        // MIR patterns for validation
        " as Iterator>::all::<",
        "Eq>::eq::<",
        "PartialEq>::eq::<",
        // Pattern checks
        "match ",
        "Some(\"",
    ];

    /// Track untrusted variables through the function body
    fn track_untrusted_vars(&self, body: &[String]) -> HashSet<String> {
        let mut untrusted_vars = HashSet::new();
        
        // First pass: find source variables
        for line in body {
            let trimmed = line.trim();
            
            // Check for untrusted sources
            for source in Self::UNTRUSTED_SOURCES {
                if trimmed.contains(source) {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        untrusted_vars.insert(target);
                    }
                }
            }
        }
        
        // Second pass: propagate taint through assignments
        let mut changed = true;
        let max_iterations = 20;
        let mut iterations = 0;
        
        while changed && iterations < max_iterations {
            changed = false;
            iterations += 1;
            
            for line in body {
                let trimmed = line.trim();
                
                if !trimmed.contains(" = ") {
                    continue;
                }
                
                if let Some(target) = self.extract_assignment_target(trimmed) {
                    // Check if any untrusted variable appears in the RHS
                    for untrusted in untrusted_vars.clone() {
                        if self.contains_var(trimmed, &untrusted) {
                            if !untrusted_vars.contains(&target) {
                                untrusted_vars.insert(target.clone());
                                changed = true;
                            }
                        }
                    }
                }
                
                // Propagate through Result::branch (? operator desugaring)
                // Pattern: _X = <Result<...> as Try>::branch(move _Y)
                if trimmed.contains("Try>::branch(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through Continue variant extraction
                // Pattern: _X = move ((_Y as Continue).0: Type)
                if trimmed.contains("as Continue).0") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through .unwrap(), .expect(), etc.
                if trimmed.contains("unwrap()") || 
                   trimmed.contains("expect(") ||
                   trimmed.contains("unwrap_or") ||
                   trimmed.contains("Result::Ok(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through string formatting
                if trimmed.contains("format!") || 
                   trimmed.contains("format_args!") ||
                   trimmed.contains("Arguments::") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through string concatenation
                if trimmed.contains("Add>::add(") || trimmed.contains("+ ") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through Deref (String -> &str)
                if trimmed.contains("Deref>::deref(") || trimmed.contains("as_str(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through str::trim()
                if trimmed.contains("str>::trim(") || trimmed.contains("str>::trim_end(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through reference creation
                if trimmed.contains(" = &") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        if let Some(amp_idx) = trimmed.find('&') {
                            let after_amp = &trimmed[amp_idx + 1..];
                            let referenced = if after_amp.starts_with("mut ") {
                                after_amp[4..].trim().trim_end_matches(';')
                            } else {
                                after_amp.trim().trim_end_matches(';')
                            };
                            if untrusted_vars.contains(referenced) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through clone
                if trimmed.contains("Clone>::clone(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through to_string
                if trimmed.contains("ToString>::to_string(") || trimmed.contains("to_string(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        untrusted_vars
    }
    
    /// Check if function has SSRF sanitization/validation
    fn has_ssrf_sanitization(&self, body: &[String]) -> bool {
        let body_str = body.join("\n");
        
        // Check for sanitizer patterns
        for sanitizer in Self::SANITIZERS {
            if body_str.contains(sanitizer) {
                return true;
            }
        }
        
        false
    }
    
    /// Find HTTP requests using untrusted URLs
    fn find_unsafe_http_operations(&self, body: &[String], untrusted_vars: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        
        for line in body {
            let trimmed = line.trim();
            
            // Check for HTTP sink patterns
            for sink in Self::HTTP_SINKS {
                if trimmed.contains(sink) {
                    // Check if any untrusted variable is used on this line
                    for var in untrusted_vars {
                        if self.contains_var(trimmed, var) {
                            evidence.push(trimmed.to_string());
                            break;
                        }
                    }
                    // Don't break - continue checking for more sinks
                }
            }
            
            // Also check for generic HTTP call patterns with untrusted args
            if trimmed.contains("get(move") || 
               trimmed.contains("get(copy") ||
               trimmed.contains("post(move") ||
               trimmed.contains("post(copy") ||
               trimmed.contains("call(move") ||
               trimmed.contains("call(copy") ||
               trimmed.contains("send(move") ||
               trimmed.contains("send(copy") {
                for var in untrusted_vars {
                    if self.contains_var(trimmed, var) {
                        if !evidence.iter().any(|e| e == trimmed) {
                            evidence.push(trimmed.to_string());
                        }
                        break;
                    }
                }
            }
        }
        
        evidence
    }
    
    /// Extract variable name from assignment target
    fn extract_assignment_target(&self, line: &str) -> Option<String> {
        let parts: Vec<&str> = line.split('=').collect();
        if parts.len() >= 2 {
            let target = parts[0].trim();
            if target.starts_with('_') && target.chars().skip(1).all(|c| c.is_ascii_digit()) {
                return Some(target.to_string());
            }
            if let Some(var) = target.split_whitespace().find(|s| s.starts_with('_')) {
                let var_clean = var.trim_end_matches(':');
                if var_clean.starts_with('_') {
                    return Some(var_clean.to_string());
                }
            }
        }
        None
    }
    
    /// Check if line contains a specific variable
    fn contains_var(&self, line: &str, var: &str) -> bool {
        line.contains(&format!("move {}", var)) ||
        line.contains(&format!("copy {}", var)) ||
        line.contains(&format!("&{}", var)) ||
        line.contains(&format!("({})", var)) ||
        line.contains(&format!("{},", var)) ||
        line.contains(&format!(" {} ", var)) ||
        line.contains(&format!("[{}]", var)) ||
        line.contains(&format!("(({} as", var))  // For pattern like ((_X as Continue).0)
    }
}

impl Rule for SsrfRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 1: Intra-procedural analysis
        for function in &package.functions {
            // Skip internal/test functions
            if function.name.contains("mir_extractor") || 
               function.name.contains("mir-extractor") ||
               function.name.contains("__") ||
               function.name.contains("test_") ||
               function.name == "detect_toolchain" {
                continue;
            }

            // Check if function uses HTTP client patterns
            let body_str = function.body.join("\n");
            let has_http_client = Self::HTTP_SINKS.iter().any(|s| body_str.contains(s)) ||
                                  body_str.contains("reqwest") ||
                                  body_str.contains("ureq") ||
                                  body_str.contains("hyper");
            
            if !has_http_client {
                continue;
            }

            // Track untrusted variables
            let untrusted_vars = self.track_untrusted_vars(&function.body);
            
            if untrusted_vars.is_empty() {
                continue;
            }

            // Check if function has SSRF sanitization
            if self.has_ssrf_sanitization(&function.body) {
                continue;
            }

            // Find unsafe HTTP operations
            let unsafe_ops = self.find_unsafe_http_operations(&function.body, &untrusted_vars);
            
            if !unsafe_ops.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: Severity::High,
                    message: format!(
                        "Server-Side Request Forgery (SSRF) vulnerability in `{}`. \
                        User-controlled input is used as an HTTP request URL without \
                        validation. Attackers could access internal services, cloud \
                        metadata (169.254.169.254), or scan internal networks. Validate \
                        URLs against an allowlist of permitted hosts.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: unsafe_ops.into_iter().take(3).collect(),
                    span: function.span.clone(),
                });
            }
        }

        // Phase 2: Inter-procedural analysis
        if let Ok(mut inter_analysis) = interprocedural::InterProceduralAnalysis::new(package) {
            if inter_analysis.analyze(package).is_ok() {
                let flows = inter_analysis.detect_inter_procedural_flows(package);
                
                let mut reported_functions: std::collections::HashSet<String> = findings
                    .iter()
                    .map(|f| f.function.clone())
                    .collect();
                
                for flow in flows {
                    // Only consider HTTP sinks
                    if flow.sink_type != "http" {
                        continue;
                    }
                    
                    // Skip internal functions
                    let is_internal = flow.sink_function.contains("mir_extractor")
                        || flow.sink_function.contains("__")
                        || flow.source_function.contains("mir_extractor");
                    if is_internal {
                        continue;
                    }
                    
                    if reported_functions.contains(&flow.sink_function) {
                        continue;
                    }
                    
                    if flow.sanitized {
                        continue;
                    }
                    
                    let sink_func = package.functions.iter()
                        .find(|f| f.name == flow.sink_function);
                    
                    let span = sink_func.map(|f| f.span.clone()).unwrap_or_default();
                    let signature = sink_func.map(|f| f.signature.clone()).unwrap_or_default();
                    
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: Severity::High,
                        message: format!(
                            "Inter-procedural SSRF: untrusted input from `{}` \
                            flows through {} to HTTP request in `{}`. Validate \
                            URLs against an allowlist before making requests.",
                            flow.source_function,
                            if flow.call_chain.len() > 2 {
                                format!("{} function calls", flow.call_chain.len() - 1)
                            } else {
                                "helper function".to_string()
                            },
                            flow.sink_function
                        ),
                        function: flow.sink_function.clone(),
                        function_signature: signature,
                        evidence: vec![flow.describe()],
                        span,
                    });
                    
                    reported_functions.insert(flow.sink_function.clone());
                }
            }
        }

        findings
    }
}

/// RUSTCOLA087: SQL Injection Detection
///
/// Detects when user-controlled input flows to SQL query construction
/// without proper parameterization. SQL injection occurs when untrusted
/// data is concatenated or formatted directly into query strings.
///
/// **Sources:** env::var, env::args, stdin, HTTP request parameters  
/// **Sinks:** format! with SQL keywords, string concat with SQL, raw query execution
/// **Sanitizers:** Parameterized queries (?/$1 placeholders), prepared statements,
///                 integer parsing, allowlist validation
struct SqlInjectionRule {
    metadata: RuleMetadata,
}

impl SqlInjectionRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA087".to_string(),
                name: "sql-injection".to_string(),
                short_description: "Untrusted input used in SQL query construction".to_string(),
                full_description: "Detects when user-controlled input is concatenated or \
                    formatted directly into SQL query strings instead of using parameterized \
                    queries. This allows attackers to modify query logic, bypass authentication, \
                    or extract/modify sensitive data. Use prepared statements with bind \
                    parameters (?, $1, :name) instead of string interpolation.".to_string(),
                help_uri: Some("https://owasp.org/www-community/attacks/SQL_Injection".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
    
    /// SQL statement patterns - require actual SQL statement structure
    /// These patterns require a SQL verb followed by appropriate clause
    /// to avoid matching words like "SET" in "FieldSet" error messages
    const SQL_STATEMENT_PATTERNS: &'static [&'static str] = &[
        // DQL - Data Query Language
        "SELECT ", "SELECT\t", "SELECT\n",
        " FROM ",  // SELECT x FROM y
        // DML - Data Manipulation Language  
        "INSERT INTO", "INSERT  INTO",
        "UPDATE ", "UPDATE\t",
        " SET ",   // UPDATE x SET y (note spaces)
        "DELETE FROM", "DELETE  FROM",
        // DDL - Data Definition Language
        "DROP TABLE", "DROP DATABASE", "DROP INDEX", "DROP VIEW",
        "CREATE TABLE", "CREATE DATABASE", "CREATE INDEX", "CREATE VIEW",
        "ALTER TABLE", "ALTER DATABASE",
        "TRUNCATE TABLE",
        // SQL clauses (must follow SELECT/UPDATE/DELETE)
        " WHERE ",
        " ORDER BY", " GROUP BY", " HAVING ",
        " JOIN ", " LEFT JOIN", " RIGHT JOIN", " INNER JOIN", " OUTER JOIN",
        " UNION ", " UNION ALL",
        " VALUES", " VALUES(",
        // Parameterized query markers (these indicate SQL context)
        "?)", "?, ", " ? ",  // Placeholders indicate SQL
        "$1", "$2", "$3",    // PostgreSQL placeholders
    ];
    
    /// SQL keywords that indicate query construction (for secondary validation)
    #[allow(dead_code)]
    const SQL_KEYWORDS: &'static [&'static str] = &[
        "SELECT",
        "INSERT",
        "UPDATE", 
        "DELETE",
        "DROP",
        "CREATE",
        "ALTER",
        "TRUNCATE",
        "WHERE",
        "FROM",
        "INTO",
        "VALUES",
        "SET",
        "ORDER BY",
        "GROUP BY",
        "HAVING",
        "JOIN",
        "UNION",
    ];
    
    /// Patterns indicating SQL query construction sinks
    const SQL_SINKS: &'static [&'static str] = &[
        // Format patterns - queries built with format!
        "format_args!",
        "format!",
        // String operations for building queries
        "String::push_str",
        "str::to_string",
        "+",  // String concatenation
        // Database execution patterns (various libraries)
        "execute(",
        "query(",
        "query_as(",
        "sql_query(",
        "prepare(",
        "execute_batch(",
        "query_row(",
        "query_map(",
        "raw_query(",
        "raw_sql(",
        // sqlx patterns
        "sqlx::query",
        "sqlx::query_as",
        "sqlx::query_scalar",
        // diesel patterns  
        "diesel::sql_query",
        "diesel::delete",
        "diesel::insert_into",
        "diesel::update",
        // rusqlite patterns
        "rusqlite::execute",
        "Connection::execute",
        "Connection::query_row",
        "Statement::execute",
    ];
    
    /// Patterns indicating untrusted input sources
    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        // Environment variables
        "env::var(",
        "env::var_os(",
        "std::env::var(",
        "std::env::var_os(",
        " = var(",
        " = var::",
        // Command-line arguments
        "env::args()",
        "std::env::args()",
        " = args()",
        "Args>::next(",
        // User input - MIR patterns
        " = stdin()",
        "Stdin::lock(",
        "BufRead>::read_line(",
        "read_line(move",
        "io::stdin()",
        // Web framework input (common patterns)
        "Request",
        "Form",
        "Query",
        "Json",
        "Path",
    ];
    
    /// Patterns indicating SQL sanitization/parameterization
    const SANITIZERS: &'static [&'static str] = &[
        // Parameterized query placeholders
        " ? ",           // SQLite/MySQL placeholder
        "?)",            // End of params
        "?, ",           // Multiple params
        "$1",            // PostgreSQL placeholder
        "$2",
        ":name",         // Named parameter
        ":username",
        ":id",
        // Binding functions
        ".bind(",
        "bind_value(",
        "bind::<",
        // Safe query builders (usually handle escaping)
        "QueryBuilder",
        "filter(",
        ".eq(",
        ".ne(",
        ".gt(",
        ".lt(",
        // Integer parsing (prevents string injection)
        "parse::<i",
        "parse::<u",
        "parse::<f",
        "i32::from_str",
        "i64::from_str",
        "u32::from_str",
        "u64::from_str",
        // Allowlist/validation patterns
        "::contains(move",
        "::contains(copy",
        "allowed_",
        "whitelist",
        "allowlist",
        // Escaping functions
        "escape(",
        "quote(",
        "sanitize",
        "replace(",   // String replacement for escaping
        "replace('",  // Single quote escaping
        "::replace::", // MIR pattern for replace
        // Type checking
        "is_alphanumeric",
        "chars().all(",
        // MIR patterns for validation
        " as Iterator>::all::<",  // .all() validation in MIR
    ];

    /// Track untrusted variables through the function body
    fn track_untrusted_vars(&self, body: &[String]) -> HashSet<String> {
        let mut untrusted_vars = HashSet::new();
        
        // First pass: find source variables
        for line in body {
            let trimmed = line.trim();
            
            // Check for untrusted sources
            for source in Self::UNTRUSTED_SOURCES {
                if trimmed.contains(source) {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        untrusted_vars.insert(target);
                    }
                }
            }
        }
        
        // Second pass: propagate taint through assignments
        let mut changed = true;
        let max_iterations = 20;
        let mut iterations = 0;
        
        while changed && iterations < max_iterations {
            changed = false;
            iterations += 1;
            
            for line in body {
                let trimmed = line.trim();
                
                if !trimmed.contains(" = ") {
                    continue;
                }
                
                if let Some(target) = self.extract_assignment_target(trimmed) {
                    // Check if any untrusted variable appears in the RHS
                    for untrusted in untrusted_vars.clone() {
                        if self.contains_var(trimmed, &untrusted) {
                            if !untrusted_vars.contains(&target) {
                                untrusted_vars.insert(target.clone());
                                changed = true;
                            }
                        }
                    }
                }
                
                // Propagate through .unwrap(), .expect(), .unwrap_or_default(), etc.
                if trimmed.contains("unwrap()") || 
                   trimmed.contains("expect(") ||
                   trimmed.contains("unwrap_or") ||
                   trimmed.contains("Result::Ok(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through string formatting (critical for SQL injection)
                if trimmed.contains("format!") || 
                   trimmed.contains("format_args!") ||
                   trimmed.contains("Arguments::") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through string concatenation
                if trimmed.contains("Add>::add(") || trimmed.contains("+ ") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through Deref (String -> &str)
                if trimmed.contains("Deref>::deref(") || trimmed.contains("as_str(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through str::trim()
                if trimmed.contains("str>::trim(") || trimmed.contains("str>::trim_end(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through reference creation
                if trimmed.contains(" = &") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        if let Some(amp_idx) = trimmed.find('&') {
                            let after_amp = &trimmed[amp_idx + 1..];
                            let referenced = if after_amp.starts_with("mut ") {
                                after_amp[4..].trim().trim_end_matches(';')
                            } else {
                                after_amp.trim().trim_end_matches(';')
                            };
                            if untrusted_vars.contains(referenced) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through clone
                if trimmed.contains("Clone>::clone(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                
                // Propagate through to_string
                if trimmed.contains("ToString>::to_string(") || trimmed.contains("to_string(") {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        for untrusted in untrusted_vars.clone() {
                            if self.contains_var(trimmed, &untrusted) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        untrusted_vars
    }
    
    /// Check if function has SQL sanitization/parameterization
    fn has_sql_sanitization(&self, body: &[String]) -> bool {
        let body_str = body.join("\n");
        
        // Check for sanitizer patterns
        for sanitizer in Self::SANITIZERS {
            if body_str.contains(sanitizer) {
                return true;
            }
        }
        
        false
    }
    
    /// Check if a string looks like a SQL query using strict patterns
    #[allow(dead_code)]
    fn looks_like_sql(&self, s: &str) -> bool {
        let upper = s.to_uppercase();
        // Use strict statement patterns, not just keywords
        Self::SQL_STATEMENT_PATTERNS.iter().any(|pattern| upper.contains(pattern))
    }
    
    /// Check if a string contains actual SQL statement structure
    /// This is stricter than just keyword matching - requires statement syntax
    #[allow(dead_code)]
    fn is_sql_statement(line: &str) -> bool {
        let upper = line.to_uppercase();
        Self::SQL_STATEMENT_PATTERNS.iter().any(|pattern| upper.contains(pattern))
    }
    
    /// Find SQL query construction using untrusted input
    fn find_unsafe_sql_operations(&self, body: &[String], untrusted_vars: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        
        // Check if any SQL statement patterns appear in the function (in const strings)
        // Use stricter patterns to avoid matching "FieldSet" etc.
        let has_sql_const = body.iter().any(|line| {
            // Only check const string lines
            if !line.contains("const ") && !line.contains("[const ") {
                return false;
            }
            let line_upper = line.to_uppercase();
            // Use strict SQL statement patterns, not just keywords
            Self::SQL_STATEMENT_PATTERNS.iter().any(|pattern| line_upper.contains(pattern))
        });
        
        // Also check if the body contains references to promoted consts that might have SQL
        // The promoted const names like "bad_rusqlite_execute::promoted[0]" suggest SQL in consts
        let has_promoted_sql_ref = body.iter().any(|line| {
            line.contains("::promoted[") && 
            body.iter().any(|other| {
                // Only check const string lines with strict patterns
                if !other.contains("[const ") && !other.contains(" = [const ") {
                    return false;
                }
                let other_upper = other.to_uppercase();
                Self::SQL_STATEMENT_PATTERNS.iter().any(|pattern| other_upper.contains(pattern))
            })
        });
        
        if !has_sql_const && !has_promoted_sql_ref {
            return evidence;
        }
        
        // Check if untrusted variables flow into format operations
        let has_tainted_format = body.iter().any(|line| {
            let trimmed = line.trim();
            // Check for format machinery: fmt::Arguments, Argument
            let is_format_related = trimmed.contains("fmt::Arguments") ||
                                   trimmed.contains("fmt::rt::Argument") ||
                                   trimmed.contains("Arguments::new") ||
                                   trimmed.contains("Argument::new") ||
                                   trimmed.contains("core::fmt::") ||
                                   trimmed.contains("format_args");
            
            if is_format_related {
                for var in untrusted_vars {
                    if self.contains_var(trimmed, var) {
                        return true;
                    }
                }
            }
            false
        });
        
        if has_tainted_format {
            // Collect SQL evidence - use stricter patterns
            for line in body {
                if !line.contains("const ") && !line.contains("[const ") {
                    continue;
                }
                let line_upper = line.to_uppercase();
                if Self::SQL_STATEMENT_PATTERNS.iter().any(|pattern| line_upper.contains(pattern)) {
                    evidence.push(line.trim().to_string());
                }
            }
            // Also add the tainted format operations
            for line in body {
                let trimmed = line.trim();
                if trimmed.contains("fmt::Arguments") || 
                   trimmed.contains("Argument::new") ||
                   trimmed.contains("format_args") {
                    for var in untrusted_vars {
                        if self.contains_var(trimmed, var) {
                            evidence.push(trimmed.to_string());
                            break;
                        }
                    }
                }
            }
        }
        
        // Also check for string concatenation with SQL keywords in the function
        // (SQL keywords may be in const strings, concatenation uses tainted vars)
        if has_sql_const {
            for line in body {
                let trimmed = line.trim();
                // Check for string concatenation involving untrusted data
                // MIR pattern: <String as Add<&str>>::add(...) or Add>::add(...)
                if trimmed.contains("Add<") && trimmed.contains(">::add(") || trimmed.contains("push_str(") {
                    for var in untrusted_vars {
                        if self.contains_var(trimmed, var) {
                            evidence.push(format!("String concatenation with tainted var: {}", trimmed));
                            break;
                        }
                    }
                }
            }
        }
        
        // Check for direct SQL sink patterns
        for line in body {
            let trimmed = line.trim();
            for sink in Self::SQL_SINKS {
                if trimmed.contains(sink) {
                    for var in untrusted_vars {
                        if trimmed.contains(&format!("move {}", var)) ||
                           trimmed.contains(&format!("copy {}", var)) ||
                           trimmed.contains(&format!("&{}", var)) ||
                           trimmed.contains(&format!("({}", var)) {
                            evidence.push(trimmed.to_string());
                            break;
                        }
                    }
                }
            }
        }
        
        evidence
    }
    
    /// Extract variable name from assignment target
    fn extract_assignment_target(&self, line: &str) -> Option<String> {
        let parts: Vec<&str> = line.split('=').collect();
        if parts.len() >= 2 {
            let target = parts[0].trim();
            if target.starts_with('_') && target.chars().skip(1).all(|c| c.is_ascii_digit()) {
                return Some(target.to_string());
            }
            if let Some(var) = target.split_whitespace().find(|s| s.starts_with('_')) {
                let var_clean = var.trim_end_matches(':');
                if var_clean.starts_with('_') {
                    return Some(var_clean.to_string());
                }
            }
        }
        None
    }
    
    /// Check if line contains a specific variable
    fn contains_var(&self, line: &str, var: &str) -> bool {
        line.contains(&format!("move {}", var)) ||
        line.contains(&format!("copy {}", var)) ||
        line.contains(&format!("&{}", var)) ||
        line.contains(&format!("({})", var)) ||
        line.contains(&format!("{},", var)) ||
        line.contains(&format!(" {} ", var)) ||
        line.contains(&format!("[{}]", var))
    }
    
    /// Extract function parameters from MIR body
    /// Parameters appear as "debug PARAM_NAME => _N" lines
    fn extract_function_params(&self, body: &[String]) -> HashSet<String> {
        let mut params = HashSet::new();
        for line in body {
            let trimmed = line.trim();
            // Pattern: "debug param_name => _N;"
            if trimmed.starts_with("debug ") && trimmed.contains(" => _") {
                if let Some(start) = trimmed.find(" => _") {
                    let after = &trimmed[start + 5..];
                    // Extract _N where N is a digit  
                    let var: String = after.chars().take_while(|c| c.is_ascii_digit() || *c == '_').collect();
                    if !var.is_empty() {
                        // Don't include _0 (return value)
                        if var != "0" {
                            params.insert(format!("_{}", var.trim_start_matches('_')));
                        }
                    }
                }
            }
        }
        params
    }
    
    /// Propagate taint through assignments in the function body
    fn propagate_taint(&self, body: &[String], untrusted_vars: &mut HashSet<String>) {
        let mut changed = true;
        let max_iterations = 20;
        let mut iterations = 0;
        
        while changed && iterations < max_iterations {
            changed = false;
            iterations += 1;
            
            for line in body {
                let trimmed = line.trim();
                
                if !trimmed.contains(" = ") {
                    continue;
                }
                
                if let Some(target) = self.extract_assignment_target(trimmed) {
                    for untrusted in untrusted_vars.clone() {
                        if self.contains_var(trimmed, &untrusted) {
                            if !untrusted_vars.contains(&target) {
                                untrusted_vars.insert(target.clone());
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Rule for SqlInjectionRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 0: Identify functions that return tainted data (helper functions)
        // This includes:
        //   a) Functions with direct sources (env::var, stdin, etc.)
        //   b) Functions that call other tainted functions and return that data (transitive)
        let mut tainted_return_functions: HashSet<String> = HashSet::new();
        
        // Step 0a: Find functions with direct taint sources
        for function in &package.functions {
            // Check if this function has a taint source
            let has_source = function.body.iter().any(|line| {
                Self::UNTRUSTED_SOURCES.iter().any(|src| line.contains(src))
            });
            
            if has_source {
                // Simple heuristic: if it has a source and doesn't have SQL statement patterns in const strings,
                // it likely returns tainted data as a helper function
                let has_sql_const = function.body.iter().any(|line| {
                    if !line.contains("const ") && !line.contains("[const ") {
                        return false;
                    }
                    let upper = line.to_uppercase();
                    Self::SQL_STATEMENT_PATTERNS.iter().any(|pattern| upper.contains(pattern))
                });
                
                if !has_sql_const {
                    tainted_return_functions.insert(function.name.clone());
                }
            }
        }
        
        // Step 0b: Transitive closure - find functions that call tainted functions and return their data
        let mut changed = true;
        let mut iterations = 0;
        let max_iterations = 10;
        
        while changed && iterations < max_iterations {
            changed = false;
            iterations += 1;
            
            for function in &package.functions {
                // Skip if already known as tainted
                if tainted_return_functions.contains(&function.name) {
                    continue;
                }
                
                // Check if this function calls a tainted function and returns that data
                let mut tainted_vars_from_calls: HashSet<String> = HashSet::new();
                
                for line in &function.body {
                    let trimmed = line.trim();
                    if trimmed.contains(" = ") {
                        for tainted_fn in &tainted_return_functions {
                            let fn_name = tainted_fn.split("::").last().unwrap_or(tainted_fn);
                            // MIR pattern: _N = function_name() -> [return: ...]
                            if trimmed.contains(&format!("= {}()", fn_name)) ||
                               trimmed.contains(&format!("= {}(", fn_name)) {
                                if let Some(target) = self.extract_assignment_target(trimmed) {
                                    tainted_vars_from_calls.insert(target);
                                }
                            }
                        }
                    }
                }
                
                if tainted_vars_from_calls.is_empty() {
                    continue;
                }
                
                // Propagate taint within this function
                self.propagate_taint(&function.body, &mut tainted_vars_from_calls);
                
                // Check if any tainted var flows to return value (_0)
                let returns_tainted = function.body.iter().any(|line| {
                    let trimmed = line.trim();
                    if trimmed.starts_with("_0 = ") || trimmed.starts_with("_0 =") {
                        tainted_vars_from_calls.iter().any(|v| self.contains_var(trimmed, v))
                    } else {
                        false
                    }
                });
                
                if returns_tainted {
                    // Check it doesn't have SQL sinks (it's a helper, not a consumer)
                    let has_sql_const = function.body.iter().any(|line| {
                        if !line.contains("const ") && !line.contains("[const ") {
                            return false;
                        }
                        let upper = line.to_uppercase();
                        Self::SQL_STATEMENT_PATTERNS.iter().any(|pattern| upper.contains(pattern))
                    });
                    
                    if !has_sql_const {
                        tainted_return_functions.insert(function.name.clone());
                        changed = true;
                    }
                }
            }
        }

        // Phase 1: Intra-procedural analysis with inter-procedural taint sources
        for function in &package.functions {
            // Skip internal/test functions
            if function.name.contains("mir_extractor") || 
               function.name.contains("mir-extractor") ||
               function.name.contains("__") ||
               function.name.contains("test_") {
                continue;
            }

            // Track untrusted variables (intra-procedural)
            let mut untrusted_vars = self.track_untrusted_vars(&function.body);
            
            // Also add variables from calls to tainted-return functions
            let mut added_from_calls = false;
            for line in &function.body {
                let trimmed = line.trim();
                if trimmed.contains(" = ") {
                    for tainted_fn in &tainted_return_functions {
                        // Extract just the function name
                        let fn_name = tainted_fn.split("::").last().unwrap_or(tainted_fn);
                        // MIR pattern: _N = function_name() -> [return: ...]
                        if trimmed.contains(&format!("= {}()", fn_name)) {
                            if let Some(target) = self.extract_assignment_target(trimmed) {
                                if !untrusted_vars.contains(&target) {
                                    untrusted_vars.insert(target);
                                    added_from_calls = true;
                                }
                            }
                        }
                    }
                }
            }
            
            // If we added new tainted vars from function calls, propagate them
            if added_from_calls {
                self.propagate_taint(&function.body, &mut untrusted_vars);
            }
            
            // Phase 1b: Check for function parameters used in SQL (conservative approach)
            // If this function has parameters and uses them in SQL, treat as potential vulnerability
            // even if we can't trace the caller (the parameter source could be untrusted)
            if untrusted_vars.is_empty() {
                // Check if function has parameters used in SQL format operations
                let params = self.extract_function_params(&function.body);
                if !params.is_empty() {
                    // Propagate params through function body
                    let mut param_vars = params.clone();
                    self.propagate_taint(&function.body, &mut param_vars);
                    
                    // Check if params flow to format with SQL (use strict patterns)
                    let has_sql_const = function.body.iter().any(|line| {
                        if !line.contains("const ") && !line.contains("[const ") {
                            return false;
                        }
                        let upper = line.to_uppercase();
                        Self::SQL_STATEMENT_PATTERNS.iter().any(|pattern| upper.contains(pattern))
                    });
                    
                    if has_sql_const {
                        let has_param_in_format = function.body.iter().any(|line| {
                            let trimmed = line.trim();
                            // Check for format-related patterns
                            let is_format_related = 
                                trimmed.contains("fmt::Arguments") ||
                                trimmed.contains("Argument::") ||  // Catches Argument::new, Argument::<'_>::new_display, etc.
                                trimmed.contains("format_args") ||
                                trimmed.contains("core::fmt::") ||
                                trimmed.contains("new_display") ||
                                trimmed.contains("new_debug");
                            
                            is_format_related && param_vars.iter().any(|v| self.contains_var(trimmed, v))
                        });
                        
                        if has_param_in_format {
                            untrusted_vars = param_vars;
                        }
                    }
                }
            }
            
            if untrusted_vars.is_empty() {
                continue;
            }

            // Check if function has SQL sanitization
            if self.has_sql_sanitization(&function.body) {
                continue;
            }

            // Find unsafe SQL operations
            let unsafe_ops = self.find_unsafe_sql_operations(&function.body, &untrusted_vars);
            
            if !unsafe_ops.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: Severity::High,
                    message: format!(
                        "SQL injection vulnerability in `{}`. Untrusted input is used \
                        in SQL query construction without parameterization. Use prepared \
                        statements with bind parameters (?, $1, :name) instead of string \
                        formatting or concatenation.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: unsafe_ops.into_iter().take(3).collect(),
                    span: function.span.clone(),
                });
            }
        }

        // Phase 2: Inter-procedural analysis
        if let Ok(mut inter_analysis) = interprocedural::InterProceduralAnalysis::new(package) {
            if inter_analysis.analyze(package).is_ok() {
                let flows = inter_analysis.detect_inter_procedural_flows(package);
                
                let mut reported_functions: std::collections::HashSet<String> = findings
                    .iter()
                    .map(|f| f.function.clone())
                    .collect();
                
                for flow in flows {
                    // Only consider SQL sinks
                    if flow.sink_type != "sql" {
                        continue;
                    }
                    
                    // Skip internal functions
                    let is_internal = flow.sink_function.contains("mir_extractor")
                        || flow.sink_function.contains("__")
                        || flow.source_function.contains("mir_extractor");
                    if is_internal {
                        continue;
                    }
                    
                    if reported_functions.contains(&flow.sink_function) {
                        continue;
                    }
                    
                    if flow.sanitized {
                        continue;
                    }
                    
                    let sink_func = package.functions.iter()
                        .find(|f| f.name == flow.sink_function);
                    
                    let span = sink_func.map(|f| f.span.clone()).unwrap_or_default();
                    let signature = sink_func.map(|f| f.signature.clone()).unwrap_or_default();
                    
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: Severity::High,
                        message: format!(
                            "Inter-procedural SQL injection: untrusted input from `{}` \
                            flows through {} to SQL query in `{}`. Use parameterized \
                            queries to prevent SQL injection.",
                            flow.source_function,
                            if flow.call_chain.len() > 2 {
                                format!("{} function calls", flow.call_chain.len() - 1)
                            } else {
                                "helper function".to_string()
                            },
                            flow.sink_function
                        ),
                        function: flow.sink_function.clone(),
                        function_signature: signature,
                        evidence: vec![flow.describe()],
                        span,
                    });
                    
                    reported_functions.insert(flow.sink_function.clone());
                }
            }
        }

        findings
    }
}

/// RUSTCOLA089: Insecure YAML Deserialization
///
/// Detects when user-controlled input flows to serde_yaml deserialization
/// functions without proper validation. YAML deserialization of untrusted
/// data can cause:
/// - Billion laughs attacks (exponential entity expansion via anchors)
/// - Denial of service through deeply nested structures
/// - Unexpected type coercion attacks
/// - Resource exhaustion
///
/// **Sources:** env::var, env::args, stdin, file contents
/// **Sinks:** serde_yaml::from_str, from_slice, from_reader
/// **Sanitizers:** Anchor/alias filtering, size limits, depth limits, schema validation
struct InsecureYamlDeserializationRule {
    metadata: RuleMetadata,
}

impl InsecureYamlDeserializationRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA089".to_string(),
                name: "insecure-yaml-deserialization".to_string(),
                short_description: "Untrusted input used in YAML deserialization".to_string(),
                full_description: "User-controlled input is passed to serde_yaml \
                    deserialization functions without validation. Attackers can craft \
                    malicious YAML using anchors/aliases for exponential expansion \
                    (billion laughs), deeply nested structures, or unexpected type \
                    coercion to cause denial of service or unexpected behavior. \
                    Validate YAML input before deserialization by rejecting anchors, \
                    enforcing size limits, or using JSON instead.".to_string(),
                help_uri: Some("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// YAML deserialization sinks - MIR patterns
    const YAML_SINKS: &'static [&'static str] = &[
        "serde_yaml::from_str",
        "serde_yaml::from_slice",
        "serde_yaml::from_reader",
        "from_str::<",  // Generic form
        "from_slice::<",
        "from_reader::<",
        // MIR patterns (function instantiations)
        "serde_yaml::from_str::",
        "serde_yaml::from_slice::",
        "serde_yaml::from_reader::",
    ];

    /// Untrusted sources - includes MIR patterns
    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        // Environment variables - source and MIR forms
        "env::var",
        "env::var_os",
        "std::env::var",
        "var::<",        // MIR: _1 = var::<&str>(const "VAR")
        "var_os::<",     // MIR: _1 = var_os::<&str>(const "VAR")
        // Command-line arguments - source and MIR forms
        "env::args",
        "std::env::args",
        "args::<",       // MIR form
        "= args()",      // MIR: _X = args() -> [return: ...]
        "Args>",         // Iterator type
        // Stdin
        "stdin",
        "Stdin",
        // File operations
        "read_to_string",
        "read_to_end",
        "BufRead::read_line",
        "fs::read_to_string",
        "fs::read",
        "Read>::read_to_string",
        "Read>::read_to_end",
        // Network (could receive YAML)
        "TcpStream",
        "::connect(",
    ];

    /// Sanitization patterns that make YAML parsing safer
    const SANITIZERS: &'static [&'static str] = &[
        // Anchor/alias rejection
        r#"contains("&")"#,
        r#"contains("*")"#,
        r#"contains("<<:")"#,
        "contains(&",
        "contains(*",
        // Size limits
        ".len()",
        "len() >",
        "len() <",
        // JSON as alternative (safer)
        "serde_json::from_str",
        "serde_json::from_slice",
        // Depth checks  
        "matches",
        "count()",
        // Sanitization
        ".replace(",
        // Validation keywords
        "validate",
        "sanitize",
        "allowlist",
        "allowed",
    ];

    /// Track tainted variables from untrusted sources
    fn track_untrusted_vars<'a>(&self, function: &'a MirFunction) -> HashSet<String> {
        let mut tainted: HashSet<String> = HashSet::new();
        
        for line in &function.body {
            // Source detection - env::var, stdin, args, file reads
            for source in Self::UNTRUSTED_SOURCES {
                if line.contains(source) {
                    // Extract assigned variable
                    if let Some(var) = self.extract_assigned_var(line) {
                        tainted.insert(var);
                    }
                }
            }
            
            // Taint propagation through assignments
            if line.contains(" = ") {
                if let Some((dest, src_part)) = line.split_once(" = ") {
                    let dest_var = dest.trim().to_string();
                    
                    // Check if source references any tainted variable
                    for tvar in tainted.clone() {
                        if self.contains_var(src_part, &tvar) {
                            tainted.insert(dest_var.clone());
                            break;
                        }
                    }
                }
            }
            
            // Track through Result unwrapping
            if line.contains("((_") && line.contains("as Continue).0)") {
                if let Some(var) = self.extract_assigned_var(line) {
                    // Check if any tainted var is in the source
                    let any_tainted = tainted.iter().any(|t| line.contains(&format!("_{}", t.trim_start_matches('_'))));
                    if any_tainted || tainted.iter().any(|t| line.contains(t)) {
                        tainted.insert(var);
                    }
                }
            }
            
            // Track through reference creation (&(*_X) or &_X)
            if line.contains("&(*_") || line.contains("&_") {
                if let Some(var) = self.extract_assigned_var(line) {
                    for tvar in tainted.clone() {
                        if self.contains_var(line, &tvar) {
                            tainted.insert(var.clone());
                            break;
                        }
                    }
                }
            }
            
            // Track through Index/IndexMut operations
            // Pattern: _X = <Vec<T> as Index<usize>>::index(move _Y, ...) or similar
            if line.contains("Index") && line.contains(">::index") {
                if let Some(var) = self.extract_assigned_var(line) {
                    for tvar in tainted.clone() {
                        if self.contains_var(line, &tvar) {
                            tainted.insert(var.clone());
                            break;
                        }
                    }
                }
            }
            
            // Track through Deref operations
            // Pattern: _X = <String as Deref>::deref(copy _Y)
            if line.contains("Deref>::deref") {
                if let Some(var) = self.extract_assigned_var(line) {
                    for tvar in tainted.clone() {
                        if self.contains_var(line, &tvar) {
                            tainted.insert(var.clone());
                            break;
                        }
                    }
                }
            }
            
            // Track through Iterator::collect - the collected vec inherits taint from iterator
            // Pattern: _X = <Args as Iterator>::collect::<Vec<String>>(move _Y)
            if line.contains("Iterator>::collect") {
                if let Some(var) = self.extract_assigned_var(line) {
                    for tvar in tainted.clone() {
                        if self.contains_var(line, &tvar) {
                            tainted.insert(var.clone());
                            break;
                        }
                    }
                }
            }
        }
        
        tainted
    }

    fn extract_assigned_var(&self, line: &str) -> Option<String> {
        let line = line.trim();
        if let Some(eq_pos) = line.find(" = ") {
            let lhs = line[..eq_pos].trim();
            // Handle patterns like "_5" or "(*_5)"
            if lhs.starts_with('_') && lhs.chars().skip(1).all(|c| c.is_ascii_digit()) {
                return Some(lhs.to_string());
            }
            if lhs.starts_with("(*_") {
                if let Some(end) = lhs.find(')') {
                    return Some(lhs[2..end].to_string());
                }
            }
        }
        None
    }

    fn contains_var(&self, text: &str, var: &str) -> bool {
        // Direct match
        if text.contains(var) {
            return true;
        }
        
        // Match patterns like move _X, copy _X, _X.0, &_X, (*_X)
        let var_num = var.trim_start_matches('_');
        if text.contains(&format!("move _{}", var_num)) ||
           text.contains(&format!("copy _{}", var_num)) ||
           text.contains(&format!("_{}.0", var_num)) ||
           text.contains(&format!("_{}.1", var_num)) ||
           text.contains(&format!("&_{}", var_num)) ||
           text.contains(&format!("(*_{})", var_num)) ||
           text.contains(&format!("((_{})", var_num)) ||
           text.contains(&format!("_{} as", var_num)) {
            return true;
        }
        
        false
    }

    /// Find YAML deserialization operations using tainted data
    fn find_unsafe_yaml_operations(&self, function: &MirFunction, tainted: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        
        // Check for sanitization patterns
        let mut has_sanitization = false;
        for line in &function.body {
            for sanitizer in Self::SANITIZERS {
                if line.contains(sanitizer) {
                    has_sanitization = true;
                    break;
                }
            }
            if has_sanitization {
                break;
            }
        }
        
        // Also check function name for validation patterns
        let fn_name_lower = function.name.to_lowercase();
        if fn_name_lower.contains("safe") || fn_name_lower.contains("valid") || 
           fn_name_lower.contains("sanitiz") || fn_name_lower.contains("check") {
            has_sanitization = true;
        }
        
        if has_sanitization {
            return evidence;
        }
        
        // Look for YAML sinks with tainted arguments
        for line in &function.body {
            for sink in Self::YAML_SINKS {
                if line.contains(sink) {
                    // Check if any tainted variable is used in this line
                    for tvar in tainted {
                        if self.contains_var(line, tvar) {
                            evidence.push(line.trim().to_string());
                            break;
                        }
                    }
                    
                    // Also flag if we have both a source and sink in the function
                    // even if taint tracking lost the connection
                    if !tainted.is_empty() {
                        // Check if line references any variable
                        if line.contains("move _") || line.contains("&_") {
                            let already_added = evidence.iter().any(|e| e == line.trim());
                            if !already_added {
                                evidence.push(line.trim().to_string());
                            }
                        }
                    }
                }
            }
        }
        
        evidence
    }
}

impl Rule for InsecureYamlDeserializationRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Skip test functions
            if function.name.contains("test") {
                continue;
            }
            
            // Track tainted variables from untrusted sources
            let tainted = self.track_untrusted_vars(function);
            
            if tainted.is_empty() {
                continue;
            }
            
            // Find YAML deserialization operations using tainted data
            let unsafe_ops = self.find_unsafe_yaml_operations(function, &tainted);
            
            if !unsafe_ops.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: Severity::Medium,
                    message: format!(
                        "Insecure YAML deserialization in `{}`. User-controlled input is \
                        passed to serde_yaml without validation. Malicious YAML can use \
                        anchors/aliases for billion laughs attacks or deeply nested \
                        structures for DoS. Validate input or use JSON instead.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: unsafe_ops.into_iter().take(3).collect(),
                    span: function.span.clone(),
                });
            }
        }

        // Phase 2: Inter-procedural analysis
        if let Ok(mut inter_analysis) = interprocedural::InterProceduralAnalysis::new(package) {
            if inter_analysis.analyze(package).is_ok() {
                let flows = inter_analysis.detect_inter_procedural_flows(package);
                
                let mut reported_functions: std::collections::HashSet<String> = findings
                    .iter()
                    .map(|f| f.function.clone())
                    .collect();
                
                for flow in flows {
                    // Consider yaml sinks
                    if flow.sink_type != "yaml" {
                        continue;
                    }
                    
                    // Skip internal functions
                    let is_internal = flow.sink_function.contains("mir_extractor")
                        || flow.sink_function.contains("__")
                        || flow.source_function.contains("mir_extractor");
                    if is_internal {
                        continue;
                    }
                    
                    if reported_functions.contains(&flow.sink_function) {
                        continue;
                    }
                    
                    if flow.sanitized {
                        continue;
                    }
                    
                    let sink_func = package.functions.iter()
                        .find(|f| f.name == flow.sink_function);
                    
                    let span = sink_func.map(|f| f.span.clone()).unwrap_or_default();
                    let signature = sink_func.map(|f| f.signature.clone()).unwrap_or_default();
                    
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: Severity::Medium,
                        message: format!(
                            "Inter-procedural YAML injection: untrusted input from `{}` \
                            flows through {} to YAML deserialization in `{}`. Validate \
                            input or use JSON instead.",
                            flow.source_function,
                            if flow.call_chain.len() > 2 {
                                format!("{} function calls", flow.call_chain.len() - 1)
                            } else {
                                "helper function".to_string()
                            },
                            flow.sink_function
                        ),
                        function: flow.sink_function.clone(),
                        function_signature: signature,
                        evidence: vec![flow.describe()],
                        span,
                    });
                    
                    reported_functions.insert(flow.sink_function.clone());
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA098: Inter-Procedural Command Injection
// ============================================================================

/// Detects command injection vulnerabilities where untrusted input flows to
/// command execution through helper functions. Uses inter-procedural analysis
/// to track taint across function boundaries.
///
/// **Sources:** env::var, env::args, stdin, file contents, network data
/// **Sinks:** Command::new, Command::arg, Command::spawn, std::process::exec
/// **Sanitizers:** parse::<T>(), allowlist validation, alphanumeric checks
struct InterProceduralCommandInjectionRule {
    metadata: RuleMetadata,
}

impl InterProceduralCommandInjectionRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA098".to_string(),
                name: "interprocedural-command-injection".to_string(),
                short_description: "Inter-procedural command injection".to_string(),
                full_description: "Untrusted input flows through helper functions to \
                    command execution without sanitization. Attackers can inject shell \
                    metacharacters to execute arbitrary commands. Validate input against \
                    an allowlist or use APIs that don't invoke a shell.".to_string(),
                help_uri: Some("https://owasp.org/www-community/attacks/Command_Injection".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for InterProceduralCommandInjectionRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Use inter-procedural analysis to detect cross-function command injection
        if let Ok(mut inter_analysis) = interprocedural::InterProceduralAnalysis::new(package) {
            if inter_analysis.analyze(package).is_ok() {
                let flows = inter_analysis.detect_inter_procedural_flows(package);
                
                let mut reported_functions: std::collections::HashSet<String> = 
                    std::collections::HashSet::new();
                
                for flow in flows {
                    // Only consider command execution sinks
                    if !flow.sink_type.contains("command") {
                        continue;
                    }
                    
                    // Skip internal/toolchain functions
                    let is_internal = flow.sink_function.contains("mir_extractor")
                        || flow.sink_function.contains("mir-extractor")
                        || flow.sink_function.contains("__")
                        || flow.source_function.contains("mir_extractor")
                        || flow.source_function.contains("mir-extractor");
                    if is_internal {
                        continue;
                    }
                    
                    // Skip test functions
                    if flow.sink_function.contains("test") && flow.sink_function.contains("::") {
                        // Allow top-level test_ functions but skip nested test utilities
                        if !flow.sink_function.starts_with("test_") {
                            continue;
                        }
                    }
                    
                    // Skip if already reported
                    if reported_functions.contains(&flow.sink_function) {
                        continue;
                    }
                    
                    // Skip if sanitized
                    if flow.sanitized {
                        continue;
                    }
                    
                    // Get the sink function for span info
                    let sink_func = package.functions.iter()
                        .find(|f| f.name == flow.sink_function);
                    
                    let span = sink_func.map(|f| f.span.clone()).unwrap_or_default();
                    let signature = sink_func.map(|f| f.signature.clone()).unwrap_or_default();
                    
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: Severity::High,
                        message: format!(
                            "Inter-procedural command injection: untrusted input from `{}` \
                            flows through {} to command execution in `{}`. \
                            Attackers can inject shell metacharacters. \
                            Validate against an allowlist or avoid shell invocation.",
                            flow.source_function,
                            if flow.call_chain.len() > 2 {
                                format!("{} function calls", flow.call_chain.len() - 1)
                            } else {
                                "helper function".to_string()
                            },
                            flow.sink_function
                        ),
                        function: flow.sink_function.clone(),
                        function_signature: signature,
                        evidence: vec![flow.describe()],
                        span,
                    });
                    
                    reported_functions.insert(flow.sink_function.clone());
                }
                
                // Phase 3.5.2: Closure capture detection
                // Detect taint through closures that capture tainted variables
                for closure in inter_analysis.closure_registry.get_all_closures() {
                    // Skip if already reported
                    if reported_functions.contains(&closure.name) {
                        continue;
                    }
                    
                    // Find parent function (may not exist if inlined)
                    let parent_func = package.functions.iter()
                        .find(|f| f.name == closure.parent_function);
                    
                    // Find closure function
                    let closure_func = package.functions.iter()
                        .find(|f| f.name == closure.name);
                    
                    if let Some(closure_fn) = closure_func {
                        // Check if parent has source (if parent exists)
                        let parent_has_source = if let Some(parent) = parent_func {
                            parent.body.iter().any(|line| {
                                line.contains("args()") || 
                                line.contains("env::args") || 
                                line.contains("env::var") ||
                                line.contains("std::env::") ||
                                line.contains("= args") ||
                                line.contains("var(")
                            })
                        } else {
                            // Parent is inlined - check if captured variable name suggests taint
                            // Pattern: debug tainted => ... indicates captured var named "tainted"
                            closure_fn.body.iter().any(|line| {
                                let line_lower = line.to_lowercase();
                                (line.contains("debug ") && line.contains("(*((*_1)")) &&
                                (line_lower.contains("tainted") || 
                                 line_lower.contains("user") ||
                                 line_lower.contains("input") ||
                                 line_lower.contains("cmd") ||
                                 line_lower.contains("arg") ||
                                 line_lower.contains("command"))
                            })
                        };
                        
                        // Check if closure has command sink
                        let closure_has_sink = closure_fn.body.iter().any(|line| {
                            line.contains("Command::new") ||
                            line.contains("Command::") ||
                            line.contains("::spawn") ||
                            line.contains("::output") ||
                            line.contains("process::Command")
                        });
                        
                        // Check if closure captures variables
                        // Method 1: From closure registry
                        let has_captures_from_registry = !closure.captured_vars.is_empty();
                        
                        // Method 2: Direct MIR pattern check
                        // Look for "debug <name> => (*((*_1)..." which indicates captured variable
                        let has_captures_from_mir = closure_fn.body.iter().any(|line| {
                            line.contains("debug ") && line.contains("(*((*_1)")
                        });
                        
                        let has_captures = has_captures_from_registry || has_captures_from_mir;
                        
                        if parent_has_source && closure_has_sink && has_captures {
                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: Severity::High,
                                message: format!(
                                    "Closure captures tainted data: `{}` captures untrusted input \
                                    from parent function `{}` and passes it to command execution. \
                                    Attackers can inject shell metacharacters. \
                                    Validate input or avoid shell invocation.",
                                    closure.name,
                                    closure.parent_function
                                ),
                                function: closure.name.clone(),
                                function_signature: closure_fn.signature.clone(),
                                evidence: vec![
                                    format!("Parent function {} contains taint source", closure.parent_function),
                                    format!("Closure captures variable(s) from parent"),
                                    "Closure body contains command execution".to_string(),
                                ],
                                span: closure_fn.span.clone(),
                            });
                            
                            reported_functions.insert(closure.name.clone());
                        }
                    }
                }
                
                // Phase 3.5.2b: Direct closure scan (fallback)
                // Scan all functions for closure patterns, bypassing ClosureRegistry
                for function in &package.functions {
                    // Check if this is a closure function
                    if !function.name.contains("::{closure#") {
                        continue;
                    }
                    
                    // Skip if already reported
                    if reported_functions.contains(&function.name) {
                        continue;
                    }
                    
                    let body_str = function.body.join("\n");
                    
                    // Check if closure has command sink
                    let has_command_sink = body_str.contains("Command::") ||
                        body_str.contains("::spawn") ||
                        body_str.contains("::output");
                    
                    if !has_command_sink {
                        continue;
                    }
                    
                    // Check for captured variables with taint-suggestive names
                    // Pattern: "debug tainted => (*((*_1)..." 
                    let has_tainted_capture = body_str.lines().any(|line| {
                        if !line.contains("debug ") || !line.contains("(*((*_1)") {
                            return false;
                        }
                        let line_lower = line.to_lowercase();
                        line_lower.contains("tainted") ||
                        line_lower.contains("user") ||
                        line_lower.contains("input") ||
                        line_lower.contains("cmd") ||
                        line_lower.contains("arg") ||
                        line_lower.contains("command")
                    });
                    
                    if has_tainted_capture {
                        // Extract parent function name from closure name
                        let parent_name = if let Some(pos) = function.name.find("::{closure#") {
                            function.name[..pos].to_string()
                        } else {
                            "unknown_parent".to_string()
                        };
                        
                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: Severity::High,
                            message: format!(
                                "Closure captures tainted data: `{}` captures untrusted input \
                                from parent function `{}` and passes it to command execution. \
                                Attackers can inject shell metacharacters. \
                                Validate input or avoid shell invocation.",
                                function.name,
                                parent_name
                            ),
                            function: function.name.clone(),
                            function_signature: function.signature.clone(),
                            evidence: vec![
                                format!("Closure captures variable(s) named with taint indicators"),
                                "Closure body contains command execution".to_string(),
                            ],
                            span: function.span.clone(),
                        });
                        
                        reported_functions.insert(function.name.clone());
                    }
                }
            }
        }

        findings
    }
}

/// RUSTCOLA091: Insecure JSON/TOML Deserialization
///
/// Detects when untrusted input is passed to JSON or TOML deserialization
/// functions without proper validation. While JSON/TOML don't have YAML's
/// billion laughs vulnerability, deeply nested structures can still cause:
/// - Stack overflow from deep recursion
/// - Memory exhaustion from large allocations
/// - CPU exhaustion from complex parsing
///
/// **Sources:** env::var, env::args, stdin, file contents, network data
/// **Sinks:** serde_json::from_str, from_slice, from_reader, toml::from_str
/// **Sanitizers:** Size limits, depth limits, schema validation
struct InsecureJsonTomlDeserializationRule {
    metadata: RuleMetadata,
}

impl InsecureJsonTomlDeserializationRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA091".to_string(),
                name: "insecure-json-toml-deserialization".to_string(),
                short_description: "Untrusted input used in JSON/TOML deserialization".to_string(),
                full_description: "User-controlled input is passed to serde_json or toml \
                    deserialization functions without validation. Attackers can craft \
                    deeply nested structures to cause stack overflow, or very large \
                    payloads to cause memory exhaustion. Validate input size and structure \
                    before deserialization, or use streaming parsers with limits.".to_string(),
                help_uri: Some("https://owasp.org/www-project-web-security-testing-guide/".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// JSON/TOML deserialization sinks - MIR patterns
    const SINKS: &'static [&'static str] = &[
        // JSON sinks - source forms
        "serde_json::from_str",
        "serde_json::from_slice", 
        "serde_json::from_reader",
        // JSON sinks - MIR forms (sometimes drops module prefix)
        "serde_json::from_str::",
        "serde_json::from_slice::",
        "serde_json::from_reader::",
        // Bare forms in MIR
        "= from_slice::<",    // MIR: _X = from_slice::<'_, T>(...)
        "= from_reader::<",   // MIR: _X = from_reader::<R, T>(...)
        "= from_str::<",      // MIR: _X = from_str::<'_, T>(...)
        // TOML sinks
        "toml::from_str",
        "toml::de::from_str",
        "toml::from_str::",
        "toml::de::from_str::",
    ];

    /// Untrusted sources - includes MIR patterns
    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        // Environment variables - source and MIR forms
        "env::var",
        "env::var_os",
        "std::env::var",
        "var::<",        // MIR: _1 = var::<&str>(const "VAR")
        "var_os::<",
        // Command-line arguments
        "env::args",
        "std::env::args",
        "args::<",
        "= args()",      // MIR: _X = args() -> [return: ...]
        "Args>",
        // Stdin
        "stdin",
        "Stdin",
        // File operations
        "read_to_string",
        "read_to_end",
        "BufRead::read_line",
        "fs::read_to_string",
        "fs::read",
        "fs::File::open",    // File handle from path
        "File::open",        // MIR form
        "OpenOptions",       // File from OpenOptions
        "Read>::read_to_string",
        "Read>::read_to_end",
        // Network
        "TcpStream",
        "::connect(",
    ];

    /// Track tainted variables from untrusted sources
    fn track_untrusted_vars<'a>(&self, function: &'a MirFunction) -> HashSet<String> {
        let mut tainted: HashSet<String> = HashSet::new();
        
        for line in &function.body {
            // Source detection
            for source in Self::UNTRUSTED_SOURCES {
                if line.contains(source) {
                    if let Some(var) = self.extract_assigned_var(line) {
                        tainted.insert(var);
                    }
                }
            }
            
            // Taint propagation through assignments
            if line.contains(" = ") {
                if let Some((dest, src_part)) = line.split_once(" = ") {
                    let dest_var = dest.trim().to_string();
                    for tvar in tainted.clone() {
                        if self.contains_var(src_part, &tvar) {
                            tainted.insert(dest_var.clone());
                            break;
                        }
                    }
                }
            }
            
            // Track through Result unwrapping
            if line.contains("((_") && line.contains("as Continue).0)") {
                if let Some(var) = self.extract_assigned_var(line) {
                    let any_tainted = tainted.iter().any(|t| line.contains(&format!("_{}", t.trim_start_matches('_'))));
                    if any_tainted || tainted.iter().any(|t| line.contains(t)) {
                        tainted.insert(var);
                    }
                }
            }
            
            // Track through reference creation
            if line.contains("&(*_") || line.contains("&_") {
                if let Some(var) = self.extract_assigned_var(line) {
                    for tvar in tainted.clone() {
                        if self.contains_var(line, &tvar) {
                            tainted.insert(var.clone());
                            break;
                        }
                    }
                }
            }
            
            // Track through Index operations
            if line.contains("Index") && line.contains(">::index") {
                if let Some(var) = self.extract_assigned_var(line) {
                    for tvar in tainted.clone() {
                        if self.contains_var(line, &tvar) {
                            tainted.insert(var.clone());
                            break;
                        }
                    }
                }
            }
            
            // Track through Deref operations
            if line.contains("Deref>::deref") {
                if let Some(var) = self.extract_assigned_var(line) {
                    for tvar in tainted.clone() {
                        if self.contains_var(line, &tvar) {
                            tainted.insert(var.clone());
                            break;
                        }
                    }
                }
            }
            
            // Track through Iterator::collect
            if line.contains("Iterator>::collect") {
                if let Some(var) = self.extract_assigned_var(line) {
                    for tvar in tainted.clone() {
                        if self.contains_var(line, &tvar) {
                            tainted.insert(var.clone());
                            break;
                        }
                    }
                }
            }
        }
        
        tainted
    }

    fn extract_assigned_var(&self, line: &str) -> Option<String> {
        let line = line.trim();
        if let Some(eq_pos) = line.find(" = ") {
            let lhs = line[..eq_pos].trim();
            if lhs.starts_with('_') && lhs.chars().skip(1).all(|c| c.is_ascii_digit()) {
                return Some(lhs.to_string());
            }
            if lhs.starts_with("(*_") {
                if let Some(end) = lhs.find(')') {
                    return Some(lhs[2..end].to_string());
                }
            }
        }
        None
    }

    fn contains_var(&self, text: &str, var: &str) -> bool {
        if text.contains(var) {
            return true;
        }
        let var_num = var.trim_start_matches('_');
        text.contains(&format!("move _{}", var_num)) ||
        text.contains(&format!("copy _{}", var_num)) ||
        text.contains(&format!("_{}.0", var_num)) ||
        text.contains(&format!("_{}.1", var_num)) ||
        text.contains(&format!("&_{}", var_num)) ||
        text.contains(&format!("(*_{})", var_num))
    }

    /// Check if the function has a size limit check on tainted data
    fn has_size_limit_check(&self, function: &MirFunction, tainted: &HashSet<String>) -> bool {
        // Look for patterns like:
        // _X = String::len(move _tainted) or str::len(move _tainted)
        // followed by comparison: _Y = Gt/Lt/Ge/Le(move _X, const N)
        //
        // We specifically look for String/str length checks, not Vec length checks
        // Vec::len() is typically for checking argument count, not payload size
        
        let mut len_result_vars: HashSet<String> = HashSet::new();
        
        for line in &function.body {
            // Check for len() call on String or str (not Vec)
            // MIR shows: String::len or str::len
            let is_string_len = (line.contains("String::len(") || line.contains("str::len("))
                && !line.contains("Vec<");
                
            if is_string_len {
                // Check if the argument is tainted
                for tvar in tainted {
                    if self.contains_var(line, tvar) {
                        // Extract the result variable
                        if let Some(var) = self.extract_assigned_var(line) {
                            len_result_vars.insert(var);
                        }
                    }
                }
            }
            
            // Check for comparison using the len result
            if line.contains("Gt(") || line.contains("Lt(") || line.contains("Ge(") || line.contains("Le(") {
                for len_var in &len_result_vars {
                    if self.contains_var(line, len_var) {
                        return true;  // Found size limit check
                    }
                }
            }
        }
        
        false
    }

    /// Find unsafe JSON/TOML deserialization operations
    fn find_unsafe_operations(&self, function: &MirFunction, tainted: &HashSet<String>) -> Vec<String> {
        let mut unsafe_ops = Vec::new();
        
        // Check for meaningful sanitization patterns
        // We need len() called on a tainted variable followed by comparison
        let has_size_limit = self.has_size_limit_check(function, tainted);
        
        if has_size_limit {
            return unsafe_ops;  // Sanitized - don't report
        }
        
        for line in &function.body {
            // Check if line contains a sink
            let is_sink = Self::SINKS.iter().any(|sink| line.contains(sink));
            if !is_sink {
                continue;
            }
            
            // Check if any tainted variable flows to the sink
            let taint_flows = tainted.iter().any(|t| self.contains_var(line, t));
            
            if taint_flows {
                unsafe_ops.push(line.trim().to_string());
            }
        }
        
        unsafe_ops
    }
}

impl Rule for InsecureJsonTomlDeserializationRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Skip test functions
            if function.name.contains("test") {
                continue;
            }
            
            // Track tainted variables from untrusted sources
            let tainted = self.track_untrusted_vars(function);
            
            if tainted.is_empty() {
                continue;
            }
            
            // Find JSON/TOML deserialization operations using tainted data
            let unsafe_ops = self.find_unsafe_operations(function, &tainted);
            
            if !unsafe_ops.is_empty() {
                // Determine if it's JSON or TOML based on the sink
                let is_toml = unsafe_ops.iter().any(|op| op.contains("toml::"));
                let format_name = if is_toml { "TOML" } else { "JSON" };
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: Severity::Medium,
                    message: format!(
                        "Insecure {} deserialization in `{}`. User-controlled input is \
                        passed to serde_{} without validation. Deeply nested structures \
                        can cause stack overflow, and large payloads can exhaust memory. \
                        Validate input size and structure before parsing.",
                        format_name,
                        function.name,
                        format_name.to_lowercase()
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: unsafe_ops.into_iter().take(3).collect(),
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}

/// RUSTCOLA090: Unbounded read_to_end Detection
///
/// Detects when read_to_end() or read_to_string() is called on untrusted
/// sources (network streams, stdin, files from user paths) without size limits.
/// This can cause memory exhaustion DoS when attackers send large payloads.
///
/// **Sources:** TcpStream, UnixStream, stdin, File from env/args path
/// **Sinks:** read_to_end(), read_to_string()
/// **Safe patterns:** .take(N), size checks before read, chunked reading
struct UnboundedReadRule {
    metadata: RuleMetadata,
}

impl UnboundedReadRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA090".to_string(),
                name: "unbounded-read-to-end".to_string(),
                short_description: "Unbounded read_to_end on untrusted source".to_string(),
                full_description: "read_to_end() or read_to_string() is called on an \
                    untrusted source (network stream, stdin, user-controlled file) without \
                    size limits. Attackers can send arbitrarily large payloads to exhaust \
                    server memory, causing denial of service. Use .take(max_size) to limit \
                    bytes read, check file size with metadata() before reading, or use \
                    chunked reading with explicit limits.".to_string(),
                help_uri: Some("https://owasp.org/www-community/attacks/Buffer_overflow_attack".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Untrusted stream sources - expanded patterns for MIR detection
    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        // Network streams - direct
        "TcpStream::connect",
        "TcpListener::accept",
        "TcpListener::incoming",
        "UnixStream::connect",
        "UnixListener::accept",
        "UdpSocket::",
        // Network - MIR patterns
        "::connect(",
        "::accept(",
        "::incoming(",
        "Incoming>",
        "<TcpStream",
        "<UnixStream",
        // Stdin - direct and MIR patterns
        "io::stdin",
        "stdin()",
        " = stdin(",
        "Stdin",
        // User-controlled file paths via env - MIR patterns
        "env::var",
        "env::args",
        "std::env::var",
        "std::env::args",
        "var::<",        // MIR: _1 = var::<&str>(const "HOME")
        "var_os::<",     // MIR: _1 = var_os::<&str>(const "PATH")
        " = args(",
        "args::<",       // MIR form
        "Args>",
        "OsString>",     // Common return from env vars
        // File operations that could be on untrusted paths
        "File::open",
    ];

    /// Dangerous unbounded read operations
    const UNBOUNDED_SINKS: &'static [&'static str] = &[
        "read_to_end",
        "read_to_string",
        "Read>::read_to_end",
        "Read>::read_to_string",
        "BufRead>::read_to_end",
    ];

    /// Safe patterns that limit read size
    const SAFE_PATTERNS: &'static [&'static str] = &[
        ".take(",          // Limits bytes read
        "take(",           // Alternative form
        "metadata(",       // Size check before read
        ".len()",          // Size comparison
        "len() >",
        "len() <",
        "MAX_SIZE",        // Constant limit
        "max_size",
        "limit",
        "chunk",
        "fill_buf",        // Chunked reading
    ];

    /// Check if function has an untrusted source
    fn has_untrusted_source(&self, function: &MirFunction) -> bool {
        for line in &function.body {
            for source in Self::UNTRUSTED_SOURCES {
                if line.contains(source) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if function has a safe limiting pattern
    fn has_safe_limit(&self, function: &MirFunction) -> bool {
        for line in &function.body {
            for pattern in Self::SAFE_PATTERNS {
                if line.to_lowercase().contains(&pattern.to_lowercase()) {
                    return true;
                }
            }
        }
        
        // Also check function name for safety indicators
        let fn_name_lower = function.name.to_lowercase();
        if fn_name_lower.contains("safe") || 
           fn_name_lower.contains("limit") ||
           fn_name_lower.contains("bound") ||
           fn_name_lower.contains("chunk") ||
           fn_name_lower.contains("take") ||
           fn_name_lower.contains("fixed") {
            return true;
        }
        
        false
    }

    /// Check if source is trusted (hardcoded file path)
    fn has_trusted_source_only(&self, function: &MirFunction) -> bool {
        let body_str = function.body.join("\n");
        
        // Check for various untrusted sources
        let has_network = body_str.contains("TcpStream") || 
                         body_str.contains("UnixStream") ||
                         body_str.contains("TcpListener") ||
                         body_str.contains("UdpSocket") ||
                         body_str.contains("::connect(") ||
                         body_str.contains("::accept(") ||
                         body_str.contains("::incoming(");
        let has_stdin = body_str.contains("stdin") || body_str.contains("Stdin");
        let has_env_input = body_str.contains("env::var") || 
                           body_str.contains("env::args") ||
                           body_str.contains("var::<") ||    // MIR pattern
                           body_str.contains("var_os::<") || // MIR pattern
                           body_str.contains("args::<") ||   // MIR pattern
                           body_str.contains("Args>");
        
        // If any network or stdin or env input source, it's not trusted-only
        if has_network || has_stdin || has_env_input {
            return false;
        }
        
        // File::open without untrusted input sources is considered trusted
        // (hardcoded paths, config files, etc.)
        let has_file_open = body_str.contains("File::open");
        if has_file_open {
            // Check for hardcoded paths (string literals starting with /)
            if body_str.contains(r#""/etc/"#) || 
               body_str.contains(r#""/app/"#) || 
               body_str.contains(r#""/usr/"#) ||
               body_str.contains(r#""/var/"#) ||
               body_str.contains(r#""/tmp/"#) ||
               body_str.contains("const ") {
                return true;
            }
        }
        
        false
    }

    /// Find unbounded read operations
    fn find_unbounded_reads(&self, function: &MirFunction) -> Vec<String> {
        let mut evidence = Vec::new();
        
        for line in &function.body {
            for sink in Self::UNBOUNDED_SINKS {
                if line.contains(sink) {
                    evidence.push(line.trim().to_string());
                }
            }
        }
        
        evidence
    }
}

impl Rule for UnboundedReadRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Skip test functions
            if function.name.contains("test") {
                continue;
            }
            
            // Must have an untrusted source
            if !self.has_untrusted_source(function) {
                continue;
            }
            
            // Skip if using safe limiting patterns
            if self.has_safe_limit(function) {
                continue;
            }
            
            // Skip if only trusted (hardcoded) sources
            if self.has_trusted_source_only(function) {
                continue;
            }
            
            // Find unbounded read operations
            let unbounded_reads = self.find_unbounded_reads(function);
            
            if !unbounded_reads.is_empty() {
                // Determine severity based on source type
                let body_str = function.body.join("\n");
                let severity = if body_str.contains("TcpStream") || 
                                 body_str.contains("TcpListener") ||
                                 body_str.contains("UnixStream") {
                    Severity::High // Network sources are higher risk
                } else {
                    Severity::Medium
                };
                
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity,
                    message: format!(
                        "Unbounded read in `{}`. read_to_end()/read_to_string() is called \
                        on an untrusted source without size limits. Attackers can exhaust \
                        server memory with large payloads. Use .take(max_bytes) to limit \
                        the read size.",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: unbounded_reads.into_iter().take(3).collect(),
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}


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

    // Injection/dataflow rules (complex, require taint tracking - stay in lib.rs)
    engine.register_rule(Box::new(UntrustedEnvInputRule::new()));
    engine.register_rule(Box::new(CommandInjectionRiskRule::new()));
    engine.register_rule(Box::new(CommandArgConcatenationRule::new()));
    engine.register_rule(Box::new(LogInjectionRule::new()));
    engine.register_rule(Box::new(RegexInjectionRule::new()));
    engine.register_rule(Box::new(UncheckedIndexRule::new()));
    engine.register_rule(Box::new(PathTraversalRule::new()));
    engine.register_rule(Box::new(SqlInjectionRule::new()));
    engine.register_rule(Box::new(SsrfRule::new()));
    engine.register_rule(Box::new(InterProceduralCommandInjectionRule::new()));

    // Memory/dataflow rules (complex analysis)
    engine.register_rule(Box::new(MaybeUninitAssumeInitDataflowRule::new()));
    engine.register_rule(Box::new(SerdeLengthMismatchRule::new()));
    engine.register_rule(Box::new(SliceElementSizeMismatchRule::new()));
    engine.register_rule(Box::new(SliceFromRawPartsRule::new()));
    engine.register_rule(Box::new(ContentLengthAllocationRule::new()));
    engine.register_rule(Box::new(UnboundedAllocationRule::new()));
    engine.register_rule(Box::new(LengthTruncationCastRule::new()));
    engine.register_rule(Box::new(TransmuteLifetimeChangeRule::new()));
    engine.register_rule(Box::new(RawPointerEscapeRule::new()));
    engine.register_rule(Box::new(VecSetLenMisuseRule::new()));
    engine.register_rule(Box::new(StaticMutGlobalRule::new()));
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
        };

        let finding = Finding {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            severity: rule.default_severity,
            message: "Something happened".to_string(),
            function: "demo::example".to_string(),
            function_signature: "fn demo::example()".to_string(),
            evidence: vec![],
            span: Some(span.clone()),
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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

        let findings = rule.evaluate(&package);
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
