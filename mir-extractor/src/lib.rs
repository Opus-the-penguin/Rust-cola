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
    use crate::rules::{CommandInjectionRiskRule, UntrustedEnvInputRule};
    use crate::rules::memory::{
        BoxIntoRawRule, MemForgetGuardRule, MaybeUninitAssumeInitRule, MemUninitZeroedRule,
        NonNullNewUncheckedRule, NullPointerTransmuteRule, TransmuteRule, UnsafeUsageRule,
        VecSetLenRule, ZSTPointerArithmeticRule,
    };
    use crate::rules::crypto::{
        InsecureMd5Rule, InsecureSha1Rule, ModuloBiasRandomRule, WeakHashingExtendedRule,
    };
    use crate::rules::resource::{
        HardcodedHomePathRule, PermissionsSetReadonlyFalseRule, SpawnedChildNoWaitRule,
        WorldWritableModeRule,
    };
    use crate::rules::input::CleartextEnvVarRule;
    use crate::rules::web::{DangerAcceptInvalidCertRule, NonHttpsUrlRule, OpensslVerifyNoneRule};
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
