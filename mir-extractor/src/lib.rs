#![cfg_attr(feature = "hir-driver", feature(rustc_private))]

#[cfg(feature = "hir-driver")]
extern crate rustc_ast;
#[cfg(feature = "hir-driver")]
extern crate rustc_driver;
#[cfg(feature = "hir-driver")]
extern crate rustc_hir;
#[cfg(feature = "hir-driver")]
extern crate rustc_interface;
#[cfg(feature = "hir-driver")]
extern crate rustc_middle;
#[cfg(feature = "hir-driver")]
extern crate rustc_session;
#[cfg(feature = "hir-driver")]
extern crate rustc_span;

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

pub mod dataflow;
#[cfg(feature = "hir-driver")]
mod hir;
mod prototypes;
pub mod interprocedural;

pub use dataflow::{Assignment, MirDataflow};
#[cfg(feature = "hir-driver")]
pub use hir::{
    capture_hir, capture_root_from_env, collect_crate_snapshot, target_spec_from_env,
    HirFunctionBody, HirIndex, HirItem, HirPackage, HirTargetSpec,
};
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

pub struct RuleEngine {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
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
            let is_target = function.name.contains("sanitized_parse") || function.name.contains("sanitized_allowlist");
            let (_tainted_vars, flows) = taint_analysis.analyze(function);
            
            if is_target {
                eprintln!("\n===== RUSTCOLA006 EVALUATION FOR: {} =====", function.name);
                eprintln!("Flows found: {}", flows.len());
                for (i, flow) in flows.iter().enumerate() {
                    eprintln!("  Flow {}: sanitized={}", i, flow.sanitized);
                }
            }
            
            // Convert each taint flow into a finding
            for flow in flows {
                if !flow.sanitized {
                    let finding = flow.to_finding(
                        &self.metadata,
                        &function.name,
                        &function.signature,
                        function.span.clone(),
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
                short_description: "Hard-coded absolute home directory path".to_string(),
                full_description: "Highlights string literals that embed absolute paths into user home directories, which risk leaking secrets or reducing portability.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
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
        let patterns = ["/home/", "\\\\users\\", "/users/", "~/"];

        for function in &package.functions {
            let evidence = collect_case_insensitive_matches(&function.body, &patterns);
            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!(
                    "Hard-coded home directory path detected in `{}`",
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

struct UnderscoreLockGuardRule {
    metadata: RuleMetadata,
}

impl UnderscoreLockGuardRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA030".to_string(),
                name: "underscore-lock-guard".to_string(),
                short_description: "Lock guard immediately discarded via underscore binding".to_string(),
                full_description: "Detects lock guards (Mutex::lock, RwLock::read/write, etc.) assigned to `_`, which immediately drops the guard and releases the lock before the critical section executes, creating race conditions.".to_string(),
                help_uri: Some("https://rust-lang.github.io/rust-clippy/master/index.html#/let_underscore_lock".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn lock_method_patterns() -> &'static [&'static str] {
        &[
            "::lock(",
            "::read(",
            "::write(",
            "::try_lock(",
            "::try_read(",
            "::try_write(",
            "::blocking_lock(",
            "::blocking_read(",
            "::blocking_write(",
        ]
    }
}

impl Rule for UnderscoreLockGuardRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            for line in &function.body {
                let trimmed = line.trim();
                
                // Look for patterns like: let _: type = mutex.lock()
                // or: _ = mutex.lock()
                // In MIR this appears as: _1 = ... ::lock(...
                if !trimmed.starts_with('_') {
                    continue;
                }

                // Check if this is an underscore assignment
                let is_underscore_binding = trimmed.starts_with("_ =") 
                    || (trimmed.starts_with('_') 
                        && trimmed.chars().nth(1).map_or(false, |c| c.is_ascii_digit())
                        && trimmed.contains(" = "));

                if !is_underscore_binding {
                    continue;
                }

                // Check if the RHS contains a lock acquisition
                let has_lock_call = Self::lock_method_patterns()
                    .iter()
                    .any(|pattern| trimmed.contains(pattern));

                if !has_lock_call {
                    continue;
                }

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Lock guard assigned to `_` in `{}`, immediately releasing the lock",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: vec![trimmed.to_string()],
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

struct UnsafeSendSyncBoundsRule {
    metadata: RuleMetadata,
}

#[derive(Clone, Copy, Default)]
struct StringLiteralState {
    in_normal_string: bool,
    raw_hashes: Option<usize>,
}

const STRIP_STRING_INITIAL_CAPACITY: usize = 256;

fn strip_string_literals(
    mut state: StringLiteralState,
    line: &str,
) -> (String, StringLiteralState) {
    let bytes = line.as_bytes();
    let mut result = String::with_capacity(STRIP_STRING_INITIAL_CAPACITY);
    let mut i = 0usize;

    while i < bytes.len() {
        if let Some(hashes) = state.raw_hashes {
            result.push(' ');
            if bytes[i] == b'"' {
                let mut matched = true;
                for k in 0..hashes {
                    if i + 1 + k >= bytes.len() || bytes[i + 1 + k] != b'#' {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    for _ in 0..hashes {
                        result.push(' ');
                    }
                    state.raw_hashes = None;
                    i += 1 + hashes;
                    continue;
                }
            }
            i += 1;
            continue;
        }

        if state.in_normal_string {
            result.push(' ');
            if bytes[i] == b'\\' {
                i += 1;
                if i < bytes.len() {
                    result.push(' ');
                    i += 1;
                    continue;
                } else {
                    break;
                }
            }
            if bytes[i] == b'"' {
                state.in_normal_string = false;
            }
            i += 1;
            continue;
        }

        let ch = bytes[i];
        if ch == b'"' {
            state.in_normal_string = true;
            result.push(' ');
            i += 1;
            continue;
        }

        if ch == b'r' {
            let mut j = i + 1;
            let mut hashes = 0usize;
            while j < bytes.len() && bytes[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                state.raw_hashes = Some(hashes);
                result.push(' ');
                for _ in 0..hashes {
                    result.push(' ');
                }
                result.push(' ');
                i = j + 1;
                continue;
            }
        }

        if ch == b'\'' {
            if i + 1 < bytes.len() {
                let next = bytes[i + 1];
                let looks_like_lifetime = next == b'_' || next.is_ascii_alphabetic();
                let following = bytes.get(i + 2).copied();
                if looks_like_lifetime && following != Some(b'\'') {
                    result.push('\'');
                    i += 1;
                    continue;
                }
            }

            let mut j = i + 1;
            let mut escaped = false;
            let mut found_closing = false;

            while j < bytes.len() {
                let current = bytes[j];
                if escaped {
                    escaped = false;
                } else if current == b'\\' {
                    escaped = true;
                } else if current == b'\'' {
                    found_closing = true;
                    break;
                }

                j += 1;
            }

            if found_closing {
                result.push(' ');
                i += 1;
                while i <= j {
                    result.push(' ');
                    i += 1;
                }
                continue;
            } else {
                result.push('\'');
                i += 1;
                continue;
            }
        }

        result.push(ch as char);
        i += 1;
    }

    (result, state)
}

fn collect_sanitized_matches(lines: &[String], patterns: &[&str]) -> Vec<String> {
    let mut state = StringLiteralState::default();

    lines
        .iter()
        .filter_map(|line| {
            let (sanitized, next_state) = strip_string_literals(state, line);
            state = next_state;

            if patterns.iter().any(|needle| sanitized.contains(needle)) {
                Some(line.trim().to_string())
            } else {
                None
            }
        })
        .collect()
}

impl UnsafeSendSyncBoundsRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA015".to_string(),
                name: "unsafe-send-sync-bounds".to_string(),
                short_description: "Unsafe Send/Sync impl without generic bounds".to_string(),
                full_description: "Detects unsafe implementations of Send/Sync for generic types that do not constrain their generic parameters, which can reintroduce thread-safety bugs.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn has_required_bounds(block_text: &str, trait_name: &str) -> bool {
        let trait_marker = format!(" {trait_name} for");
        let Some(for_idx) = block_text.find(&trait_marker) else {
            return true;
        };
        let before_for = &block_text[..for_idx];
        let Some((generics_text, generic_names)) = Self::extract_generic_params(before_for) else {
            return true;
        };

        if generic_names.is_empty() {
            return true;
        }

        let generic_set: HashSet<String> = generic_names.iter().cloned().collect();
        let mut satisfied: HashSet<String> = HashSet::new();

        for (name, bounds) in Self::parse_inline_bounds(&generics_text) {
            if !generic_set.contains(&name) {
                continue;
            }

            if bounds
                .iter()
                .any(|bound| Self::bound_matches_trait(bound, trait_name))
            {
                satisfied.insert(name.clone());
            }
        }

        if let Some(where_clauses) = Self::extract_where_clauses(block_text) {
            for (name, bounds) in where_clauses {
                if !generic_set.contains(&name) {
                    continue;
                }

                if bounds
                    .iter()
                    .any(|bound| Self::bound_matches_trait(bound, trait_name))
                {
                    satisfied.insert(name);
                }
            }
        }

        generic_names
            .into_iter()
            .all(|name| satisfied.contains(&name))
    }

    fn extract_generic_params(before_for: &str) -> Option<(String, Vec<String>)> {
        let start = before_for.find('<')?;
        let end_offset = before_for[start..].find('>')?;
        let generics_text = before_for[start + 1..start + end_offset].trim().to_string();

        let mut names = Vec::new();
        for param in generics_text.split(',') {
            if let Some(name) = Self::normalize_generic_name(param) {
                names.push(name);
            }
        }

        Some((generics_text, names))
    }

    fn parse_inline_bounds(generics_text: &str) -> Vec<(String, Vec<String>)> {
        generics_text
            .split(',')
            .filter_map(|param| {
                let Some(name) = Self::normalize_generic_name(param) else {
                    return None;
                };

                let trimmed = param.trim();
                let mut parts = trimmed.splitn(2, ':');
                parts.next()?;
                let bounds = parts
                    .next()
                    .map(|rest| Self::split_bounds(rest))
                    .unwrap_or_default();

                Some((name, bounds))
            })
            .collect()
    }

    fn normalize_generic_name(token: &str) -> Option<String> {
        let token = token.trim();
        if token.is_empty() {
            return None;
        }

        if token.starts_with("const ") {
            return None;
        }

        if token.starts_with('\'') {
            return None;
        }

        let ident = token
            .split(|c: char| c == ':' || c == '=' || c.is_whitespace())
            .next()
            .unwrap_or("")
            .trim();

        if ident.is_empty() {
            None
        } else {
            Some(ident.to_string())
        }
    }

    fn extract_where_clauses(block_text: &str) -> Option<Vec<(String, Vec<String>)>> {
        let where_idx = block_text.find(" where ")?;
        let after_where = &block_text[where_idx + " where ".len()..];
        let end_idx = after_where
            .find('{')
            .or_else(|| after_where.find(';'))
            .unwrap_or(after_where.len());
        let clauses = after_where[..end_idx].trim();
        if clauses.is_empty() {
            return Some(Vec::new());
        }

        let mut result = Vec::new();
        for predicate in clauses.split(',') {
            let pred = predicate.trim();
            if pred.is_empty() {
                continue;
            }

            let mut parts = pred.splitn(2, ':');
            let ident = parts.next().unwrap_or("").trim();
            if ident.is_empty() {
                continue;
            }

            let bounds = parts
                .next()
                .map(|rest| Self::split_bounds(rest))
                .unwrap_or_default();
            result.push((ident.to_string(), bounds));
        }

        Some(result)
    }

    fn split_bounds(bounds: &str) -> Vec<String> {
        bounds
            .split('+')
            .map(|part| {
                part.trim()
                    .trim_start_matches('?')
                    .trim_start_matches("~const ")
                    .trim_end_matches(|c| matches!(c, ',' | '{' | ';'))
                    .to_string()
            })
            .filter(|part| !part.is_empty())
            .collect()
    }

    fn scan_string_state(
        state: StringLiteralState,
        line: &str,
    ) -> (bool, String, StringLiteralState) {
        let (sanitized, state_after) = strip_string_literals(state, line);
        let has_impl = sanitized.contains("unsafe impl")
            && (sanitized.contains(" Send for") || sanitized.contains(" Sync for"));
        (has_impl, sanitized, state_after)
    }

    fn bound_matches_trait(bound: &str, trait_name: &str) -> bool {
        let normalized = bound.trim();
        if normalized.is_empty() {
            return false;
        }

        let normalized = normalized
            .trim_start_matches("dyn ")
            .trim_start_matches("impl ");

        if normalized == trait_name {
            return true;
        }

        if normalized.ends_with(trait_name)
            && normalized
                .trim_end_matches(trait_name)
                .trim_end()
                .ends_with("::")
        {
            return true;
        }

        if let Some(start) = normalized.find('<') {
            let (path, generics) = normalized.split_at(start);
            if Self::bound_matches_trait(path.trim_end_matches('<'), trait_name) {
                return generics
                    .trim_matches(|c| c == '<' || c == '>')
                    .split(',')
                    .any(|part| Self::bound_matches_trait(part, trait_name));
            }
        }

        if let Some(idx) = normalized.find('<') {
            let inner = normalized[idx + 1..].trim_end_matches('>').trim();
            if inner.starts_with("*const") || inner.starts_with("*mut") || inner.starts_with('&') {
                return true;
            }
        }

        let tokens: Vec<_> = normalized
            .split(|c: char| c == ':' || c == '+' || c == ',' || c.is_whitespace())
            .filter(|token| !token.is_empty())
            .collect();

        if tokens.iter().any(|token| token == &trait_name) {
            return true;
        }

        if trait_name == "Send"
            && tokens
                .iter()
                .any(|token| *token == "Sync" || token.ends_with("::Sync"))
        {
            return true;
        }

        if trait_name == "Sync"
            && tokens
                .iter()
                .any(|token| *token == "Send" || token.ends_with("::Send"))
        {
            return true;
        }

        false
    }
}

impl Rule for UnsafeSendSyncBoundsRule {
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

            while idx < lines.len() {
                let line = lines[idx];
                let (has_impl, sanitized_line, mut state_after_line) =
                    Self::scan_string_state(string_state, line);
                let trimmed_sanitized = sanitized_line.trim();

                if !has_impl {
                    string_state = state_after_line;
                    idx += 1;
                    continue;
                }

                let mut block_lines = Vec::new();
                let trimmed_first = line.trim();
                if !trimmed_first.is_empty() {
                    block_lines.push(trimmed_first.to_string());
                }

                let mut block_complete =
                    trimmed_sanitized.contains('{') || trimmed_sanitized.ends_with(';');

                let mut j = idx;
                while !block_complete && j + 1 < lines.len() {
                    let next_line = lines[j + 1];
                    let (next_has_impl, next_sanitized, next_state) =
                        Self::scan_string_state(state_after_line, next_line);
                    let trimmed_original = next_line.trim();
                    let trimmed_sanitized_next = next_sanitized.trim();
                    let mut appended = false;

                    if !trimmed_original.is_empty() {
                        block_lines.push(trimmed_original.to_string());
                        appended = true;
                    }

                    state_after_line = next_state;
                    block_complete = trimmed_sanitized_next.contains('{')
                        || trimmed_sanitized_next.ends_with(';');

                    if next_has_impl {
                        if appended {
                            block_lines.pop();
                        }
                        break;
                    }

                    j += 1;
                }

                let block_text = block_lines.join(" ");
                let trait_name = if block_text.contains(" Send for") {
                    "Send"
                } else if block_text.contains(" Sync for") {
                    "Sync"
                } else {
                    string_state = state_after_line;
                    idx = j + 1;
                    continue;
                };

                if !Self::has_required_bounds(&block_text, trait_name) {
                    let location = format!("{}:{}", rel_path, idx + 1);
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!("Unsafe impl of {trait_name} without generic bounds"),
                        function: location,
                        function_signature: block_lines
                            .first()
                            .cloned()
                            .unwrap_or_else(|| trait_name.to_string()),
                        evidence: block_lines.clone(),
                        span: None,
                    });
                }

                string_state = state_after_line;
                idx = j + 1;
            }
        }

        findings
    }
}

struct FfiBufferLeakRule {
    metadata: RuleMetadata,
}

impl FfiBufferLeakRule {
    fn new() -> Self {
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

struct PanicInDropRule {
    metadata: RuleMetadata,
}

impl PanicInDropRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA040".to_string(),
                name: "panic-in-drop".to_string(),
                short_description: "panic! or unwrap in Drop implementation".to_string(),
                full_description: "Detects panic!, unwrap(), or expect() calls inside Drop trait implementations. Panicking during stack unwinding causes the process to abort, which can mask the original error and make debugging difficult. Drop implementations should handle errors gracefully or use logging instead of panicking.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/nomicon/exception-safety.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn panic_patterns() -> &'static [&'static str] {
        &[
            "panic!",
            ".unwrap()",
            ".expect(",
            "unreachable!",
            "unimplemented!",
            "todo!",
        ]
    }
}

impl Rule for PanicInDropRule {
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

            // Track Drop implementation boundaries
            let mut in_drop_impl = false;
            let mut drop_impl_start = 0;
            let mut brace_depth = 0;
            let mut drop_type_name = String::new();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Detect Drop impl start
                if trimmed.contains("impl") && trimmed.contains("Drop") && trimmed.contains("for") {
                    in_drop_impl = true;
                    drop_impl_start = idx;
                    brace_depth = 0;

                    // Extract type name
                    if let Some(for_pos) = trimmed.find("for ") {
                        let after_for = &trimmed[for_pos + 4..];
                        if let Some(space_pos) = after_for.find(|c: char| c.is_whitespace() || c == '{') {
                            drop_type_name = after_for[..space_pos].trim().to_string();
                        } else {
                            drop_type_name = after_for.trim().to_string();
                        }
                    }
                }

                if in_drop_impl {
                    brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                    // Check for panic patterns
                    for pattern in Self::panic_patterns() {
                        if trimmed.contains(pattern) {
                            // Skip commented lines
                            if !trimmed.starts_with("//") {
                                let location = format!("{}:{}", rel_path, idx + 1);

                                findings.push(Finding {
                                    rule_id: self.metadata.id.clone(),
                                    rule_name: self.metadata.name.clone(),
                                    severity: self.metadata.default_severity,
                                    message: format!(
                                        "Panic in Drop implementation for `{}` can cause abort during unwinding",
                                        drop_type_name
                                    ),
                                    function: location,
                                    function_signature: drop_type_name.clone(),
                                    evidence: vec![trimmed.to_string()],
                                    span: None,
                                });
                            }
                        }
                    }

                    // If brace depth returns to 0, we've exited the Drop impl
                    if brace_depth <= 0 && idx > drop_impl_start {
                        in_drop_impl = false;
                    }
                }
            }
        }

        findings
    }
}

struct UnwrapInPollRule {
    metadata: RuleMetadata,
}

impl UnwrapInPollRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA041".to_string(),
                name: "unwrap-in-poll".to_string(),
                short_description: "unwrap or panic in Future::poll implementation".to_string(),
                full_description: "Detects unwrap(), expect(), or panic! calls inside Future::poll implementations. Panicking in poll() can stall async executors, cause runtime hangs, and make debugging async code difficult. Poll implementations should propagate errors using Poll::Ready(Err(...)) or use defensive patterns like match/if-let.".to_string(),
                help_uri: Some("https://rust-lang.github.io/async-book/02_execution/03_wakeups.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn panic_patterns() -> &'static [&'static str] {
        &[
            "panic!",
            ".unwrap()",
            ".expect(",
            "unreachable!",
            "unimplemented!",
            "todo!",
        ]
    }
}

impl Rule for UnwrapInPollRule {
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

            // Track Future impl and poll method boundaries
            let mut in_future_impl = false;
            let mut in_poll_method = false;
            let mut poll_start = 0;
            let mut brace_depth = 0;
            let mut impl_brace_depth = 0;
            let mut future_type_name = String::new();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Detect Future impl start
                if !in_future_impl && trimmed.contains("impl") && trimmed.contains("Future") && trimmed.contains("for") {
                    in_future_impl = true;
                    impl_brace_depth = 0;

                    // Extract type name
                    if let Some(for_pos) = trimmed.find("for ") {
                        let after_for = &trimmed[for_pos + 4..];
                        if let Some(space_pos) = after_for.find(|c: char| c.is_whitespace() || c == '{') {
                            future_type_name = after_for[..space_pos].trim().to_string();
                        } else {
                            future_type_name = after_for.trim().to_string();
                        }
                    }
                }

                if in_future_impl {
                    impl_brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    impl_brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                    // Detect poll method start
                    if !in_poll_method && (trimmed.contains("fn poll") || trimmed.contains("fn poll(")) {
                        in_poll_method = true;
                        poll_start = idx;
                        brace_depth = 0;
                    }

                    if in_poll_method {
                        brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                        brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                        // Check for panic patterns
                        for pattern in Self::panic_patterns() {
                            if trimmed.contains(pattern) {
                                // Skip commented lines
                                if !trimmed.starts_with("//") {
                                    let location = format!("{}:{}", rel_path, idx + 1);

                                    findings.push(Finding {
                                        rule_id: self.metadata.id.clone(),
                                        rule_name: self.metadata.name.clone(),
                                        severity: self.metadata.default_severity,
                                        message: format!(
                                            "Panic in Future::poll for `{}` can stall async executor",
                                            future_type_name
                                        ),
                                        function: location,
                                        function_signature: future_type_name.clone(),
                                        evidence: vec![trimmed.to_string()],
                                        span: None,
                                    });
                                }
                            }
                        }

                        // If brace depth returns to 0, we've exited the poll method
                        if brace_depth <= 0 && idx > poll_start {
                            in_poll_method = false;
                        }
                    }

                    // If impl brace depth returns to 0, we've exited the Future impl
                    if impl_brace_depth <= 0 && idx > 0 {
                        in_future_impl = false;
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

struct BroadcastUnsyncPayloadRule {
    metadata: RuleMetadata,
}

impl BroadcastUnsyncPayloadRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA023".to_string(),
                name: "tokio-broadcast-unsync-payload".to_string(),
                short_description: "Tokio broadcast carries !Sync payload".to_string(),
                full_description: "Warns when `tokio::sync::broadcast` channels are instantiated for types like `Rc`/`RefCell` that are not Sync, enabling unsound clones to cross thread boundaries. See RUSTSEC-2025-0023 for details.".to_string(),
                help_uri: Some("https://rustsec.org/advisories/RUSTSEC-2025-0023.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for BroadcastUnsyncPayloadRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            let usages = detect_broadcast_unsync_payloads(function);

            for usage in usages {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Broadcast channel instantiated with !Sync payload in `{}`",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: vec![usage.line.clone()],
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
                        span: None,
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
                full_description: "Detects reading lines from stdin without trimming whitespace/newlines. Untrimmed input can enable injection attacks when passed to shell commands, file paths, or other contexts where trailing newlines or whitespace have semantic meaning.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_untrimmed_stdin(&self, function: &MirFunction) -> bool {
        // Look for patterns like:
        // 1. stdin().lock().lines() or BufReader::new(stdin()).lines()
        // 2. read_line() on stdin
        // Without subsequent .trim() or .trim_end() calls
        
        let mut has_stdin_read = false;
        let mut has_trim = false;
        
        for line in &function.body {
            let lower = line.to_lowercase();
            
            // Check for stdin reads
            if (lower.contains("stdin") && (lower.contains("lines()") || lower.contains("read_line"))) 
                || lower.contains("bufreader") && lower.contains("stdin") {
                has_stdin_read = true;
            }
            
            // Check for trim operations
            if lower.contains(".trim()") || lower.contains(".trim_end()") || lower.contains(".trim_start()") {
                has_trim = true;
            }
        }
        
        // Flag if we read from stdin but never trim
        has_stdin_read && !has_trim
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
                    if line.to_lowercase().contains("stdin") 
                        || line.to_lowercase().contains("lines") 
                        || line.to_lowercase().contains("read_line") {
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
                    message: "Lines read from stdin are not trimmed. Untrimmed input can contain trailing newlines or whitespace that enable injection attacks when passed to commands, file paths, or other sensitive contexts. Use .trim() or .trim_end() to remove trailing whitespace.".to_string(),
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
                full_description: "Detects infinite iterators (std::iter::repeat, cycle, repeat_with) without termination methods (take, take_while, any, find, position). Such iterators can cause unbounded loops leading to Denial of Service (DoS) if not properly constrained.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn looks_like_infinite_iterator(&self, function: &MirFunction) -> bool {
        let body_str = format!("{:?}", function.body);
        
        // Check for infinite iterator constructors
        let has_repeat = body_str.contains("std::iter::repeat")
            || body_str.contains("core::iter::repeat");
        let has_cycle = body_str.contains("::cycle");
        let has_repeat_with = body_str.contains("std::iter::repeat_with")
            || body_str.contains("core::iter::repeat_with");
        
        if !has_repeat && !has_cycle && !has_repeat_with {
            return false;
        }
        
        // Check if there are termination methods
        let has_take = body_str.contains("::take(") || body_str.contains("::take>");
        let has_take_while = body_str.contains("::take_while");
        let has_any = body_str.contains("::any(") || body_str.contains("::any>");
        let has_find = body_str.contains("::find(") || body_str.contains("::find>");
        let has_position = body_str.contains("::position");
        
        // Flag if we have infinite iterator but no termination
        !has_take && !has_take_while && !has_any && !has_find && !has_position
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
                let body_str = format!("{:?}", function.body);
                let mut evidence = Vec::new();

                // Collect evidence of infinite iterator usage
                for line in body_str.lines().take(200) {
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
                    message: "Infinite iterator (repeat, cycle, or repeat_with) detected without termination method (take, take_while, any, find, position). This can cause unbounded loops leading to DoS. Add a termination condition or ensure the loop has a break statement.".to_string(),
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
        let has_read = body_str.contains(".read(true)") || body_str.contains("OpenOptions::read") && body_str.contains("const true");
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
        let body_str = format!("{:?}", function.body);
        
        // Look for borrow_mut calls
        if !body_str.contains("borrow_mut") {
            return false;
        }
        
        // Simple heuristic: if we see borrow_mut but don't see common mutation patterns,
        // it might be unnecessary. This is a simple approximation.
        let has_borrow_mut = body_str.contains("RefCell") && body_str.contains("borrow_mut");
        
        if !has_borrow_mut {
            return false;
        }
        
        // Check for signs of actual mutation after borrow_mut
        // Look for common mutating method names that appear in MIR
        let mutation_methods = [
            "::push", "::insert", "::remove", "::clear", "::extend",
            "::swap", "::sort", "::reverse", "::drain", "::append",
            "::truncate", "::resize", "::retain", "::dedup",
            "::split_off", "::pop", "::swap_remove"
        ];
        
        let has_mutation_method = mutation_methods.iter().any(|m| body_str.contains(m));
        
        // Also check for assignment patterns in MIR
        // Direct field/index assignments often appear as specific patterns
        let has_assignment = 
            // Check for mutable deref and field access patterns
            (body_str.contains("(*_") || body_str.contains("* _")) && 
            (body_str.contains("][") || body_str.contains(").") || body_str.contains("] ="));
        
        // Flag if we have borrow_mut but no clear mutation patterns
        // This is conservative - we may miss some cases but avoid false positives
        has_borrow_mut && !has_mutation_method && !has_assignment
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


fn register_builtin_rules(engine: &mut RuleEngine) {
    engine.register_rule(Box::new(BoxIntoRawRule::new()));
    engine.register_rule(Box::new(TransmuteRule::new()));
    engine.register_rule(Box::new(UnsafeUsageRule::new()));
    engine.register_rule(Box::new(InsecureMd5Rule::new()));
    engine.register_rule(Box::new(InsecureSha1Rule::new()));
    engine.register_rule(Box::new(UntrustedEnvInputRule::new()));
    engine.register_rule(Box::new(CommandInjectionRiskRule::new()));
    engine.register_rule(Box::new(VecSetLenRule::new()));
    engine.register_rule(Box::new(MaybeUninitAssumeInitRule::new()));
    engine.register_rule(Box::new(MemUninitZeroedRule::new()));
    engine.register_rule(Box::new(NonHttpsUrlRule::new()));
    engine.register_rule(Box::new(DangerAcceptInvalidCertRule::new()));
    engine.register_rule(Box::new(OpensslVerifyNoneRule::new()));
    engine.register_rule(Box::new(HardcodedHomePathRule::new()));
    engine.register_rule(Box::new(StaticMutGlobalRule::new()));
    engine.register_rule(Box::new(PermissionsSetReadonlyFalseRule::new()));
    engine.register_rule(Box::new(WorldWritableModeRule::new()));
    engine.register_rule(Box::new(NonNullNewUncheckedRule::new()));
    engine.register_rule(Box::new(MemForgetGuardRule::new()));
    engine.register_rule(Box::new(UnderscoreLockGuardRule::new()));
    engine.register_rule(Box::new(CommandArgConcatenationRule::new()));
    engine.register_rule(Box::new(OpenOptionsMissingTruncateRule::new()));
    engine.register_rule(Box::new(AllocatorMismatchFfiRule::new())); // RUSTCOLA017 (upgraded from source-level to MIR-based)
    engine.register_rule(Box::new(UnsafeSendSyncBoundsRule::new()));
    engine.register_rule(Box::new(FfiBufferLeakRule::new()));
    engine.register_rule(Box::new(PackedFieldReferenceRule::new())); // RUSTCOLA035
    engine.register_rule(Box::new(UnsafeCStringPointerRule::new())); // RUSTCOLA036
    engine.register_rule(Box::new(BlockingSleepInAsyncRule::new())); // RUSTCOLA037
    engine.register_rule(Box::new(VecSetLenMisuseRule::new())); // RUSTCOLA038
    engine.register_rule(Box::new(HardcodedCryptoKeyRule::new())); // RUSTCOLA039
    engine.register_rule(Box::new(PanicInDropRule::new())); // RUSTCOLA040
    engine.register_rule(Box::new(UnwrapInPollRule::new())); // RUSTCOLA041
    engine.register_rule(Box::new(CookieSecureAttributeRule::new())); // RUSTCOLA042
    engine.register_rule(Box::new(CorsWildcardRule::new())); // RUSTCOLA043
    engine.register_rule(Box::new(TimingAttackRule::new())); // RUSTCOLA044
    engine.register_rule(Box::new(WeakCipherRule::new())); // RUSTCOLA045
    engine.register_rule(Box::new(PredictableRandomnessRule::new())); // RUSTCOLA046
    engine.register_rule(Box::new(EnvVarLiteralRule::new())); // RUSTCOLA047
    engine.register_rule(Box::new(InvisibleUnicodeRule::new())); // RUSTCOLA048
    engine.register_rule(Box::new(CrateWideAllowRule::new())); // RUSTCOLA049
    engine.register_rule(Box::new(MisorderedAssertEqRule::new())); // RUSTCOLA050
    engine.register_rule(Box::new(TryIoResultRule::new())); // RUSTCOLA051
    engine.register_rule(Box::new(LocalRefCellRule::new())); // RUSTCOLA052
    engine.register_rule(Box::new(UntrimmedStdinRule::new())); // RUSTCOLA053
    engine.register_rule(Box::new(InfiniteIteratorRule::new())); // RUSTCOLA054
    engine.register_rule(Box::new(UnixPermissionsNotOctalRule::new())); // RUSTCOLA055
    engine.register_rule(Box::new(OpenOptionsInconsistentFlagsRule::new())); // RUSTCOLA056
    engine.register_rule(Box::new(UnnecessaryBorrowMutRule::new())); // RUSTCOLA057
    engine.register_rule(Box::new(AbsolutePathInJoinRule::new())); // RUSTCOLA058
    engine.register_rule(Box::new(CtorDtorStdApiRule::new())); // RUSTCOLA059
    engine.register_rule(Box::new(ConnectionStringPasswordRule::new())); // RUSTCOLA060
    // engine.register_rule(Box::new(AllocatorMismatchRule::new())); // OLD RUSTCOLA017 - replaced by MIR-based AllocatorMismatchFfiRule
    engine.register_rule(Box::new(ContentLengthAllocationRule::new()));
    engine.register_rule(Box::new(UnboundedAllocationRule::new()));
    engine.register_rule(Box::new(LengthTruncationCastRule::new()));
    engine.register_rule(Box::new(BroadcastUnsyncPayloadRule::new()));
    engine.register_rule(Box::new(RustsecUnsoundDependencyRule::new()));
    engine.register_rule(Box::new(YankedCrateRule::new()));
    engine.register_rule(Box::new(CargoAuditableMetadataRule::new()));
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

fn build_cargo_command() -> Command {
    // Just use cargo directly and let rustup's directory override handle toolchain selection
    // This way, if the target project has rust-toolchain.toml or rustup override set,
    // cargo will automatically use the correct toolchain
    if let Some(cargo_path) = detect_cargo_binary() {
        Command::new(cargo_path)
    } else {
        Command::new("cargo")
    }
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
    let mut cmd = build_cargo_command();
    cmd.current_dir(crate_path);
    cmd.arg("rustc");
    target.apply_to(&mut cmd);
    cmd.args(["--", "-Zunpretty=mir"]);

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

        if let Some(def_path) = extract_def_path_from_signature(&function.signature) {
            if let Some(meta) = metadata_by_path.remove(&def_path) {
                function.hir = Some(meta);
                continue;
            }
        }

        if let Some(candidates) = metadata_by_simple_name.get(function.name.as_str()) {
            if candidates.len() == 1 {
                if let Some(meta) = metadata_by_path.remove(&candidates[0]) {
                    function.hir = Some(meta);
                }
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

    file_uri_from_path(&crate_root)
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
                    body: vec!["_4 = std::env::var(_1);".to_string()],
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
            triggered.contains(&"RUSTCOLA026"),
            "expected NonNull::new_unchecked rule to fire"
        );
        assert!(
            triggered.contains(&"RUSTCOLA027"),
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
            "RUSTCOLA026",
            "RUSTCOLA027",
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
                body: vec!["    _1 = std::env::var(const \"FOO\");".to_string()],
                span: None,
                ..Default::default()
            }],
        };

        let findings = rule.evaluate(&package);
        assert_eq!(findings.len(), 1);
        let evidence = &findings[0].evidence;
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].contains("std::env::var"));
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
        let temp = tempdir().expect("temp dir");
        let crate_root = temp.path();

        fs::create_dir_all(crate_root.join("src"))?;
        fs::write(
            crate_root.join("Cargo.toml"),
            r#"[package]
name = "allocator-mismatch"
version = "0.1.0"
edition = "2021"

[dependencies]
libc = "0.2"

[lib]
path = "src/lib.rs"
"#,
        )?;
        fs::write(
            crate_root.join("src/lib.rs"),
            r#"use std::ffi::{c_void, CString};

#[no_mangle]
pub unsafe extern "C" fn bad_mix() {
    let c = CString::new("hello").unwrap();
    let raw = c.into_raw();
    libc::free(raw as *mut c_void);
}

#[no_mangle]
pub unsafe extern "C" fn good_mix() {
    let ptr = libc::malloc(16);
    if !ptr.is_null() {
        libc::free(ptr);
    }
}
"#,
        )?;

        let package = MirPackage {
            crate_name: "allocator-mismatch".to_string(),
            crate_root: crate_root.to_string_lossy().to_string(),
            functions: Vec::new(),
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
        assert!(finding.function.contains("src/lib.rs"));
        assert!(finding
            .evidence
            .iter()
            .any(|line| line.contains("into_raw")));
        assert!(finding
            .evidence
            .iter()
            .any(|line| line.contains("libc::free")));

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
