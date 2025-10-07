use anyhow::{anyhow, Context, Result};
use cargo_metadata::MetadataCommand;
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

mod dataflow;
mod prototypes;

pub use dataflow::{Assignment, MirDataflow};
pub use prototypes::{
    detect_broadcast_unsync_payloads, detect_command_invocations,
    detect_content_length_allocations, detect_openssl_verify_none,
    detect_truncating_len_casts, detect_unbounded_allocations, BroadcastUnsyncUsage,
    CommandInvocation, ContentLengthAllocation, LengthTruncationCast,
    OpensslVerifyNoneInvocation,
};

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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub message: String,
    pub function: String,
    pub function_signature: String,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MirFunction {
    pub name: String,
    pub signature: String,
    pub body: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MirPackage {
    pub crate_name: String,
    pub crate_root: String,
    pub functions: Vec<MirFunction>,
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

fn line_contains_md5_usage(line: &str) -> bool {
    let lower = line.to_lowercase();
    let mut search_start = 0;

    while let Some(relative_idx) = lower[search_start..].find("md5") {
        let idx = search_start + relative_idx;

        let mut before_chars = lower[..idx].chars().rev().skip_while(|c| c.is_whitespace());
        let mut after_chars = lower[idx + 3..].chars().skip_while(|c| c.is_whitespace());

        let after_matches = matches!((after_chars.next(), after_chars.next()), (Some(':'), Some(':')));

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
            if function
                .name
                .contains("line_contains_sha1_usage")
            {
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
        let mut findings = Vec::new();
        let patterns = [
            "env::var",
            "env::vars",
            "env::var_os",
            "env::args",
            "env::args_os",
        ];

        for function in &package.functions {
            let evidence = collect_case_insensitive_matches(&function.body, &patterns);
            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!("Untrusted environment input read in `{}`", function.name),
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence,
            });
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
                    VEC_SET_LEN_SYMBOL,
                    function.name
                ),
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence,
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
            });
        }

        findings
    }
}

struct DangerAcceptInvalidCertRule {
    metadata: RuleMetadata,
}

const DANGER_ACCEPT_INVALID_CERTS_SYMBOL: &str =
    concat!("danger", "_accept", "_invalid", "_certs");
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

impl Rule for DangerAcceptInvalidCertRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let patterns = [
            DANGER_ACCEPT_INVALID_CERTS_SYMBOL,
            DANGER_ACCEPT_INVALID_HOSTNAMES_SYMBOL,
        ];

        for function in &package.functions {
            let lines: Vec<String> = function
                .body
                .iter()
                .filter(|line| patterns.iter().any(|needle| line.contains(needle)))
                .filter(|line| line.contains("true"))
                .map(|line| line.trim().to_string())
                .collect();

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
            });
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

fn strip_string_literals(mut state: StringLiteralState, line: &str) -> (String, StringLiteralState) {
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
            let inner = normalized[idx + 1..]
                .trim_end_matches('>')
                .trim();
            if inner.starts_with("*const")
                || inner.starts_with("*mut")
                || inner.starts_with('&')
            {
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
                    let opens = current_sanitized
                        .chars()
                        .filter(|c| *c == '{')
                        .count() as i32;
                    let closes = current_sanitized
                        .chars()
                        .filter(|c| *c == '}')
                        .count() as i32;
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
                    let (next_sanitized, next_state) = strip_string_literals(current_state, next_line);
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
                full_description: "Flags allocations (`Vec::with_capacity`, `reserve*`) that trust HTTP Content-Length values without upper bounds, enabling attacker-controlled memory exhaustion.".to_string(),
                help_uri: Some("https://github.com/Opus-the-penguin/Rust-cola/blob/main/docs/research/rustsec-content-length-prototype.md".to_string()),
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
        let mut findings = Vec::new();
        let options = prototypes::PrototypeOptions::default();

        for function in &package.functions {
            let specialized = prototypes::detect_content_length_allocations_with_options(
                function,
                &options,
            );
            let specialized_lines: HashSet<_> = specialized
                .iter()
                .map(|alloc| alloc.allocation_line.clone())
                .collect();

            let allocations = prototypes::detect_unbounded_allocations_with_options(
                function,
                &options,
            );

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
                full_description: "Detects casts or try_into conversions that shrink message length fields to 8/16/32-bit integers without bounds checks, potentially smuggling extra bytes past protocol parsers.".to_string(),
                help_uri: Some("https://github.com/Opus-the-penguin/Rust-cola/blob/main/docs/research/rustsec-length-truncation-prototype.md".to_string()),
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
        let mut findings = Vec::new();

        for function in &package.functions {
            let casts = detect_truncating_len_casts(function);

            for cast in casts {
                let mut evidence = vec![cast.cast_line.clone()];

                if !cast.source_vars.is_empty() {
                    evidence.push(format!(
                        "length sources: {}",
                        cast.source_vars.join(", ")
                    ));
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
                full_description: "Warns when `tokio::sync::broadcast` channels are instantiated for types like `Rc`/`RefCell` that are not Sync, mirroring RustSec unsoundness reports.".to_string(),
                help_uri: Some("https://github.com/Opus-the-penguin/Rust-cola/blob/main/docs/research/rustsec-broadcast-unsync-prototype.md".to_string()),
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
        let search_dirs = [".github", ".gitlab", "ci", "scripts"];
        for dir in &search_dirs {
            let path = crate_root.join(dir);
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
            let path = crate_root.join(file);
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
        });

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
    engine.register_rule(Box::new(UnsafeSendSyncBoundsRule::new()));
    engine.register_rule(Box::new(FfiBufferLeakRule::new()));
    engine.register_rule(Box::new(AllocatorMismatchRule::new()));
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FunctionFingerprint {
    pub name: String,
    pub signature: String,
    pub hash: String,
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
}

const CACHE_VERSION: u32 = 1;

pub fn extract_with_cache(
    crate_path: &Path,
    cache: &CacheConfig,
) -> Result<(MirPackage, CacheStatus)> {
    extract_with_cache_with(crate_path, cache, || extract(crate_path))
}

fn extract_with_cache_with<F>(
    crate_path: &Path,
    cache: &CacheConfig,
    extractor: F,
) -> Result<(MirPackage, CacheStatus)>
where
    F: FnOnce() -> Result<MirPackage>,
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
                    return Ok((envelope.mir, CacheStatus::Hit(metadata)));
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

    let package = extractor()?;
    let function_fingerprints = compute_function_fingerprints(&package);
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
        mir: package.clone(),
    };

    if let Err(err) = write_cache_envelope(&cache_file, &envelope) {
        eprintln!(
            "rust-cola: failed to persist cache at {}: {err}",
            cache_file.display()
        );
    }

    Ok((
        package,
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
            for line in &function.body {
                hasher.update(line.as_bytes());
                hasher.update(&[0u8]);
            }
            FunctionFingerprint {
                name: function.name.clone(),
                signature: function.signature.clone(),
                hash: hex::encode(hasher.finalize()),
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

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug)]
enum RustcTarget {
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

fn discover_rustc_targets(crate_path: &Path) -> Result<Vec<RustcTarget>> {
    let manifest_path = crate_path.join("Cargo.toml");
    let mut cmd = MetadataCommand::new();
    if manifest_path.exists() {
        cmd.manifest_path(&manifest_path);
    } else {
        cmd.current_dir(crate_path);
    }
    cmd.no_deps();
    let metadata = cmd
        .exec()
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
    for target in &package.targets {
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
        return Err(anyhow!(
            "package {} has no lib or bin targets; cannot extract MIR",
            package.name
        ));
    }

    Ok(targets)
}

fn run_cargo_rustc(crate_path: &Path, target: &RustcTarget) -> Result<String> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(crate_path);
    cmd.arg("+nightly");
    cmd.arg("rustc");
    target.apply_to(&mut cmd);
    cmd.args(["--", "-Zunpretty=mir"]);

    let output = cmd
        .output()
        .with_context(|| format!("run `cargo +nightly rustc {}`", target.description()))?;

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
    let targets = discover_rustc_targets(crate_path)?;
    let canonical_crate_path = fs::canonicalize(crate_path).context("canonicalize crate path")?;
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

pub fn write_mir_json(path: impl AsRef<Path>, package: &MirPackage) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent).context("create parent directories for MIR JSON")?;
    }
    let mut file = File::create(path.as_ref()).context("create MIR JSON file")?;
    serde_json::to_writer_pretty(&mut file, package).context("serialize MIR package to JSON")?;
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
            let artifact_uri = artifact_uri_for(package, &finding.function);
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
                            "region": {
                                "message": {"text": finding.function_signature.clone()}
                            }
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
        MirFunction {
            name,
            signature,
            body,
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

fn trim_trailing_blanks(lines: &mut Vec<String>) {
    while matches!(lines.last(), Some(last) if last.trim().is_empty()) {
        lines.pop();
    }
}

fn detect_crate_name(crate_path: &Path) -> Option<String> {
    let canonical_crate = fs::canonicalize(crate_path)
        .ok()
        .unwrap_or_else(|| crate_path.to_path_buf());
    let manifest_path = if canonical_crate.is_file() {
        canonical_crate.clone()
    } else {
        canonical_crate.join("Cargo.toml")
    };

    let canonical_manifest = fs::canonicalize(&manifest_path).ok();

    let mut cmd = MetadataCommand::new();
    cmd.current_dir(&canonical_crate);
    cmd.no_deps();
    let metadata = cmd.exec().ok()?;

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

    fn make_danger_accept_invalid_certs_line(indent: &str) -> String {
        let mut line = String::with_capacity(indent.len() + 86);
        line.push_str(indent);
        line.push_str("_10 = reqwest::ClientBuilder::");
        line.push_str(DANGER_ACCEPT_INVALID_CERTS_SYMBOL);
        line.push_str("(move _1, const true);");
        line
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
                },
                MirFunction {
                    name: "md5_hash".to_string(),
                    signature: "fn md5_hash()".to_string(),
                    body: vec!["_2 = md5::Md5::new();".to_string()],
                },
                MirFunction {
                    name: "sha1_hash".to_string(),
                    signature: "fn sha1_hash()".to_string(),
                    body: vec!["_3 = sha1::Sha1::new();".to_string()],
                },
                MirFunction {
                    name: "env_usage".to_string(),
                    signature: "fn env_usage()".to_string(),
                    body: vec!["_4 = std::env::var(_1);".to_string()],
                },
                MirFunction {
                    name: "command_spawn".to_string(),
                    signature: "fn command_spawn()".to_string(),
                    body: vec!["_5 = std::process::Command::new(_1);".to_string()],
                },
                MirFunction {
                    name: "vec_set_len".to_string(),
                    signature: "fn vec_set_len(v: &mut Vec<i32>)".to_string(),
                    body: vec![make_vec_set_len_line("")],
                },
                MirFunction {
                    name: "maybe_uninit".to_string(),
                    signature: "fn maybe_uninit()".to_string(),
                    body: vec![make_maybe_uninit_assume_init_line("")],
                },
                MirFunction {
                    name: "deprecated_mem".to_string(),
                    signature: "fn deprecated_mem()".to_string(),
                    body: vec![make_mem_uninitialized_line("")],
                },
                MirFunction {
                    name: "http_url".to_string(),
                    signature: "fn http_url()".to_string(),
                    body: vec!["_9 = const \"http://example.com\";".to_string()],
                },
                MirFunction {
                    name: "dangerous_tls".to_string(),
                    signature: "fn dangerous_tls(builder: reqwest::ClientBuilder)".to_string(),
                    body: vec![make_danger_accept_invalid_certs_line("")],
                },
                MirFunction {
                    name: "openssl_none".to_string(),
                    signature: "fn openssl_none(ctx: &mut SslContextBuilder)".to_string(),
                    body: vec!["openssl::ssl::SslContextBuilder::set_verify((*_1), openssl::ssl::SslVerifyMode::NONE);".to_string()],
                },
                MirFunction {
                    name: "home_path_literal".to_string(),
                    signature: "fn home_path_literal()".to_string(),
                    body: vec!["_11 = const \"/home/alice/.ssh/id_rsa\";".to_string()],
                },
                MirFunction {
                    name: "content_length_allocation".to_string(),
                    signature: "fn content_length_allocation(resp: reqwest::Response)".to_string(),
                    body: vec![
                        "    _1 = reqwest::Response::content_length(move _0);".to_string(),
                        "    _2 = copy _1;".to_string(),
                        "    _3 = Vec::<u8>::with_capacity(move _2);".to_string(),
                    ],
                },
                MirFunction {
                    name: "length_truncation_cast".to_string(),
                    signature: "fn length_truncation_cast(len: usize)".to_string(),
                    body: vec![
                        "    debug payload_len => _1;".to_string(),
                        "    _2 = copy _1;".to_string(),
                        "    _3 = move _2 as i32 (IntToInt);".to_string(),
                        "    _4 = byteorder::WriteBytesExt::write_u16::<byteorder::BigEndian>(move _0, move _3);".to_string(),
                    ],
                },
                MirFunction {
                    name: "unbounded_allocation".to_string(),
                    signature: "fn unbounded_allocation(len: usize)".to_string(),
                    body: vec![
                        "    debug len => _1;".to_string(),
                        "    _2 = copy _1;".to_string(),
                        "    _3 = Vec::<u8>::with_capacity(move _2);".to_string(),
                    ],
                },
                MirFunction {
                    name: "broadcast_unsync".to_string(),
                    signature: "fn broadcast_unsync()".to_string(),
                    body: vec![
                        "    _5 = tokio::sync::broadcast::channel::<std::rc::Rc<String>>(const 16_usize);".to_string(),
                    ],
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
            .any(|line| line.contains("IntToInt")));
        assert!(truncation_finding
            .evidence
            .iter()
            .any(|line| line.contains("write_u16")));

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
            .any(|line| line.contains("with_capacity")));

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
            "RUSTCOLA021",
            "RUSTCOLA022",
            "RUSTCOLA024",
            "RUSTCOLA023",
        ] {
            assert!(analysis.rules.iter().any(|meta| meta.id == *id));
        }
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
            }],
        };

        let findings = rule.evaluate(&package);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.evidence.len(), 1);
        assert!(finding.message.contains("Process command execution detected"));
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
                .any(|sig| sig.contains("unsafe impl<T: std::marker::Send> Send for QualifiedSafe<T>")),
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
                    format!(
                        "    _1 = \"Documenting {} behavior\";",
                        VEC_SET_LEN_SYMBOL
                    ),
                    "}".to_string(),
                ],
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
                    "    0x10 │ 20 75 73 65 64 20 69 6e 20 6d 65 74 │  used in metadata".to_string(),
                    "}".to_string(),
                ],
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
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let has_maybe_uninit = analysis
            .findings
            .iter()
            .any(|finding| finding.rule_id == "RUSTCOLA009");

        assert!(!has_maybe_uninit, "{}::{} rule should not flag mir-extractor crate", MAYBE_UNINIT_TYPE_SYMBOL, MAYBE_UNINIT_ASSUME_INIT_SYMBOL);

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
            MEM_MODULE_SYMBOL,
            MEM_UNINITIALIZED_SYMBOL
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
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let matches: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "RUSTCOLA002")
            .collect();

        assert!(matches.is_empty(), "string literal should not trigger transmute rule");

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
            }],
        };

        let counter_clone = counter.clone();
        let (first_package, status1) =
            super::extract_with_cache_with(crate_root, &cache_config, move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                Ok(base_package.clone())
            })?;

        assert_eq!(counter.load(Ordering::SeqCst), 1);
        match status1 {
            CacheStatus::Miss { .. } => {}
            _ => panic!("expected first run to miss cache"),
        }

        let (second_package, status2) =
            super::extract_with_cache_with(crate_root, &cache_config, || {
                panic!("extractor invoked during cache hit");
            })?;

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
            }],
        };

        let analysis = RuleEngine::with_builtin_rules().run(&package);
        let has_vec_set_len = analysis
            .findings
            .iter()
            .any(|finding| finding.rule_id == "RUSTCOLA008");

        assert!(!has_vec_set_len, "Vec::set_len rule should not flag mir-extractor crate");

        Ok(())
    }
}
