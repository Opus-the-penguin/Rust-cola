//! Injection vulnerability rules.
//!
//! Rules detecting injection vulnerabilities:
//! - Untrusted env input (RUSTCOLA006)
//! - Command injection (RUSTCOLA007, RUSTCOLA098)
//! - Command argument concatenation (RUSTCOLA031)
//! - Log injection (RUSTCOLA076)
//! - SQL injection (RUSTCOLA087)
//! - Path traversal (RUSTCOLA086)
//! - SSRF (RUSTCOLA088)
//! - Regex injection (RUSTCOLA079)
//! - Unchecked index (RUSTCOLA080)

use std::collections::{HashMap, HashSet};

use crate::dataflow::taint::TaintAnalysis;
use crate::interprocedural;
use crate::rules::utils::{command_rule_should_skip, INPUT_SOURCE_PATTERNS, LOG_SINK_PATTERNS};
use crate::{
    detect_command_invocations, extract_span_from_mir_line, Finding, MirPackage, Rule,
    RuleMetadata, RuleOrigin, Severity,
};

// ============================================================================
// RUSTCOLA006 - UntrustedEnvInputRule
// ============================================================================

pub struct UntrustedEnvInputRule {
    metadata: RuleMetadata,
}

impl UntrustedEnvInputRule {
    pub fn new() -> Self {
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
        let taint_analysis = TaintAnalysis::new();
        let mut findings = Vec::new();

        for function in &package.functions {
            let (_tainted_vars, flows) = taint_analysis.analyze(function);

            for flow in flows {
                if !flow.sanitized {
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

// ============================================================================
// RUSTCOLA007 - CommandInjectionRiskRule
// ============================================================================

pub struct CommandInjectionRiskRule {
    metadata: RuleMetadata,
}

impl CommandInjectionRiskRule {
    pub fn new() -> Self {
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

// ============================================================================
// RUSTCOLA031 - CommandArgConcatenationRule
// ============================================================================

pub struct CommandArgConcatenationRule {
    metadata: RuleMetadata,
}

impl CommandArgConcatenationRule {
    pub fn new() -> Self {
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

// ============================================================================
// RUSTCOLA076 - LogInjectionRule
// ============================================================================

pub struct LogInjectionRule {
    metadata: RuleMetadata,
}

impl LogInjectionRule {
    pub fn new() -> Self {
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
        
        for line in body {
            let trimmed = line.trim();
            
            // Check if this line contains an input source
            let is_source = INPUT_SOURCE_PATTERNS.iter().any(|p| trimmed.contains(p));
            
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
        
        for line in body {
            let trimmed = line.trim();
            
            // Check if this is a log sink
            let is_log_sink = LOG_SINK_PATTERNS.iter().any(|p| trimmed.contains(p));
            
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
    fn find_logging_helpers(package: &MirPackage) -> HashSet<String> {
        let mut helpers = HashSet::new();
        
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
                let is_log_sink = LOG_SINK_PATTERNS.iter().any(|p| trimmed.contains(p));
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
                let helper_name = helper.split("::").last().unwrap_or(helper);
                if trimmed.contains(&format!("{}(", helper_name)) {
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
        
        let logging_helpers = Self::find_logging_helpers(package);

        for function in &package.functions {
            if function.name.contains("mir_extractor") || function.name.contains("mir-extractor") {
                continue;
            }

            let untrusted_vars = Self::track_untrusted_vars(&function.body);
            
            if untrusted_vars.is_empty() {
                continue;
            }

            let mut injections = Self::find_log_injections(&function.body, &untrusted_vars);
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

// ============================================================================
// RUSTCOLA079 - RegexInjectionRule
// ============================================================================

pub struct RegexInjectionRule {
    metadata: RuleMetadata,
}

impl RegexInjectionRule {
    pub fn new() -> Self {
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
        INPUT_SOURCE_PATTERNS
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
    fn has_validation_guard(body: &[String], untrusted_vars: &HashSet<String>) -> bool {
        let validation_funcs = ["validate", "sanitize", "is_valid", "check_pattern"];
        let mut validation_result_var: Option<String> = None;
        
        for line in body {
            let trimmed = line.trim();
            
            for validator in &validation_funcs {
                if trimmed.to_lowercase().contains(validator) {
                    for var in untrusted_vars {
                        if Self::contains_var(trimmed, var) {
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
            
            if let Some(ref result_var) = validation_result_var {
                if trimmed.contains("switchInt") && Self::contains_var(trimmed, result_var) {
                    return true;
                }
            }
        }
        
        false
    }

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

    fn track_untrusted_vars(body: &[String]) -> HashSet<String> {
        let mut untrusted_vars = HashSet::new();
        let source_patterns = Self::input_source_patterns();
        let sanitizer_patterns = Self::sanitizer_patterns();
        
        let mut ref_aliases: HashMap<String, String> = HashMap::new();
        for line in body {
            let trimmed = line.trim();
            if let Some(eq_pos) = trimmed.find(" = &") {
                let lhs = trimmed[..eq_pos].trim();
                let rhs = &trimmed[eq_pos + 3..].trim();
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
            let is_source = source_patterns.iter().any(|p| trimmed.contains(p));
            
            if is_source {
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    if let Some(var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        untrusted_vars.insert(var.to_string());
                    }
                }
                
                if trimmed.contains("read_line(") {
                    if let Some(start) = trimmed.find("read_line(") {
                        let after = &trimmed[start..];
                        if let Some(copy_pos) = after.rfind("copy _") {
                            let var_start = &after[copy_pos + 5..];
                            if let Some(end) = var_start.find(|c: char| !c.is_alphanumeric() && c != '_') {
                                let var = &var_start[..end];
                                if var.starts_with('_') {
                                    untrusted_vars.insert(var.to_string());
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
        
        untrusted_vars
    }

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

    fn find_regex_injections(body: &[String], untrusted_vars: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        let regex_sinks = Self::regex_sink_patterns();
        
        for line in body {
            let trimmed = line.trim();
            let is_regex_sink = regex_sinks.iter().any(|p| trimmed.contains(p));
            
            if is_regex_sink {
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
        
        let mut tainted_closures: HashSet<String> = HashSet::new();
        
        for function in &package.functions {
            if function.name.contains("{closure") {
                continue;
            }
            
            let untrusted_vars = Self::track_untrusted_vars(&function.body);
            if untrusted_vars.is_empty() {
                continue;
            }
            
            let combinator_patterns = ["and_then", "map(", "filter(", "filter_map(", "unwrap_or_else("];
            for line in &function.body {
                let trimmed = line.trim();
                for pattern in &combinator_patterns {
                    if trimmed.contains(pattern) {
                        for var in &untrusted_vars {
                            if Self::contains_var(trimmed, var) {
                                tainted_closures.insert(function.name.clone());
                                break;
                            }
                        }
                    }
                }
            }
        }

        for function in &package.functions {
            if function.name.contains("mir_extractor") || function.name.contains("mir-extractor") {
                continue;
            }

            let is_closure = function.name.contains("{closure");
            let mut untrusted_vars = if is_closure {
                let parent_name = function.name.split("::{closure").next().unwrap_or("");
                if tainted_closures.contains(parent_name) {
                    let mut vars = HashSet::new();
                    for line in &function.body {
                        let trimmed = line.trim();
                        if trimmed.starts_with("debug ") && trimmed.contains(" => _") {
                            if let Some(var) = trimmed.split(" => _").nth(1) {
                                let var = var.trim_end_matches(';');
                                vars.insert(format!("_{}", var));
                            }
                        }
                    }
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
            
            if is_closure && !untrusted_vars.is_empty() {
                Self::propagate_taint_in_body(&function.body, &mut untrusted_vars);
            }
            
            if untrusted_vars.is_empty() {
                continue;
            }

            if Self::has_validation_guard(&function.body, &untrusted_vars) {
                continue;
            }

            let injections = Self::find_regex_injections(&function.body, &untrusted_vars);
            
            if !injections.is_empty() {
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

// ============================================================================
// RUSTCOLA080 - UncheckedIndexRule
// ============================================================================

pub struct UncheckedIndexRule {
    metadata: RuleMetadata,
}

impl UncheckedIndexRule {
    pub fn new() -> Self {
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

    fn input_source_patterns() -> &'static [&'static str] {
        INPUT_SOURCE_PATTERNS
    }

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

    fn track_untrusted_indices(body: &[String], tainted_return_funcs: &HashSet<String>) -> HashSet<String> {
        let mut untrusted_vars = HashSet::new();
        let source_patterns = Self::input_source_patterns();
        
        let mut mut_refs: HashMap<String, String> = HashMap::new();
        for line in body {
            let trimmed = line.trim();
            if trimmed.contains("= &mut _") {
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    let source = trimmed[eq_pos + 3..].trim();
                    if let Some(target_var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        if let Some(src_start) = source.find('_') {
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
        
        for line in body {
            let trimmed = line.trim();
            let is_source = source_patterns.iter().any(|p| trimmed.contains(p));
            
            if is_source {
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    if let Some(var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        untrusted_vars.insert(var.to_string());
                    }
                }
                
                if trimmed.contains("read_line") {
                    for (ref_var, target_var) in &mut_refs {
                        if trimmed.contains(ref_var) {
                            untrusted_vars.insert(target_var.clone());
                        }
                    }
                }
            }
            
            if !tainted_return_funcs.is_empty() {
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let source = trimmed[eq_pos + 3..].trim();
                    for func_name in tainted_return_funcs {
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
        
        let mut changed = true;
        while changed {
            changed = false;
            for line in body {
                let trimmed = line.trim();
                let uses_untrusted = untrusted_vars.iter().any(|v| Self::contains_var(trimmed, v));
                
                if !uses_untrusted {
                    continue;
                }
                
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let target = trimmed[..eq_pos].trim();
                    if let Some(target_var) = target.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .find(|s| s.starts_with('_'))
                    {
                        if !untrusted_vars.contains(target_var) {
                            let dominated_by_untrusted = 
                                trimmed.contains("::parse") || 
                                trimmed.contains("parse::") ||
                                trimmed.contains("from_str") ||
                                trimmed.contains("::unwrap(") || 
                                trimmed.contains("::expect(") ||
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

    fn has_bounds_validation(body: &[String], untrusted_vars: &HashSet<String>) -> bool {
        let mut comparison_vars: HashSet<String> = HashSet::new();
        
        for line in body {
            let trimmed = line.trim();
            
            if trimmed.contains("::get(") || trimmed.contains("::get_mut(") || trimmed.contains("::get::<") {
                continue;
            }
            
            if trimmed.contains(".len()") || trimmed.contains("::len(") {
                for var in untrusted_vars {
                    if Self::contains_var(trimmed, var) {
                        return true;
                    }
                }
            }
            
            if (trimmed.contains("::min(") || trimmed.contains("::max(")) && 
               (trimmed.contains("len") || trimmed.contains("_")) {
                for var in untrusted_vars {
                    if Self::contains_var(trimmed, var) {
                        return true;
                    }
                }
            }
            
            let has_comparison = trimmed.contains("Lt(") || trimmed.contains("Le(") || 
                                  trimmed.contains("Gt(") || trimmed.contains("Ge(");
            if has_comparison {
                for var in untrusted_vars {
                    if Self::contains_var(trimmed, var) {
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

    fn find_unsafe_indexing(body: &[String], untrusted_vars: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        
        for line in body {
            let trimmed = line.trim();
            
            if trimmed.contains("::index(") || trimmed.contains("::index_mut(") {
                if trimmed.contains("::get(") || trimmed.contains("::get_mut(") {
                    continue;
                }
                
                if let Some(idx_start) = trimmed.find("::index") {
                    let after_index = &trimmed[idx_start..];
                    if let Some(comma_pos) = after_index.find(", ") {
                        let index_arg = &after_index[comma_pos + 2..];
                        for var in untrusted_vars {
                            if Self::contains_var(index_arg, var) {
                                evidence.push(trimmed.to_string());
                                break;
                            }
                        }
                    }
                }
            }
            
            if trimmed.contains('[') && trimmed.contains(']') {
                if trimmed.contains("= [") {
                    continue;
                }
                
                if trimmed.contains("let ") || trimmed.contains("::get") {
                    continue;
                }
                
                if let Some(bracket_start) = trimmed.find('[') {
                    if let Some(bracket_end) = trimmed[bracket_start..].find(']') {
                        let index_content = &trimmed[bracket_start + 1..bracket_start + bracket_end];
                        
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
    
    fn find_tainted_return_functions(package: &MirPackage) -> HashSet<String> {
        let mut tainted_funcs = HashSet::new();
        let source_patterns = Self::input_source_patterns();
        
        for function in &package.functions {
            if function.name.contains("mir_extractor") || 
               function.name.contains("mir-extractor") ||
               function.name.contains("__") {
                continue;
            }
            
            let has_source = function.body.iter().any(|line| {
                source_patterns.iter().any(|p| line.contains(p))
            });
            
            if !has_source {
                continue;
            }
            
            let empty_set = HashSet::new();
            let tainted = Self::track_untrusted_indices(&function.body, &empty_set);
            
            let returns_tainted = function.body.iter().any(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with("_0 = ") || trimmed.starts_with("_0 =") {
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
        
        let tainted_return_funcs = Self::find_tainted_return_functions(package);

        for function in &package.functions {
            if function.name.contains("mir_extractor") || 
               function.name.contains("mir-extractor") ||
               function.name.contains("__") {
                continue;
            }

            let untrusted_vars = Self::track_untrusted_indices(&function.body, &tainted_return_funcs);
            
            if untrusted_vars.is_empty() {
                continue;
            }

            if Self::has_bounds_validation(&function.body, &untrusted_vars) {
                continue;
            }

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

/// Register all injection rules with the rule engine.
pub fn register_injection_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(UntrustedEnvInputRule::new()));
    engine.register_rule(Box::new(CommandInjectionRiskRule::new()));
    engine.register_rule(Box::new(CommandArgConcatenationRule::new()));
    engine.register_rule(Box::new(LogInjectionRule::new()));
    engine.register_rule(Box::new(RegexInjectionRule::new()));
    engine.register_rule(Box::new(UncheckedIndexRule::new()));
    engine.register_rule(Box::new(PathTraversalRule::new()));
    engine.register_rule(Box::new(SsrfRule::new()));
    engine.register_rule(Box::new(SqlInjectionRule::new()));
    engine.register_rule(Box::new(InterProceduralCommandInjectionRule::new()));
}

// ============================================================================
// RUSTCOLA086 - PathTraversalRule
// ============================================================================

pub struct PathTraversalRule {
    metadata: RuleMetadata,
}

impl PathTraversalRule {
    pub fn new() -> Self {
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
    
    const FS_SINKS: &'static [&'static str] = &[
        "fs::read_to_string", "fs::read", "File::open", "std::fs::read_to_string",
        "std::fs::read", "std::fs::File::open", "OpenOptions::open",
        "read_to_string(", "read_to_string::<", "fs::write", "fs::create_dir",
        "fs::create_dir_all", "std::fs::write", "std::fs::create_dir",
        "std::fs::create_dir_all", "File::create", "std::fs::File::create",
        "create_dir_all::<", "create_dir::<", "fs::remove_file", "fs::remove_dir",
        "fs::remove_dir_all", "std::fs::remove_file", "std::fs::remove_dir",
        "std::fs::remove_dir_all", "remove_file::<", "remove_dir::<",
        "remove_dir_all::<", "fs::copy", "fs::rename", "std::fs::copy",
        "std::fs::rename", "copy::<", "rename::<", "Path::join",
        "PathBuf::push", "PathBuf::join",
    ];
    
    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        "env::var(", "env::var_os(", "std::env::var(", "std::env::var_os(",
        " = var(", " = var::", "env::args()", "std::env::args()", " = args(",
        "Args>::next(", " = stdin()", "Stdin::lock(", "BufRead>::read_line(",
        "read_line(move", "io::stdin()",
    ];
    
    const SANITIZERS: &'static [&'static str] = &[
        "canonicalize(", "starts_with(", "strip_prefix(", "is_relative(",
        "is_absolute(", "::contains(move", "::contains(copy", "slice::<impl",
        "String::replace", "str::replace", ".filter(", "chars().all(",
        "is_alphanumeric", "validate", "sanitize", "check_path", "is_safe", "safe_join",
    ];

    fn track_untrusted_paths(&self, body: &[String]) -> HashSet<String> {
        let mut untrusted_vars = HashSet::new();
        
        for line in body {
            let trimmed = line.trim();
            for source in Self::UNTRUSTED_SOURCES {
                if trimmed.contains(source) {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        untrusted_vars.insert(target);
                    }
                }
            }
        }
        
        let mut changed = true;
        let mut iterations = 0;
        
        while changed && iterations < 20 {
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
        
        // Handle read_line buffer tainting
        for line in body {
            if line.contains("read_line(") {
                if let Some(buffer_ref) = Self::extract_read_line_buffer(line) {
                    if let Some(actual_var) = Self::resolve_reference(body, &buffer_ref) {
                        untrusted_vars.insert(actual_var);
                    } else {
                        untrusted_vars.insert(buffer_ref);
                    }
                }
            }
        }
        
        untrusted_vars
    }
    
    fn resolve_reference(body: &[String], ref_var: &str) -> Option<String> {
        for line in body {
            let trimmed = line.trim();
            if trimmed.starts_with(ref_var) && trimmed.contains(" = &") {
                if let Some(amp_idx) = trimmed.find('&') {
                    let after_amp = &trimmed[amp_idx + 1..];
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
    
    fn extract_read_line_buffer(line: &str) -> Option<String> {
        if let Some(idx) = line.find("read_line(") {
            let after = &line[idx..];
            if let Some(comma_idx) = after.find(',') {
                let second_arg = &after[comma_idx + 1..];
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
    
    fn has_path_sanitization(&self, body: &[String], _untrusted_vars: &HashSet<String>) -> bool {
        let body_str = body.join("\n");
        
        for sanitizer in Self::SANITIZERS {
            if body_str.contains(sanitizer) {
                return true;
            }
        }
        
        if body_str.contains("switchInt(") {
            if body_str.contains("contains(") || 
               body_str.contains("starts_with(") ||
               body_str.contains("is_relative()") ||
               body_str.contains("strip_prefix(") {
                return true;
            }
        }
        
        if body_str.contains("Err(") && 
           (body_str.contains("Permission") || 
            body_str.contains("Invalid") ||
            body_str.contains("traversal") ||
            body_str.contains("not in allow")) {
            return true;
        }
        
        false
    }
    
    fn find_unsafe_fs_operations(&self, body: &[String], untrusted_vars: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        
        for line in body {
            let trimmed = line.trim();
            for sink in Self::FS_SINKS {
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
    
    fn contains_var(&self, line: &str, var: &str) -> bool {
        line.contains(&format!("move {}", var)) ||
        line.contains(&format!("copy {}", var)) ||
        line.contains(&format!("&{}", var)) ||
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

        for function in &package.functions {
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

            let untrusted_vars = self.track_untrusted_paths(&function.body);
            
            if untrusted_vars.is_empty() {
                continue;
            }

            if self.has_path_sanitization(&function.body, &untrusted_vars) {
                continue;
            }

            let unsafe_ops = self.find_unsafe_fs_operations(&function.body, &untrusted_vars);
            
            if !unsafe_ops.is_empty() {
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

        // Inter-procedural analysis
        if let Ok(mut inter_analysis) = interprocedural::InterProceduralAnalysis::new(package) {
            if inter_analysis.analyze(package).is_ok() {
                let flows = inter_analysis.detect_inter_procedural_flows(package);
                
                let mut reported_functions: HashSet<String> = findings
                    .iter()
                    .map(|f| f.function.clone())
                    .collect();
                
                for flow in flows {
                    if flow.sink_type != "filesystem" {
                        continue;
                    }
                    
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
                    
                    reported_functions.insert(flow.sink_function.clone());
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA088 - SsrfRule
// ============================================================================

pub struct SsrfRule {
    metadata: RuleMetadata,
}

impl SsrfRule {
    pub fn new() -> Self {
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
    
    const HTTP_SINKS: &'static [&'static str] = &[
        "reqwest::blocking::get", "reqwest::get", "blocking::get",
        "Client>::get", "Client>::post", "Client>::put", "Client>::delete",
        "Client>::patch", "Client>::head", "ClientBuilder", "RequestBuilder>::send",
        "ureq::get", "ureq::post", "ureq::put", "ureq::delete", "ureq::request",
        "Agent>::get", "Agent>::post", "Request>::call", "hyper::Client",
        "hyper::Request", "Request>::builder", "Uri::from_str", "http::Request",
        "get::<&String>", "get::<&str>", "post::<&String>", "post::<&str>",
    ];
    
    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        "env::var(", "env::var_os(", "std::env::var(", "std::env::var_os(",
        " = var(", " = var::", "var::<&str>", "var_os::<", "env::args()",
        "std::env::args()", " = args()", "Args>::next(", "args().collect",
        " = stdin()", "Stdin::lock(", "Stdin>::lock", "BufRead>::read_line(",
        "read_line(move", "io::stdin()", "Lines>::next(", "fs::read_to_string(",
        "read_to_string(move", "read_to_string::", "BufReader>::read",
        "Read>::read", "Request", "Form", "Query", "Json", "Path",
    ];
    
    const SANITIZERS: &'static [&'static str] = &[
        "Url::parse(", "url::Url::parse(", "Uri::from_str(", "host_str(",
        "scheme(", "starts_with(", "ends_with(", "contains(", "allowed",
        "whitelist", "allowlist", "trusted", "permitted", "localhost",
        "127.0.0.1", "169.254.169.254", "192.168.", "10.", "172.", ".internal",
        "== \"https\"", "== \"http\"", "is_alphanumeric", "chars().all(",
        " as Iterator>::all::<", "Eq>::eq::<", "PartialEq>::eq::<",
        "match ", "Some(\"",
    ];

    fn track_untrusted_vars(&self, body: &[String]) -> HashSet<String> {
        let mut untrusted_vars = HashSet::new();
        
        for line in body {
            let trimmed = line.trim();
            for source in Self::UNTRUSTED_SOURCES {
                if trimmed.contains(source) {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        untrusted_vars.insert(target);
                    }
                }
            }
        }
        
        let mut changed = true;
        let mut iterations = 0;
        
        while changed && iterations < 20 {
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
        
        untrusted_vars
    }
    
    fn has_ssrf_sanitization(&self, body: &[String]) -> bool {
        let body_str = body.join("\n");
        for sanitizer in Self::SANITIZERS {
            if body_str.contains(sanitizer) {
                return true;
            }
        }
        false
    }
    
    fn find_unsafe_http_operations(&self, body: &[String], untrusted_vars: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        
        for line in body {
            let trimmed = line.trim();
            for sink in Self::HTTP_SINKS {
                if trimmed.contains(sink) {
                    for var in untrusted_vars {
                        if self.contains_var(trimmed, var) {
                            evidence.push(trimmed.to_string());
                            break;
                        }
                    }
                }
            }
        }
        
        evidence
    }
    
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
    
    fn contains_var(&self, line: &str, var: &str) -> bool {
        line.contains(&format!("move {}", var)) ||
        line.contains(&format!("copy {}", var)) ||
        line.contains(&format!("&{}", var)) ||
        line.contains(&format!("({})", var)) ||
        line.contains(&format!("{},", var)) ||
        line.contains(&format!(" {} ", var)) ||
        line.contains(&format!("[{}]", var)) ||
        line.contains(&format!("(({} as", var))
    }
}

impl Rule for SsrfRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("mir_extractor") || 
               function.name.contains("mir-extractor") ||
               function.name.contains("__") ||
               function.name.contains("test_") ||
               function.name == "detect_toolchain" {
                continue;
            }

            let body_str = function.body.join("\n");
            let has_http_client = Self::HTTP_SINKS.iter().any(|s| body_str.contains(s)) ||
                                  body_str.contains("reqwest") ||
                                  body_str.contains("ureq") ||
                                  body_str.contains("hyper");
            
            if !has_http_client {
                continue;
            }

            let untrusted_vars = self.track_untrusted_vars(&function.body);
            
            if untrusted_vars.is_empty() {
                continue;
            }

            if self.has_ssrf_sanitization(&function.body) {
                continue;
            }

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

        // Inter-procedural analysis
        if let Ok(mut inter_analysis) = interprocedural::InterProceduralAnalysis::new(package) {
            if inter_analysis.analyze(package).is_ok() {
                let flows = inter_analysis.detect_inter_procedural_flows(package);
                
                let mut reported_functions: HashSet<String> = findings
                    .iter()
                    .map(|f| f.function.clone())
                    .collect();
                
                for flow in flows {
                    if flow.sink_type != "http" {
                        continue;
                    }
                    
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

// ============================================================================
// RUSTCOLA087 - SqlInjectionRule
// ============================================================================

pub struct SqlInjectionRule {
    metadata: RuleMetadata,
}

impl SqlInjectionRule {
    pub fn new() -> Self {
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
    
    const SQL_STATEMENT_PATTERNS: &'static [&'static str] = &[
        "SELECT ", "SELECT\t", "SELECT\n", " FROM ", "INSERT INTO", "INSERT  INTO",
        "UPDATE ", "UPDATE\t", " SET ", "DELETE FROM", "DELETE  FROM",
        "DROP TABLE", "DROP DATABASE", "DROP INDEX", "DROP VIEW",
        "CREATE TABLE", "CREATE DATABASE", "CREATE INDEX", "CREATE VIEW",
        "ALTER TABLE", "ALTER DATABASE", "TRUNCATE TABLE", " WHERE ",
        " ORDER BY", " GROUP BY", " HAVING ", " JOIN ", " LEFT JOIN",
        " RIGHT JOIN", " INNER JOIN", " OUTER JOIN", " UNION ", " UNION ALL",
        " VALUES", " VALUES(", "?)", "?, ", " ? ", "$1", "$2", "$3",
    ];
    
    const SQL_SINKS: &'static [&'static str] = &[
        "format_args!", "format!", "String::push_str", "str::to_string", "+",
        "execute(", "query(", "query_as(", "sql_query(", "prepare(",
        "execute_batch(", "query_row(", "query_map(", "raw_query(", "raw_sql(",
        "sqlx::query", "sqlx::query_as", "sqlx::query_scalar", "diesel::sql_query",
        "diesel::delete", "diesel::insert_into", "diesel::update",
        "rusqlite::execute", "Connection::execute", "Connection::query_row",
        "Statement::execute",
    ];
    
    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        "env::var(", "env::var_os(", "std::env::var(", "std::env::var_os(",
        " = var(", " = var::", "env::args()", "std::env::args()", " = args(",
        "Args>::next(", " = stdin()", "Stdin::lock(", "BufRead>::read_line(",
        "read_line(move", "io::stdin()", "Request", "Form", "Query", "Json", "Path",
    ];
    
    const SANITIZERS: &'static [&'static str] = &[
        " ? ", "?)", "?, ", "$1", "$2", ":name", ":username", ":id",
        ".bind(", "bind_value(", "bind::<", "QueryBuilder", "filter(",
        ".eq(", ".ne(", ".gt(", ".lt(", "parse::<i", "parse::<u", "parse::<f",
        "i32::from_str", "i64::from_str", "u32::from_str", "u64::from_str",
        "::contains(move", "::contains(copy", "allowed_", "whitelist", "allowlist",
        "escape(", "quote(", "sanitize", "replace(", "replace('", "::replace::",
        "is_alphanumeric", "chars().all(", " as Iterator>::all::<",
    ];

    fn track_untrusted_vars(&self, body: &[String]) -> HashSet<String> {
        let mut untrusted_vars = HashSet::new();
        
        for line in body {
            let trimmed = line.trim();
            for source in Self::UNTRUSTED_SOURCES {
                if trimmed.contains(source) {
                    if let Some(target) = self.extract_assignment_target(trimmed) {
                        untrusted_vars.insert(target);
                    }
                }
            }
        }
        
        let mut changed = true;
        let mut iterations = 0;
        
        while changed && iterations < 20 {
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
        
        untrusted_vars
    }
    
    fn has_sql_sanitization(&self, body: &[String]) -> bool {
        let body_str = body.join("\n");
        for sanitizer in Self::SANITIZERS {
            if body_str.contains(sanitizer) {
                return true;
            }
        }
        false
    }
    
    fn find_unsafe_sql_operations(&self, body: &[String], untrusted_vars: &HashSet<String>) -> Vec<String> {
        let mut evidence = Vec::new();
        
        let has_sql_const = body.iter().any(|line| {
            if !line.contains("const ") && !line.contains("[const ") {
                return false;
            }
            let line_upper = line.to_uppercase();
            Self::SQL_STATEMENT_PATTERNS.iter().any(|pattern| line_upper.contains(pattern))
        });
        
        let has_promoted_sql_ref = body.iter().any(|line| {
            line.contains("::promoted[") && 
            body.iter().any(|other| {
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
        
        let has_tainted_format = body.iter().any(|line| {
            let trimmed = line.trim();
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
            for line in body {
                if !line.contains("const ") && !line.contains("[const ") {
                    continue;
                }
                let line_upper = line.to_uppercase();
                if Self::SQL_STATEMENT_PATTERNS.iter().any(|pattern| line_upper.contains(pattern)) {
                    evidence.push(line.trim().to_string());
                }
            }
        }
        
        evidence
    }
    
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
    
    fn contains_var(&self, line: &str, var: &str) -> bool {
        line.contains(&format!("move {}", var)) ||
        line.contains(&format!("copy {}", var)) ||
        line.contains(&format!("&{}", var)) ||
        line.contains(&format!("({})", var)) ||
        line.contains(&format!("{},", var)) ||
        line.contains(&format!(" {} ", var)) ||
        line.contains(&format!("[{}]", var))
    }
    
    fn extract_function_params(&self, body: &[String]) -> HashSet<String> {
        let mut params = HashSet::new();
        for line in body {
            let trimmed = line.trim();
            if trimmed.starts_with("debug ") && trimmed.contains(" => _") {
                if let Some(start) = trimmed.find(" => _") {
                    let after = &trimmed[start + 5..];
                    let var: String = after.chars().take_while(|c| c.is_ascii_digit() || *c == '_').collect();
                    if !var.is_empty() && var != "0" {
                        params.insert(format!("_{}", var.trim_start_matches('_')));
                    }
                }
            }
        }
        params
    }
    
    fn propagate_taint(&self, body: &[String], untrusted_vars: &mut HashSet<String>) {
        let mut changed = true;
        let mut iterations = 0;
        
        while changed && iterations < 20 {
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

        // Build tainted return functions map
        let mut tainted_return_functions: HashSet<String> = HashSet::new();
        
        for function in &package.functions {
            let has_source = function.body.iter().any(|line| {
                Self::UNTRUSTED_SOURCES.iter().any(|src| line.contains(src))
            });
            
            if has_source {
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

        for function in &package.functions {
            if function.name.contains("mir_extractor") || 
               function.name.contains("mir-extractor") ||
               function.name.contains("__") ||
               function.name.contains("test_") {
                continue;
            }

            let mut untrusted_vars = self.track_untrusted_vars(&function.body);
            
            // Add taint from called functions
            for line in &function.body {
                let trimmed = line.trim();
                if trimmed.contains(" = ") {
                    for tainted_fn in &tainted_return_functions {
                        let fn_name = tainted_fn.split("::").last().unwrap_or(tainted_fn);
                        if trimmed.contains(&format!("= {}()", fn_name)) {
                            if let Some(target) = self.extract_assignment_target(trimmed) {
                                untrusted_vars.insert(target);
                            }
                        }
                    }
                }
            }
            
            // Check function parameters if no other sources
            if untrusted_vars.is_empty() {
                let params = self.extract_function_params(&function.body);
                if !params.is_empty() {
                    let mut param_vars = params.clone();
                    self.propagate_taint(&function.body, &mut param_vars);
                    
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
                            let is_format_related = 
                                trimmed.contains("fmt::Arguments") ||
                                trimmed.contains("Argument::") ||
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

            if self.has_sql_sanitization(&function.body) {
                continue;
            }

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

        // Inter-procedural analysis
        if let Ok(mut inter_analysis) = interprocedural::InterProceduralAnalysis::new(package) {
            if inter_analysis.analyze(package).is_ok() {
                let flows = inter_analysis.detect_inter_procedural_flows(package);
                
                let mut reported_functions: HashSet<String> = findings
                    .iter()
                    .map(|f| f.function.clone())
                    .collect();
                
                for flow in flows {
                    if flow.sink_type != "sql" {
                        continue;
                    }
                    
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

// ============================================================================
// RUSTCOLA098 - InterProceduralCommandInjectionRule
// ============================================================================

pub struct InterProceduralCommandInjectionRule {
    metadata: RuleMetadata,
}

impl InterProceduralCommandInjectionRule {
    pub fn new() -> Self {
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

        if let Ok(mut inter_analysis) = interprocedural::InterProceduralAnalysis::new(package) {
            if inter_analysis.analyze(package).is_ok() {
                let flows = inter_analysis.detect_inter_procedural_flows(package);
                
                let mut reported_functions: HashSet<String> = HashSet::new();
                
                for flow in flows {
                    if !flow.sink_type.contains("command") {
                        continue;
                    }
                    
                    let is_internal = flow.sink_function.contains("mir_extractor")
                        || flow.sink_function.contains("mir-extractor")
                        || flow.sink_function.contains("__")
                        || flow.source_function.contains("mir_extractor")
                        || flow.source_function.contains("mir-extractor");
                    if is_internal {
                        continue;
                    }
                    
                    if flow.sink_function.contains("test") && flow.sink_function.contains("::") {
                        if !flow.sink_function.starts_with("test_") {
                            continue;
                        }
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
                
                // Closure capture detection
                for closure in inter_analysis.closure_registry.get_all_closures() {
                    if reported_functions.contains(&closure.name) {
                        continue;
                    }
                    
                    let parent_func = package.functions.iter()
                        .find(|f| f.name == closure.parent_function);
                    
                    let closure_func = package.functions.iter()
                        .find(|f| f.name == closure.name);
                    
                    if let Some(closure_fn) = closure_func {
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
                        
                        let closure_has_sink = closure_fn.body.iter().any(|line| {
                            line.contains("Command::new") ||
                            line.contains("Command::") ||
                            line.contains("::spawn") ||
                            line.contains("::output") ||
                            line.contains("process::Command")
                        });
                        
                        let has_captures = !closure.captured_vars.is_empty() ||
                            closure_fn.body.iter().any(|line| {
                                line.contains("debug ") && line.contains("(*((*_1)")
                            });
                        
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
                
                // Direct closure scan fallback
                for function in &package.functions {
                    if !function.name.contains("::{closure#") {
                        continue;
                    }
                    
                    if reported_functions.contains(&function.name) {
                        continue;
                    }
                    
                    let body_str = function.body.join("\n");
                    
                    let has_command_sink = body_str.contains("Command::") ||
                        body_str.contains("::spawn") ||
                        body_str.contains("::output");
                    
                    if !has_command_sink {
                        continue;
                    }
                    
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
