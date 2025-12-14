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
//! - Unchecked index (RUSTCOLA050)

use std::collections::HashSet;

use crate::dataflow::taint::TaintAnalysis;
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

/// Register all injection rules with the rule engine.
pub fn register_injection_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(UntrustedEnvInputRule::new()));
    engine.register_rule(Box::new(CommandInjectionRiskRule::new()));
    engine.register_rule(Box::new(CommandArgConcatenationRule::new()));
    engine.register_rule(Box::new(LogInjectionRule::new()));
}
