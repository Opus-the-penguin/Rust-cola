//! Injection vulnerability rules.
//!
//! Rules detecting injection vulnerabilities:
//! - Untrusted env input (RUSTCOLA006)
//! - Command injection (RUSTCOLA007, RUSTCOLA098)
//! - Command argument concatenation (RUSTCOLA019)
//! - SQL injection (RUSTCOLA087)
//! - Path traversal (RUSTCOLA086)
//! - SSRF (RUSTCOLA088)
//! - Log injection (RUSTCOLA076)
//! - Regex injection (RUSTCOLA079)
//! - Unchecked index (RUSTCOLA050)

use crate::dataflow::taint::TaintAnalysis;
use crate::rules::utils::command_rule_should_skip;
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

/// Register all injection rules with the rule engine.
pub fn register_injection_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(UntrustedEnvInputRule::new()));
    engine.register_rule(Box::new(CommandInjectionRiskRule::new()));
    engine.register_rule(Box::new(CommandArgConcatenationRule::new()));
}
