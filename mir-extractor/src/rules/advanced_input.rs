//! Advanced input validation rules.
//!
//! Deep dataflow analysis for:
//! - ADV003/RUSTCOLA201: Insecure binary deserialization (bincode, postcard)
//! - ADV004/RUSTCOLA202: Regex catastrophic backtracking
//! - ADV008/RUSTCOLA203: Uncontrolled allocation size
//! - ADV009/RUSTCOLA204: Integer overflow on untrusted input

use std::collections::{HashMap, HashSet};

use crate::{
    interprocedural::InterProceduralAnalysis, AttackComplexity, AttackVector, Confidence,
    Exploitability, Finding, MirFunction, MirPackage, PrivilegesRequired, Rule, RuleMetadata,
    RuleOrigin, Severity, UserInteraction,
};

use super::advanced_utils::{
    detect_assignment, detect_const_string_assignment, detect_len_call, detect_len_comparison,
    detect_var_alias, extract_call_args, extract_const_literals, is_untrusted_source,
    pattern_is_high_risk, unescape_rust_literal, TaintTracker,
};

// ============================================================================
// RUSTCOLA201: Insecure Binary Deserialization (was ADV003)
// ============================================================================

/// Detects binary deserialization (bincode, postcard) on untrusted input without size checks.
pub struct InsecureBinaryDeserializationRule {
    metadata: RuleMetadata,
}

impl Default for InsecureBinaryDeserializationRule {
    fn default() -> Self {
        Self::new()
    }
}

impl InsecureBinaryDeserializationRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA201".to_string(),
                name: "insecure-binary-deserialization".to_string(),
                short_description: "Detects binary deserialization on untrusted input".to_string(),
                full_description: "Binary deserialization libraries like bincode and postcard \
                    can deserialize arbitrary data structures. When processing untrusted input \
                    without size validation, attackers can craft payloads that cause excessive \
                    memory allocation or trigger other vulnerabilities."
                    .to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: vec!["502".to_string()], // CWE-502: Deserialization of Untrusted Data
                fix_suggestion: Some(
                    "Validate input size before deserialization. Use deserialize_with_limit \
                    or check buffer length against a maximum before calling deserialize."
                        .to_string(),
                ),
                exploitability: Exploitability {
                    attack_vector: AttackVector::Network,
                    attack_complexity: AttackComplexity::Low,
                    privileges_required: PrivilegesRequired::None,
                    user_interaction: UserInteraction::None,
                },
            },
        }
    }

    const SINK_PATTERNS: &'static [&'static str] = &[
        "bincode::deserialize",
        "bincode::deserialize_from",
        "bincode::config::deserialize",
        "bincode::config::deserialize_from",
        "postcard::from_bytes",
        "postcard::from_bytes_cobs",
        "postcard::take_from_bytes",
        "postcard::take_from_bytes_cobs",
    ];
}

impl Rule for InsecureBinaryDeserializationRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &package.functions {
            let mir_text = func.body.join("\n");
            let mut tracker = TaintTracker::default();
            let mut pending_len_checks: HashMap<String, String> = HashMap::new();

            for line in mir_text.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Track taint sources
                if let Some(dest) = detect_assignment(trimmed) {
                    if is_untrusted_source(trimmed) {
                        tracker.mark_source(&dest, trimmed);
                    } else if let Some(source) = tracker.find_tainted_in_line(trimmed) {
                        tracker.mark_alias(&dest, &source);
                    }
                }

                // Track length checks as sanitization
                if let Some((len_var, src_var)) = detect_len_call(trimmed) {
                    if let Some(root) = tracker.taint_roots.get(&src_var).cloned() {
                        pending_len_checks.insert(len_var, root);
                    }
                }

                if let Some(len_var) = detect_len_comparison(trimmed) {
                    if let Some(root) = pending_len_checks.remove(&len_var) {
                        tracker.sanitize_root(&root);
                    }
                }

                // Check sinks
                if let Some(sink_name) = Self::SINK_PATTERNS.iter().find(|p| trimmed.contains(*p)) {
                    let args = extract_call_args(trimmed);
                    for arg in args {
                        if let Some(root) = tracker.taint_roots.get(&arg).cloned() {
                            if tracker.sanitized_roots.contains(&root) {
                                continue;
                            }

                            let mut message = format!(
                                "Insecure binary deserialization: untrusted data flows into `{}`",
                                sink_name
                            );
                            if let Some(origin) = tracker.sources.get(&root) {
                                message.push_str(&format!("\n  source: `{}`", origin));
                            }

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                confidence: Confidence::High,
                                message,
                                function: func.name.clone(),
                                function_signature: func.signature.clone(),
                                evidence: vec![trimmed.to_string()],
                                span: func.span.clone(),
                                exploitability: self.metadata.exploitability.clone(),
                                exploitability_score: self.metadata.exploitability.score(),
                                ..Default::default()
                            });
                            break;
                        }
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA202: Regex Catastrophic Backtracking (was ADV004)
// ============================================================================

/// Detects regex patterns with nested quantifiers that trigger catastrophic backtracking.
pub struct RegexBacktrackingDosRule {
    metadata: RuleMetadata,
}

impl Default for RegexBacktrackingDosRule {
    fn default() -> Self {
        Self::new()
    }
}

impl RegexBacktrackingDosRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA202".to_string(),
                name: "regex-backtracking-dos".to_string(),
                short_description: "Detects regex patterns vulnerable to catastrophic backtracking"
                    .to_string(),
                full_description: "Regex patterns with nested quantifiers like (a+)+ can cause \
                    exponential backtracking on certain inputs. This can be exploited for \
                    denial-of-service attacks (ReDoS) by sending specially crafted input."
                    .to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: vec!["1333".to_string()], // CWE-1333: Inefficient Regular Expression
                fix_suggestion: Some(
                    "Avoid nested quantifiers. Use atomic groups or possessive quantifiers. \
                    Consider using regex crate's built-in protections or set match limits."
                        .to_string(),
                ),
                exploitability: Exploitability {
                    attack_vector: AttackVector::Network,
                    attack_complexity: AttackComplexity::Low,
                    privileges_required: PrivilegesRequired::None,
                    user_interaction: UserInteraction::None,
                },
            },
        }
    }

    const SINK_PATTERNS: &'static [&'static str] = &[
        "regex::Regex::new",
        "regex::RegexSet::new",
        "regex::builders::RegexBuilder::new",
        "regex::RegexBuilder::new",
    ];
}

impl Rule for RegexBacktrackingDosRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &package.functions {
            let mir_text = func.body.join("\n");
            let mut const_strings: HashMap<String, String> = HashMap::new();
            let mut reported_lines: HashSet<String> = HashSet::new();

            for line in mir_text.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Track constant string assignments
                if let Some((var, literal)) = detect_const_string_assignment(trimmed) {
                    const_strings.insert(var, unescape_rust_literal(&literal));
                    continue;
                }

                // Track variable aliases
                if let Some((dest, src)) = detect_var_alias(trimmed) {
                    if let Some(value) = const_strings.get(&src).cloned() {
                        const_strings.insert(dest, value);
                    }
                }

                // Check for regex compilation
                if let Some(sink) = Self::SINK_PATTERNS.iter().find(|p| trimmed.contains(*p)) {
                    // Check inline literals
                    for literal in extract_const_literals(trimmed) {
                        let unescaped = unescape_rust_literal(&literal);
                        if pattern_is_high_risk(&unescaped) {
                            let key = format!("{}::{}", sink, trimmed.trim());
                            if reported_lines.insert(key) {
                                findings.push(self.create_finding(func, sink, trimmed, &unescaped));
                            }
                        }
                    }

                    // Check tracked variables
                    let args = extract_call_args(trimmed);
                    for arg in args {
                        if let Some(pattern) = const_strings.get(&arg).cloned() {
                            if pattern_is_high_risk(&pattern) {
                                let key = format!("{}::{}", sink, trimmed.trim());
                                if reported_lines.insert(key) {
                                    findings
                                        .push(self.create_finding(func, sink, trimmed, &pattern));
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

impl RegexBacktrackingDosRule {
    fn create_finding(&self, func: &MirFunction, sink: &str, line: &str, pattern: &str) -> Finding {
        let display = if pattern.len() > 60 {
            format!("{}...", &pattern[..57])
        } else {
            pattern.to_string()
        };

        Finding {
            rule_id: self.metadata.id.clone(),
            rule_name: self.metadata.name.clone(),
            severity: self.metadata.default_severity,
            confidence: Confidence::Medium,
            message: format!(
                "Potential regex DoS: pattern `{}` compiled via `{}` may trigger catastrophic backtracking",
                display, sink
            ),
            function: func.name.clone(),
            function_signature: func.signature.clone(),
            evidence: vec![line.trim().to_string()],
            span: func.span.clone(),
            exploitability: self.metadata.exploitability.clone(),
            exploitability_score: self.metadata.exploitability.score(),
            ..Default::default()
        }
    }
}

// ============================================================================
// RUSTCOLA203: Uncontrolled Allocation Size (was ADV008)
// ============================================================================

/// Detects allocations sized from untrusted sources without upper bound validation.
pub struct UncontrolledAllocationSizeRule {
    metadata: RuleMetadata,
}

impl Default for UncontrolledAllocationSizeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl UncontrolledAllocationSizeRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA203".to_string(),
                name: "uncontrolled-allocation-size".to_string(),
                short_description: "Detects allocations sized from untrusted sources".to_string(),
                full_description: "Using untrusted input to control allocation size without \
                    validation can lead to denial-of-service through memory exhaustion. \
                    Attackers can send large values to trigger excessive memory allocation."
                    .to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: vec!["789".to_string()], // CWE-789: Memory Allocation with Excessive Size
                fix_suggestion: Some(
                    "Validate allocation size against a reasonable maximum before allocating. \
                    Use min() or clamp() to enforce upper bounds."
                        .to_string(),
                ),
                exploitability: Exploitability {
                    attack_vector: AttackVector::Network,
                    attack_complexity: AttackComplexity::Low,
                    privileges_required: PrivilegesRequired::None,
                    user_interaction: UserInteraction::None,
                },
            },
        }
    }

    const ALLOC_PATTERNS: &'static [&'static str] = &[
        "Vec::with_capacity",
        "vec::with_capacity",
        "String::with_capacity",
        "string::with_capacity",
        "HashMap::with_capacity",
        "hashmap::with_capacity",
        "HashSet::with_capacity",
        "VecDeque::with_capacity",
        "::reserve",
        "::reserve_exact",
        "alloc::alloc",
        "alloc::alloc_zeroed",
        "alloc::realloc",
        "Box::new_uninit_slice",
        "vec![",
    ];
}

impl Rule for UncontrolledAllocationSizeRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &package.functions {
            let mir_text = func.body.join("\n");
            let mut tracker = TaintTracker::default();
            let mut checked_vars: HashSet<String> = HashSet::new();

            for line in mir_text.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Track taint sources
                if let Some(dest) = detect_assignment(trimmed) {
                    if is_untrusted_source(trimmed) {
                        tracker.mark_source(&dest, trimmed);
                    } else if let Some(source) = tracker.find_tainted_in_line(trimmed) {
                        tracker.mark_alias(&dest, &source);
                    }
                }

                // Detect bounds checks (min, clamp, comparisons)
                if trimmed.contains("::min(") || trimmed.contains("::clamp(") {
                    let args = extract_call_args(trimmed);
                    for arg in &args {
                        checked_vars.insert(arg.clone());
                        if let Some(root) = tracker.taint_roots.get(arg).cloned() {
                            tracker.sanitize_root(&root);
                        }
                    }
                }

                // Check allocation sinks
                if let Some(sink) = Self::ALLOC_PATTERNS.iter().find(|p| trimmed.contains(*p)) {
                    let args = extract_call_args(trimmed);
                    for arg in args {
                        if checked_vars.contains(&arg) {
                            continue;
                        }

                        if let Some(root) = tracker.taint_roots.get(&arg).cloned() {
                            if tracker.sanitized_roots.contains(&root) {
                                continue;
                            }

                            let mut message = format!(
                                "Uncontrolled allocation size: untrusted value flows into `{}`",
                                sink
                            );
                            if let Some(origin) = tracker.sources.get(&root) {
                                message.push_str(&format!("\n  source: `{}`", origin));
                            }

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                confidence: Confidence::High,
                                message,
                                function: func.name.clone(),
                                function_signature: func.signature.clone(),
                                evidence: vec![trimmed.to_string()],
                                span: func.span.clone(),
                                exploitability: self.metadata.exploitability.clone(),
                                exploitability_score: self.metadata.exploitability.score(),
                                ..Default::default()
                            });
                            break;
                        }
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA204: Integer Overflow on Untrusted Input (was ADV009)
// ============================================================================

/// Detects arithmetic operations on untrusted input without overflow protection.
pub struct IntegerOverflowRule {
    metadata: RuleMetadata,
}

impl Default for IntegerOverflowRule {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegerOverflowRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA204".to_string(),
                name: "integer-overflow-untrusted".to_string(),
                short_description:
                    "Detects arithmetic on untrusted input without overflow protection".to_string(),
                full_description: "Arithmetic operations on values derived from untrusted sources \
                    can overflow in release builds. This can lead to incorrect calculations, \
                    buffer overflows, or denial of service."
                    .to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: vec!["190".to_string()], // CWE-190: Integer Overflow
                fix_suggestion: Some(
                    "Use checked_*, saturating_*, or wrapping_* methods for arithmetic on \
                    untrusted input. Validate input ranges before arithmetic operations."
                        .to_string(),
                ),
                exploitability: Exploitability {
                    attack_vector: AttackVector::Network,
                    attack_complexity: AttackComplexity::High,
                    privileges_required: PrivilegesRequired::None,
                    user_interaction: UserInteraction::None,
                },
            },
        }
    }

    const UNSAFE_OPS: &'static [(&'static str, &'static str)] = &[
        ("Add(", "addition"),
        ("Sub(", "subtraction"),
        ("Mul(", "multiplication"),
    ];

    const SAFE_METHODS: &'static [&'static str] = &[
        "checked_add",
        "checked_sub",
        "checked_mul",
        "checked_div",
        "saturating_add",
        "saturating_sub",
        "saturating_mul",
        "wrapping_add",
        "wrapping_sub",
        "wrapping_mul",
        "overflowing_add",
        "overflowing_sub",
        "overflowing_mul",
    ];
}

impl Rule for IntegerOverflowRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &package.functions {
            let mir_text = func.body.join("\n");
            let mut tracker = TaintTracker::default();
            let mut safe_vars: HashSet<String> = HashSet::new();

            for line in mir_text.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Track taint sources
                if let Some(dest) = detect_assignment(trimmed) {
                    if is_untrusted_source(trimmed) {
                        tracker.mark_source(&dest, trimmed);
                    } else if let Some(source) = tracker.find_tainted_in_line(trimmed) {
                        tracker.mark_alias(&dest, &source);
                    }

                    // Track safe arithmetic results
                    if Self::SAFE_METHODS.iter().any(|m| trimmed.contains(m)) {
                        safe_vars.insert(dest);
                    }
                }

                // Check for unsafe arithmetic operations
                for (op_pattern, op_name) in Self::UNSAFE_OPS {
                    if trimmed.contains(op_pattern) {
                        // Skip if result of safe method
                        if Self::SAFE_METHODS.iter().any(|m| trimmed.contains(m)) {
                            continue;
                        }

                        let args = extract_call_args(trimmed);
                        for arg in args {
                            if safe_vars.contains(&arg) {
                                continue;
                            }

                            if let Some(root) = tracker.taint_roots.get(&arg).cloned() {
                                if tracker.sanitized_roots.contains(&root) {
                                    continue;
                                }

                                let mut message = format!(
                                    "Potential integer overflow: untrusted value in {} without overflow protection",
                                    op_name
                                );
                                if let Some(origin) = tracker.sources.get(&root) {
                                    message.push_str(&format!("\n  source: `{}`", origin));
                                }

                                findings.push(Finding {
                                    rule_id: self.metadata.id.clone(),
                                    rule_name: self.metadata.name.clone(),
                                    severity: self.metadata.default_severity,
                                    confidence: Confidence::Medium,
                                    message,
                                    function: func.name.clone(),
                                    function_signature: func.signature.clone(),
                                    evidence: vec![trimmed.to_string()],
                                    span: func.span.clone(),
                                    exploitability: self.metadata.exploitability.clone(),
                                    exploitability_score: self.metadata.exploitability.score(),
                                    ..Default::default()
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// Registration
// ============================================================================

/// Register all advanced input rules with the rule engine.
pub fn register_advanced_input_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(InsecureBinaryDeserializationRule::new()));
    engine.register_rule(Box::new(RegexBacktrackingDosRule::new()));
    engine.register_rule(Box::new(UncontrolledAllocationSizeRule::new()));
    engine.register_rule(Box::new(IntegerOverflowRule::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_deser_metadata() {
        let rule = InsecureBinaryDeserializationRule::new();
        assert_eq!(rule.metadata().id, "RUSTCOLA201");
    }

    #[test]
    fn test_regex_dos_metadata() {
        let rule = RegexBacktrackingDosRule::new();
        assert_eq!(rule.metadata().id, "RUSTCOLA202");
    }

    #[test]
    fn test_allocation_size_metadata() {
        let rule = UncontrolledAllocationSizeRule::new();
        assert_eq!(rule.metadata().id, "RUSTCOLA203");
    }

    #[test]
    fn test_integer_overflow_metadata() {
        let rule = IntegerOverflowRule::new();
        assert_eq!(rule.metadata().id, "RUSTCOLA204");
    }
}
