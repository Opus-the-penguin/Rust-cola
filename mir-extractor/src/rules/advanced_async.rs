//! Advanced async and web rules.
//!
//! Deep dataflow analysis for:
//! - ADV005/RUSTCOLA205: Template/XSS injection
//! - ADV006/RUSTCOLA206: Non-Send types across async boundaries
//! - ADV007/RUSTCOLA207: Tracing span guards held across await

use std::collections::{HashMap, HashSet};

use crate::{
    AttackComplexity, AttackVector, Confidence, Exploitability, Finding, MirPackage,
    PrivilegesRequired, Rule, RuleMetadata, RuleOrigin, Severity, UserInteraction,
    interprocedural::InterProceduralAnalysis,
};

use super::advanced_utils::{
    contains_var, detect_assignment, detect_drop_calls, detect_storage_dead_vars,
    detect_var_alias, extract_call_args, TaintTracker,
};

// ============================================================================
// RUSTCOLA205: Template/XSS Injection (was ADV005)
// ============================================================================

/// Detects template/HTML responses built from unescaped user input.
pub struct TemplateInjectionRule {
    metadata: RuleMetadata,
}

impl Default for TemplateInjectionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateInjectionRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA205".to_string(),
                name: "template-injection".to_string(),
                short_description: "Detects unescaped user input in HTML responses".to_string(),
                full_description: "User input included in HTML responses without proper escaping \
                    can lead to Cross-Site Scripting (XSS) attacks. Attackers can inject \
                    malicious JavaScript that executes in victims' browsers."
                    .to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: vec!["79".to_string()], // CWE-79: XSS
                fix_suggestion: Some(
                    "Use HTML escaping functions like html_escape::encode_safe() or template \
                    engines with auto-escaping. Consider using ammonia for HTML sanitization."
                        .to_string(),
                ),
                exploitability: Exploitability {
                    attack_vector: AttackVector::Network,
                    attack_complexity: AttackComplexity::Low,
                    privileges_required: PrivilegesRequired::None,
                    user_interaction: UserInteraction::Required, // User must visit page
                },
            },
        }
    }

    const UNTRUSTED_PATTERNS: &'static [&'static str] = &[
        "env::var",
        "env::var_os",
        "env::args",
        "std::env::var",
        "std::env::args",
        "stdin",
        "TcpStream",
        "read_to_string",
        "read_to_end",
        "axum::extract",
        "warp::filters::path::param",
        "warp::filters::query::query",
        "Request::uri",
        "Request::body",
        "hyper::body::to_bytes",
    ];

    const SANITIZER_PATTERNS: &'static [&'static str] = &[
        "html_escape::encode_safe",
        "html_escape::encode_double_quoted_attribute",
        "html_escape::encode_single_quoted_attribute",
        "ammonia::clean",
        "maud::Escaped",
    ];

    const SINK_PATTERNS: &'static [&'static str] = &[
        "warp::reply::html",
        "axum::response::Html::from",
        "axum::response::Html::new",
        "rocket::response::content::Html::new",
        "rocket::response::content::Html::from",
        "HttpResponse::body",
        "HttpResponse::Ok",
    ];
}

impl Rule for TemplateInjectionRule {
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

            for line in mir_text.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                if let Some(dest) = detect_assignment(trimmed) {
                    if Self::UNTRUSTED_PATTERNS.iter().any(|p| trimmed.contains(p)) {
                        tracker.mark_source(&dest, trimmed);
                        continue;
                    }

                    // Check for sanitization
                    if Self::SANITIZER_PATTERNS.iter().any(|p| trimmed.contains(p)) {
                        if let Some(source) = tracker.find_tainted_in_line(trimmed) {
                            if let Some(root) = tracker.taint_roots.get(&source).cloned() {
                                tracker.sanitize_root(&root);
                            }
                        }
                        continue;
                    }

                    if let Some(source) = tracker.find_tainted_in_line(trimmed) {
                        tracker.mark_alias(&dest, &source);
                    }
                }

                // Check sinks
                if let Some(sink) = Self::SINK_PATTERNS.iter().find(|p| trimmed.contains(*p)) {
                    let args = extract_call_args(trimmed);
                    for arg in args {
                        if let Some(root) = tracker.taint_roots.get(&arg).cloned() {
                            if tracker.sanitized_roots.contains(&root) {
                                continue;
                            }

                            let mut message = format!(
                                "Possible template injection: unescaped input flows into `{}`",
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
// RUSTCOLA206: Non-Send Types Across Async Boundaries (was ADV006)
// ============================================================================

/// Detects non-Send types captured by multi-threaded async executors.
pub struct UnsafeSendAcrossAsyncBoundaryRule {
    metadata: RuleMetadata,
}

impl Default for UnsafeSendAcrossAsyncBoundaryRule {
    fn default() -> Self {
        Self::new()
    }
}

impl UnsafeSendAcrossAsyncBoundaryRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA206".to_string(),
                name: "unsafe-send-across-async".to_string(),
                short_description: "Detects non-Send types captured in spawned tasks".to_string(),
                full_description: "Types like Rc<T> and RefCell<T> are not thread-safe (non-Send). \
                    When captured by tokio::spawn or similar multi-threaded executors, they can \
                    cause undefined behavior if accessed from multiple threads."
                    .to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: vec!["362".to_string(), "366".to_string()], // Race Condition, Race Condition Within Thread
                fix_suggestion: Some(
                    "Use Arc<T> instead of Rc<T> and Arc<Mutex<T>> instead of RefCell<T>. \
                    Alternatively, use spawn_local() for single-threaded execution."
                        .to_string(),
                ),
                exploitability: Exploitability {
                    attack_vector: AttackVector::Local,
                    attack_complexity: AttackComplexity::High,
                    privileges_required: PrivilegesRequired::None,
                    user_interaction: UserInteraction::None,
                },
            },
        }
    }

    const NON_SEND_PATTERNS: &'static [&'static str] = &[
        "alloc::rc::Rc",
        "std::rc::Rc",
        "core::cell::RefCell",
        "std::cell::RefCell",
        "alloc::rc::Weak",
        "std::rc::Weak",
    ];

    const SAFE_PATTERNS: &'static [&'static str] = &[
        "std::sync::Arc",
        "alloc::sync::Arc",
        "std::sync::Mutex",
        "tokio::sync::Mutex",
    ];

    const SPAWN_PATTERNS: &'static [&'static str] = &[
        "tokio::spawn",
        "tokio::task::spawn",
        "tokio::task::spawn_blocking",
        "async_std::task::spawn",
        "async_std::task::spawn_blocking",
        "smol::spawn",
        "futures::executor::ThreadPool::spawn",
        "std::thread::spawn",
    ];

    const SPAWN_LOCAL_PATTERNS: &'static [&'static str] = &[
        "tokio::task::spawn_local",
        "async_std::task::spawn_local",
        "smol::spawn_local",
        "futures::task::SpawnExt::spawn_local",
    ];
}

impl Rule for UnsafeSendAcrossAsyncBoundaryRule {
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
            let mut roots: HashMap<String, String> = HashMap::new();
            let mut unsafe_roots: HashSet<String> = HashSet::new();
            let mut safe_roots: HashSet<String> = HashSet::new();
            let mut sources: HashMap<String, String> = HashMap::new();

            for line in mir_text.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                if let Some(dest) = detect_assignment(trimmed) {
                    roots.remove(&dest);

                    if Self::NON_SEND_PATTERNS.iter().any(|p| trimmed.contains(p)) {
                        roots.insert(dest.clone(), dest.clone());
                        unsafe_roots.insert(dest.clone());
                        safe_roots.remove(&dest);
                        sources.entry(dest).or_insert_with(|| trimmed.to_string());
                    } else if Self::SAFE_PATTERNS.iter().any(|p| trimmed.contains(p)) {
                        roots.insert(dest.clone(), dest.clone());
                        safe_roots.insert(dest.clone());
                        unsafe_roots.remove(&dest);
                    } else if let Some(source) = roots.keys().find(|v| contains_var(trimmed, v)).cloned() {
                        if let Some(root) = roots.get(&source).cloned() {
                            roots.insert(dest, root);
                        }
                    }
                }

                // Check spawn calls
                if let Some(spawn) = Self::SPAWN_PATTERNS.iter().find(|p| trimmed.contains(*p)) {
                    // Skip spawn_local
                    if Self::SPAWN_LOCAL_PATTERNS.iter().any(|p| trimmed.contains(p)) {
                        continue;
                    }

                    let args = extract_call_args(trimmed);
                    for arg in args {
                        if let Some(root) = roots.get(&arg).cloned() {
                            if safe_roots.contains(&root) {
                                continue;
                            }
                            if !unsafe_roots.contains(&root) {
                                continue;
                            }

                            let mut message = format!(
                                "Non-Send type captured in `{}` may cross thread boundary",
                                spawn
                            );
                            if let Some(origin) = sources.get(&root) {
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
// RUSTCOLA207: Span Guard Held Across Await (was ADV007)
// ============================================================================

/// Detects tracing span guards held across await points.
pub struct AwaitSpanGuardRule {
    metadata: RuleMetadata,
}

impl Default for AwaitSpanGuardRule {
    fn default() -> Self {
        Self::new()
    }
}

impl AwaitSpanGuardRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA207".to_string(),
                name: "span-guard-across-await".to_string(),
                short_description: "Detects tracing span guards held across await points"
                    .to_string(),
                full_description: "Tracing span guards (from span.enter()) should not be held \
                    across await points. When a task is suspended, the span context may be \
                    incorrect when resumed, leading to confusing or incorrect trace data."
                    .to_string(),
                help_uri: None,
                default_severity: Severity::Low,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: vec!["664".to_string()], // CWE-664: Improper Control of a Resource
                fix_suggestion: Some(
                    "Use span.in_scope(|| async { ... }) instead of let _guard = span.enter(). \
                    Or use tracing::Instrument trait: future.instrument(span).await"
                        .to_string(),
                ),
                exploitability: Exploitability {
                    attack_vector: AttackVector::Local,
                    attack_complexity: AttackComplexity::High,
                    privileges_required: PrivilegesRequired::Low,
                    user_interaction: UserInteraction::None,
                },
            },
        }
    }

    const GUARD_PATTERNS: &'static [&'static str] = &[
        "tracing::Span::enter",
        "tracing::span::Span::enter",
        "tracing::dispatcher::DefaultGuard::new",
    ];
}

#[derive(Clone)]
struct GuardState {
    origin: String,
    count: usize,
}

impl Rule for AwaitSpanGuardRule {
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
            let mut var_to_root: HashMap<String, String> = HashMap::new();
            let mut guard_states: HashMap<String, GuardState> = HashMap::new();
            let mut reported: HashSet<String> = HashSet::new();

            for line in mir_text.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Handle aliases
                if let Some((dest, source)) = detect_var_alias(trimmed) {
                    if let Some(root) = var_to_root.remove(&dest) {
                        if let Some(state) = guard_states.get_mut(&root) {
                            if state.count > 1 {
                                state.count -= 1;
                            } else {
                                guard_states.remove(&root);
                            }
                        }
                    }
                    if let Some(root) = var_to_root.get(&source).cloned() {
                        var_to_root.insert(dest, root.clone());
                        if let Some(state) = guard_states.get_mut(&root) {
                            state.count += 1;
                        }
                    }
                    continue;
                }

                // Detect guard creation
                if let Some(dest) = detect_assignment(trimmed) {
                    if Self::GUARD_PATTERNS.iter().any(|p| trimmed.contains(p)) {
                        var_to_root.insert(dest.clone(), dest.clone());
                        guard_states.insert(
                            dest,
                            GuardState {
                                origin: trimmed.to_string(),
                                count: 1,
                            },
                        );
                    }
                }

                // Handle drops
                for var in detect_drop_calls(trimmed) {
                    if let Some(root) = var_to_root.remove(&var) {
                        if let Some(state) = guard_states.get_mut(&root) {
                            if state.count > 1 {
                                state.count -= 1;
                            } else {
                                guard_states.remove(&root);
                            }
                        }
                    }
                }

                for var in detect_storage_dead_vars(trimmed) {
                    if let Some(root) = var_to_root.remove(&var) {
                        if let Some(state) = guard_states.get_mut(&root) {
                            if state.count > 1 {
                                state.count -= 1;
                            } else {
                                guard_states.remove(&root);
                            }
                        }
                    }
                }

                // Check for await with active guards
                if trimmed.contains(".await") || trimmed.contains("Await") || trimmed.contains("await ") {
                    for (root, state) in guard_states.iter() {
                        let key = format!("{}::{}", root, trimmed.trim());
                        if !reported.insert(key) {
                            continue;
                        }

                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            confidence: Confidence::Medium,
                            message: format!(
                                "Span guard `{}` held across await point\n  created: `{}`",
                                root,
                                state.origin
                            ),
                            function: func.name.clone(),
                            function_signature: func.signature.clone(),
                            evidence: vec![trimmed.to_string()],
                            span: func.span.clone(),
                            exploitability: self.metadata.exploitability.clone(),
                            exploitability_score: self.metadata.exploitability.score(),
                            ..Default::default()
                        });
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

/// Register all advanced async/web rules with the rule engine.
pub fn register_advanced_async_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(TemplateInjectionRule::new()));
    engine.register_rule(Box::new(UnsafeSendAcrossAsyncBoundaryRule::new()));
    engine.register_rule(Box::new(AwaitSpanGuardRule::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_injection_metadata() {
        let rule = TemplateInjectionRule::new();
        assert_eq!(rule.metadata().id, "RUSTCOLA205");
    }

    #[test]
    fn test_unsafe_send_metadata() {
        let rule = UnsafeSendAcrossAsyncBoundaryRule::new();
        assert_eq!(rule.metadata().id, "RUSTCOLA206");
    }

    #[test]
    fn test_span_guard_metadata() {
        let rule = AwaitSpanGuardRule::new();
        assert_eq!(rule.metadata().id, "RUSTCOLA207");
    }
}
