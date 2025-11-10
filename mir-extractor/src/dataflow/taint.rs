// Taint tracking infrastructure for dataflow analysis
// Tracks untrusted data from sources (env vars, network) to sinks (Command, fs)

use std::collections::{HashMap, HashSet};
use crate::{MirFunction, Finding, RuleMetadata, Severity, SourceSpan};
use super::MirDataflow;

/// Kinds of taint sources (where untrusted data originates)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSourceKind {
    EnvironmentVariable,    // env::var, env::var_os, env::vars_os
    NetworkInput,           // TcpStream::read, HttpRequest::body (future)
    FileInput,              // fs::read, File::read (future)
    CommandOutput,          // Command::output (future)
    UserInput,              // stdin, readline (future)
}

/// Kinds of taint sinks (security-sensitive operations)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSinkKind {
    CommandExecution,       // Command::new, Command::arg
    FileSystemOp,           // fs::write, fs::remove, Path::join
    SqlQuery,               // diesel::sql_query, sqlx::query (future)
    RegexCompile,           // Regex::new (future)
    NetworkWrite,           // TcpStream::write (future)
}

/// A taint source instance
#[derive(Debug, Clone)]
pub struct TaintSource {
    pub kind: TaintSourceKind,
    pub variable: String,       // MIR local (_1, _2, etc.)
    pub source_line: String,    // Original code line for reporting
    pub confidence: f32,        // 0.0-1.0, how certain we are this is tainted
}

/// A taint sink instance
#[derive(Debug, Clone)]
pub struct TaintSink {
    pub kind: TaintSinkKind,
    pub variable: String,       // MIR local that reaches sink
    pub sink_line: String,      // Original code line for reporting
    pub severity: Severity,
}

/// Registry of patterns that identify taint sources
pub struct SourceRegistry {
    patterns: Vec<SourcePattern>,
}

struct SourcePattern {
    kind: TaintSourceKind,
    function_patterns: Vec<&'static str>,
    severity: Severity,
}

impl SourceRegistry {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                SourcePattern {
                    kind: TaintSourceKind::EnvironmentVariable,
                    function_patterns: vec![
                        "std::env::var(",
                        "std::env::var_os(",
                        "std::env::vars(",
                        "std::env::vars_os(",
                        "core::env::var(",
                        "core::env::var_os(",
                    ],
                    severity: Severity::Medium,
                },
                // Future: Add NetworkInput, FileInput, etc.
            ],
        }
    }

    /// Scan function for taint sources and return detected sources
    pub fn detect_sources(&self, function: &MirFunction) -> Vec<TaintSource> {
        let mut sources = Vec::new();

        for line in &function.body {
            for pattern in &self.patterns {
                for func_pattern in &pattern.function_patterns {
                    if line.contains(func_pattern) {
                        // Extract the target variable (left side of assignment)
                        if let Some(target) = extract_assignment_target(line) {
                            sources.push(TaintSource {
                                kind: pattern.kind.clone(),
                                variable: target,
                                source_line: line.trim().to_string(),
                                confidence: 1.0,
                            });
                        }
                    }
                }
            }
        }

        sources
    }
}

/// Registry of patterns that identify taint sinks
pub struct SinkRegistry {
    patterns: Vec<SinkPattern>,
}

struct SinkPattern {
    kind: TaintSinkKind,
    function_patterns: Vec<&'static str>,
    severity: Severity,
}

impl SinkRegistry {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                SinkPattern {
                    kind: TaintSinkKind::CommandExecution,
                    function_patterns: vec![
                        "std::process::Command::new(",
                        "std::process::Command::arg(",
                        "std::process::Command::args(",
                    ],
                    severity: Severity::High,
                },
                SinkPattern {
                    kind: TaintSinkKind::FileSystemOp,
                    function_patterns: vec![
                        "std::fs::write(",
                        "std::fs::remove_file(",
                        "std::fs::remove_dir_all(",
                        "std::path::Path::join(",
                        "std::path::PathBuf::push(",
                    ],
                    severity: Severity::Medium,
                },
                // Future: Add SqlQuery, RegexCompile, etc.
            ],
        }
    }

    /// Scan function for taint sinks that use specific variables
    pub fn detect_sinks(&self, function: &MirFunction, tainted_vars: &HashSet<String>) -> Vec<TaintSink> {
        let mut sinks = Vec::new();

        for line in &function.body {
            for pattern in &self.patterns {
                for func_pattern in &pattern.function_patterns {
                    if line.contains(func_pattern) {
                        // Extract variables used in this sink
                        let used_vars = super::extract_variables(line);
                        
                        // Check if any tainted variable is used
                        for var in used_vars {
                            if tainted_vars.contains(&var) {
                                sinks.push(TaintSink {
                                    kind: pattern.kind.clone(),
                                    variable: var,
                                    sink_line: line.trim().to_string(),
                                    severity: pattern.severity,
                                });
                                break; // Only report once per line
                            }
                        }
                    }
                }
            }
        }

        sinks
    }
}

/// Registry of patterns that sanitize tainted data
pub struct SanitizerRegistry {
    patterns: Vec<SanitizerPattern>,
}

struct SanitizerPattern {
    function_patterns: Vec<&'static str>,
    sanitizes: Vec<TaintSinkKind>,  // Which sinks does this sanitize for?
}

impl SanitizerRegistry {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                SanitizerPattern {
                    // .parse::<T>() type conversions sanitize for most uses
                    function_patterns: vec![
                        ".parse::<",
                        "::parse(",
                    ],
                    sanitizes: vec![
                        TaintSinkKind::CommandExecution,
                        TaintSinkKind::FileSystemOp,
                    ],
                },
                SanitizerPattern {
                    // .chars().all() validation patterns
                    function_patterns: vec![
                        ".chars().all(",
                        "::chars().all(",
                    ],
                    sanitizes: vec![
                        TaintSinkKind::CommandExecution,
                        TaintSinkKind::FileSystemOp,
                    ],
                },
                // Future: Add regex validation, canonicalization, etc.
            ],
        }
    }

    /// Check if a variable is sanitized before reaching a sink
    /// Returns true if we can prove sanitization occurred
    pub fn is_sanitized(&self, _function: &MirFunction, _var: &str, _sink_kind: &TaintSinkKind) -> bool {
        // TODO: Implement control flow analysis to check domination
        // For Phase 1, conservatively return false (report all flows)
        false
    }
}

/// Main taint analysis engine
pub struct TaintAnalysis {
    source_registry: SourceRegistry,
    sink_registry: SinkRegistry,
    sanitizer_registry: SanitizerRegistry,
}

impl TaintAnalysis {
    pub fn new() -> Self {
        Self {
            source_registry: SourceRegistry::new(),
            sink_registry: SinkRegistry::new(),
            sanitizer_registry: SanitizerRegistry::new(),
        }
    }

    /// Perform taint analysis on a function
    /// Returns (tainted variables, detected flows)
    pub fn analyze(&self, function: &MirFunction) -> (HashSet<String>, Vec<TaintFlow>) {
        // Step 1: Detect taint sources
        let sources = self.source_registry.detect_sources(function);
        
        if sources.is_empty() {
            return (HashSet::new(), Vec::new());
        }

        // Step 2: Propagate taint through dataflow
        let dataflow = MirDataflow::new(function);
        
        let mut tainted_vars = HashSet::new();
        for source in &sources {
            tainted_vars.insert(source.variable.clone());
        }

        // Use existing taint_from to propagate
        let tainted = dataflow.taint_from(|assignment| {
            sources.iter().any(|src| assignment.target == src.variable)
        });
        tainted_vars.extend(tainted);

        // Step 3: Detect sinks that use tainted data
        let sinks = self.sink_registry.detect_sinks(function, &tainted_vars);

        // Step 4: Create flows for each source→sink pair
        let mut flows = Vec::new();
        for sink in sinks {
            // Find which source(s) contributed to this sink
            for source in &sources {
                if tainted_vars.contains(&sink.variable) {
                    // Check if sanitized (future: actual control flow analysis)
                    let sanitized = self.sanitizer_registry.is_sanitized(
                        function,
                        &sink.variable,
                        &sink.kind,
                    );

                    flows.push(TaintFlow {
                        source: source.clone(),
                        sink: sink.clone(),
                        sanitized,
                        propagation_path: vec![],  // TODO: Track actual path
                    });
                    break; // One source per sink for now
                }
            }
        }

        (tainted_vars, flows)
    }
}

/// Represents a complete taint flow from source to sink
#[derive(Debug, Clone)]
pub struct TaintFlow {
    pub source: TaintSource,
    pub sink: TaintSink,
    pub sanitized: bool,
    pub propagation_path: Vec<String>,  // Intermediate steps (for debugging)
}

impl TaintFlow {
    /// Convert this taint flow into a Finding for reporting
    pub fn to_finding(&self, rule_metadata: &RuleMetadata, function_name: &str, function_sig: &str, span: Option<SourceSpan>) -> Finding {
        let message = format!(
            "Tainted data from {} flows to {}{}",
            format_source_kind(&self.source.kind),
            format_sink_kind(&self.sink.kind),
            if self.sanitized { " (sanitized)" } else { " without sanitization" }
        );

        let evidence = vec![
            format!("Source: {}", self.source.source_line),
            format!("Sink: {}", self.sink.sink_line),
        ];

        Finding {
            rule_id: rule_metadata.id.clone(),
            rule_name: rule_metadata.name.clone(),
            severity: if self.sanitized { Severity::Low } else { self.sink.severity },
            message,
            function: function_name.to_string(),
            function_signature: function_sig.to_string(),
            evidence,
            span,
        }
    }
}

// Helper functions

fn extract_assignment_target(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if let Some(eq_pos) = trimmed.find('=') {
        let lhs = trimmed[..eq_pos].trim();
        // Handle simple case: "_1 = ..."
        if lhs.starts_with('_') && lhs.chars().skip(1).all(|c| c.is_ascii_digit()) {
            return Some(lhs.to_string());
        }
        // Handle tuple destructuring: "(_1, _2) = ..."
        if lhs.starts_with('(') && lhs.ends_with(')') {
            let inner = &lhs[1..lhs.len()-1];
            // Return first variable in tuple for simplicity
            if let Some(first) = inner.split(',').next() {
                let var = first.trim();
                if var.starts_with('_') {
                    return Some(var.to_string());
                }
            }
        }
    }
    None
}

fn format_source_kind(kind: &TaintSourceKind) -> &'static str {
    match kind {
        TaintSourceKind::EnvironmentVariable => "environment variable",
        TaintSourceKind::NetworkInput => "network input",
        TaintSourceKind::FileInput => "file input",
        TaintSourceKind::CommandOutput => "command output",
        TaintSourceKind::UserInput => "user input",
    }
}

fn format_sink_kind(kind: &TaintSinkKind) -> &'static str {
    match kind {
        TaintSinkKind::CommandExecution => "command execution",
        TaintSinkKind::FileSystemOp => "file system operation",
        TaintSinkKind::SqlQuery => "SQL query",
        TaintSinkKind::RegexCompile => "regex compilation",
        TaintSinkKind::NetworkWrite => "network write",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_function(lines: &[&str]) -> MirFunction {
        MirFunction {
            name: "test_fn".to_string(),
            signature: "fn test_fn()".to_string(),
            body: lines.iter().map(|l| l.to_string()).collect(),
            span: None,
            ..Default::default()
        }
    }

    #[test]
    fn detects_env_var_source() {
        let func = make_function(&[
            "_1 = std::env::var(move _2);",
        ]);
        
        let registry = SourceRegistry::new();
        let sources = registry.detect_sources(&func);
        
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].kind, TaintSourceKind::EnvironmentVariable);
        assert_eq!(sources[0].variable, "_1");
    }

    #[test]
    fn detects_command_sink() {
        let func = make_function(&[
            "_1 = std::env::var(move _2);",
            "_3 = std::process::Command::arg(move _1);",
        ]);
        
        let mut tainted = HashSet::new();
        tainted.insert("_1".to_string());
        
        let registry = SinkRegistry::new();
        let sinks = registry.detect_sinks(&func, &tainted);
        
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0].kind, TaintSinkKind::CommandExecution);
    }

    #[test]
    fn full_taint_analysis() {
        let func = make_function(&[
            "_1 = std::env::var(move _2);",
            "_3 = copy _1;",
            "_4 = std::process::Command::arg(move _3);",
        ]);
        
        let analysis = TaintAnalysis::new();
        let (tainted_vars, flows) = analysis.analyze(&func);
        
        assert!(tainted_vars.contains("_1"));
        assert!(tainted_vars.contains("_3"));
        assert_eq!(flows.len(), 1);
        assert!(!flows[0].sanitized);
    }

    #[test]
    fn no_false_positive_on_hardcoded() {
        let func = make_function(&[
            "_1 = const \"hardcoded\";",
            "_2 = std::process::Command::arg(move _1);",
        ]);
        
        let analysis = TaintAnalysis::new();
        let (_tainted_vars, flows) = analysis.analyze(&func);
        
        assert_eq!(flows.len(), 0, "Hardcoded strings should not be tainted");
    }
}
