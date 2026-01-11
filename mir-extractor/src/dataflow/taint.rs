// Taint tracking infrastructure for dataflow analysis
// Tracks untrusted data from sources (env vars, network) to sinks (Command, fs)

use std::collections::{HashMap, HashSet, VecDeque};
use crate::{MirFunction, Finding, RuleMetadata, Severity, SourceSpan};
use super::MirDataflow;

/// Basic block in MIR control flow graph
#[derive(Debug, Clone)]
struct BasicBlock {
    id: String,              // e.g., "bb0", "bb1"
    statements: Vec<String>, // Statements in this block
    terminator: Option<String>, // goto, switchInt, return, etc.
    successors: Vec<String>, // Which blocks this can jump to
}

/// Control flow graph for a MIR function
struct ControlFlowGraph {
    blocks: HashMap<String, BasicBlock>,
    _entry_block: String, // Usually "bb0"
}

impl ControlFlowGraph {
    /// Parse MIR body into a control flow graph
    fn from_mir(function: &MirFunction) -> Self {
        let mut blocks = HashMap::new();
        let mut current_block: Option<BasicBlock> = None;
        let entry_block = "bb0".to_string();

        for line in &function.body {
            let trimmed = line.trim();
            
            // Start of a new basic block
            if trimmed.starts_with("bb") && trimmed.contains(": {") {
                // Save previous block
                if let Some(block) = current_block.take() {
                    blocks.insert(block.id.clone(), block);
                }
                
                // Extract block ID (e.g., "bb0" from "bb0: {")
                let id = trimmed.split(':').next().unwrap().trim().to_string();
                current_block = Some(BasicBlock {
                    id,
                    statements: Vec::new(),
                    terminator: None,
                    successors: Vec::new(),
                });
            }
            // Terminator (goto, switchInt, return, etc.)
            else if trimmed.contains("goto") || trimmed.contains("switchInt") || 
                    trimmed.contains("return") || trimmed.contains("-> [return:") {
                if let Some(ref mut block) = current_block {
                    block.terminator = Some(trimmed.to_string());
                    // Extract successor blocks
                    block.successors = Self::extract_successors(trimmed);
                }
            }
            // Regular statement in the current block
            else if !trimmed.is_empty() && !trimmed.starts_with("}") && current_block.is_some() {
                if let Some(ref mut block) = current_block {
                    block.statements.push(trimmed.to_string());
                }
            }
        }
        
        // Save last block
        if let Some(block) = current_block {
            blocks.insert(block.id.clone(), block);
        }

        Self { blocks, _entry_block: entry_block }
    }

    /// Extract successor block IDs from a terminator
    fn extract_successors(terminator: &str) -> Vec<String> {
        let mut successors = Vec::new();
        
        // Extract "bbN" patterns
        let mut i = 0;
        let chars: Vec<char> = terminator.chars().collect();
        while i < chars.len() {
            if i + 1 < chars.len() && chars[i] == 'b' && chars[i + 1] == 'b' {
                i += 2;
                let mut num = String::new();
                while i < chars.len() && chars[i].is_ascii_digit() {
                    num.push(chars[i]);
                    i += 1;
                }
                if !num.is_empty() {
                    successors.push(format!("bb{}", num));
                }
            } else {
                i += 1;
            }
        }
        
        successors
    }

    /// Check if a basic block containing the sink is guarded by a sanitization check
    /// Returns true if the block is only reachable when the guard variable is true/non-zero
    fn is_guarded_by(&self, sink_block_id: &str, guard_var: &str) -> bool {
        // Find the block that contains the switchInt on the guard variable
        for (_block_id, block) in &self.blocks {
            if let Some(ref terminator) = block.terminator {
                // Look for: switchInt(move _3) -> [0: bbX, otherwise: bbY]
                // where _3 is the guard variable
                if terminator.contains("switchInt") && terminator.contains(guard_var) {
                    // Extract the "otherwise" target (where guard is true)
                    let successors = &block.successors;
                    
                    // The pattern is: switchInt(var) -> [0: bb_false, otherwise: bb_true]
                    // If there are 2 successors, the second one (or "otherwise") is the true branch
                    if successors.len() >= 2 {
                        let true_branch = &successors[1]; // "otherwise" branch
                        
                        // Check if sink_block is reachable from the true branch
                        return self.is_reachable_from(true_branch, sink_block_id);
                    }
                }
            }
        }
        
        false
    }

    /// Check if target_block is reachable from start_block
    fn is_reachable_from(&self, start_block: &str, target_block: &str) -> bool {
        if start_block == target_block {
            return true;
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start_block.to_string());
        visited.insert(start_block.to_string());

        while let Some(block_id) = queue.pop_front() {
            if block_id == target_block {
                return true;
            }

            if let Some(block) = self.blocks.get(&block_id) {
                for successor in &block.successors {
                    if !visited.contains(successor) {
                        visited.insert(successor.clone());
                        queue.push_back(successor.clone());
                    }
                }
            }
        }

        false
    }
}

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
    _severity: Severity,
}

impl SourceRegistry {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                SourcePattern {
                    kind: TaintSourceKind::EnvironmentVariable,
                    function_patterns: vec![
                        " = var::",           // Most common in MIR (fully qualified import)
                        " = var(",            // Alternative
                        "std::env::var(",     // Full path
                        "std::env::var_os(",
                        "core::env::var(",
                        "core::env::var_os(",
                    ],
                    _severity: Severity::Medium,
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
                        "Command::new::",     // With generics in MIR
                        "Command::arg::",     // With generics in MIR
                        "Command::args::",    // With generics in MIR
                    ],
                    severity: Severity::High,
                },
                SinkPattern {
                    kind: TaintSinkKind::FileSystemOp,
                    function_patterns: vec![
                        "std::fs::write::",
                        "std::fs::remove_file::",
                        "std::fs::remove_dir::",
                        "std::path::Path::join::",
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
    pub(crate) patterns: Vec<SanitizerPattern>,
}

pub(crate) struct SanitizerPattern {
    pub(crate) function_patterns: Vec<&'static str>,
    pub(crate) sanitizes: Vec<TaintSinkKind>,  // Which sinks does this sanitize for?
}

impl SanitizerRegistry {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                SanitizerPattern {
                    // .parse::<T>() type conversions sanitize for most uses
                    // Patterns: core::str::<impl str>::parse::<u16>, etc.
                    function_patterns: vec![
                        "::parse::<",
                    ],
                    sanitizes: vec![
                        TaintSinkKind::CommandExecution,
                        TaintSinkKind::FileSystemOp,
                    ],
                },
                SanitizerPattern {
                    // .chars().all() validation patterns
                    // Pattern: <Chars<'_> as Iterator>::all::<{closure@
                    function_patterns: vec![
                        " as Iterator>::all::<",
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

    /// Check if a variable is sanitized between source and sink
    /// Returns true if we detect sanitization patterns in the function body
    pub fn is_sanitized(&self, function: &MirFunction, var: &str, sink_kind: &TaintSinkKind) -> bool {
        // Look for sanitization patterns that operate on this variable
        for line in &function.body {
            // Check if this line involves the variable
            if line.contains(var) {
                // Check if it matches any sanitization pattern
                for pattern in &self.patterns {
                    // Check if this pattern sanitizes for this sink type
                    if pattern.sanitizes.contains(sink_kind) {
                        for func_pattern in &pattern.function_patterns {
                            if line.contains(func_pattern) {
                                // Found sanitization!
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
        let is_target_function = function.name.contains("sanitized_parse") || function.name.contains("sanitized_allowlist");
        
        if is_target_function {
            eprintln!("\n========== ANALYZING TARGET FUNCTION: {} ==========", function.name);
        }
        
        // Step 1: Detect taint sources
        let sources = self.source_registry.detect_sources(function);
        
        if is_target_function {
            eprintln!("Found {} sources", sources.len());
            
            // Show basic block structure to understand control flow
            eprintln!("\n--- MIR Basic Block Structure ---");
            for line in &function.body {
                let trimmed = line.trim();
                if trimmed.starts_with("bb") && trimmed.contains(':') {
                    eprintln!("{}", trimmed);
                } else if trimmed.contains("switchInt") || trimmed.contains("goto") || trimmed.contains("return") {
                    eprintln!("  {}", trimmed);
                }
            }
            eprintln!("--- End Basic Blocks ---\n");
        }
        
        if sources.is_empty() {
            return (HashSet::new(), Vec::new());
        }

        // Step 2: Identify sanitized variables
        // These are variables that result from sanitizing operations on tainted data
        let sanitized_vars = self.detect_sanitized_variables(function, &sources);

        // Step 3: Propagate taint through dataflow
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

        // Don't remove sanitized vars - we'll check paths instead

        // Step 4: Detect sinks that use tainted data
        let sinks = self.sink_registry.detect_sinks(function, &tainted_vars);

        // Step 5: Create flows and check if each flow goes through sanitization
        let mut flows = Vec::new();
        for sink in sinks {
            // Find which source(s) contributed to this sink
            for source in &sources {
                if tainted_vars.contains(&sink.variable) {
                    // Check if this sink is sanitized by tracing backward
                    let is_sanitized = self.is_flow_sanitized(
                        function,
                        &sink.variable,
                        &sanitized_vars,
                        &tainted_vars
                    );
                    
                    flows.push(TaintFlow {
                        source: source.clone(),
                        sink: sink.clone(),
                        sanitized: is_sanitized,
                        propagation_path: vec![],  // Path tracking done at inter-procedural level
                    });
                    break; // One source per sink for now
                }
            }
        }

        (tainted_vars, flows)
    }

    /// Check if a flow from source to sink goes through a sanitization operation
    /// This includes both dataflow sanitization (parse) and control-flow guards (if checks)
    fn is_flow_sanitized(
        &self,
        function: &MirFunction,
        sink_var: &str,
        sanitized_vars: &HashSet<String>,
        tainted_vars: &HashSet<String>,
    ) -> bool {
        // First, check dataflow-based sanitization (e.g., parse())
        // Build a reverse dependency map: for each variable, track what it depends on
        let mut depends_on: HashMap<String, HashSet<String>> = HashMap::new();
        
        for line in &function.body {
            // Look for assignments: _X = ... _Y ...
            if let Some(target) = extract_assignment_target(line) {
                // Extract all variables referenced on the right-hand side
                let deps = extract_referenced_variables(line);
                depends_on.entry(target).or_insert_with(HashSet::new).extend(deps);
            }
        }

        // BFS backward from sink to find if we reach a sanitized variable
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(sink_var.to_string());
        visited.insert(sink_var.to_string());

        while let Some(var) = queue.pop_front() {
            // If this variable is sanitized via dataflow (e.g., parse result), flow is sanitized
            if sanitized_vars.contains(&var) {
                return true;
            }

            // Otherwise, add its dependencies to the queue
            if let Some(deps) = depends_on.get(&var) {
                for dep in deps {
                    // Only follow dependencies that are tainted (part of the taint flow)
                    if !visited.contains(dep) && tainted_vars.contains(dep) {
                        visited.insert(dep.clone());
                        queue.push_back(dep.clone());
                    }
                }
            }
        }

        // Second, check control-flow-based sanitization (e.g., if chars().all())
        // Build the control flow graph
        let cfg = ControlFlowGraph::from_mir(function);
        
        // Find which basic block contains the sink operation
        let sink_block = self.find_sink_block(function, sink_var);
        
        if let Some(sink_bb) = sink_block {
            // Check if any sanitized variable guards this sink block
            for sanitized_var in sanitized_vars {
                if cfg.is_guarded_by(&sink_bb, sanitized_var) {
                    return true;
                }
            }
        }

        false
    }

    /// Find which basic block contains the sink operation for the given variable
    fn find_sink_block(&self, function: &MirFunction, sink_var: &str) -> Option<String> {
        let mut current_block: Option<String> = None;
        
        for line in &function.body {
            let trimmed = line.trim();
            
            // Track which block we're in
            if trimmed.starts_with("bb") && trimmed.contains(": {") {
                current_block = Some(trimmed.split(':').next().unwrap().trim().to_string());
            }
            // Look for sink operations that use this variable
            else if trimmed.contains(sink_var) {
                // Check if this is a sink operation (Command::arg, fs::write, etc.)
                if trimmed.contains("Command::arg") || 
                   trimmed.contains("Command::new") ||
                   trimmed.contains("fs::write") ||
                   trimmed.contains("fs::remove") ||
                   trimmed.contains("Path::join") {
                    return current_block;
                }
            }
        }
        
        None
    }

    /// Detect variables that are results of sanitizing operations
    /// These variables should not propagate taint even if their inputs were tainted
    fn detect_sanitized_variables(&self, function: &MirFunction, _sources: &[TaintSource]) -> HashSet<String> {
        let mut sanitized_vars = HashSet::new();

        // Look for sanitization patterns in the function body
        for line in &function.body {
            // Check if this line is a sanitizing operation
            let is_sanitizing = self.sanitizer_registry.patterns.iter().any(|pattern| {
                pattern.function_patterns.iter().any(|p| line.contains(p))
            });

            if is_sanitizing {
                // Extract the target variable (left side of assignment)
                if let Some(target) = extract_assignment_target(line) {
                    sanitized_vars.insert(target);
                }
            }
        }

        sanitized_vars
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

        Finding::new(
            rule_metadata.id.clone(),
            rule_metadata.name.clone(),
            if self.sanitized { Severity::Low } else { self.sink.severity },
            message,
            function_name.to_string(),
            function_sig.to_string(),
            evidence,
            span,
        )
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

/// Extract all variables referenced on the right-hand side of an assignment
/// E.g., "_1 = add(_2, _3)" returns ["_2", "_3"]
fn extract_referenced_variables(line: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let trimmed = line.trim();
    
    // Find the right-hand side (after '=')
    if let Some(eq_pos) = trimmed.find('=') {
        let rhs = &trimmed[eq_pos + 1..];
        
        // Look for all occurrences of _N where N is digits
        let mut i = 0;
        let chars: Vec<char> = rhs.chars().collect();
        while i < chars.len() {
            if chars[i] == '_' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit() {
                let mut var = String::from("_");
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    var.push(chars[i]);
                    i += 1;
                }
                vars.push(var);
            } else {
                i += 1;
            }
        }
    }
    
    vars
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
            "_3 = Command::arg::<&str>(move _4, move _1) -> [return: bb1, unwind: bb2];",
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
            "_4 = Command::arg::<&str>(move _5, move _3) -> [return: bb1, unwind: bb2];",
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
            "_2 = Command::arg::<&str>(move _3, move _1) -> [return: bb1, unwind: bb2];",
        ]);
        
        let analysis = TaintAnalysis::new();
        let (_tainted_vars, flows) = analysis.analyze(&func);
        
        assert_eq!(flows.len(), 0, "Hardcoded strings should not be tainted");
    }
}
