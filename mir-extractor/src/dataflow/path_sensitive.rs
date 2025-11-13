//! Path-sensitive taint analysis
//!
//! This module analyzes taint flow separately for each execution path through a function's CFG.
//! This enables detecting vulnerabilities where only some branches lack sanitization.

use std::collections::{HashMap, HashSet};
use super::cfg::{ControlFlowGraph, BasicBlock, Terminator};
use super::closure::ClosureInfo;
use crate::MirFunction;

/// Taint state for a variable
#[derive(Debug, Clone, PartialEq)]
pub enum TaintState {
    /// Variable is clean (not tainted)
    Clean,
    
    /// Variable is tainted from a source
    Tainted {
        source_type: String,  // e.g., "environment", "network", "file"
        source_location: String,  // e.g., "env::args", "TcpStream::read"
    },
    
    /// Variable was tainted but has been sanitized
    Sanitized {
        sanitizer: String,  // e.g., "validate_input", "parse::<i32>"
    },
}

/// Result of analyzing a single path
#[derive(Debug, Clone)]
pub struct PathAnalysisResult {
    /// The execution path (sequence of block IDs)
    pub path: Vec<String>,
    
    /// Whether this path reaches a sink with tainted data
    pub has_vulnerable_sink: bool,
    
    /// Sink calls found on this path
    pub sink_calls: Vec<SinkCall>,
    
    /// Source calls found on this path
    pub source_calls: Vec<SourceCall>,
    
    /// Sanitization calls found on this path
    pub sanitizer_calls: Vec<SanitizerCall>,
}

#[derive(Debug, Clone)]
pub struct SinkCall {
    pub block_id: String,
    pub statement: String,
    pub sink_function: String,
    pub tainted_args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SourceCall {
    pub block_id: String,
    pub statement: String,
    pub source_function: String,
    pub result_var: String,
}

#[derive(Debug, Clone)]
pub struct SanitizerCall {
    pub block_id: String,
    pub statement: String,
    pub sanitizer_function: String,
    pub sanitized_var: String,
}

/// Path-sensitive taint analysis
pub struct PathSensitiveTaintAnalysis {
    cfg: ControlFlowGraph,
    /// Taint state: (block_id, variable) -> TaintState
    taint_map: HashMap<(String, String), TaintState>,
}

impl PathSensitiveTaintAnalysis {
    /// Create a new path-sensitive analysis for the given CFG
    pub fn new(cfg: ControlFlowGraph) -> Self {
        Self {
            cfg,
            taint_map: HashMap::new(),
        }
    }
    
    /// Analyze all paths through the function
    pub fn analyze(&mut self, function: &MirFunction) -> PathSensitiveResult {
        self.analyze_with_initial_taint(function, HashMap::new())
    }
    
    /// Analyze all paths through a closure function with captured variable taint
    pub fn analyze_closure(
        &mut self,
        function: &MirFunction,
        closure_info: &ClosureInfo,
    ) -> PathSensitiveResult {
        let initial_taint = self.build_initial_taint_from_captures(closure_info);
        self.analyze_with_initial_taint(function, initial_taint)
    }
    
    /// Build initial taint state from captured variables
    fn build_initial_taint_from_captures(
        &self,
        closure_info: &ClosureInfo,
    ) -> HashMap<String, TaintState> {
        let mut taint = HashMap::new();
        
        // For each captured variable, if it's tainted, add it to initial taint
        // The captured variable is accessed via ((*_1).N) where N is the field index
        for capture in &closure_info.captured_vars {
            if let super::closure::TaintState::Tainted { source_type, .. } = &capture.taint_state {
                // Closure environment is always _1 in the closure body
                // Field access is ((*_1).N) where N is the field index
                let env_var = format!("((*_1).{})", capture.field_index);
                taint.insert(
                    env_var,
                    TaintState::Tainted {
                        source_type: source_type.clone(),
                        source_location: format!(
                            "captured from {}",
                            closure_info.parent_function
                        ),
                    },
                );
            }
        }
        
        taint
    }
    
    /// Analyze all paths with given initial taint state
    fn analyze_with_initial_taint(
        &mut self,
        function: &MirFunction,
        initial_taint: HashMap<String, TaintState>,
    ) -> PathSensitiveResult {
        let paths = self.cfg.get_all_paths();
        
        let mut path_results = Vec::new();
        let mut has_any_vulnerable_path = false;
        
        for path in paths {
            let result = self.analyze_path(&path, function, &initial_taint);
            
            if result.has_vulnerable_sink {
                has_any_vulnerable_path = true;
            }
            
            path_results.push(result);
        }
        
        let total_paths = path_results.len();
        
        PathSensitiveResult {
            path_results,
            has_any_vulnerable_path,
            total_paths,
        }
    }
    
    /// Analyze a single execution path
    fn analyze_path(
        &mut self,
        path: &[String],
        _function: &MirFunction,
        initial_taint: &HashMap<String, TaintState>,
    ) -> PathAnalysisResult {
        // Initialize taint state for this path with captured variables (if closure)
        let mut current_taint: HashMap<String, TaintState> = initial_taint.clone();
        
        // Track taint sources from function parameters
        // For now, assume param _1 is potentially tainted from env::args
        // (This is simplified - real implementation would parse function signature)
        
        let mut sink_calls = Vec::new();
        let mut source_calls = Vec::new();
        let mut sanitizer_calls = Vec::new();
        
        // Process each block in the path
        for block_id in path {
            if let Some(block) = self.cfg.get_block(block_id) {
                self.process_block(
                    block,
                    &mut current_taint,
                    &mut sink_calls,
                    &mut source_calls,
                    &mut sanitizer_calls,
                );
            }
        }
        
        // Determine if this path is vulnerable
        let has_vulnerable_sink = !sink_calls.is_empty();
        
        PathAnalysisResult {
            path: path.to_vec(),
            has_vulnerable_sink,
            sink_calls,
            source_calls,
            sanitizer_calls,
        }
    }
    
    /// Process a single basic block
    fn process_block(
        &self,
        block: &BasicBlock,
        current_taint: &mut HashMap<String, TaintState>,
        sink_calls: &mut Vec<SinkCall>,
        source_calls: &mut Vec<SourceCall>,
        sanitizer_calls: &mut Vec<SanitizerCall>,
    ) {
        // Process statements in the block
        for statement in &block.statements {
            self.process_statement(
                &block.id,
                statement,
                current_taint,
                sink_calls,
                source_calls,
                sanitizer_calls,
            );
        }
        
        // Process terminator (for function calls)
        self.process_terminator(
            &block.id,
            &block.terminator,
            current_taint,
            sink_calls,
            source_calls,
            sanitizer_calls,
        );
    }
    
    /// Process a statement (assignment, etc.)
    fn process_statement(
        &self,
        block_id: &str,
        statement: &str,
        current_taint: &mut HashMap<String, TaintState>,
        sink_calls: &mut Vec<SinkCall>,
        source_calls: &mut Vec<SourceCall>,
        sanitizer_calls: &mut Vec<SanitizerCall>,
    ) {
        // Check for sink calls (e.g., "_11 = execute_command(copy _12) -> [...]")
        if statement.contains("execute_command")
            || statement.contains("Command::new")
            || statement.contains("Command::spawn")
            || statement.contains("Command::arg")
            || statement.contains("exec")
        {
            // This is a sink call - extract the argument
            if let Some(paren_start) = statement.find('(') {
                if let Some(paren_end) = statement.find(')') {
                    let args_str = &statement[paren_start + 1..paren_end];
                    
                    // Extract all arguments (can be multiple, comma-separated)
                    let mut tainted_args = Vec::new();
                    for arg in args_str.split(',') {
                        if let Some(arg_var) = Self::extract_variable(arg.trim()) {
                            // Check if the argument is tainted
                            if matches!(
                                current_taint.get(&arg_var),
                                Some(TaintState::Tainted { .. })
                            ) {
                                tainted_args.push(arg_var);
                            }
                        }
                    }
                    
                    // If any argument is tainted, this is a vulnerable sink
                    if !tainted_args.is_empty() {
                        let sink_name = if statement.contains("Command::spawn") {
                            "Command::spawn"
                        } else if statement.contains("Command::arg") {
                            "Command::arg"
                        } else if statement.contains("Command::new") {
                            "Command::new"
                        } else {
                            "execute_command"
                        };
                        
                        sink_calls.push(SinkCall {
                            block_id: block_id.to_string(),
                            statement: statement.to_string(),
                            sink_function: sink_name.to_string(),
                            tainted_args,
                        });
                    }
                }
            }
        }
        
        // Parse assignments: _1 = move _2; or _3 = &_1;
        if let Some((lhs, rhs)) = Self::parse_assignment(statement) {
            // Check for environment field access (closure captured variables)
            // Pattern: _7 = deref_copy ((*_1).0: &std::string::String)
            if let Some(env_field) = Self::extract_env_field_access(&rhs) {
                // This is accessing a captured variable in a closure
                // The env_field will be something like "((*_1).0)"
                if let Some(taint) = current_taint.get(&env_field) {
                    // Propagate taint from captured variable to the local variable
                    current_taint.insert(lhs.clone(), taint.clone());
                }
            }
            // Propagate taint from RHS to LHS
            else if let Some(rhs_var) = Self::extract_variable(&rhs) {
                if let Some(taint) = current_taint.get(&rhs_var) {
                    current_taint.insert(lhs.clone(), taint.clone());
                }
            }
            
            // Check for source patterns
            if Self::is_source_call(&rhs) {
                current_taint.insert(lhs.clone(), TaintState::Tainted {
                    source_type: "environment".to_string(),
                    source_location: rhs.clone(),
                });
                
                source_calls.push(SourceCall {
                    block_id: block_id.to_string(),
                    statement: statement.to_string(),
                    source_function: rhs.clone(),
                    result_var: lhs.clone(),
                });
            }
            
            // Check for sanitizer patterns
            if Self::is_sanitizer_call(&rhs) {
                if let Some(input_var) = Self::extract_variable(&rhs) {
                    current_taint.insert(lhs.clone(), TaintState::Sanitized {
                        sanitizer: rhs.clone(),
                    });
                    
                    sanitizer_calls.push(SanitizerCall {
                        block_id: block_id.to_string(),
                        statement: statement.to_string(),
                        sanitizer_function: rhs.clone(),
                        sanitized_var: input_var,
                    });
                }
            }
        }
    }
    
    /// Process a terminator (mainly for function calls)
    fn process_terminator(
        &self,
        _block_id: &str,
        terminator: &Terminator,
        _current_taint: &mut HashMap<String, TaintState>,
        _sink_calls: &mut Vec<SinkCall>,
        _source_calls: &mut Vec<SourceCall>,
        _sanitizer_calls: &mut Vec<SanitizerCall>,
    ) {
        // For Call terminators, we need to look at the preceding statement
        // to determine what function is being called and with what arguments
        // This is simplified for now - real implementation would parse call syntax
        
        if let Terminator::Call { .. } = terminator {
            // Look for sink patterns in the block's statements
            // (In real MIR, function calls appear before the Call terminator)
            // For now, we'll use a simplified heuristic
        }
    }
    
    /// Parse an assignment statement
    fn parse_assignment(statement: &str) -> Option<(String, String)> {
        if let Some(eq_pos) = statement.find(" = ") {
            let lhs = statement[..eq_pos].trim();
            let rhs = statement[eq_pos + 3..].trim().trim_end_matches(';');
            Some((lhs.to_string(), rhs.to_string()))
        } else {
            None
        }
    }
    
    /// Extract a variable name from an expression
    fn extract_variable(expr: &str) -> Option<String> {
        let expr = expr.trim();
        
        // Handle: move _1, copy _2
        if expr.starts_with("move ") {
            return Some(expr[5..].trim().split(|c: char| !c.is_numeric() && c != '_').next()?.to_string());
        }
        if expr.starts_with("copy ") {
            return Some(expr[5..].trim().split(|c: char| !c.is_numeric() && c != '_').next()?.to_string());
        }
        
        // Handle: &_3, &mut _4
        if expr.starts_with("&mut ") {
            return Some(expr[5..].trim().split(|c: char| !c.is_numeric() && c != '_').next()?.to_string());
        }
        if expr.starts_with('&') {
            return Some(expr[1..].trim().split(|c: char| !c.is_numeric() && c != '_').next()?.to_string());
        }
        
        // Handle function calls: extract first argument
        // E.g., "deref(copy _16)" -> "_16"
        // E.g., "<String as Deref>::deref(copy _16)" -> "_16"
        if expr.contains('(') {
            if let Some(start) = expr.find('(') {
                if let Some(end) = expr.find(')') {
                    let arg = &expr[start + 1..end];
                    return Self::extract_variable(arg); // Recursive call
                }
            }
        }
        
        // Simple variable: _1, _2, etc.
        if expr.starts_with('_') {
            if let Some(end) = expr.find(|c: char| !c.is_numeric() && c != '_') {
                return Some(expr[..end].to_string());
            }
            return Some(expr.to_string());
        }
        
        None
    }
    
    /// Extract environment field access pattern
    /// Pattern: deref_copy ((*_1).0: &std::string::String)
    /// Returns: Some("((*_1).0)") if pattern matches
    fn extract_env_field_access(expr: &str) -> Option<String> {
        let expr = expr.trim();
        
        // Look for deref_copy followed by environment field access
        if expr.starts_with("deref_copy ") {
            // Extract the part inside parentheses after deref_copy
            if let Some(start) = expr.find('(') {
                if let Some(end) = expr[start..].find(':') {
                    let field_expr = &expr[start..start + end].trim();
                    // Should be something like "((*_1).0"
                    if field_expr.contains("(*_1).") {
                        // Extract the full field access including closing paren
                        // e.g., "((*_1).0)"
                        let field_access = field_expr.to_string() + ")";
                        return Some(field_access);
                    }
                }
            }
        }
        
        None
    }
    
    /// Check if an expression is a source call
    fn is_source_call(expr: &str) -> bool {
        expr.contains("env::args")
            || expr.contains("env::var")
            || expr.contains("std::env::args")
            || expr.contains("std::env::var")
            || expr.contains("args()") // Simplified MIR format
            || expr.contains("var(")   // Simplified MIR format
    }
    
    /// Check if an expression is a sanitizer call
    fn is_sanitizer_call(expr: &str) -> bool {
        expr.contains("validate_input")
            || expr.contains("sanitize")
            || expr.contains("parse::<")
            || expr.contains("to_string()")
    }
}

/// Result of path-sensitive analysis
#[derive(Debug)]
pub struct PathSensitiveResult {
    /// Results for each path
    pub path_results: Vec<PathAnalysisResult>,
    
    /// True if at least one path is vulnerable
    pub has_any_vulnerable_path: bool,
    
    /// Total number of paths analyzed
    pub total_paths: usize,
}

impl PathSensitiveResult {
    /// Get vulnerable paths
    pub fn vulnerable_paths(&self) -> Vec<&PathAnalysisResult> {
        self.path_results
            .iter()
            .filter(|r| r.has_vulnerable_sink)
            .collect()
    }
    
    /// Get safe paths
    pub fn safe_paths(&self) -> Vec<&PathAnalysisResult> {
        self.path_results
            .iter()
            .filter(|r| !r.has_vulnerable_sink)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_assignment() {
        assert_eq!(
            PathSensitiveTaintAnalysis::parse_assignment("_1 = move _2;"),
            Some(("_1".to_string(), "move _2".to_string()))
        );
        
        assert_eq!(
            PathSensitiveTaintAnalysis::parse_assignment("_3 = &_1;"),
            Some(("_3".to_string(), "&_1".to_string()))
        );
    }
    
    #[test]
    fn test_extract_variable() {
        assert_eq!(
            PathSensitiveTaintAnalysis::extract_variable("move _1"),
            Some("_1".to_string())
        );
        
        assert_eq!(
            PathSensitiveTaintAnalysis::extract_variable("&_2"),
            Some("_2".to_string())
        );
        
        assert_eq!(
            PathSensitiveTaintAnalysis::extract_variable("&mut _3"),
            Some("_3".to_string())
        );
    }
    
    #[test]
    fn test_is_source_call() {
        assert!(PathSensitiveTaintAnalysis::is_source_call("std::env::args()"));
        assert!(PathSensitiveTaintAnalysis::is_source_call("env::var(\"PATH\")"));
        assert!(!PathSensitiveTaintAnalysis::is_source_call("some_function()"));
    }
    
    #[test]
    fn test_is_sanitizer_call() {
        assert!(PathSensitiveTaintAnalysis::is_sanitizer_call("validate_input(_1)"));
        assert!(PathSensitiveTaintAnalysis::is_sanitizer_call("parse::<i32>()"));
        assert!(!PathSensitiveTaintAnalysis::is_sanitizer_call("some_function()"));
    }
    
    #[test]
    fn test_extract_env_field_access() {
        // Test closure environment field access
        assert_eq!(
            PathSensitiveTaintAnalysis::extract_env_field_access(
                "deref_copy ((*_1).0: &std::string::String)"
            ),
            Some("((*_1).0)".to_string())
        );
        
        assert_eq!(
            PathSensitiveTaintAnalysis::extract_env_field_access(
                "deref_copy ((*_1).1: &i32)"
            ),
            Some("((*_1).1)".to_string())
        );
        
        // Should not match non-environment patterns
        assert_eq!(
            PathSensitiveTaintAnalysis::extract_env_field_access("move _1"),
            None
        );
        
        assert_eq!(
            PathSensitiveTaintAnalysis::extract_env_field_access("deref_copy _2"),
            None
        );
    }
}
