#![allow(unused_variables, dead_code, unused_imports)]

//! Path-sensitive taint analysis
//!
//! This module analyzes taint flow separately for each execution path through a function's CFG.
//! This enables detecting vulnerabilities where only some branches lack sanitization.

use std::collections::HashMap;
use super::cfg::{ControlFlowGraph, BasicBlock, Terminator};
use super::closure::ClosureInfo;
use super::field::{FieldTaintMap, FieldTaint, FieldPath};
use super::{DataflowSummary, TaintPropagation};
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
    
    /// Whether the return value (_0) is tainted at the end of the path
    pub return_tainted: bool,
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
    pub fn analyze(
        &mut self, 
        function: &MirFunction,
        callee_summaries: Option<&HashMap<String, DataflowSummary>>
    ) -> PathSensitiveResult {
        self.analyze_with_initial_taint(function, HashMap::new(), callee_summaries)
    }
    
    /// Analyze all paths through a closure function with captured variable taint
    pub fn analyze_closure(
        &mut self,
        function: &MirFunction,
        closure_info: &ClosureInfo,
        callee_summaries: Option<&HashMap<String, DataflowSummary>>
    ) -> PathSensitiveResult {
        let initial_taint = self.build_initial_taint_from_captures(closure_info);
        self.analyze_with_initial_taint(function, initial_taint, callee_summaries)
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
    pub fn analyze_with_initial_taint(
        &mut self,
        function: &MirFunction,
        initial_taint: HashMap<String, TaintState>,
        callee_summaries: Option<&HashMap<String, DataflowSummary>>
    ) -> PathSensitiveResult {
        println!("[DEBUG] Processing function: {}", function.name);
        let paths = self.cfg.get_all_paths();
        
        let mut path_results = Vec::new();
        let mut has_any_vulnerable_path = false;
        
        for path in paths {
            // Use field-sensitive analysis by default
            let result = self.analyze_path_field_sensitive(&path, function, &initial_taint, callee_summaries);
            
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
    
    /// Analyze a single execution path (field-sensitive version)
    fn analyze_path_field_sensitive(
        &mut self,
        path: &[String],
        _function: &MirFunction,
        initial_taint: &HashMap<String, TaintState>,
        callee_summaries: Option<&HashMap<String, DataflowSummary>>
    ) -> PathAnalysisResult {
        // Initialize field-sensitive taint state
        let mut field_map = FieldTaintMap::new();
        
        // Convert initial taint to field map
        for (var, taint_state) in initial_taint {
            Self::set_field_taint_state(&mut field_map, var, taint_state);
        }
        
        let mut sink_calls = Vec::new();
        let mut source_calls = Vec::new();
        let mut sanitizer_calls = Vec::new();
        let mut alias_map = HashMap::new();
        
        // Process each block in the path
        for block_id in path {
            if let Some(block) = self.cfg.get_block(block_id) {
                self.process_block_field_sensitive(
                    block,
                    &mut field_map,
                    &mut sink_calls,
                    &mut source_calls,
                    &mut sanitizer_calls,
                    callee_summaries,
                    &mut alias_map
                );
            }
        }
        
        // Determine if this path is vulnerable
        let has_vulnerable_sink = !sink_calls.is_empty();
        
        // Check if return value is tainted
        let return_tainted = matches!(
            field_map.get_field_taint(&super::field::FieldPath::whole_var("_0".to_string())),
            super::field::FieldTaint::Tainted { .. }
        );
        
        PathAnalysisResult {
            path: path.to_vec(),
            has_vulnerable_sink,
            sink_calls,
            source_calls,
            sanitizer_calls,
            return_tainted,
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
        
        // Check if return value is tainted
        let return_tainted = matches!(current_taint.get("_0"), Some(TaintState::Tainted { .. }));
        
        PathAnalysisResult {
            path: path.to_vec(),
            has_vulnerable_sink,
            sink_calls,
            source_calls,
            sanitizer_calls,
            return_tainted,
        }
    }
    
    /// Process a single basic block (field-sensitive version)
    fn process_block_field_sensitive(
        &self,
        block: &BasicBlock,
        field_map: &mut FieldTaintMap,
        sink_calls: &mut Vec<SinkCall>,
        source_calls: &mut Vec<SourceCall>,
        sanitizer_calls: &mut Vec<SanitizerCall>,
        callee_summaries: Option<&HashMap<String, DataflowSummary>>,
        alias_map: &mut HashMap<String, String>
    ) {
        // Process statements in the block
        for statement in &block.statements {
            self.process_statement_field_sensitive(
                &block.id,
                statement,
                field_map,
                sink_calls,
                source_calls,
                sanitizer_calls,
                callee_summaries,
                alias_map
            );
        }
        
        // Process terminator (for function calls)
        self.process_terminator_field_sensitive(
            &block.id,
            &block.statements,
            &block.terminator,
            field_map,
            sink_calls,
            source_calls,
            sanitizer_calls,
            callee_summaries,
            alias_map
        );
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
    
    /// Process a statement (assignment, etc.) with field-sensitive analysis
    fn process_statement_field_sensitive(
        &self,
        block_id: &str,
        statement: &str,
        field_map: &mut FieldTaintMap,
        sink_calls: &mut Vec<SinkCall>,
        source_calls: &mut Vec<SourceCall>,
        sanitizer_calls: &mut Vec<SanitizerCall>,
        callee_summaries: Option<&HashMap<String, DataflowSummary>>,
        alias_map: &mut HashMap<String, String>
    ) {
        use super::field::parser;

        // Handle alias definition: _N = deref_copy (_M.0: ...)
        if let Some((lhs, rhs)) = Self::parse_assignment(statement) {
             if rhs.starts_with("deref_copy ") {
                 let source = rhs[11..].trim();
                 // Check if source is a field access like (_1.0: ...)
                 if let Some(field_path) = parser::parse_field_access(source) {
                     // If it's a field of _1 (the generator), record alias
                     if field_path.base_var == "_1" {
                         // lhs is _N
                         if let Some(lhs_var) = parser::extract_base_var(&lhs) {
                             alias_map.insert(lhs_var, field_path.to_string());
                         }
                     }
                 }
             }
        }

        // Apply aliases to statement
        let mut statement_str = statement.to_string();
        for (alias, target) in alias_map.iter() {
            let alias_pattern = alias.as_str();
            let target_pattern = target.as_str();
            
            let mut temp_stmt = String::new();
            let mut pos = 0;
            
            while let Some(idx) = statement_str[pos..].find(alias_pattern) {
                let start = pos + idx;
                let end = start + alias_pattern.len();
                
                // Check if whole word (followed by non-digit)
                let is_whole_word = if end < statement_str.len() {
                    !statement_str.as_bytes()[end].is_ascii_digit()
                } else {
                    true
                };
                
                temp_stmt.push_str(&statement_str[pos..start]);
                
                if is_whole_word {
                    temp_stmt.push_str(target_pattern);
                } else {
                    temp_stmt.push_str(alias_pattern);
                }
                
                pos = end;
            }
            temp_stmt.push_str(&statement_str[pos..]);
            statement_str = temp_stmt;
        }
        
        let statement = statement_str.as_str();
        
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
                        let arg_trimmed = arg.trim();
                        // Check if the argument is tainted (field-sensitive)
                        if Self::is_field_tainted(field_map, arg_trimmed) {
                            if let Some(arg_var) = parser::extract_base_var(arg_trimmed) {
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
        
        // Parse assignments: _1 = move _2; or (_1.0: Type) = move _2;
        if let Some((lhs, rhs_raw)) = Self::parse_assignment(statement) {
            // Strip terminator info (-> [return: ...])
            let rhs = if let Some(idx) = rhs_raw.find(" -> [") {
                rhs_raw[..idx].trim().to_string()
            } else {
                rhs_raw
            };

            // Check if LHS is a field access
            let is_field_write = parser::contains_field_access(&lhs);
            
            // Check for environment field access (closure captured variables)
            // Pattern: _7 = deref_copy ((*_1).0: &std::string::String)
            if let Some(env_field) = Self::extract_env_field_access(&rhs) {
                // This is accessing a captured variable in a closure
                let taint_state = Self::get_field_taint_state(field_map, &env_field);
                Self::set_field_taint_state(field_map, &lhs, &taint_state);
            }
            // Propagate taint from RHS to LHS (field-sensitive)
            else if parser::contains_field_access(&rhs) || Self::extract_variable(&rhs).is_some() {
                // Get taint from RHS (could be field or variable)
                let rhs_taint = if parser::contains_field_access(&rhs) {
                    Self::get_field_taint_state(field_map, &rhs)
                } else if let Some(var) = Self::extract_variable(&rhs) {
                    let t = Self::get_field_taint_state(field_map, &var);
                    t
                } else {
                    Self::get_field_taint_state(field_map, &rhs)
                };
                
                // Set taint on LHS
                if is_field_write {
                    // Writing to a specific field - only that field becomes tainted
                    Self::set_field_taint_state(field_map, &lhs, &rhs_taint);
                } else {
                    // Writing to entire variable - propagate to all fields
                    Self::set_field_taint_state(field_map, &lhs, &rhs_taint);
                }
            }
            
            // Check for source patterns
            if Self::is_source_call(&rhs) {
                let taint = TaintState::Tainted {
                    source_type: "environment".to_string(),
                    source_location: rhs.clone(),
                };
                Self::set_field_taint_state(field_map, &lhs, &taint);
                
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
                    let taint = TaintState::Sanitized {
                        sanitizer: rhs.clone(),
                    };
                    Self::set_field_taint_state(field_map, &lhs, &taint);
                    
                    sanitizer_calls.push(SanitizerCall {
                        block_id: block_id.to_string(),
                        statement: statement.to_string(),
                        sanitizer_function: rhs.clone(),
                        sanitized_var: input_var,
                    });
                }
            }
            // Check for closure/coroutine creation
            else if rhs.starts_with("{closure@") || rhs.starts_with("{coroutine@") {
                if let Some(summaries) = callee_summaries {
                    // Extract index (#N)
                    if let Some(hash_pos) = rhs.find("(#") {
                        if let Some(close_paren) = rhs[hash_pos..].find(')') {
                            let index_str = &rhs[hash_pos+2..hash_pos+close_paren];
                            if let Ok(index) = index_str.parse::<usize>() {
                                // Look for a summary ending with ::{closure#N}
                                let suffix = format!("::{{closure#{}}}", index);
                                for (name, summary) in summaries {
                                    if name.ends_with(&suffix) {
                                        if summary.returns_tainted {
                                            println!("[DEBUG] Closure/Coroutine {} returns tainted data, propagating to {}", name, lhs);
                                            let taint = TaintState::Tainted {
                                                source_type: "propagated".to_string(),
                                                source_location: format!("via {}", name),
                                            };
                                            Self::set_field_taint_state(field_map, &lhs, &taint);
                                        } else {
                                            println!("[DEBUG] Closure/Coroutine {} found but returns CLEAN", name);
                                        }
                                        
                                        // Check for ParamToSink (closure environment flows to sink)
                                        let mut has_sink_flow = false;
                                        for prop in &summary.propagation {
                                            if let TaintPropagation::ParamToSink { param, sink_type: _ } = prop {
                                                // Param 0 is the closure environment
                                                if *param == 0 {
                                                    has_sink_flow = true;
                                                }
                                            }
                                        }
                                        
                                        if has_sink_flow {
                                            // If closure reads from environment and sinks it, we need to check captured vars
                                            // This is handled in analyze_closure, but here we can flag the closure object
                                            println!("[DEBUG] Closure {} has ParamToSink flow", name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Check for general function calls that return tainted data
            else if rhs.ends_with(')') {
                // Find matching open parenthesis for the function call
                // We scan backwards to find the parenthesis that balances the last ')'
                let mut balance = 0;
                let mut open_paren_pos = None;
                for (i, c) in rhs.char_indices().rev() {
                    if c == ')' {
                        balance += 1;
                    } else if c == '(' {
                        balance -= 1;
                        if balance == 0 {
                            open_paren_pos = Some(i);
                            break;
                        }
                    }
                }

                if let Some(paren_pos) = open_paren_pos {
                    let func_name_full = rhs[..paren_pos].trim();
                    // Extract short name for heuristic checks
                    let func_name_short = if let Some(idx) = func_name_full.rfind("::") {
                        &func_name_full[idx+2..]
                    } else {
                        func_name_full
                    };
                    
                    // Parse arguments
                    let mut args = Vec::new();
                    if let Some(close_paren) = rhs.rfind(')') {
                        let args_str = &rhs[paren_pos+1..close_paren];
                        for arg in args_str.split(',') {
                            let arg = arg.trim();
                            if !arg.is_empty() {
                                args.push(arg);
                            }
                        }
                    }

                    let mut propagated_taint = None;

                    // Check summaries
                    if let Some(summaries) = callee_summaries {
                        for (name, summary) in summaries {
                            // Check if func_name matches summary name
                            let match_found = name == func_name_full 
                                || name.ends_with(&format!("::{}", func_name_full))
                                || func_name_full.ends_with(&format!("::{}", name));
                                
                            if match_found {
                                // Check explicit return taint
                                if summary.returns_tainted {
                                    println!("[DEBUG] Function call {} returns tainted data, propagating to {}", func_name_full, lhs);
                                    propagated_taint = Some(TaintState::Tainted {
                                        source_type: "propagated".to_string(),
                                        source_location: format!("via {}", func_name_full),
                                    });
                                }

                                // Check propagation from params
                                for prop in &summary.propagation {
                                    if let TaintPropagation::ParamToReturn(param_idx) = prop {
                                        if let Some(arg_str) = args.get(*param_idx) {
                                            // Check if argument is tainted
                                            let is_tainted = if parser::contains_field_access(arg_str) {
                                                matches!(Self::get_field_taint_state(field_map, arg_str), TaintState::Tainted { .. })
                                            } else if let Some(arg_var) = Self::extract_variable(arg_str) {
                                                matches!(Self::get_field_taint_state(field_map, &arg_var), TaintState::Tainted { .. })
                                            } else {
                                                false
                                            };

                                            if is_tainted {
                                                // println!("[DEBUG] Function call {} propagates taint from arg {} to return {}", func_name_full, param_idx, lhs);
                                                propagated_taint = Some(TaintState::Tainted {
                                                    source_type: "propagated".to_string(),
                                                    source_location: format!("via {}", func_name_full),
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    // Heuristic: Propagate taint for known methods if no summary exists
                    if propagated_taint.is_none() {
                        let heuristic_methods = [
                            "into_future",
                            "poll",
                            "new",
                            "new_unchecked",
                            "from",
                            "deref",
                            "as_ref",
                            "clone"
                        ];
                        
                        if heuristic_methods.iter().any(|m| func_name_short == *m) {
                            // Propagate from first argument
                            if let Some(first_arg) = args.first() {
                                let is_tainted = if parser::contains_field_access(first_arg) {
                                    matches!(Self::get_field_taint_state(field_map, first_arg), TaintState::Tainted { .. })
                                } else if let Some(arg_var) = Self::extract_variable(first_arg) {
                                    let t = Self::get_field_taint_state(field_map, &arg_var);
                                    matches!(t, TaintState::Tainted { .. })
                                } else {
                                    false
                                };
                                
                                if is_tainted {
                                    // println!("[DEBUG] Heuristic: Function call {} propagates taint from arg to return {}", func_name_full, lhs);
                                    propagated_taint = Some(TaintState::Tainted {
                                        source_type: "propagated".to_string(),
                                        source_location: format!("via {}", func_name_full),
                                    });
                                } else if func_name_short == "into_future" {
                                     println!("[DEBUG] Heuristic arg check failed for arg '{}' (var: {:?})", first_arg, Self::extract_variable(first_arg));
                                }
                            }
                        } else if func_name_short == "into_future" {
                             println!("[DEBUG] Heuristic mismatch: '{}' not in list", func_name_short);
                        }
                    }

                    if let Some(taint) = propagated_taint {
                        Self::set_field_taint_state(field_map, &lhs, &taint);
                    }
                }
            }
        }
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
    
    /// Process a terminator (field-sensitive version)
    fn process_terminator_field_sensitive(
        &self,
        _block_id: &str,
        _statements: &[String],
        terminator: &Terminator,
        _field_map: &mut FieldTaintMap,
        _sink_calls: &mut Vec<SinkCall>,
        _source_calls: &mut Vec<SourceCall>,
        _sanitizer_calls: &mut Vec<SanitizerCall>,
        _callee_summaries: Option<&HashMap<String, DataflowSummary>>,
        _alias_map: &mut HashMap<String, String>
    ) {
        // For Call terminators, we need to look at the preceding statement
        // to determine what function is being called and with what arguments
        // This is simplified for now - real implementation would parse call syntax
        
        if let Terminator::Call { .. } = terminator {
            // Logic for call terminators is currently handled in process_statement_field_sensitive
            // which sees the assignment statement corresponding to the call.
            // Future improvements could handle calls that are not assignments here.
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
            let var = expr[5..].trim().split(|c: char| !c.is_numeric() && c != '_').next()?;
            if var.is_empty() { return None; }
            return Some(var.to_string());
        }
        if expr.starts_with("copy ") {
            let var = expr[5..].trim().split(|c: char| !c.is_numeric() && c != '_').next()?;
            if var.is_empty() { return None; }
            return Some(var.to_string());
        }
        
        // Handle: &_3, &mut _4
        if expr.starts_with("&mut ") {
            let var = expr[5..].trim().split(|c: char| !c.is_numeric() && c != '_').next()?;
            if var.is_empty() { return None; }
            return Some(var.to_string());
        }
        if expr.starts_with('&') {
            let var = expr[1..].trim().split(|c: char| !c.is_numeric() && c != '_').next()?;
            if var.is_empty() { return None; }
            return Some(var.to_string());
        }
        
        // Handle function calls: extract first argument
        // E.g., "deref(copy _16)" -> "_16"
        // E.g., "<String as Deref>::deref(copy _16)" -> "_16"
        if expr.contains('(') {
            if let Some(start) = expr.find('(') {
                if let Some(end) = expr.rfind(')') {
                    if start < end {
                        let arg = &expr[start + 1..end];
                        // Only recurse if it looks like a function call, not a field access
                        // Field access usually has ':' inside parens
                        if !arg.contains(':') {
                            return Self::extract_variable(arg); // Recursive call
                        }
                    }
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
                    // Handle async closure pattern: (_1.0
                    if field_expr.starts_with("(_1.") {
                         // Convert (_1.0 to ((*_1).0)
                         // field_expr is "(_1.0"
                         if let Ok(idx) = field_expr[4..].parse::<usize>() {
                             return Some(format!("((*_1).{})", idx));
                         }
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
    
    /// Convert TaintState to FieldTaint
    fn taint_state_to_field_taint(taint: &TaintState) -> FieldTaint {
        match taint {
            TaintState::Clean => FieldTaint::Clean,
            TaintState::Tainted { source_type, source_location } => FieldTaint::Tainted {
                source_type: source_type.clone(),
                source_location: source_location.clone(),
            },
            TaintState::Sanitized { sanitizer } => FieldTaint::Sanitized {
                sanitizer: sanitizer.clone(),
            },
        }
    }
    
    /// Convert FieldTaint to TaintState
    fn field_taint_to_taint_state(taint: &FieldTaint) -> TaintState {
        match taint {
            FieldTaint::Clean => TaintState::Clean,
            FieldTaint::Tainted { source_type, source_location } => TaintState::Tainted {
                source_type: source_type.clone(),
                source_location: source_location.clone(),
            },
            FieldTaint::Sanitized { sanitizer } => TaintState::Sanitized {
                sanitizer: sanitizer.clone(),
            },
            FieldTaint::Unknown => TaintState::Clean, // Conservative: treat unknown as clean
        }
    }
    
    /// Check if a variable or field is tainted in the field-sensitive map
    fn is_field_tainted(field_map: &FieldTaintMap, var_or_field: &str) -> bool {
        use super::field::parser;
        
        // Try to parse as field access first
        if parser::contains_field_access(var_or_field) {
            if let Some(field_path) = parser::parse_field_access(var_or_field) {
                return matches!(field_map.get_field_taint(&field_path), FieldTaint::Tainted { .. });
            }
        }
        
        // Fall back to whole variable check
        if let Some(base_var) = parser::extract_base_var(var_or_field) {
            let whole_var_path = FieldPath::whole_var(base_var);
            return matches!(field_map.get_field_taint(&whole_var_path), FieldTaint::Tainted { .. })
                || field_map.has_tainted_field(&whole_var_path.base_var);
        }
        
        false
    }
    
    /// Get taint state for a variable or field from the field-sensitive map
    fn get_field_taint_state(field_map: &FieldTaintMap, var_or_field: &str) -> TaintState {
        use super::field::parser;
        
        // Strip prefixes like &mut, move, copy, etc. to handle MIR expressions
        let mut clean_expr = var_or_field.trim();
        loop {
            if clean_expr.starts_with("&mut ") {
                clean_expr = &clean_expr[5..].trim();
            } else if clean_expr.starts_with("move ") {
                clean_expr = &clean_expr[5..].trim();
            } else if clean_expr.starts_with("copy ") {
                clean_expr = &clean_expr[5..].trim();
            } else if clean_expr.starts_with("&") {
                clean_expr = &clean_expr[1..].trim();
            } else if clean_expr.starts_with("deref_copy ") {
                 clean_expr = &clean_expr[11..].trim();
            } else {
                break;
            }
        }

        // Try to parse as field access first
        if parser::contains_field_access(clean_expr) {
            if let Some(field_path) = parser::parse_field_access(clean_expr) {
                let field_taint = field_map.get_field_taint(&field_path);
                return Self::field_taint_to_taint_state(&field_taint);
            }
        }
        
        // Fall back to whole variable check
        if let Some(base_var) = parser::extract_base_var(var_or_field) {
            let whole_var_path = FieldPath::whole_var(base_var);
            let field_taint = field_map.get_field_taint(&whole_var_path);
            return Self::field_taint_to_taint_state(&field_taint);
        }
        
        TaintState::Clean
    }
    
    /// Set taint for a variable or field in the field-sensitive map
    fn set_field_taint_state(field_map: &mut FieldTaintMap, var_or_field: &str, taint: &TaintState) {
        use super::field::parser;
        
        let field_taint = Self::taint_state_to_field_taint(taint);
        
        // Strip prefixes like &mut, move, copy, etc. to handle MIR expressions
        let mut clean_expr = var_or_field.trim();
        loop {
            if clean_expr.starts_with("&mut ") {
                clean_expr = &clean_expr[5..].trim();
            } else if clean_expr.starts_with("move ") {
                clean_expr = &clean_expr[5..].trim();
            } else if clean_expr.starts_with("copy ") {
                clean_expr = &clean_expr[5..].trim();
            } else if clean_expr.starts_with("&") {
                clean_expr = &clean_expr[1..].trim();
            } else if clean_expr.starts_with("deref_copy ") {
                 clean_expr = &clean_expr[11..].trim();
            } else {
                break;
            }
        }

        // Try to parse as field access first
        if parser::contains_field_access(clean_expr) {
            if let Some(field_path) = parser::parse_field_access(clean_expr) {
                field_map.set_field_taint(field_path, field_taint);
                return;
            }
        }
        
        // Fall back to whole variable
        if let Some(base_var) = parser::extract_base_var(var_or_field) {
            field_map.set_var_taint(&base_var, field_taint);
        }
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
    
    #[test]
    fn test_field_sensitive_helpers() {
        use super::super::field::FieldTaintMap;
        
        let mut field_map = FieldTaintMap::new();
        
        // Test setting and getting field taint
        let taint = TaintState::Tainted {
            source_type: "test".to_string(),
            source_location: "test_source".to_string(),
        };
        
        PathSensitiveTaintAnalysis::set_field_taint_state(&mut field_map, "(_1.0: String)", &taint);
        
        // Check that the field is tainted
        assert!(PathSensitiveTaintAnalysis::is_field_tainted(&field_map, "(_1.0: String)"));
        
        // Check that a different field is not tainted
        assert!(!PathSensitiveTaintAnalysis::is_field_tainted(&field_map, "(_1.1: i32)"));
        
        // Test whole variable taint
        PathSensitiveTaintAnalysis::set_field_taint_state(&mut field_map, "_2", &taint);
        assert!(PathSensitiveTaintAnalysis::is_field_tainted(&field_map, "_2"));
    }
}
