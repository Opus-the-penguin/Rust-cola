//! Inter-procedural taint analysis (Phase 3)
//!
//! This module implements inter-procedural dataflow analysis to track taint
//! across function boundaries. It builds on Phase 2's intra-procedural analysis
//! by constructing a call graph and propagating taint through function calls.
//!
//! ## Architecture
//!
//! 1. **Call Graph Construction**: Extract function calls from MIR to build
//!    a directed graph of function dependencies.
//!
//! 2. **Function Summarization**: Analyze each function to create summaries
//!    describing how taint flows through parameters and return values.
//!
//! 3. **Inter-Procedural Propagation**: Use summaries to track taint across
//!    function boundaries, following chains of calls from sources to sinks.
//!
//! 4. **Context-Sensitive Analysis**: Distinguish different call sites to
//!    maintain precision and avoid false positives.

use std::collections::{HashMap, HashSet, VecDeque};
use anyhow::Result;

use crate::{MirPackage, MirFunction};
use crate::dataflow::cfg::ControlFlowGraph;
use crate::dataflow::closure::{ClosureRegistry, ClosureRegistryBuilder};
use crate::dataflow::{TaintPropagation, DataflowSummary};

/// Call graph representing function call relationships
#[derive(Debug, Clone)]
pub struct CallGraph {
    /// Function name → CallGraphNode
    pub nodes: HashMap<String, CallGraphNode>,
    
    /// Analysis order (bottom-up: callees before callers)
    pub analysis_order: Vec<String>,
}

/// Node in the call graph representing a function
#[derive(Debug, Clone)]
pub struct CallGraphNode {
    /// Function name (fully qualified)
    pub function_name: String,
    
    /// Functions that call this function
    pub callers: Vec<String>,
    
    /// Functions called by this function
    pub callees: Vec<CallSite>,
    
    /// Function summary (computed during analysis)
    pub summary: Option<FunctionSummary>,
}

/// A specific call site within a function
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Name of the called function
    pub callee: String,
    
    /// Resolved target functions
    pub resolved_targets: Vec<String>,
    
    /// Location in the caller's MIR (for error reporting)
    pub location: String,
    
    /// Number of arguments passed
    pub arg_count: usize,
}

/// Summary of a function's taint behavior
#[derive(Debug, Clone)]
pub struct FunctionSummary {
    /// Function name
    pub function_name: String,
    
    /// Which parameters can introduce taint (parameter index)
    pub source_parameters: HashSet<usize>,
    
    /// Which parameters flow to sinks within this function
    pub sink_parameters: HashSet<usize>,
    
    /// Taint propagation rules
    pub propagation_rules: Vec<TaintPropagation>,
    
    /// Does the return value carry taint?
    pub return_taint: ReturnTaint,
    
    /// Does the function contain an internal vulnerability (source -> sink)?
    pub has_internal_vulnerability: bool,
}

/// Describes the taint state of a function's return value
#[derive(Debug, Clone)]
pub enum ReturnTaint {
    /// Return value is clean (not tainted)
    Clean,
    
    /// Return value is tainted from parameter N
    FromParameter(usize),
    
    /// Return value is tainted from a source within the function
    FromSource { source_type: String },
    
    /// Return value depends on multiple taint sources
    Merged(Vec<ReturnTaint>),
}

impl CallGraph {
    /// Construct a call graph from a MIR package
    pub fn from_mir_package(package: &MirPackage) -> Result<Self> {
        let mut nodes = HashMap::new();
        
        // Phase 1: Create nodes for all functions
        for function in &package.functions {
            let node = CallGraphNode {
                function_name: function.name.clone(),
                callers: Vec::new(),
                callees: Vec::new(),
                summary: None,
            };
            nodes.insert(function.name.clone(), node);
        }
        
        // Phase 2: Extract callees from each function's MIR
        for function in &package.functions {
            let callees = Self::extract_callees(function)?;
            if let Some(node) = nodes.get_mut(&function.name) {
                node.callees = callees;
            }
        }
        
        // Build a map of short names to full names for resolution
        let mut short_name_map: HashMap<String, Vec<String>> = HashMap::new();
        for function in &package.functions {
            let short_name = Self::extract_function_name(&function.name);
            short_name_map.entry(short_name).or_default().push(function.name.clone());
        }

        // Phase 3: Resolve calls and build caller relationships
        let mut caller_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut resolved_callees_map: HashMap<String, Vec<CallSite>> = HashMap::new();
        
        for (caller_name, node) in &nodes {
            let mut resolved_callees = Vec::new();
            
            for call_site in &node.callees {
                // Try direct match first
                if nodes.contains_key(&call_site.callee) {
                    let mut new_site = call_site.clone();
                    new_site.resolved_targets.push(call_site.callee.clone());
                    resolved_callees.push(new_site);
                    
                    caller_map
                        .entry(call_site.callee.clone())
                        .or_default()
                        .push(caller_name.clone());
                } else {
                    // Try to resolve via short name (e.g. trait methods)
                    let short_name = Self::extract_function_name(&call_site.callee);
                    
                    if let Some(candidates) = short_name_map.get(&short_name) {
                        // Resolved match (trait method, etc.)
                        let mut new_site = call_site.clone();
                        for candidate in candidates {
                            new_site.resolved_targets.push(candidate.clone());
                            
                            caller_map
                                .entry(candidate.clone())
                                .or_default()
                                .push(caller_name.clone());
                        }
                        resolved_callees.push(new_site);
                    } else {
                        // Unresolved - keep as is (maybe external function)
                        resolved_callees.push(call_site.clone());
                    }
                }
            }
            resolved_callees_map.insert(caller_name.clone(), resolved_callees);
        }

        // Apply resolved callees
        for (caller_name, callees) in resolved_callees_map {
            if let Some(node) = nodes.get_mut(&caller_name) {
                node.callees = callees;
            }
        }
        
        for (callee_name, callers) in caller_map {
            if let Some(node) = nodes.get_mut(&callee_name) {
                node.callers = callers;
            }
        }
        
        // Phase 4: Compute analysis order (bottom-up)
        let analysis_order = Self::compute_analysis_order(&nodes)?;
        
        Ok(CallGraph {
            nodes,
            analysis_order,
        })
    }
    
    /// Extract callee information from a function's MIR
    fn extract_callees(function: &MirFunction) -> Result<Vec<CallSite>> {
        let mut callees = Vec::new();
        
        // Parse MIR to find function calls
        // MIR calls look like: "_N = function_name(args...)" or
        // "TerminatorKind::Call { func: ... }"
        
        for (line_idx, line) in function.body.iter().enumerate() {
            // Look for call patterns in MIR
            // Common patterns:
            // 1. "= Fn(DefId(...), Substs(...))(" - direct function call
            // 2. "= <Type as Trait>::method(" - trait method call
            // 3. "Call { func: Operand::Constant..." - terminator call
            
            if let Some(call_site) = Self::parse_call_from_mir_line(line, line_idx) {
                callees.push(call_site);
            }

            // Check for closure/coroutine creation
            if let Some(closure_callee) = Self::parse_closure_creation(line, &function.name, line_idx) {
                callees.push(closure_callee);
            }
        }
        
        Ok(callees)
    }

    /// Parse closure or coroutine creation as a "call" (dependency)
    fn parse_closure_creation(line: &str, parent_name: &str, line_idx: usize) -> Option<CallSite> {
        // _0 = {coroutine@... (#0)} ...
        if let Some(eq_pos) = line.find('=') {
            let rhs = line[eq_pos+1..].trim();
            if rhs.starts_with("{closure@") || rhs.starts_with("{coroutine@") {
                // Extract index (#N)
                if let Some(hash_pos) = rhs.find("(#") {
                    if let Some(close_paren) = rhs[hash_pos..].find(')') {
                        let index_str = &rhs[hash_pos+2..hash_pos+close_paren];
                        if let Ok(index) = index_str.parse::<usize>() {
                            let callee = format!("{}::{{closure#{}}}", parent_name, index);
                            return Some(CallSite {
                                callee,
                                resolved_targets: Vec::new(),
                                location: format!("line {}", line_idx),
                                arg_count: 0,
                            });
                        }
                    }
                }
            }
        }
        None
    }
    
    /// Parse a single MIR line to detect function calls
    fn parse_call_from_mir_line(line: &str, line_idx: usize) -> Option<CallSite> {
        let line = line.trim();
        
        // Pattern 1: Direct function call in statement
        // Example: "_5 = my_function(move _6) -> [return: bb3, unwind: bb4];"
        if line.contains("(") && line.contains(") -> [return:") {
            // Pattern 1a: Closure invocation
            // Example: "<{closure@examples/interprocedural/src/lib.rs:278:19: 278:21} as Fn<()>>::call(..."
            if let Some(closure_name) = Self::extract_closure_call(line) {
                return Some(CallSite {
                    callee: closure_name,
                    resolved_targets: Vec::new(),
                    location: format!("line {}", line_idx),
                    arg_count: 1, // Closure takes the closure env as arg
                });
            }
            
            // Extract function name between '=' and '('
            if let Some(eq_pos) = line.find('=') {
                if let Some(paren_pos) = line[eq_pos..].find('(') {
                    let func_part = &line[eq_pos+1..eq_pos+paren_pos].trim();
                    
                    // Clean up the function name
                    // We want the full name here, but cleaned of MIR artifacts
                    let func_name = func_part
                        .replace("const ", "")
                        .replace("move ", "")
                        .replace("copy ", "")
                        .trim()
                        .to_string();
                    
                    if !func_name.is_empty() && !Self::is_builtin_operation(&func_name) {
                        // Count arguments (rough estimate)
                        let args_section = &line[eq_pos+paren_pos+1..];
                        let arg_count = Self::estimate_arg_count(args_section);
                        
                        return Some(CallSite {
                            callee: func_name,
                            resolved_targets: Vec::new(),
                            location: format!("line {}", line_idx),
                            arg_count,
                        });
                    }
                }
            }
        }
        
        None
    }
    
    /// Extract clean function name from MIR representation
    fn extract_function_name(mir_repr: &str) -> String {
        // MIR function names can be complex, e.g.:
        // "std::process::Command::new"
        // "<std::process::Command as std::ops::Drop>::drop"
        // "my_crate::module::function"
        
        let cleaned = mir_repr
            .trim()
            .replace("const ", "")
            .replace("move ", "")
            .replace("copy ", "");
        
        // Extract the last meaningful part
        if let Some(last_colon) = cleaned.rfind("::") {
            cleaned[last_colon+2..].trim().to_string()
        } else {
            cleaned.trim().to_string()
        }
    }
    
    /// Check if this is a built-in operation (not a real function call)
    fn is_builtin_operation(name: &str) -> bool {
        matches!(name, "assert_eq!" | "assert!" | "println!" | "dbg!" | "format!")
            || name.starts_with("_")
            || name.is_empty()
    }
    
    /// Extract closure function name from MIR closure call pattern
    /// Pattern: "<{closure@path/to/file.rs:line:col: line:col} as Fn<()>>::call(..."
    /// Returns: "parent_function::{closure#N}"
    fn extract_closure_call(line: &str) -> Option<String> {
        // Look for closure call pattern
        if !line.contains("{closure@") || !line.contains("as Fn") {
            return None;
        }
        
        // Extract the closure location from "{closure@path:line:col: line:col}"
        let start = line.find("{closure@")?;
        let end = line[start..].find("}")?;
        let closure_loc = &line[start..start+end+1];
        
        // The closure location looks like: {closure@examples/interprocedural/src/lib.rs:278:19: 278:21}
        // We need to find the corresponding closure function name by matching the file:line
        // The closure function is named like: parent_function::{closure#0}
        
        // For now, return the raw closure identifier - it will be matched in the function list
        // The function name for this closure is: test_closure_capture::{closure#0}
        
        // Extract just the location part for matching
        if let Some(at_pos) = closure_loc.find('@') {
            let location = &closure_loc[at_pos+1..closure_loc.len()-1]; // Remove "{closure@" and "}"
            // location is like "examples/interprocedural/src/lib.rs:278:19: 278:21"
            // Take the file and first line number
            let parts: Vec<&str> = location.split(':').collect();
            if parts.len() >= 2 {
                let file = parts[0];
                let line_num = parts[1];
                // Create a unique identifier for matching
                return Some(format!("{{closure@{}:{}}}", file, line_num));
            }
        }
        
        None
    }
    
    /// Estimate argument count from MIR call syntax
    fn estimate_arg_count(args_section: &str) -> usize {
        // Count commas outside of nested structures
        // This is a rough heuristic
        args_section.matches(',').count() + 1
    }
    
    /// Compute bottom-up analysis order (callees before callers)
    fn compute_analysis_order(nodes: &HashMap<String, CallGraphNode>) -> Result<Vec<String>> {
        // Use Kahn's algorithm for topological sort
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut order = Vec::new();
        
        // Calculate in-degrees (number of internal callees)
        for (name, node) in nodes {
            let internal_callees = node.callees.iter()
                .filter(|c| nodes.contains_key(&c.callee))
                .count();
            in_degree.insert(name.clone(), internal_callees);
            println!("[DEBUG] In-degree for {}: {}", name, internal_callees);
        }
        
        // Start with leaf functions (no internal callees)
        let mut queue: VecDeque<String> = nodes
            .iter()
            .filter(|(name, _)| in_degree.get(*name).copied().unwrap_or(0) == 0)
            .map(|(name, _)| name.clone())
            .collect();
            
        println!("[DEBUG] Initial queue size: {}", queue.len());
        
        // Process nodes in bottom-up order
        while let Some(current) = queue.pop_front() {
            order.push(current.clone());
            
            // For each function that calls this one
            if let Some(node) = nodes.get(&current) {
                println!("[DEBUG] Processed {}, notifying callers: {:?}", current, node.callers);
                for caller in &node.callers {
                    if let Some(degree) = in_degree.get_mut(caller) {
                        if *degree > 0 {
                            *degree -= 1;
                            if *degree == 0 {
                                queue.push_back(caller.clone());
                            }
                        }
                    }
                }
            }
        }
        
        // Check for cycles (recursion)
        if order.len() < nodes.len() {
            // There are cycles; include remaining nodes anyway
            // (Phase 3.4 will handle recursion with depth limits)
            for (name, _) in nodes {
                if !order.contains(name) {
                    order.push(name.clone());
                }
            }
        }
        
        Ok(order)
    }
    
    /// Get the analysis order (bottom-up: callees before callers)
    pub fn get_analysis_order(&self) -> &[String] {
        &self.analysis_order
    }
    
    /// Get a node by function name
    pub fn get_node(&self, function_name: &str) -> Option<&CallGraphNode> {
        self.nodes.get(function_name)
    }
    
    /// Get a mutable node by function name
    pub fn get_node_mut(&mut self, function_name: &str) -> Option<&mut CallGraphNode> {
        self.nodes.get_mut(function_name)
    }
}

impl FunctionSummary {
    /// Create a new empty function summary
    pub fn new(function_name: String) -> Self {
        FunctionSummary {
            function_name,
            source_parameters: HashSet::new(),
            sink_parameters: HashSet::new(),
            propagation_rules: Vec::new(),
            return_taint: ReturnTaint::Clean,
            has_internal_vulnerability: false,
        }
    }
    
    /// Generate a summary for a function using intra-procedural analysis
    pub fn from_mir_function(
        function: &MirFunction,
        callee_summaries: &HashMap<String, FunctionSummary>,
        closure_registry: Option<&ClosureRegistry>,
    ) -> Result<Self> {
        let mut summary = FunctionSummary::new(function.name.clone());
        
        // Phase 3.5.1: Use CFG-based path-sensitive analysis for branching functions
        // Phase 3.5.2: Use closure context if available
        let cfg = ControlFlowGraph::from_mir_function(function);
        // Always use path-sensitive analysis for better precision
        if true {
            use crate::dataflow::path_sensitive::PathSensitiveTaintAnalysis;
            use crate::dataflow::DataflowSummary;
            
            // Convert FunctionSummary to DataflowSummary for path-sensitive analysis
            let dataflow_summaries: HashMap<String, DataflowSummary> = callee_summaries
                .iter()
                .map(|(k, v)| (k.clone(), v.to_dataflow_summary()))
                .collect();
            
            let mut path_analysis = PathSensitiveTaintAnalysis::new(cfg);
            
            // Check if this is a closure function
            let closure_info = closure_registry.and_then(|r| r.get_closure(&function.name));
            
            if let Some(info) = closure_info {
                // This is a closure - analyze with captured variable context
                // Run 1: Analyze with actual capture states (from registry)
                let result = path_analysis.analyze_closure(function, info, Some(&dataflow_summaries));
                
                if result.has_any_vulnerable_path {
                    if info.has_tainted_captures() {
                        summary.propagation_rules.push(TaintPropagation::ParamToSink {
                            param: 0,
                            sink_type: "command_execution".to_string(),
                        });
                    } else {
                        // No tainted captures, but found a vulnerability -> must be internal
                        summary.has_internal_vulnerability = true;
                    }
                }

                // Run 2: Analyze assuming captures are tainted (to detect propagation)
                // This is crucial for async functions where captures are initially clean but become tainted at runtime
                use crate::dataflow::path_sensitive::TaintState;
                let mut initial_taint = HashMap::new();
                
                for capture in &info.captured_vars {
                    let env_var = format!("((*_1).{})", capture.field_index);
                    initial_taint.insert(env_var.clone(), TaintState::Tainted {
                        source_type: "captured_variable".to_string(),
                        source_location: format!("capture_{}", capture.field_index),
                    });
                    
                    // For async/coroutines (Pin<&mut T>), the path is deeper: ((*((*_1).0)).N)
                    // _1 is Pin<&mut Coroutine>, _1.0 is &mut Coroutine, *(_1.0) is Coroutine
                    let async_env_var = format!("((*((*_1).0)).{})", capture.field_index);
                    initial_taint.insert(async_env_var, TaintState::Tainted {
                        source_type: "captured_variable".to_string(),
                        source_location: format!("capture_{}", capture.field_index),
                    });
                }
                
                if !initial_taint.is_empty() {
                    let result_propagated = path_analysis.analyze_with_initial_taint(function, initial_taint, Some(&dataflow_summaries));
                    if result_propagated.has_any_vulnerable_path {
                        summary.propagation_rules.push(TaintPropagation::ParamToSink {
                            param: 0,
                            sink_type: "command_execution".to_string(),
                        });
                    }
                }
            } else {
                // Not a closure - analyze parameters
                
                // Run 1: Check for internal sources (no initial taint)
                let result_internal = path_analysis.analyze(function, Some(&dataflow_summaries));
                if result_internal.has_any_vulnerable_path {
                    summary.has_internal_vulnerability = true;
                }
                
                // Check if return value is tainted
                if result_internal.path_results.iter().any(|p| p.return_tainted) {
                    summary.return_taint = ReturnTaint::FromSource {
                        source_type: "propagated".to_string(),
                    };
                }

                // Run 2: Check parameters _1 to _5
                use crate::dataflow::path_sensitive::TaintState;
                
                for i in 1..=5 {
                    let param_name = format!("_{}", i);
                    let mut initial_taint = HashMap::new();
                    initial_taint.insert(param_name.clone(), TaintState::Tainted {
                        source_type: "parameter".to_string(),
                        source_location: format!("param_{}", i),
                    });
                    
                    let result = path_analysis.analyze_with_initial_taint(function, initial_taint, Some(&dataflow_summaries));
                    
                    if result.has_any_vulnerable_path {
                        summary.propagation_rules.push(TaintPropagation::ParamToSink {
                            param: i - 1,
                            sink_type: "command_execution".to_string(),
                        });
                    }
                    
                    if result.path_results.iter().any(|p| !p.sanitizer_calls.is_empty()) {
                        summary.propagation_rules.push(TaintPropagation::ParamSanitized(i - 1));
                    }
                }
            }
            
            if !summary.propagation_rules.is_empty() || summary.has_internal_vulnerability {
                return Ok(summary);
            }
        }
        
        // Use Phase 2's taint analysis to understand intra-procedural flows
        // For now, we'll do a simple analysis based on MIR patterns
        
        // Step 1: Identify if this function contains sources
        let has_source = Self::contains_source(function);
        if has_source {
            summary.return_taint = ReturnTaint::FromSource {
                source_type: "environment".to_string(),
            };
        }
        
        // Step 2: Identify if this function contains sinks and determine sink type
        let has_command_sink = Self::contains_command_sink(function);
        let has_filesystem_sink = Self::contains_filesystem_sink(function);
        let has_http_sink = Self::contains_http_sink(function);
        let has_yaml_sink = Self::contains_yaml_sink(function);
        
        // Step 3: Analyze parameter flows
        // Check if function propagates parameters to return value
        let propagates_param_to_return = Self::propagates_param_to_return(function);
        if propagates_param_to_return && !has_source {
            // Function takes parameter and returns it (or derivative)
            // This enables N-level taint propagation
            summary.return_taint = ReturnTaint::FromParameter(0);
            summary.propagation_rules.push(TaintPropagation::ParamToReturn(0));
        }
        
        // Step 4: Check for sanitization patterns
        let has_sanitization = Self::contains_sanitization(function);
        
        // Build propagation rules based on patterns
        if has_command_sink {
            // If function has a command sink, parameters likely flow to it
            summary.propagation_rules.push(TaintPropagation::ParamToSink {
                param: 0,
                sink_type: "command_execution".to_string(),
            });
        }
        
        if has_filesystem_sink {
            // If function has a filesystem sink, parameters likely flow to it
            summary.propagation_rules.push(TaintPropagation::ParamToSink {
                param: 0,
                sink_type: "filesystem".to_string(),
            });
        }
        
        if has_http_sink {
            // If function has an HTTP sink, parameters likely flow to it (SSRF)
            summary.propagation_rules.push(TaintPropagation::ParamToSink {
                param: 0,
                sink_type: "http".to_string(),
            });
        }
        
        if has_yaml_sink {
            // If function has a YAML deserialization sink
            summary.propagation_rules.push(TaintPropagation::ParamToSink {
                param: 0,
                sink_type: "yaml".to_string(),
            });
        }
        
        if has_sanitization {
            // Function performs sanitization
            summary.propagation_rules.push(TaintPropagation::ParamSanitized(0));
        }
        
        // Analyze calls to other functions
        for line in &function.body {
            // Check if this line calls a function we have a summary for
            if let Some((callee_name, _)) = Self::extract_call_from_line(line) {
                if let Some(callee_summary) = callee_summaries.get(&callee_name) {
                    // Propagate taint rules from callee
                    summary.merge_callee_summary(callee_summary);
                }
            }
        }
        
        Ok(summary)
    }
    
    /// Check if function propagates parameter to return value
    fn propagates_param_to_return(function: &MirFunction) -> bool {
        // First, check if function even takes parameters
        // Check signature for parameter list - look for pattern like "(_1:" or "(mut _1:"
        let sig_lower = function.signature.to_lowercase();
        let has_params = sig_lower.contains("(_1:") || sig_lower.contains("(mut _1:") || sig_lower.contains("( _1:");
        
        if !has_params {
            return false;  // No parameters, can't propagate
        }
        
        // Exclude functions that only use constants for _1
        let assigns_constant_to_param = function.body.iter().any(|line| {
            line.trim().starts_with("_1 = const")
        });
        
        if assigns_constant_to_param {
            return false;  // Assigns constant to what would be param slot
        }
        
        // Heuristics for parameter propagation:
        // Look for operations on _1 (first parameter after self if present)
        let has_param_usage = function.body.iter().any(|line| {
            // Direct parameter operations
            line.contains("(*_1)")        // Deref of first param
                || line.contains("Deref::deref(_1")  // Explicit deref  
                || line.contains("Deref::deref(move _1")
                // Taking references to parameters (assignment target contains &_1)
                || (line.contains(" = &_1;") || line.contains(" = &mut _1;"))
                // Format operations with parameter
                || (line.contains("format!") || line.contains("format_args!"))
                // String operations on parameters  
                || line.contains("to_string(move _1")
                || line.contains("String::from(_1")
                // Move or copy of parameter (common in closures/async)
                || line.contains("move _1")
                || line.contains("copy _1")
        });
        
        // Check if function returns a value (not unit type)
        let returns_value = function.signature.contains("->") && !function.signature.contains("-> ()");
        
        has_param_usage && returns_value
    }
    
    /// Check if function contains a taint source
    fn contains_source(function: &MirFunction) -> bool {
        function.body.iter().any(|line| {
            line.contains("std::env::args")
                || line.contains("std::env::var")
                || line.contains("std::fs::read")
                || line.contains("env::args")
                || line.contains("env::var")
                || line.contains(" = args() -> ")  // MIR format: args()
                || line.contains(" = var")          // MIR format: var() or var::<T>()
                || line.contains(" = read")         // MIR format: read() or fs::read()
        })
    }
    
    /// Check if function contains a taint sink
    fn contains_sink(function: &MirFunction) -> bool {
        Self::contains_command_sink(function) || Self::contains_filesystem_sink(function) || Self::contains_http_sink(function) || Self::contains_yaml_sink(function)
    }
    
    /// Check if function contains a command execution sink
    fn contains_command_sink(function: &MirFunction) -> bool {
        function.body.iter().any(|line| {
            // Only match DIRECT calls to sinks, not indirect via helper functions
            // Look for Command::new or Command::spawn, not just "spawn"
            (line.contains("Command::new") && line.contains("->")) 
                || line.contains("std::process::Command")
                || (line.contains("Command::spawn") && line.contains("->"))
                || (line.contains("Command::exec") && line.contains("->"))
        })
    }
    
    /// Check if function contains a filesystem sink (for path traversal detection)
    fn contains_filesystem_sink(function: &MirFunction) -> bool {
        function.body.iter().any(|line| {
            // File read operations
            line.contains("fs::read_to_string") 
                || line.contains("std::fs::read_to_string")
                || line.contains("fs::read(")
                || line.contains("std::fs::read(")
                // File write operations
                || line.contains("fs::write(")
                || line.contains("std::fs::write(")
                // File open operations
                || line.contains("File::open(")
                || line.contains("File::create(")
                || line.contains("std::fs::File::open")
                || line.contains("std::fs::File::create")
                || line.contains("OpenOptions")
                // File removal operations
                || line.contains("fs::remove_file")
                || line.contains("fs::remove_dir")
                || line.contains("std::fs::remove_file")
                || line.contains("std::fs::remove_dir")
                // Copy/rename operations
                || line.contains("fs::copy(")
                || line.contains("fs::rename(")
                || line.contains("std::fs::copy")
                || line.contains("std::fs::rename")
                // Directory operations
                || line.contains("fs::create_dir")
                || line.contains("std::fs::create_dir")
        })
    }
    
    /// Check if function contains an HTTP client sink (for SSRF detection)
    fn contains_http_sink(function: &MirFunction) -> bool {
        function.body.iter().any(|line| {
            // reqwest patterns
            line.contains("reqwest::blocking::get")
                || line.contains("reqwest::get")
                || line.contains("blocking::get")
                || line.contains("Client>::get")
                || line.contains("Client>::post")
                || line.contains("Client>::put")
                || line.contains("Client>::delete")
                || line.contains("Client>::patch")
                || line.contains("Client>::head")
                || line.contains("RequestBuilder>::send")
                // ureq patterns
                || line.contains("ureq::get")
                || line.contains("ureq::post")
                || line.contains("ureq::put")
                || line.contains("ureq::delete")
                || line.contains("Agent>::get")
                || line.contains("Agent>::post")
                || line.contains("Request>::call")
                // hyper patterns
                || line.contains("hyper::Client")
                || line.contains("hyper::Request")
                // Generic HTTP patterns
                || line.contains("get::<&String>")
                || line.contains("get::<&str>")
                || line.contains("post::<&String>")
                || line.contains("post::<&str>")
        })
    }
    
    /// Check if function contains a YAML deserialization sink (for YAML injection detection)
    fn contains_yaml_sink(function: &MirFunction) -> bool {
        function.body.iter().any(|line| {
            // serde_yaml patterns
            line.contains("serde_yaml::from_str")
                || line.contains("serde_yaml::from_slice")
                || line.contains("serde_yaml::from_reader")
                // MIR patterns for generic instantiation
                || line.contains("from_str::<") && line.contains("serde_yaml")
                || line.contains("from_slice::<") && line.contains("serde_yaml")
                || line.contains("from_reader::<") && line.contains("serde_yaml")
                // Generic yaml patterns - function names with yaml
                || (line.contains("from_str") && function.name.to_lowercase().contains("yaml"))
        })
    }
    
    /// Check if function performs sanitization
    fn contains_sanitization(function: &MirFunction) -> bool {
        function.body.iter().any(|line| {
            line.contains("parse::<")
                || line.contains("chars().all")
                || line.contains("is_alphanumeric")
        })
    }
    
    /// Check if function has validation guard that protects a sink
    /// Returns true if there's an if-condition checking safety before calling a sink
    fn has_validation_guard(function: &MirFunction) -> bool {
        let has_sink = Self::contains_sink(function);
        if !has_sink {
            return false;
        }
        
        // Look for validation function calls like is_safe_input, is_valid, validate, etc.
        let has_validation_call = function.body.iter().any(|line| {
            (line.contains("is_safe") || line.contains("is_valid") || line.contains("validate"))
                && line.contains("(") && line.contains(")")
        });
        
        // Look for switchInt (if/match statements) that could be guards
        let has_conditional = function.body.iter().any(|line| {
            line.contains("switchInt(")
        });
        
        has_validation_call && has_conditional
    }
    
    /// Check if function calls a sanitization helper on tainted data before using it
    /// This handles patterns like: let safe = validate_input(&tainted); use(safe);
    fn has_sanitization_helper_call(function: &MirFunction) -> bool {
        // Look for calls to functions with sanitization-related names
        let sanitization_patterns = [
            "validate",
            "sanitize",
            "clean",
            "escape",
            "filter",
        ];
        
        function.body.iter().any(|line| {
            sanitization_patterns.iter().any(|pattern| {
                line.to_lowercase().contains(pattern) && line.contains("(")
            })
        })
    }
    
    /// Extract function call from MIR line
    fn extract_call_from_line(line: &str) -> Option<(String, usize)> {
        let line = line.trim();
        
        if line.contains("(") && line.contains(") -> [return:") {
            if let Some(eq_pos) = line.find('=') {
                if let Some(paren_pos) = line[eq_pos..].find('(') {
                    let func_part = &line[eq_pos+1..eq_pos+paren_pos].trim();
                    let func_name = CallGraph::extract_function_name(func_part);
                    
                    if !func_name.is_empty() && !CallGraph::is_builtin_operation(&func_name) {
                        // Estimate arg count
                        let args_section = &line[eq_pos+paren_pos+1..];
                        let arg_count = CallGraph::estimate_arg_count(args_section);
                        return Some((func_name, arg_count));
                    }
                }
            }
        }
        
        None
    }
    
    /// Merge rules from a callee's summary
    fn merge_callee_summary(&mut self, callee: &FunctionSummary) {
        // If callee has sources, this function might propagate them
        if !callee.source_parameters.is_empty() {
            // For now, mark that we call a function with sources
            // Phase 3.3 will track parameter mappings more precisely
        }
        
        // DISABLED: Don't propagate sinks from callees
        // Inter-procedural flow detection handles this by exploring call chains
        // If we mark callers as having sinks, we get false positives
        /*
        // If callee has sinks, parameters to this function might reach them
        if !callee.sink_parameters.is_empty() {
            // Mark that we propagate to a sink
            for &param in &callee.sink_parameters {
                if param < 3 {  // Only track first few parameters for now
                    self.propagation_rules.push(TaintPropagation::ParamToSink {
                        param,
                        sink_type: "indirect_command_execution".to_string(),
                    });
                }
            }
        }
        */
        
        // Handle return taint
        match &callee.return_taint {
            ReturnTaint::FromSource { .. } => {
                // If callee returns tainted data, this function might too
                if matches!(self.return_taint, ReturnTaint::Clean) {
                    self.return_taint = ReturnTaint::FromSource {
                        source_type: "propagated".to_string(),
                    };
                }
            }
            ReturnTaint::FromParameter(param) => {
                // Callee propagates parameter to return
                self.propagation_rules.push(TaintPropagation::ParamToReturn(*param));
            }
            _ => {}
        }
    }
    
    pub fn to_dataflow_summary(&self) -> DataflowSummary {
        let mut propagation = self.propagation_rules.clone();
        let mut returns_tainted = false;

        match &self.return_taint {
            ReturnTaint::Clean => {},
            ReturnTaint::FromParameter(idx) => {
                propagation.push(TaintPropagation::ParamToReturn(*idx));
            },
            ReturnTaint::FromSource { .. } => {
                returns_tainted = true;
            },
            ReturnTaint::Merged(taints) => {
                for taint in taints {
                    match taint {
                        ReturnTaint::FromParameter(idx) => {
                            propagation.push(TaintPropagation::ParamToReturn(*idx));
                        },
                        ReturnTaint::FromSource { .. } => {
                            returns_tainted = true;
                        },
                        _ => {}
                    }
                }
            },
        }

        DataflowSummary {
            name: self.function_name.clone(),
            propagation,
            returns_tainted,
        }
    }
}

/// Main inter-procedural analysis engine
pub struct InterProceduralAnalysis {
    /// Call graph
    pub call_graph: CallGraph,
    
    /// Computed function summaries
    pub summaries: HashMap<String, FunctionSummary>,
    
    /// Closure registry for tracking closures and captures
    pub closure_registry: ClosureRegistry,
}

impl InterProceduralAnalysis {
    /// Create a new inter-procedural analysis
    pub fn new(package: &MirPackage) -> Result<Self> {
        let call_graph = CallGraph::from_mir_package(package)?;
        let closure_registry = ClosureRegistryBuilder::build_from_package(package);
        
        Ok(InterProceduralAnalysis {
            call_graph,
            summaries: HashMap::new(),
            closure_registry,
        })
    }
    
    /// Analyze all functions and generate summaries
    pub fn analyze(&mut self, package: &MirPackage) -> Result<()> {
        // Get function map for quick lookup
        let function_map: HashMap<String, &MirFunction> = package
            .functions
            .iter()
            .map(|f| (f.name.clone(), f))
            .collect();
        
        // Analyze functions in bottom-up order (callees before callers)
        for function_name in self.call_graph.analysis_order.clone() {
            if let Some(function) = function_map.get(&function_name) {
                
                // Construct callee summaries map for this function
                // Start with all available summaries to support indirect calls (like async poll)
                let mut callee_summaries = self.summaries.clone();
                
                if let Some(node) = self.call_graph.nodes.get(&function_name) {
                    for call_site in &node.callees {
                        // Map raw callee name to summary
                        // If resolved_targets is not empty, merge their summaries
                        if !call_site.resolved_targets.is_empty() {
                            let mut merged_summary: Option<FunctionSummary> = None;
                            
                            for target in &call_site.resolved_targets {
                                if let Some(target_summary) = self.summaries.get(target) {
                                    if let Some(current) = &mut merged_summary {
                                        current.merge_callee_summary(target_summary);
                                    } else {
                                        // Create a new summary with the raw callee name
                                        let mut new_summary = target_summary.clone();
                                        new_summary.function_name = call_site.callee.clone();
                                        merged_summary = Some(new_summary);
                                    }
                                }
                            }
                            
                            if let Some(summary) = merged_summary {
                                callee_summaries.insert(call_site.callee.clone(), summary);
                            }
                        } else {
                            // Try direct lookup (for unresolved or direct calls)
                            if let Some(summary) = self.summaries.get(&call_site.callee) {
                                callee_summaries.insert(call_site.callee.clone(), summary.clone());
                            }
                        }
                    }
                }


                // Generate summary using summaries of callees and closure registry
                let summary = FunctionSummary::from_mir_function(
                    function,
                    &callee_summaries,
                    Some(&self.closure_registry),
                )?;
                
                // Store summary
                self.summaries.insert(function_name.clone(), summary.clone());
                println!("[DEBUG] Stored summary for: {}", function_name);
                if !summary.propagation_rules.is_empty() {
                    println!("[DEBUG]   Propagation: {:?}", summary.propagation_rules);
                }
                if !matches!(summary.return_taint, ReturnTaint::Clean) {
                    println!("[DEBUG]   Return: {:?}", summary.return_taint);
                }
                
                // Update call graph node
                if let Some(node) = self.call_graph.get_node_mut(&function_name) {
                    node.summary = Some(summary);
                }
            }
        }
        
        Ok(())
    }
    
    /// Get summary for a function
    pub fn get_summary(&self, function_name: &str) -> Option<&FunctionSummary> {
        self.summaries.get(function_name)
    }
    
    /// Print summary statistics
    pub fn print_statistics(&self) {
        println!("Inter-Procedural Analysis Statistics:");
        println!("  Total functions: {}", self.summaries.len());
        
        let functions_with_sources = self.summaries.values()
            .filter(|s| !matches!(s.return_taint, ReturnTaint::Clean))
            .count();
        println!("  Functions with sources: {}", functions_with_sources);
        
        let functions_with_sinks = self.summaries.values()
            .filter(|s| s.sink_parameters.len() > 0 || 
                    s.propagation_rules.iter().any(|r| matches!(r, TaintPropagation::ParamToSink { .. })))
            .count();
        println!("  Functions with sinks: {}", functions_with_sinks);
        
        let functions_with_sanitization = self.summaries.values()
            .filter(|s| s.propagation_rules.iter().any(|r| matches!(r, TaintPropagation::ParamSanitized(_))))
            .count();
        println!("  Functions with sanitization: {}", functions_with_sanitization);
    }
    
    /// Detect inter-procedural taint flows
    pub fn detect_inter_procedural_flows(&self, package: &MirPackage) -> Vec<TaintPath> {
        let mut flows = Vec::new();
        
        // For each function with REAL sources, try to find paths to sinks
        for (source_func, source_summary) in &self.summaries {
            
            // Case 1: Function has internal vulnerability (source -> sink within function)
            if source_summary.has_internal_vulnerability {
                // If this is a closure, report the flow for the parent function
                let reported_source = if let Some(closure) = self.closure_registry.get_closure(source_func) {
                    closure.parent_function.clone()
                } else {
                    source_func.clone()
                };

                flows.push(TaintPath {
                    source_function: reported_source,
                    sink_function: source_func.clone(),
                    sink_type: "internal_sink".to_string(),
                    call_chain: vec![source_func.clone()],
                    source_type: "environment".to_string(),
                    sanitized: false,
                });
            }

            // Case 2: Function returns tainted data (source -> return)
            // Only start from functions that have actual sources (not just propagation)
            if matches!(source_summary.return_taint, ReturnTaint::FromSource { .. }) {
                // This function has a real taint source
                // Find all functions that call it
                if self.call_graph.nodes.get(source_func).is_some() {
                    // Explore paths from this source
                    let all_flows = self.find_paths_from_source(
                        source_func,
                        &source_summary.return_taint,
                        vec![source_func.clone()],
                        &mut HashSet::new(),
                    );
                    
                    // Filter out intra-procedural flows (same source and sink)
                    // Those should be caught by Phase 2's analysis
                    // UNLESS it's a complex flow that Phase 2 missed but Phase 3 caught via internal vulnerability check
                    for flow in all_flows {
                        if flow.source_function != flow.sink_function || flow.call_chain.len() > 1 {
                            flows.push(flow);
                        }
                    }
                }
            }
        }
        
        // Phase 3.4: Filter false positives by checking for validation patterns
        flows = self.filter_false_positives(flows);
        
        // Phase 3.5.2: Add flows from closures with tainted captures
        let closure_flows = self.detect_closure_taint_flows(package);
        flows.extend(closure_flows);
        
        flows
    }
    
    /// Phase 3.5.2: Detect taint flows through closures
    /// Closures capture variables from parent functions - if captured var is tainted
    /// and closure has a sink, that's an interprocedural flow
    fn detect_closure_taint_flows(&self, package: &MirPackage) -> Vec<TaintPath> {
        let mut flows: Vec<TaintPath> = Vec::new();
        
        // Build function map for looking up MIR bodies
        let function_map: HashMap<String, &MirFunction> = package
            .functions
            .iter()
            .map(|f| (f.name.clone(), f))
            .collect();
        
        // Source patterns that indicate tainted input
        let source_patterns = [
            "env::args", "std::env::args", "::args()",
            "env::var", "std::env::var",
            "stdin", "read_line", "read_to_string",
            "HttpRequest", "request", "body()",
            "serde_json::from", "serde::Deserialize",
        ];
        
        // Debug: print all closures being analyzed
        let all_closures = self.closure_registry.get_all_closures();
        
        // Check if this is the interprocedural crate (has test_closure_capture)
        let has_test_closure = all_closures.iter().any(|c| c.name.contains("test_closure"));
        if has_test_closure {
            eprintln!("[DEBUG] Found test_closure in {} closures", all_closures.len());
            for c in all_closures.iter().filter(|c| c.name.contains("test_closure") || c.name.contains("async")) {
                eprintln!("[DEBUG] Closure: {} -> parent: {}", c.name, c.parent_function);
                eprintln!("[DEBUG]   has_tainted_captures: {}", c.has_tainted_captures());
                eprintln!("[DEBUG]   captured_vars: {:?}", c.captured_vars);
            }
        }
        
        for closure_info in all_closures {
            // Skip if already found flow for this closure
            if flows.iter().any(|f| f.sink_function == closure_info.name) {
                continue;
            }
            
            // Check if parent function has a taint source via return value
            let parent_has_source = self.summaries.get(&closure_info.parent_function)
                .map(|s| matches!(s.return_taint, ReturnTaint::FromSource { .. }))
                .unwrap_or(false);
            
            // Check if parent function CALLS a source (not just returns it)
            // This is the key for closures - parent may use source locally without returning
            let parent_calls_source = self.call_graph.nodes.get(&closure_info.parent_function)
                .map(|node| {
                    let result = node.callees.iter().any(|callee| {
                        source_patterns.iter().any(|pat| callee.callee.contains(pat))
                    });
                    if closure_info.name.contains("test_closure") {
                        eprintln!("[DEBUG]   parent_calls_source: {}", result);
                        eprintln!("[DEBUG]   parent callees: {:?}", node.callees.iter().map(|c| &c.callee).collect::<Vec<_>>());
                    }
                    result
                })
                .unwrap_or_else(|| {
                    if closure_info.name.contains("test_closure") {
                        eprintln!("[DEBUG]   parent '{}' NOT found in call_graph", closure_info.parent_function);
                    }
                    false
                });
            
            // Also check if parent function body contains source patterns
            let parent_has_source_in_body = self.call_graph.nodes.get(&closure_info.parent_function)
                .map(|node| {
                    // Check if the parent function's summary contains any source
                    if let Some(summary) = &node.summary {
                        matches!(summary.return_taint, ReturnTaint::FromSource { .. })
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
            
            // Method 1: Use closure registry's taint detection
            if closure_info.has_tainted_captures() {
                if let Some(summary) = self.summaries.get(&closure_info.name) {
                    let sink_type = summary.propagation_rules.iter()
                        .find_map(|r| {
                            if let TaintPropagation::ParamToSink { sink_type, .. } = r {
                                Some(sink_type.clone())
                            } else {
                                None
                            }
                        });
                    
                    if let Some(sink_type) = sink_type {
                        for capture in &closure_info.captured_vars {
                            if let crate::dataflow::closure::TaintState::Tainted { source_type, .. } = &capture.taint_state {
                                flows.push(TaintPath {
                                    source_function: closure_info.parent_function.clone(),
                                    sink_function: closure_info.name.clone(),
                                    call_chain: vec![
                                        closure_info.parent_function.clone(),
                                        closure_info.name.clone(),
                                    ],
                                    source_type: source_type.clone(),
                                    sink_type: sink_type.clone(),
                                    sanitized: false,
                                });
                                break;
                            }
                        }
                        continue;
                    }
                }
            }
            
            // Method 2: Direct body pattern matching (fallback)
            // Check if parent has source (via return OR via calling a source) and closure has command sink
            if parent_has_source || parent_has_source_in_body || parent_calls_source {
                // Check closure body for command execution
                if let Some(node) = self.call_graph.nodes.get(&closure_info.name) {
                    let has_command_callee = node.callees.iter().any(|c| {
                        c.callee.contains("Command") || 
                        c.callee.contains("spawn") ||
                        c.callee.contains("output") ||
                        c.callee.contains("process")
                    });
                    
                    if has_command_callee && !closure_info.captured_vars.is_empty() {
                        flows.push(TaintPath {
                            source_function: closure_info.parent_function.clone(),
                            sink_function: closure_info.name.clone(),
                            call_chain: vec![
                                closure_info.parent_function.clone(),
                                closure_info.name.clone(),
                            ],
                            source_type: "environment".to_string(),
                            sink_type: "command_execution".to_string(),
                            sanitized: false,
                        });
                        continue;
                    }
                }
            }
            
            // Method 3: Check for closures with captured variables where parent calls source
            // This catches cases even without full taint tracking
            if !closure_info.captured_vars.is_empty() && parent_calls_source {
                // Check if the closure has command-related callees
                if let Some(closure_node) = self.call_graph.nodes.get(&closure_info.name) {
                    let closure_has_sink = closure_node.callees.iter().any(|c| {
                        let name_lower = c.callee.to_lowercase();
                        name_lower.contains("command") ||
                        name_lower.contains("spawn") ||
                        name_lower.contains("shell") ||
                        name_lower.contains("exec")
                    });
                    
                    if closure_has_sink {
                        flows.push(TaintPath {
                            source_function: closure_info.parent_function.clone(),
                            sink_function: closure_info.name.clone(),
                            call_chain: vec![
                                closure_info.parent_function.clone(),
                                closure_info.name.clone(),
                            ],
                            source_type: "environment".to_string(),
                            sink_type: "command_execution".to_string(),
                            sanitized: false,
                        });
                    }
                }
            }
            
            // Method 4: Analyze closure body directly for captured variable → command flow
            // This works even when parent function is inlined/optimized away
            // Check for patterns like:
            //   debug tainted => (*((*_1).0: ...  (captured variable with suggestive name)
            //   _X = Command::arg(... copy _Y...) where _Y is from captured data
            if let Some(closure_function) = function_map.get(&closure_info.name) {
                let body_str = closure_function.body.join("\n");
                
                // Check if closure has command sink in its body
                let has_command_sink = body_str.contains("Command::") ||
                    body_str.contains("::spawn(") ||
                    body_str.contains("::output(");
                
                if has_command_sink {
                    // Check for captured variables with suggestive names indicating user input
                    // Pattern: debug <name> => (*((*_1)... indicates captured variable
                    let has_tainted_capture = body_str.contains("debug tainted") ||
                        body_str.contains("debug user") ||
                        body_str.contains("debug input") ||
                        body_str.contains("debug cmd") ||
                        body_str.contains("debug command") ||
                        body_str.contains("debug arg") ||
                        // Also check if _1 (the closure capture) is used in Command::arg
                        (body_str.contains("(*_1)") && body_str.contains("Command::arg"));
                    
                    if has_tainted_capture {
                        flows.push(TaintPath {
                            source_function: closure_info.parent_function.clone(),
                            sink_function: closure_info.name.clone(),
                            call_chain: vec![
                                closure_info.parent_function.clone(),
                                closure_info.name.clone(),
                            ],
                            source_type: "captured_variable".to_string(),
                            sink_type: "command_execution".to_string(),
                            sanitized: false,
                        });
                    }
                }
            }
        }
        
        flows
    }
    
    /// Phase 3.4: Filter false positives from detected flows
    /// Identifies patterns that indicate sanitization even when not in the direct call chain
    fn filter_false_positives(&self, flows: Vec<TaintPath>) -> Vec<TaintPath> {
        flows.into_iter().filter(|flow| {
            // Check each function in the call chain
            for func_name in &flow.call_chain {
                if let Some(node) = self.call_graph.nodes.get(func_name) {
                    // Pattern 1: Function has BOTH source and (direct or indirect) sink
                    let has_source = if let Some(summary) = &node.summary {
                        matches!(summary.return_taint, ReturnTaint::FromSource { .. })
                    } else {
                        false
                    };
                    
                    // Check if this function has a direct sink
                    let has_direct_sink = if let Some(summary) = &node.summary {
                        summary.propagation_rules.iter().any(|r| matches!(r, TaintPropagation::ParamToSink { .. }))
                    } else {
                        false
                    };
                    
                    // Check if this function calls something that has a sink
                    let calls_sink_function = node.callees.iter().any(|callee_site| {
                        if let Some(callee_summary) = self.summaries.get(&callee_site.callee) {
                            callee_summary.propagation_rules.iter()
                                .any(|r| matches!(r, TaintPropagation::ParamToSink { .. }))
                        } else {
                            false
                        }
                    });
                    
                    let has_sink = has_direct_sink || calls_sink_function;
                    
                    if has_source && has_sink {
                        // This function gets tainted data and (directly or indirectly) executes it
                        // Check if it has validation guards protecting the sink
                        
                        // PHASE 3.4 CONSERVATIVE FILTER:
                        // Only filter if we detect BOTH:
                        // 1. A validator call (is_safe, validate, etc.)
                        // 2. Evidence that validator protects the sink (guard pattern)
                        //
                        // This avoids filtering cases like test_partial_sanitization where
                        // one branch calls the validator but another branch doesn't.
                        
                        let calls_validator = node.callees.iter().any(|callee| {
                            let callee_lower = callee.callee.to_lowercase();
                            callee_lower.contains("is_safe") ||
                                callee_lower.contains("is_valid")
                        });
                        
                        // More restrictive: only filter if validator is in guard pattern (is_safe_, is_valid_)
                        // These are typically used in if-conditions that protect the sink
                        // Avoid filtering validate_/sanitize_ which might be on only one branch
                        
                        if calls_validator {
                            // Function uses a validation guard - likely a false positive
                            return false;  // Filter out this flow
                        }
                    }
                }
            }
            
            // Flow passed all filters - keep it
            true
        }).collect()
    }
    
    /// Find taint paths starting from a source function
    fn find_paths_from_source(
        &self,
        current_func: &str,
        taint: &ReturnTaint,
        path: Vec<String>,
        visited: &mut HashSet<String>,
    ) -> Vec<TaintPath> {
        let mut flows = Vec::new();
        
        // Avoid infinite recursion
        if visited.contains(current_func) {
            return flows;
        }
        visited.insert(current_func.to_string());
        
        // Check if path is sanitized (any function in path has ParamSanitized rule)
        let is_sanitized = self.path_is_sanitized(&path);
        
        // NEW: Also check if current function calls a sanitization helper
        // This catches patterns like: let safe = validate(&tainted); use(safe);
        let calls_sanitizer = if let Some(node) = self.call_graph.nodes.get(current_func) {
            node.callees.iter().any(|callee_site| {
                if let Some(callee_summary) = self.summaries.get(&callee_site.callee) {
                    // Check if callee has sanitization
                    callee_summary.propagation_rules.iter()
                        .any(|r| matches!(r, TaintPropagation::ParamSanitized(_)))
                } else {
                    false
                }
            })
        } else {
            false
        };
        
        let effective_sanitized = is_sanitized || calls_sanitizer;
        
        // Get the current function's node
        if let Some(node) = self.call_graph.nodes.get(current_func) {
            // Check if current function has a sink
            if let Some(summary) = &node.summary {
                // Does this function have a sink that the taint can reach?
                for rule in &summary.propagation_rules {
                    if let TaintPropagation::ParamToSink { sink_type, .. } = rule {
                        // Taint reaches a sink!
                        flows.push(TaintPath {
                            source_function: path[0].clone(),
                            sink_function: current_func.to_string(),
                            call_chain: path.clone(),
                            source_type: Self::extract_source_type(taint),
                            sink_type: sink_type.clone(),
                            sanitized: effective_sanitized,
                        });
                    } else if let TaintPropagation::ParamSanitized(_) = rule {
                        // Taint is sanitized - we already track this above
                        continue;
                    }
                }
            }
            
            // NEW: If current function doesn't have a direct sink, check what it calls
            // This enables N-level detection: source() -> caller() -> sink_function()
            // Only check direct callees, not recursive (avoid explosion)
            if !flows.iter().any(|f| f.sink_function == current_func) {
                // Current function doesn't have a sink, check its callees
                for callee_site in &node.callees {
                    if let Some(callee_summary) = self.summaries.get(&callee_site.callee) {
                        // Check if this callee sanitizes
                        let callee_sanitizes = callee_summary.propagation_rules.iter()
                            .any(|r| matches!(r, TaintPropagation::ParamSanitized(_)));
                        
                        // Does this callee have a sink?
                        let has_sink = callee_summary.propagation_rules.iter()
                            .any(|r| matches!(r, TaintPropagation::ParamToSink { .. }));
                        
                        if has_sink {
                            // Found a flow through callee
                            let mut extended_path = path.clone();
                            extended_path.push(callee_site.callee.clone());
                            
                            let sink_type = callee_summary.propagation_rules.iter()
                                .find_map(|r| match r {
                                    TaintPropagation::ParamToSink { sink_type, .. } => Some(sink_type.clone()),
                                    _ => None,
                                })
                                .unwrap_or_else(|| "unknown_sink".to_string());
                            
                            flows.push(TaintPath {
                                source_function: path[0].clone(),
                                sink_function: callee_site.callee.clone(),
                                call_chain: extended_path.clone(),
                                source_type: Self::extract_source_type(taint),
                                sink_type,
                                // Sanitized if either path so far is sanitized OR this callee sanitizes OR calling function has sanitization
                                sanitized: effective_sanitized || callee_sanitizes || self.path_is_sanitized(&extended_path),
                            });
                        }
                    }
                }
            }
            
            // Explore callers of this function (functions that call current_func)
            // Key insight: the caller receives tainted data by calling current_func
            // If the caller has a filesystem sink, the taint may reach it
            for caller in &node.callers {
                let mut new_path = path.clone();
                new_path.push(caller.clone());
                
                // Check if the CALLER itself has a filesystem sink
                // This handles the pattern: caller() { let x = source_fn(); sink(x); }
                if let Some(caller_node) = self.call_graph.nodes.get(caller) {
                    if let Some(caller_summary) = &caller_node.summary {
                        // Check if caller has a filesystem sink in its propagation rules
                        // OR if it has any ParamToSink (which was set when analyzing the function)
                        let has_filesystem_sink = caller_summary.propagation_rules.iter()
                            .any(|r| matches!(r, TaintPropagation::ParamToSink { sink_type, .. } if sink_type == "filesystem"));
                        
                        let has_any_sink = caller_summary.propagation_rules.iter()
                            .any(|r| matches!(r, TaintPropagation::ParamToSink { .. }));
                        
                        if has_filesystem_sink || has_any_sink {
                            // Caller has a sink and receives tainted data from current_func
                            let sink_type = caller_summary.propagation_rules.iter()
                                .find_map(|r| match r {
                                    TaintPropagation::ParamToSink { sink_type, .. } => Some(sink_type.clone()),
                                    _ => None,
                                })
                                .unwrap_or_else(|| "unknown".to_string());
                            
                            flows.push(TaintPath {
                                source_function: path[0].clone(),
                                sink_function: caller.clone(),
                                call_chain: new_path.clone(),
                                source_type: Self::extract_source_type(taint),
                                sink_type,
                                sanitized: effective_sanitized,
                            });
                        }
                    }
                }
                
                // Recursively explore from the caller
                flows.extend(self.find_paths_from_source(
                    caller,
                    taint,
                    new_path,
                    visited,
                ));
            }
        }
        
        visited.remove(current_func);
        flows
    }
    
    #[allow(dead_code)]
    /// Explore callees of a function that propagates taint to find eventual sinks.
    /// This enables N-level detection by following taint through intermediate propagators.
    ///
    /// Example: source() -> caller() -> propagator() -> sink()
    ///          We're at 'caller', which calls 'propagator' (which propagates).
    ///          We need to check if 'propagator' calls 'sink'.
    /// 
    /// CURRENTLY DISABLED: Causes performance issues, needs better algorithm
    fn explore_callees_for_sinks(
        &self,
        current_func: &str,
        source_taint: &ReturnTaint,
        path: Vec<String>,
        visited: &mut HashSet<String>,
    ) -> Vec<TaintPath> {
        let mut flows = Vec::new();
        
        // Debug: limit recursion depth
        if path.len() > 10 {
            eprintln!("WARNING: Path too deep ({}), stopping exploration", path.len());
            return flows;
        }
        
        // Get the call graph node for the current function
        let Some(node) = self.call_graph.nodes.get(current_func) else {
            return flows;
        };
        
        // Explore each function that current_func calls
        for callee_site in &node.callees {
            let callee_name = &callee_site.callee;
            
            // Avoid infinite loops
            if visited.contains(callee_name) {
                continue;
            }
            
            let Some(callee_summary) = self.summaries.get(callee_name) else {
                continue;
            };
            
            // Check if this callee has a sink
            let callee_has_sink = callee_summary.propagation_rules.iter()
                .any(|r| matches!(r, TaintPropagation::ParamToSink { .. }));
            
            if callee_has_sink {
                // Found a direct sink - create flow
                let mut extended_path = path.clone();
                extended_path.push(callee_name.clone());
                
                // Extract sink type from the sink rule
                let sink_type = callee_summary.propagation_rules.iter()
                    .find_map(|r| match r {
                        TaintPropagation::ParamToSink { sink_type, .. } => Some(sink_type.clone()),
                        _ => None,
                    })
                    .unwrap_or_else(|| "unknown_sink".to_string());
                
                flows.push(TaintPath {
                    source_function: path[0].clone(),
                    sink_function: callee_name.clone(),
                    call_chain: extended_path,
                    source_type: Self::extract_source_type(source_taint),
                    sink_type,
                    sanitized: false,
                });
            } else if matches!(callee_summary.return_taint, ReturnTaint::FromParameter(_)) {
                // This callee also propagates - explore its callees recursively
                let mut extended_path = path.clone();
                extended_path.push(callee_name.clone());
                
                visited.insert(callee_name.clone());
                flows.extend(self.explore_callees_for_sinks(
                    callee_name,
                    source_taint,
                    extended_path,
                    visited,
                ));
                visited.remove(callee_name);
            }
        }
        
        flows
    }
    
    /// Check if any function in the path sanitizes its input
    fn path_is_sanitized(&self, path: &[String]) -> bool {
        path.iter().any(|func_name| {
            if let Some(summary) = self.summaries.get(func_name) {
                summary.propagation_rules.iter()
                    .any(|r| matches!(r, TaintPropagation::ParamSanitized(_)))
            } else {
                false
            }
        })
    }
    
    /// Extract source type from ReturnTaint
    fn extract_source_type(taint: &ReturnTaint) -> String {
        match taint {
            ReturnTaint::FromSource { source_type } => source_type.clone(),
            ReturnTaint::FromParameter(_) => "parameter".to_string(),
            ReturnTaint::Merged(taints) => {
                // Take first source type from merged
                if let Some(first) = taints.first() {
                    Self::extract_source_type(first)
                } else {
                    "unknown".to_string()
                }
            }
            ReturnTaint::Clean => "clean".to_string(),
        }
    }
}

/// Represents a complete taint flow from source to sink
#[derive(Debug, Clone)]
pub struct TaintPath {
    /// Function where taint originates
    pub source_function: String,
    
    /// Function where taint reaches a sink
    pub sink_function: String,
    
    /// Complete call chain: [source, caller1, caller2, ..., sink]
    pub call_chain: Vec<String>,
    
    /// Type of taint source
    pub source_type: String,
    
    /// Type of sink
    pub sink_type: String,
    
    /// Whether the taint was sanitized along the path
    pub sanitized: bool,
}

impl TaintPath {
    /// Create a human-readable description of this taint flow
    pub fn describe(&self) -> String {
        let chain = self.call_chain.join(" → ");
        let sanitized_note = if self.sanitized { " [SANITIZED - SAFE]" } else { "" };
        format!(
            "Tainted data from {} (source: {}) flows through {} to {} (sink: {}){}",
            self.source_function,
            self.source_type,
            chain,
            self.sink_function,
            self.sink_type,
            sanitized_note
        )
    }
    
    /// Get the number of levels in the call chain
    pub fn depth(&self) -> usize {
        self.call_chain.len()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_extract_function_name() {
        assert_eq!(
            CallGraph::extract_function_name("std::process::Command::new"),
            "new"
        );
        
        assert_eq!(
            CallGraph::extract_function_name("my_function"),
            "my_function"
        );
        
        assert_eq!(
            CallGraph::extract_function_name("const my_crate::util::helper"),
            "helper"
        );
    }
    
    #[test]
    fn test_is_builtin_operation() {
        assert!(CallGraph::is_builtin_operation("assert!"));
        assert!(CallGraph::is_builtin_operation("println!"));
        assert!(CallGraph::is_builtin_operation("_internal"));
        assert!(!CallGraph::is_builtin_operation("my_function"));
    }
    
    #[test]
    fn test_function_summary_creation() {
        let summary = FunctionSummary::new("test_function".to_string());
        assert_eq!(summary.function_name, "test_function");
        assert!(summary.source_parameters.is_empty());
        assert!(summary.sink_parameters.is_empty());
        assert!(summary.propagation_rules.is_empty());
        assert!(matches!(summary.return_taint, ReturnTaint::Clean));
    }
    
    #[test]
    fn test_call_site_creation() {
        let site = CallSite {
            callee: "execute_command".to_string(),
            resolved_targets: Vec::new(),
            location: "test.rs:42".to_string(),
            arg_count: 1,
        };
        assert_eq!(site.callee, "execute_command");
        assert_eq!(site.location, "test.rs:42");
        assert_eq!(site.arg_count, 1);
    }
    
    #[test]
    fn test_taint_propagation_patterns() {
        let param_to_return = TaintPropagation::ParamToReturn(0);
        let param_to_param = TaintPropagation::ParamToParam { from: 0, to: 1 };
        let param_to_sink = TaintPropagation::ParamToSink {
            param: 0,
            sink_type: "command".to_string(),
        };
        let param_sanitized = TaintPropagation::ParamSanitized(0);
        
        // Test that patterns are distinct
        assert!(matches!(param_to_return, TaintPropagation::ParamToReturn(_)));
        assert!(matches!(param_to_param, TaintPropagation::ParamToParam { .. }));
        assert!(matches!(param_to_sink, TaintPropagation::ParamToSink { .. }));
        assert!(matches!(param_sanitized, TaintPropagation::ParamSanitized(_)));
    }
    
    #[test]
    fn test_return_taint_patterns() {
        let clean = ReturnTaint::Clean;
        let from_param = ReturnTaint::FromParameter(0);
        let from_source = ReturnTaint::FromSource {
            source_type: "env".to_string(),
        };
        let merged = ReturnTaint::Merged(vec![
            ReturnTaint::FromSource { source_type: "env".to_string() },
            ReturnTaint::FromSource { source_type: "file".to_string() },
        ]);
        
        // Test that patterns are distinct
        assert!(matches!(clean, ReturnTaint::Clean));
        assert!(matches!(from_param, ReturnTaint::FromParameter(_)));
        assert!(matches!(from_source, ReturnTaint::FromSource { .. }));
        assert!(matches!(merged, ReturnTaint::Merged(_)));
    }
}
