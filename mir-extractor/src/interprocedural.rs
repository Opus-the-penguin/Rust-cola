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
}

/// Describes how taint propagates through a function
#[derive(Debug, Clone)]
pub enum TaintPropagation {
    /// Parameter N flows to return value
    ParamToReturn(usize),
    
    /// Parameter N flows to parameter M (for &mut parameters)
    ParamToParam { from: usize, to: usize },
    
    /// Parameter N flows to a sink
    ParamToSink { param: usize, sink_type: String },
    
    /// Parameter N is sanitized by this function
    ParamSanitized(usize),
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
        
        // Phase 3: Build caller relationships (reverse edges)
        let mut caller_map: HashMap<String, Vec<String>> = HashMap::new();
        for (caller_name, node) in &nodes {
            for call_site in &node.callees {
                caller_map
                    .entry(call_site.callee.clone())
                    .or_default()
                    .push(caller_name.clone());
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
        }
        
        Ok(callees)
    }
    
    /// Parse a single MIR line to detect function calls
    fn parse_call_from_mir_line(line: &str, line_idx: usize) -> Option<CallSite> {
        let line = line.trim();
        
        // Pattern 1: Direct function call in statement
        // Example: "_5 = my_function(move _6) -> [return: bb3, unwind: bb4];"
        if line.contains("(") && line.contains(") -> [return:") {
            // Extract function name between '=' and '('
            if let Some(eq_pos) = line.find('=') {
                if let Some(paren_pos) = line[eq_pos..].find('(') {
                    let func_part = &line[eq_pos+1..eq_pos+paren_pos].trim();
                    
                    // Clean up the function name
                    let func_name = Self::extract_function_name(func_part);
                    
                    if !func_name.is_empty() && !Self::is_builtin_operation(&func_name) {
                        // Count arguments (rough estimate)
                        let args_section = &line[eq_pos+paren_pos+1..];
                        let arg_count = Self::estimate_arg_count(args_section);
                        
                        return Some(CallSite {
                            callee: func_name,
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
        
        // Calculate in-degrees (number of callees)
        for (name, node) in nodes {
            in_degree.insert(name.clone(), node.callees.len());
        }
        
        // Start with leaf functions (no callees)
        let mut queue: VecDeque<String> = nodes
            .iter()
            .filter(|(_, node)| node.callees.is_empty())
            .map(|(name, _)| name.clone())
            .collect();
        
        // Process nodes in bottom-up order
        while let Some(current) = queue.pop_front() {
            order.push(current.clone());
            
            // For each function that calls this one
            if let Some(node) = nodes.get(&current) {
                for caller in &node.callers {
                    if let Some(degree) = in_degree.get_mut(caller) {
                        *degree -= 1;
                        if *degree == 0 {
                            queue.push_back(caller.clone());
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
        }
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
}
