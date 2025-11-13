/// Closure analysis module for tracking taint through closures and higher-order functions
/// 
/// This module provides:
/// - Detection of closure creation, invocation, and bodies in MIR
/// - Tracking of captured variables and their taint states
/// - Mapping between parent function variables and closure environment fields
/// - Analysis of taint propagation through closure captures

use std::collections::HashMap;
use crate::MirFunction;

/// Capture mode for closure variables
#[derive(Debug, Clone, PartialEq)]
pub enum CaptureMode {
    /// Captured by value (move)
    ByValue,
    /// Captured by reference (&)
    ByRef,
    /// Captured by mutable reference (&mut)
    ByMutRef,
}

/// Taint state for closure analysis
#[derive(Debug, Clone, PartialEq)]
pub enum TaintState {
    Clean,
    Tainted {
        source_type: String,
        source_location: String,
    },
    Sanitized {
        sanitizer: String,
    },
}

/// A variable captured by a closure
#[derive(Debug, Clone)]
pub struct CapturedVariable {
    /// Field index in closure environment (.0, .1, .2, etc.)
    pub field_index: usize,
    
    /// Original variable name in parent function
    pub parent_var: String,
    
    /// How the variable is captured
    pub capture_mode: CaptureMode,
    
    /// Taint state of the captured variable
    pub taint_state: TaintState,
}

/// Information about a closure definition
#[derive(Debug, Clone)]
pub struct ClosureInfo {
    /// Closure name (e.g., "test_func::{closure#0}")
    pub name: String,
    
    /// Parent function name (e.g., "test_func")
    pub parent_function: String,
    
    /// Closure number (e.g., 0 for {closure#0})
    pub closure_index: usize,
    
    /// Variables captured by this closure
    pub captured_vars: Vec<CapturedVariable>,
    
    /// Location in source code
    pub source_location: Option<String>,
}

impl ClosureInfo {
    /// Create a new closure info
    pub fn new(name: String, parent: String, index: usize) -> Self {
        ClosureInfo {
            name,
            parent_function: parent,
            closure_index: index,
            captured_vars: Vec::new(),
            source_location: None,
        }
    }
    
    /// Check if this closure captures any tainted variables
    pub fn has_tainted_captures(&self) -> bool {
        self.captured_vars.iter().any(|cap| {
            matches!(cap.taint_state, TaintState::Tainted { .. })
        })
    }
}

/// Registry for tracking closures across a codebase
pub struct ClosureRegistry {
    /// Maps closure names to their info
    closures: HashMap<String, ClosureInfo>,
    
    /// Maps parent function names to their closures
    parent_to_closures: HashMap<String, Vec<String>>,
    
    /// Maps closure creation sites to closure names
    /// Key: (parent_function, closure_variable)
    closure_bindings: HashMap<(String, String), String>,
}

impl ClosureRegistry {
    /// Create a new empty closure registry
    pub fn new() -> Self {
        ClosureRegistry {
            closures: HashMap::new(),
            parent_to_closures: HashMap::new(),
            closure_bindings: HashMap::new(),
        }
    }
    
    /// Register a closure
    pub fn register_closure(&mut self, info: ClosureInfo) {
        let name = info.name.clone();
        let parent = info.parent_function.clone();
        
        // Add to closures map
        self.closures.insert(name.clone(), info);
        
        // Add to parent mapping
        self.parent_to_closures
            .entry(parent)
            .or_insert_with(Vec::new)
            .push(name);
    }
    
    /// Get closure info by name
    pub fn get_closure(&self, name: &str) -> Option<&ClosureInfo> {
        self.closures.get(name)
    }
    
    /// Get all closures for a parent function
    pub fn get_closures_for_parent(&self, parent: &str) -> Vec<&ClosureInfo> {
        if let Some(closure_names) = self.parent_to_closures.get(parent) {
            closure_names.iter()
                .filter_map(|name| self.closures.get(name))
                .collect()
        } else {
            Vec::new()
        }
    }
    
    /// Bind a closure variable to a closure
    pub fn bind_closure(&mut self, parent: String, var: String, closure_name: String) {
        self.closure_bindings.insert((parent, var), closure_name);
    }
    
    /// Look up which closure a variable refers to
    pub fn get_closure_binding(&self, parent: &str, var: &str) -> Option<&String> {
        self.closure_bindings.get(&(parent.to_string(), var.to_string()))
    }
    
    /// Get all parent function names that have closures
    pub fn get_all_parents(&self) -> Vec<String> {
        self.parent_to_closures.keys().cloned().collect()
    }
    
    /// Get all closures in the registry
    pub fn get_all_closures(&self) -> Vec<&ClosureInfo> {
        self.closures.values().collect()
    }
}

impl Default for ClosureRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing a closure registry from a MIR package
pub struct ClosureRegistryBuilder {
    registry: ClosureRegistry,
}

impl ClosureRegistryBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        ClosureRegistryBuilder {
            registry: ClosureRegistry::new(),
        }
    }
    
    /// Build closure registry from a slice of MIR functions
    pub fn build(functions: &[MirFunction]) -> ClosureRegistry {
        let mut builder = Self::new();
        
        // First pass: identify all closures and their parents
        for function in functions {
            if let Some((parent, index)) = parse_closure_name(&function.name) {
                let info = ClosureInfo::new(
                    function.name.clone(),
                    parent.clone(),
                    index,
                );
                builder.registry.register_closure(info);
            }
        }
        
        // Second pass: extract captures from parent functions
        for function in functions {
            builder.process_function(function);
        }
        
        // Third pass: analyze taint in parent functions and propagate to closures
        for function in functions {
            builder.analyze_taint_for_function(function);
        }
        
        builder.registry
    }
    
    /// Build closure registry from a MIR package
    pub fn build_from_package(package: &crate::MirPackage) -> ClosureRegistry {
        Self::build(&package.functions)
    }
    
    /// Analyze taint in a function and propagate to its closures
    fn analyze_taint_for_function(&mut self, function: &MirFunction) {
        // Build a simple taint map for this function
        let mut taint_map: std::collections::HashMap<String, TaintState> = std::collections::HashMap::new();
        let mut var_aliases: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        
        for line in &function.body {
            let trimmed = line.trim();
            
            // Parse assignments
            if let Some(eq_pos) = trimmed.find(" = ") {
                let lhs = trimmed[..eq_pos].trim();
                let rhs = trimmed[eq_pos + 3..].trim().trim_end_matches(';');
                
                // Check if RHS is a source (env::args, args(), etc.)
                if rhs.contains("args()") || rhs.contains("env::args") || rhs.contains("env::var") {
                    taint_map.insert(lhs.to_string(), TaintState::Tainted {
                        source_type: "environment".to_string(),
                        source_location: rhs.to_string(),
                    });
                }
                // Check if RHS is a function call - propagate taint from arguments
                else if rhs.contains("(") && rhs.contains("move ") {
                    // Extract variables from "move _X" patterns in the RHS
                    let mut tainted_in_args = false;
                    for word in rhs.split_whitespace() {
                        if word.starts_with('_') {
                            let var = word.trim_end_matches(|c: char| !c.is_numeric() && c != '_');
                            if taint_map.contains_key(var) {
                                tainted_in_args = true;
                                break;
                            }
                        }
                    }
                    
                    if tainted_in_args {
                        // Propagate taint to LHS
                        taint_map.insert(lhs.to_string(), TaintState::Tainted {
                            source_type: "propagated".to_string(),
                            source_location: "function_call".to_string(),
                        });
                    }
                }
                // Check if RHS is a reference or copy
                else if rhs.starts_with("&") || rhs.starts_with("copy ") || rhs.starts_with("move ") {
                    // Extract the source variable
                    let source_var = if rhs.starts_with("&mut ") {
                        rhs[5..].trim()
                    } else if rhs.starts_with("&") {
                        rhs[1..].trim()
                    } else if rhs.starts_with("copy ") {
                        rhs[5..].trim()
                    } else if rhs.starts_with("move ") {
                        rhs[5..].trim()
                    } else {
                        rhs
                    };
                    
                    // Extract just the variable name (e.g., "_1" from "_1;")
                    let source_var = source_var.split(|c: char| !c.is_numeric() && c != '_')
                        .next()
                        .unwrap_or(source_var);
                    
                    // Create alias mapping
                    var_aliases.insert(lhs.to_string(), source_var.to_string());
                    
                    // Propagate taint
                    if let Some(taint) = taint_map.get(source_var) {
                        taint_map.insert(lhs.to_string(), taint.clone());
                    }
                }
            }
        }
        
        // Propagate taint through aliases transitively
        let mut changed = true;
        while changed {
            changed = false;
            for (var, alias) in &var_aliases {
                if taint_map.contains_key(var) {
                    continue;
                }
                if let Some(taint) = taint_map.get(alias) {
                    taint_map.insert(var.clone(), taint.clone());
                    changed = true;
                }
            }
        }
        
        // Update closures with taint information
        let closures_for_this_function = self.registry.get_closures_for_parent(&function.name);
        let closure_names: Vec<String> = closures_for_this_function.iter()
            .map(|c| c.name.clone())
            .collect();
        
        for closure_name in closure_names {
            if let Some(info) = self.registry.closures.get_mut(&closure_name) {
                for capture in &mut info.captured_vars {
                    // Resolve the parent var through aliases if needed
                    let mut resolved_var = capture.parent_var.clone();
                    
                    // Follow alias chain
                    for _ in 0..10 { // Limit iterations to prevent infinite loop
                        if let Some(alias) = var_aliases.get(&resolved_var) {
                            resolved_var = alias.clone();
                        } else {
                            break;
                        }
                    }
                    
                    // Check if the resolved variable is tainted
                    if let Some(taint) = taint_map.get(&resolved_var) {
                        capture.taint_state = taint.clone();
                    }
                }
            }
        }
    }
    
    /// Process a single function to find closure creations
    fn process_function(&mut self, function: &MirFunction) {
        for line in &function.body {
            // Look for closure creation
            if let Some((closure_var, location, captures)) = parse_closure_creation(line) {
                // Try to find which closure this refers to based on parent function
                // The location string contains file:line:col, which we can use to match
                // For now, we'll use a simpler approach: look for closures with this parent
                let closure_name = self.find_closure_for_parent(&function.name, &location);
                
                if let Some(closure_name) = closure_name {
                    // Bind this variable to the closure
                    self.registry.bind_closure(
                        function.name.clone(),
                        closure_var.clone(),
                        closure_name.clone(),
                    );
                    
                    // Process captures
                    if let Some(info) = self.registry.closures.get_mut(&closure_name) {
                        // Add source location
                        info.source_location = Some(location.clone());
                        
                        // Process each captured variable
                        for (field_index, (_capture_name, capture_value)) in captures.iter().enumerate() {
                            // Determine capture mode
                            let capture_mode = if capture_value.starts_with("move ") {
                                CaptureMode::ByValue
                            } else if capture_value.starts_with("&mut ") {
                                CaptureMode::ByMutRef
                            } else if capture_value.starts_with('&') {
                                CaptureMode::ByRef
                            } else {
                                CaptureMode::ByValue // Default
                            };
                            
                            // Extract the actual variable from capture_value
                            let parent_var = Self::extract_var_from_capture(capture_value);
                            
                            // Create captured variable (taint state will be filled in later)
                            let captured = CapturedVariable {
                                field_index,
                                parent_var: parent_var.clone(),
                                capture_mode,
                                taint_state: TaintState::Clean, // Default, will be updated
                            };
                            
                            info.captured_vars.push(captured);
                        }
                    }
                }
            }
        }
    }
    
    /// Find the closure name for a given parent function and location
    /// When a parent function has multiple closures, we match by location or order
    fn find_closure_for_parent(&self, parent: &str, _location: &str) -> Option<String> {
        // Get all closures for this parent
        let closures_for_parent: Vec<_> = self.registry.closures.values()
            .filter(|info| info.parent_function == parent)
            .collect();
        
        if closures_for_parent.is_empty() {
            return None;
        }
        
        // If there's only one closure for this parent, return it
        if closures_for_parent.len() == 1 {
            return Some(closures_for_parent[0].name.clone());
        }
        
        // For multiple closures, we'd need to match by location
        // For now, find the first one that doesn't have a source_location set yet
        for info in &closures_for_parent {
            if info.source_location.is_none() {
                return Some(info.name.clone());
            }
        }
        
        // If all have locations, we need to parse and match - for now return first
        Some(closures_for_parent[0].name.clone())
    }
    
    /// Find closure by its source location (old implementation, keeping for reference)
    #[allow(dead_code)]
    fn find_closure_by_location(&self, location: &str) -> Option<String> {
        // Location format: {closure@examples/interprocedural/src/lib.rs:278:19: 278:21}
        // We need to match this against registered closures
        // For now, we'll use a simple heuristic: extract parent from current analysis context
        // and match by index if the location matches
        
        // This is a simplified approach - in production, we'd parse the location more carefully
        for (name, info) in &self.registry.closures {
            if let Some(ref loc) = info.source_location {
                if loc == location {
                    return Some(name.clone());
                }
            }
            // Also try to match if we haven't set source_location yet
            // Extract numbers from location
            if let Some(_start) = location.rfind(':') {
                if let Some(_line_start) = location[.._start].rfind(':') {
                    // This is a new closure, try to match by parent function name
                    // which should be in the current context
                }
            }
        }
        
        // If no exact match, try to infer from the closures we know about
        // For a more robust implementation, we could extract line numbers and match
        None
    }
    
    /// Extract variable name from capture value
    /// "move _6" -> "_6"
    /// "&_3" -> "_3"
    /// "&mut _4" -> "_4"
    fn extract_var_from_capture(capture_value: &str) -> String {
        let trimmed = capture_value.trim();
        
        if trimmed.starts_with("move ") {
            trimmed[5..].trim().to_string()
        } else if trimmed.starts_with("&mut ") {
            trimmed[5..].trim().to_string()
        } else if trimmed.starts_with('&') {
            trimmed[1..].trim().to_string()
        } else {
            // Handle "copy _X" or just "_X"
            trimmed.split_whitespace().last().unwrap_or(trimmed).to_string()
        }
    }
}

impl Default for ClosureRegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a function name represents a closure
pub fn is_closure_function(name: &str) -> bool {
    name.contains("::{closure#")
}

/// Parse closure name to extract parent and index
/// 
/// # Examples
/// ```
/// let (parent, index) = parse_closure_name("test_func::{closure#0}").unwrap();
/// assert_eq!(parent, "test_func");
/// assert_eq!(index, 0);
/// ```
pub fn parse_closure_name(name: &str) -> Option<(String, usize)> {
    if let Some(pos) = name.find("::{closure#") {
        let parent = name[..pos].to_string();
        let rest = &name[pos + 11..]; // Skip "::{closure#"
        
        // Extract number before closing '}'
        if let Some(end) = rest.find('}') {
            if let Ok(index) = rest[..end].parse::<usize>() {
                return Some((parent, index));
            }
        }
    }
    None
}

/// Extract closure creation from MIR statement
/// 
/// Looks for patterns like:
/// `_5 = {closure@examples/interprocedural/src/lib.rs:278:19: 278:21} { tainted: move _6 };`
pub fn parse_closure_creation(statement: &str) -> Option<(String, String, Vec<(String, String)>)> {
    // Pattern: _X = {closure@<location>} { <captures> }
    if !statement.contains("{closure@") {
        return None;
    }
    
    // Extract LHS variable
    let lhs = if let Some(eq_pos) = statement.find(" = ") {
        statement[..eq_pos].trim().to_string()
    } else {
        return None;
    };
    
    // Extract closure location
    let location = if let Some(start) = statement.find("{closure@") {
        if let Some(end) = statement[start..].find('}') {
            statement[start..start + end + 1].to_string()
        } else {
            return None;
        }
    } else {
        return None;
    };
    
    // Extract captures
    let mut captures = Vec::new();
    
    // Look for capture list after location: { var: value, ... }
    if let Some(capture_start) = statement.rfind(" { ") {
        if let Some(capture_end) = statement[capture_start..].rfind('}') {
            let capture_str = &statement[capture_start + 3..capture_start + capture_end];
            
            // Parse comma-separated captures
            for capture in capture_str.split(',') {
                let capture = capture.trim();
                if let Some(colon_pos) = capture.find(": ") {
                    let var_name = capture[..colon_pos].trim().to_string();
                    let value = capture[colon_pos + 2..].trim().to_string();
                    captures.push((var_name, value));
                }
            }
        }
    }
    
    Some((lhs, location, captures))
}

/// Detect closure invocation in MIR
/// 
/// Looks for patterns like:
/// `_7 = <{closure@...} as Fn<()>>::call(move _8, const ());`
pub fn is_closure_call(statement: &str) -> bool {
    statement.contains(" as Fn<") && statement.contains(">::call(")
        || statement.contains(" as FnMut<") && statement.contains(">::call_mut(")
        || statement.contains(" as FnOnce<") && statement.contains(">::call_once(")
}

/// Extract closure variable from invocation
pub fn parse_closure_call(statement: &str) -> Option<(String, String)> {
    if !is_closure_call(statement) {
        return None;
    }
    
    // Extract result variable
    let result_var = if let Some(eq_pos) = statement.find(" = ") {
        statement[..eq_pos].trim().to_string()
    } else {
        return None;
    };
    
    // Extract closure variable from call(move _X, ...)
    if let Some(call_start) = statement.find("::call(")
            .or_else(|| statement.find("::call_mut("))
            .or_else(|| statement.find("::call_once(")) {
        if let Some(paren_end) = statement[call_start..].find(')') {
            let args = &statement[call_start + 7..call_start + paren_end];
            
            // First argument is the closure
            if let Some(comma_pos) = args.find(',') {
                let closure_arg = args[..comma_pos].trim();
                // Remove "move " prefix if present
                let closure_var = if closure_arg.starts_with("move ") {
                    closure_arg[5..].trim().to_string()
                } else {
                    closure_arg.to_string()
                };
                return Some((result_var, closure_var));
            }
        }
    }
    
    None
}

/// Detect environment field access in closure body
/// 
/// Looks for patterns like:
/// `_7 = deref_copy ((*_1).0: &std::string::String);`
pub fn parse_env_field_access(statement: &str) -> Option<(String, usize)> {
    // Pattern: ((*_X).N: <type>)
    if !statement.contains("(*_") {
        return None;
    }
    
    // Extract LHS variable first
    let lhs = if let Some(eq_pos) = statement.find(" = ") {
        statement[..eq_pos].trim().to_string()
    } else {
        return None;
    };
    
    // Find the pattern: ((*_1).0: ...)
    if let Some(start) = statement.find("((*_") {
        // Find the dot after the closing parenthesis
        if let Some(dot_start) = statement[start..].find(").") {
            let after_dot = &statement[start + dot_start + 2..];
            
            // Extract field number
            let field_str = after_dot.chars()
                .take_while(|c| c.is_numeric())
                .collect::<String>();
                
            if let Ok(field_index) = field_str.parse::<usize>() {
                return Some((lhs, field_index));
            }
        }
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_is_closure_function() {
        assert!(is_closure_function("test_func::{closure#0}"));
        assert!(is_closure_function("module::test::{closure#5}"));
        assert!(!is_closure_function("regular_function"));
    }
    
    #[test]
    fn test_parse_closure_name() {
        let (parent, index) = parse_closure_name("test_func::{closure#0}").unwrap();
        assert_eq!(parent, "test_func");
        assert_eq!(index, 0);
        
        let (parent, index) = parse_closure_name("module::nested::func::{closure#3}").unwrap();
        assert_eq!(parent, "module::nested::func");
        assert_eq!(index, 3);
        
        assert!(parse_closure_name("not_a_closure").is_none());
    }
    
    #[test]
    fn test_parse_closure_creation() {
        let stmt = "_5 = {closure@examples/interprocedural/src/lib.rs:278:19: 278:21} { tainted: move _6 };";
        let (lhs, location, captures) = parse_closure_creation(stmt).unwrap();
        
        assert_eq!(lhs, "_5");
        assert!(location.starts_with("{closure@"));
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].0, "tainted");
        assert_eq!(captures[0].1, "move _6");
    }
    
    #[test]
    fn test_is_closure_call() {
        assert!(is_closure_call("<{closure@...} as Fn<()>>::call(move _8, const ())"));
        assert!(is_closure_call("<{closure@...} as FnMut<()>>::call_mut(move _8, const ())"));
        assert!(is_closure_call("<{closure@...} as FnOnce<()>>::call_once(move _8, const ())"));
        assert!(!is_closure_call("regular_function_call()"));
    }
    
    #[test]
    fn test_parse_closure_call() {
        let stmt = "_7 = <{closure@...} as Fn<()>>::call(move _8, const ()) -> [return: bb5, unwind: bb7];";
        let (result, closure_var) = parse_closure_call(stmt).unwrap();
        
        assert_eq!(result, "_7");
        assert_eq!(closure_var, "_8");
    }
    
    #[test]
    fn test_parse_env_field_access() {
        let stmt = "_7 = deref_copy ((*_1).0: &std::string::String);";
        let (lhs, field) = parse_env_field_access(stmt).unwrap();
        
        assert_eq!(lhs, "_7");
        assert_eq!(field, 0);
    }
}
