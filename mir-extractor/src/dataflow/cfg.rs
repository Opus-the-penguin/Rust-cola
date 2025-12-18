//! Control Flow Graph (CFG) extraction from MIR
//!
//! This module parses MIR basic blocks to build a control flow graph for path-sensitive analysis.

use std::collections::{HashMap, HashSet};
use crate::MirFunction;

/// Control Flow Graph extracted from MIR basic blocks
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    /// Map from block ID to BasicBlock
    pub blocks: HashMap<String, BasicBlock>,
    /// Map from block ID to successor block IDs
    pub edges: HashMap<String, Vec<String>>,
    /// Entry block (usually "bb0")
    pub entry_block: String,
    /// Exit blocks (blocks with Return terminator)
    pub exit_blocks: Vec<String>,
}

/// A basic block in the control flow graph
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: String,
    /// Statements in the block (assignments, calls, etc.)
    pub statements: Vec<String>,
    /// Terminator that determines control flow
    pub terminator: Terminator,
}

/// Terminator instruction that ends a basic block
#[derive(Debug, Clone)]
pub enum Terminator {
    /// Unconditional jump: goto -> bb5
    Goto { target: String },
    
    /// Conditional branch: switchInt(x) -> [0: bb1, otherwise: bb2]
    SwitchInt {
        /// Condition variable being tested
        condition: String,
        /// Map of values to target blocks
        targets: Vec<(String, String)>,  // (value, target_block)
        /// Default target (otherwise case)
        otherwise: Option<String>,
    },
    
    /// Function return
    Return,
    
    /// Function call with potential branches (return/unwind)
    Call {
        /// Target block on successful return
        return_target: Option<String>,
        /// Target block on unwind (panic)
        unwind_target: Option<String>,
    },
    
    /// Assertion (similar to Call)
    Assert {
        /// Target block if assertion passes
        success_target: String,
        /// Target block if assertion fails
        failure_target: Option<String>,
    },
    
    /// Drop value (can unwind)
    Drop {
        target: String,
        unwind_target: Option<String>,
    },
    
    /// Unreachable code
    Unreachable,
    
    /// Unknown or unparsed terminator
    Unknown(String),
}

impl ControlFlowGraph {
    /// Extract CFG from a MIR function's body
    pub fn from_mir_function(function: &MirFunction) -> Self {
        let mut blocks = HashMap::new();
        let mut edges = HashMap::new();
        let mut exit_blocks = Vec::new();
        
        // Parse basic blocks from function body
        let parsed_blocks = Self::parse_basic_blocks(&function.body);
        
        for (id, block) in parsed_blocks {
            // Extract edges from terminator
            let successors = Self::extract_successors(&block.terminator);
            if !successors.is_empty() {
                edges.insert(id.clone(), successors);
            }
            
            // Track exit blocks
            if matches!(block.terminator, Terminator::Return) {
                exit_blocks.push(id.clone());
            }
            
            blocks.insert(id, block);
        }
        
        ControlFlowGraph {
            blocks,
            edges,
            entry_block: "bb0".to_string(),
            exit_blocks,
        }
    }
    
    /// Get the number of basic blocks in the CFG
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
    
    /// Parse basic blocks from MIR body lines
    fn parse_basic_blocks(body: &[String]) -> HashMap<String, BasicBlock> {
        let mut blocks = HashMap::new();
        let mut current_block_id: Option<String> = None;
        let mut current_statements = Vec::new();
        let mut current_terminator: Option<Terminator> = None;
        
        for line in body {
            let trimmed = line.trim();
            
            // Check for block start: "bb0: {"
            if let Some(block_id) = Self::extract_block_id(trimmed) {
                // Save previous block if any
                if let Some(id) = current_block_id.take() {
                    if let Some(term) = current_terminator.take() {
                        blocks.insert(id.clone(), BasicBlock {
                            id,
                            statements: std::mem::take(&mut current_statements),
                            terminator: term,
                        });
                    }
                }
                
                // Start new block
                current_block_id = Some(block_id);
                current_statements.clear();
                current_terminator = None;
            }
            // Check for terminator instructions
            else if trimmed.starts_with("goto ")
                || trimmed.starts_with("switchInt")
                || trimmed.starts_with("return")
                || trimmed.contains(" -> [return:")
                || trimmed.starts_with("assert(")
                || trimmed.starts_with("drop(")
                || trimmed.starts_with("unreachable")
            {
                // If this is a call (has " = " and " -> [return:"), also add it as a statement
                // This ensures we can analyze taint flow through function call results
                if trimmed.contains(" = ") && trimmed.contains(" -> [return:") {
                    current_statements.push(trimmed.to_string());
                }
                current_terminator = Some(Self::parse_terminator(trimmed));
            }
            // Regular statement
            else if !trimmed.is_empty()
                && !trimmed.starts_with("}")
                && !trimmed.starts_with("scope")
                && !trimmed.starts_with("debug")
                && !trimmed.starts_with("let")
            {
                current_statements.push(trimmed.to_string());
            }
        }
        
        // Save last block
        if let Some(id) = current_block_id {
            if let Some(term) = current_terminator {
                blocks.insert(id.clone(), BasicBlock {
                    id,
                    statements: current_statements,
                    terminator: term,
                });
            }
        }
        
        blocks
    }
    
    /// Extract block ID from line like "bb0: {"
    fn extract_block_id(line: &str) -> Option<String> {
        if line.starts_with("bb") && line.contains(": {") {
            let id = line.split(": {").next()?;
            Some(id.to_string())
        } else {
            None
        }
    }
    
    /// Parse a terminator instruction
    fn parse_terminator(line: &str) -> Terminator {
        let line = line.trim().trim_end_matches(';');
        
        // goto -> bb5
        if let Some(rest) = line.strip_prefix("goto -> ") {
            return Terminator::Goto {
                target: rest.to_string(),
            };
        }
        
        // return
        if line == "return" {
            return Terminator::Return;
        }
        
        // unreachable
        if line == "unreachable" {
            return Terminator::Unreachable;
        }
        
        // switchInt(move _5) -> [0: bb12, otherwise: bb7]
        if let Some(rest) = line.strip_prefix("switchInt(") {
            if let Some(paren_end) = rest.find(") -> [") {
                let condition = rest[..paren_end].to_string();
                let targets_str = &rest[paren_end + 6..];  // Skip ") -> ["
                
                let mut targets = Vec::new();
                let mut otherwise = None;
                
                // Parse targets: "0: bb12, 1: bb13, otherwise: bb7]"
                for part in targets_str.trim_end_matches(']').split(", ") {
                    if let Some((value, block)) = part.split_once(": ") {
                        if value == "otherwise" {
                            otherwise = Some(block.to_string());
                        } else {
                            targets.push((value.to_string(), block.to_string()));
                        }
                    }
                }
                
                return Terminator::SwitchInt {
                    condition,
                    targets,
                    otherwise,
                };
            }
        }
        
        // Function call: some_func() -> [return: bb2, unwind continue]
        if line.contains(" -> [return:") {
            let mut return_target = None;
            let mut unwind_target = None;
            
            if let Some(arrow_pos) = line.find(" -> [") {
                let targets_str = &line[arrow_pos + 5..];  // Skip " -> ["
                
                for part in targets_str.trim_end_matches(']').split(", ") {
                    if let Some(rest) = part.strip_prefix("return: ") {
                        return_target = Some(rest.to_string());
                    } else if let Some(rest) = part.strip_prefix("unwind: ") {
                        unwind_target = Some(rest.to_string());
                    }
                }
            }
            
            return Terminator::Call {
                return_target,
                unwind_target,
            };
        }
        
        // assert: assert(cond) -> [success: bb5, unwind: bb6]
        if let Some(rest) = line.strip_prefix("assert(") {
            if let Some(arrow_pos) = rest.find(" -> [") {
                let targets_str = &rest[arrow_pos + 5..];
                let mut success_target = String::new();
                let mut failure_target = None;
                
                for part in targets_str.trim_end_matches(']').split(", ") {
                    if let Some(rest) = part.strip_prefix("success: ") {
                        success_target = rest.to_string();
                    } else if let Some(rest) = part.strip_prefix("unwind: ") {
                        failure_target = Some(rest.to_string());
                    }
                }
                
                return Terminator::Assert {
                    success_target,
                    failure_target,
                };
            }
        }
        
        // drop: drop(_x) -> [return: bb3, unwind: bb4]
        if let Some(rest) = line.strip_prefix("drop(") {
            if let Some(arrow_pos) = rest.find(" -> [") {
                let targets_str = &rest[arrow_pos + 5..];
                let mut target = String::new();
                let mut unwind_target = None;
                
                for part in targets_str.trim_end_matches(']').split(", ") {
                    if let Some(rest) = part.strip_prefix("return: ") {
                        target = rest.to_string();
                    } else if let Some(rest) = part.strip_prefix("unwind: ") {
                        unwind_target = Some(rest.to_string());
                    }
                }
                
                return Terminator::Drop {
                    target,
                    unwind_target,
                };
            }
        }
        
        // Unknown terminator
        Terminator::Unknown(line.to_string())
    }
    
    /// Extract successor block IDs from a terminator
    fn extract_successors(terminator: &Terminator) -> Vec<String> {
        match terminator {
            Terminator::Goto { target } => vec![target.clone()],
            
            Terminator::SwitchInt { targets, otherwise, .. } => {
                let mut successors: Vec<String> = targets.iter()
                    .map(|(_, block)| block.clone())
                    .collect();
                if let Some(other) = otherwise {
                    successors.push(other.clone());
                }
                successors
            }
            
            Terminator::Return | Terminator::Unreachable => vec![],
            
            Terminator::Call { return_target, unwind_target } => {
                let mut successors = Vec::new();
                if let Some(ret) = return_target {
                    successors.push(ret.clone());
                }
                if let Some(unw) = unwind_target {
                    successors.push(unw.clone());
                }
                successors
            }
            
            Terminator::Assert { success_target, failure_target } => {
                let mut successors = vec![success_target.clone()];
                if let Some(fail) = failure_target {
                    successors.push(fail.clone());
                }
                successors
            }
            
            Terminator::Drop { target, unwind_target } => {
                let mut successors = vec![target.clone()];
                if let Some(unw) = unwind_target {
                    successors.push(unw.clone());
                }
                successors
            }
            
            Terminator::Unknown(_) => vec![],
        }
    }
    
    /// Enumerate all paths from entry to exit blocks
    /// Returns paths as sequences of block IDs
    pub fn get_all_paths(&self) -> Vec<Vec<String>> {
        // println!("[DEBUG] get_all_paths: entry={}, exit_blocks={:?}, blocks={}", self.entry_block, self.exit_blocks, self.blocks.len());
        let mut paths = Vec::new();
        let mut current_path = Vec::new();
        let mut visited = HashSet::new();
        
        // Aggressive limits to prevent memory explosion on large crates
        // With 1000 functions x 2 analyses x 32 paths = 64,000 max path analyses
        const MAX_PATHS: usize = 1000;
        const MAX_DEPTH: usize = 50;
        self.dfs_paths(&self.entry_block, &mut current_path, &mut visited, &mut paths, 0, MAX_DEPTH, MAX_PATHS);
        
        // println!("[DEBUG] Found {} paths", paths.len());
        paths
    }
    
    /// Depth-first search to enumerate paths
    fn dfs_paths(
        &self,
        current_block: &str,
        current_path: &mut Vec<String>,
        visited: &mut HashSet<String>,
        paths: &mut Vec<Vec<String>>,
        depth: usize,
        max_depth: usize,
        max_paths: usize,
    ) {
        // Prevent infinite loops, path explosion, and excessive path count
        if depth > max_depth || visited.contains(current_block) || paths.len() >= max_paths {
            return;
        }
        
        current_path.push(current_block.to_string());
        visited.insert(current_block.to_string());
        
        // Check if this is an exit block
        if self.exit_blocks.contains(&current_block.to_string()) {
            paths.push(current_path.clone());
        } else if let Some(successors) = self.edges.get(current_block) {
            // Explore each successor
            for successor in successors {
                if paths.len() >= max_paths {
                    break; // Stop exploring if we hit the limit
                }
                self.dfs_paths(
                    successor,
                    current_path,
                    visited,
                    paths,
                    depth + 1,
                    max_depth,
                    max_paths,
                );
            }
        }
        
        // Backtrack
        current_path.pop();
        visited.remove(current_block);
    }
    
    /// Get the basic block for a given ID
    pub fn get_block(&self, block_id: &str) -> Option<&BasicBlock> {
        self.blocks.get(block_id)
    }
    
    /// Check if the CFG has any branching (multiple paths)
    pub fn has_branching(&self) -> bool {
        self.edges.values().any(|successors| successors.len() > 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_goto() {
        let term = ControlFlowGraph::parse_terminator("goto -> bb5;");
        match term {
            Terminator::Goto { target } => assert_eq!(target, "bb5"),
            _ => panic!("Expected Goto"),
        }
    }
    
    #[test]
    fn test_parse_return() {
        let term = ControlFlowGraph::parse_terminator("return;");
        assert!(matches!(term, Terminator::Return));
    }
    
    #[test]
    fn test_parse_switch_int() {
        let term = ControlFlowGraph::parse_terminator(
            "switchInt(move _5) -> [0: bb12, otherwise: bb7];"
        );
        match term {
            Terminator::SwitchInt { condition, targets, otherwise } => {
                assert_eq!(condition, "move _5");
                assert_eq!(targets.len(), 1);
                assert_eq!(targets[0], ("0".to_string(), "bb12".to_string()));
                assert_eq!(otherwise, Some("bb7".to_string()));
            }
            _ => panic!("Expected SwitchInt"),
        }
    }
    
    #[test]
    fn test_parse_call() {
        let term = ControlFlowGraph::parse_terminator(
            "some_func() -> [return: bb2, unwind continue];"
        );
        match term {
            Terminator::Call { return_target, .. } => {
                assert_eq!(return_target, Some("bb2".to_string()));
            }
            _ => panic!("Expected Call"),
        }
    }
}
