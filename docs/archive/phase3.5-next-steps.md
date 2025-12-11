# Phase 3.5: Next Steps and Quick Start Guide

## Current Status ✅

**Phase 3.4 Complete!**
- 0% false positive rate (down from 15.4%)
- ~91% recall (10/11 vulnerable cases)
- Successfully pushed to GitHub
- Comprehensive documentation created

## Phase 3.5 Overview

**Goal:** Achieve 100% recall while maintaining 0% FP rate by adding:
1. Branch-sensitive taint tracking (fixes test_partial_sanitization)
2. Closure capture analysis
3. Trait method resolution
4. Async function support

**Full roadmap:** See `docs/phase3.5-roadmap.md`

## Quick Start: Begin with Branch Analysis (Phase 3.5.1)

### Why Start Here?
- **Highest impact:** Fixes our last false negative (test_partial_sanitization)
- **Builds foundation:** CFG analysis needed for other features
- **Clear scope:** Well-defined problem with known test case

### The Problem

```rust
pub fn test_partial_sanitization() {
    let input = std::env::args().nth(1).unwrap_or_default();
    
    if input.contains("safe") {
        let safe = validate_input(&input);  // Path 1: SAFE ✅
        execute_command(&safe);
    } else {
        execute_command(&input);            // Path 2: VULNERABLE ❌
    }
}
```

**Current behavior:** Marked as SAFE (sees validate_input call)  
**Expected behavior:** Should detect VULNERABLE (else branch has no validation)

### Implementation Steps

#### Step 1: Extract Control Flow Graph (1-2 hours)

**Create new module:** `mir-extractor/src/dataflow/cfg.rs`

```rust
use crate::MirFunction;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub blocks: HashMap<String, BasicBlock>,
    pub edges: HashMap<String, Vec<String>>,
    pub entry_block: String,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: String,
    pub statements: Vec<String>,  // Simplified for now
    pub terminator: Terminator,
}

#[derive(Debug, Clone)]
pub enum Terminator {
    Goto { target: String },
    SwitchInt { targets: Vec<String> },  // if/match branches
    Return,
    Call { target: Option<String> },
}

impl ControlFlowGraph {
    pub fn from_mir_function(function: &MirFunction) -> Self {
        // Parse function.basic_blocks JSON
        // Extract block IDs, statements, terminators
        // Build edge map
        
        todo!("Extract CFG from MIR basic_blocks")
    }
    
    pub fn get_all_paths(&self) -> Vec<Vec<String>> {
        // DFS to enumerate paths from entry to all returns
        // Limit to reasonable depth (e.g., 20 blocks)
        
        todo!("Enumerate execution paths")
    }
}
```

**Test:** Create unit test with simple if/else function, verify CFG structure.

#### Step 2: Path-Sensitive Taint Analysis (2-3 hours)

**Create:** `mir-extractor/src/dataflow/path_sensitive.rs`

```rust
use super::cfg::{ControlFlowGraph, BasicBlock};
use crate::interprocedural::{TaintState, FunctionSummary};

pub struct PathSensitiveTaintAnalysis {
    cfg: ControlFlowGraph,
    // Map: (BlockId, Variable) -> TaintState
    taint_at_block: HashMap<(String, String), TaintState>,
}

impl PathSensitiveTaintAnalysis {
    pub fn new(cfg: ControlFlowGraph) -> Self {
        Self {
            cfg,
            taint_at_block: HashMap::new(),
        }
    }
    
    pub fn analyze(&mut self, initial_taint: HashMap<String, TaintState>) -> AnalysisResult {
        let paths = self.cfg.get_all_paths();
        
        let mut vulnerable_paths = Vec::new();
        let mut safe_paths = Vec::new();
        
        for path in paths {
            let result = self.analyze_path(&path, &initial_taint);
            
            if result.has_vulnerable_sink {
                vulnerable_paths.push(path);
            } else {
                safe_paths.push(path);
            }
        }
        
        AnalysisResult {
            vulnerable_paths,
            safe_paths,
            has_any_vulnerable_path: !vulnerable_paths.is_empty(),
        }
    }
    
    fn analyze_path(&mut self, path: &[String], initial_taint: &HashMap<String, TaintState>) -> PathResult {
        let mut current_taint = initial_taint.clone();
        let mut has_vulnerable_sink = false;
        
        for block_id in path {
            let block = &self.cfg.blocks[block_id];
            
            // Process statements in block
            for statement in &block.statements {
                self.process_statement(statement, &mut current_taint);
            }
            
            // Check terminator for sinks
            if self.is_sink_call(&block.terminator, &current_taint) {
                has_vulnerable_sink = true;
            }
        }
        
        PathResult { has_vulnerable_sink }
    }
    
    fn process_statement(&self, stmt: &str, taint: &mut HashMap<String, TaintState>) {
        // Parse statement, update taint map
        // Handle: assignments, function calls, sanitization
        
        todo!("Implement statement processing")
    }
    
    fn is_sink_call(&self, terminator: &Terminator, taint: &HashMap<String, TaintState>) -> bool {
        // Check if terminator is a call to sink with tainted arg
        
        todo!("Check for tainted sink calls")
    }
}

pub struct AnalysisResult {
    pub vulnerable_paths: Vec<Vec<String>>,
    pub safe_paths: Vec<Vec<String>>,
    pub has_any_vulnerable_path: bool,
}

struct PathResult {
    has_vulnerable_sink: bool,
}
```

**Test:** Create test case with if/else, verify both paths are analyzed separately.

#### Step 3: Integrate with FunctionSummary (1 hour)

**Modify:** `mir-extractor/src/interprocedural.rs`

```rust
use crate::dataflow::cfg::ControlFlowGraph;
use crate::dataflow::path_sensitive::PathSensitiveTaintAnalysis;

impl FunctionSummary {
    pub fn from_mir_function_with_cfg(function: &MirFunction, package: &MirPackage) -> Self {
        // Check if function has branching
        if function.has_branching() {
            // Use path-sensitive analysis
            let cfg = ControlFlowGraph::from_mir_function(function);
            let mut analysis = PathSensitiveTaintAnalysis::new(cfg);
            
            // Get initial taint from params
            let initial_taint = Self::get_initial_taint_from_params(function);
            
            let result = analysis.analyze(initial_taint);
            
            // If ANY path is vulnerable, mark function as having sink
            if result.has_any_vulnerable_path {
                return Self::create_summary_with_sink(function);
            } else {
                return Self::create_summary_safe(function);
            }
        } else {
            // Use existing simple analysis
            Self::from_mir_function(function, package)
        }
    }
    
    fn has_branching(&self, function: &MirFunction) -> bool {
        // Check if function.basic_blocks has SwitchInt terminators
        
        todo!("Detect branching in MIR")
    }
}
```

**Test:** Run on test_partial_sanitization, verify it's now detected as vulnerable.

#### Step 4: Test and Validate (1 hour)

**Run full test suite:**

```bash
cd /Users/peteralbert/Projects/Rust-cola
cargo test --test test_function_summaries test_inter_procedural_detection -- --nocapture
```

**Expected results:**
- test_partial_sanitization: Should appear in vulnerable flows ✅
- test_branching_sanitization: Should still be detected ✅
- All other tests: Should remain unchanged ✅

**Calculate new metrics:**
- Recall: Should be 100% (11/11) up from ~91%
- FP rate: Should remain 0%

### Estimated Timeline

| Task | Time | Cumulative |
|------|------|------------|
| CFG extraction | 1-2 hours | 2 hours |
| Path enumeration | 1 hour | 3 hours |
| Path-sensitive analysis | 2-3 hours | 6 hours |
| Integration | 1 hour | 7 hours |
| Testing & debugging | 1-2 hours | 9 hours |
| **Total** | **~7-9 hours** | **1-2 coding sessions** |

## After Phase 3.5.1: Continue with Closures

Once branch analysis is working, the next easiest feature is **closure support** (Phase 3.5.2):

### Why Closures Next?
- Simpler than traits (no dynamic dispatch)
- Well-structured in MIR
- Clear test case (test_closure_capture)
- Builds on existing call graph infrastructure

### High-Level Approach

1. **Detect closures:** Function names contain `{closure#N}`
2. **Extract captures:** Parse upvar_decls from MIR
3. **Propagate taint:** Captured variables inherit taint from parent
4. **Analyze body:** Treat like regular function with captured params

**See full details in:** `docs/phase3.5-roadmap.md` → Feature 2

## Resources

### Documentation
- **Phase 3.5 Roadmap:** `docs/phase3.5-roadmap.md` (full technical design)
- **Phase 3.4 Results:** `docs/phase3.4-false-positive-reduction.md` (baseline)
- **Test Cases:** `examples/interprocedural/src/lib.rs` (all 17 test cases)

### MIR References
- MIR Guide: https://rustc-dev-guide.rust-lang.org/mir/index.html
- Control Flow: https://rustc-dev-guide.rust-lang.org/mir/controlflow.html
- Basic Blocks: https://rustc-dev-guide.rust-lang.org/mir/basic-blocks.html

### Codebase Context
- **Inter-procedural analysis:** `mir-extractor/src/interprocedural.rs` (~1100 lines)
- **Dataflow module:** `mir-extractor/src/dataflow/` (taint analysis)
- **Tests:** `mir-extractor/tests/test_function_summaries.rs`

## Commands to Get Started

```bash
# Navigate to project
cd /Users/peteralbert/Projects/Rust-cola

# Create new CFG module
mkdir -p mir-extractor/src/dataflow
touch mir-extractor/src/dataflow/cfg.rs
touch mir-extractor/src/dataflow/path_sensitive.rs

# Update module declarations
# Add to mir-extractor/src/dataflow/mod.rs:
# pub mod cfg;
# pub mod path_sensitive;

# Run tests to see current baseline
cargo test --test test_function_summaries test_inter_procedural_detection -- --nocapture

# Look at test_partial_sanitization in detail
grep -A 10 "test_partial_sanitization" examples/interprocedural/src/lib.rs

# Examine MIR structure for this function
cargo build --manifest-path examples/interprocedural/Cargo.toml
cargo run --bin mir-extractor -- --crate-path examples/interprocedural --mir-json target/partial_mir.json
cat target/partial_mir.json | jq '.functions[] | select(.name | contains("partial_sanitization"))'
```

## Success Metrics for Phase 3.5.1

**Before starting, establish baseline:**
- Current recall: ~91% (10/11)
- Current FP rate: 0%
- test_partial_sanitization: SANITIZED (false negative)

**After Phase 3.5.1 completion:**
- Target recall: 100% (11/11) ✅
- Target FP rate: 0% (maintained) ✅
- test_partial_sanitization: VULNERABLE ✅

**Performance:**
- Analysis time should be <2x slower than Phase 3.4
- Memory usage should be reasonable (<100MB for test suite)

## Questions to Answer During Implementation

1. **CFG Extraction:**
   - How are basic blocks represented in our MIR JSON?
   - What terminator types do we need to handle?
   - How deep should we enumerate paths (depth limit)?

2. **Taint Tracking:**
   - How do we represent taint state per-block?
   - When should we merge paths vs keep separate?
   - How do we detect sanitization on a specific branch?

3. **Integration:**
   - Should all functions use CFG analysis or only branching ones?
   - How do we handle loops in the CFG?
   - What about indirect branches (match with many arms)?

## Ready to Start?

**Immediate next command:**
```bash
# Mark first todo as in-progress
# Then create cfg.rs module and start implementing ControlFlowGraph
```

**First concrete task:**
1. Examine MIR structure for test_partial_sanitization
2. Understand how if/else branches appear in basic_blocks
3. Sketch out CFG data structure
4. Write unit test for simple if/else CFG extraction

---

**Status:** Ready to begin Phase 3.5.1  
**Next Action:** Start CFG implementation  
**Goal:** Fix test_partial_sanitization false negative
