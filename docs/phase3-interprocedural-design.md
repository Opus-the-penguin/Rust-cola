# Phase 3: Inter-Procedural Taint Analysis - Design Document

**Status:** Planning  
**Started:** November 10, 2025  
**Goal:** Extend taint tracking across function boundaries to detect vulnerabilities involving multi-function data flows

## Executive Summary

Phase 2 achieved **0% false positive rate** with intra-procedural (single-function) taint analysis. However, it cannot detect vulnerabilities where:
- Tainted data is passed through function parameters
- Functions return tainted values that flow to sinks elsewhere
- Sanitization happens in helper functions

**Phase 3 Goal:** Implement inter-procedural analysis to track taint across function calls while maintaining our 0% FP rate.

## Motivation

### Current Limitations

```rust
// ❌ Phase 2 CANNOT detect this
fn get_user_input() -> String {
    std::env::args().nth(1).unwrap()  // Source
}

fn execute_query(query: &str) {
    Command::new("sh").arg("-c").arg(query).spawn();  // Sink
}

fn vulnerable_code() {
    let input = get_user_input();
    execute_query(&input);  // Taint flows across 2 function calls
}
```

```rust
// ❌ Phase 2 CANNOT detect this
fn sanitize_input(input: &str) -> String {
    input.chars().all(|c| c.is_alphanumeric())
        .then(|| input.to_string())
        .unwrap_or_default()
}

fn safe_code() {
    let input = std::env::args().nth(1).unwrap();
    let clean = sanitize_input(&input);  // Sanitization in helper
    Command::new("sh").arg("-c").arg(&clean).spawn();  // Actually safe!
}
```

### Real-World Impact

Analysis of InfluxDB showed that most security-critical functions call helper functions. To be truly effective, we need inter-procedural analysis.

## Design Overview

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│         Phase 3: Inter-Procedural Analysis              │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────────┐    ┌──────────────────┐          │
│  │  Call Graph      │───▶│  Function        │          │
│  │  Construction    │    │  Summaries       │          │
│  └──────────────────┘    └──────────────────┘          │
│           │                       │                     │
│           ▼                       ▼                     │
│  ┌──────────────────┐    ┌──────────────────┐          │
│  │  Taint           │───▶│  Context-        │          │
│  │  Propagation     │    │  Sensitive       │          │
│  │  (Dataflow)      │    │  Analysis        │          │
│  └──────────────────┘    └──────────────────┘          │
│           │                       │                     │
│           └───────────┬───────────┘                     │
│                       ▼                                 │
│           ┌──────────────────────┐                      │
│           │   Path Validation    │                      │
│           │   (Phase 2 CFG)      │                      │
│           └──────────────────────┘                      │
└─────────────────────────────────────────────────────────┘
```

### Core Components

1. **Call Graph Construction**
   - Build directed graph of function calls from MIR
   - Handle direct calls, method calls, trait dispatch
   - Support for closures and async functions

2. **Function Summaries**
   - Track which parameters are sources/sinks/sanitizers
   - Record taint propagation rules (e.g., param 0 → return)
   - Handle ownership/borrowing semantics

3. **Inter-Procedural Dataflow**
   - Bottom-up analysis (callees before callers)
   - Context-sensitive (distinguish call sites)
   - Fixed-point iteration for recursion

4. **Integration with Phase 2**
   - Reuse CFG and sanitization detection
   - Maintain 0% FP rate with precise modeling
   - Incremental analysis for performance

## Detailed Design

### 1. Function Summary Model

```rust
#[derive(Debug, Clone)]
pub struct FunctionSummary {
    /// Function identifier
    pub function_name: String,
    
    /// Which parameters can introduce taint
    pub source_parameters: HashSet<usize>,
    
    /// Which parameters flow to sinks within this function
    pub sink_parameters: HashSet<usize>,
    
    /// Which parameters are sanitized within this function
    pub sanitized_parameters: HashSet<usize>,
    
    /// Taint propagation rules: param index → destinations
    pub propagation_rules: Vec<TaintPropagation>,
    
    /// Return value taint sources
    pub return_taint: TaintSource,
    
    /// Function call graph information
    pub callees: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum TaintPropagation {
    /// Parameter N flows to return value
    ParamToReturn(usize),
    
    /// Parameter N flows to parameter M (for mutable refs)
    ParamToParam(usize, usize),
    
    /// Parameter N flows to sink (command execution, etc.)
    ParamToSink { param: usize, sink_type: SinkType },
    
    /// Parameter N is sanitized by this function
    ParamSanitized(usize),
}

#[derive(Debug, Clone)]
pub enum TaintSource {
    /// Return is clean
    Clean,
    
    /// Return is tainted from parameter N
    FromParameter(usize),
    
    /// Return is tainted from global source (env, file, etc.)
    FromSource(SourceType),
    
    /// Return depends on multiple sources
    Merged(Vec<TaintSource>),
}
```

### 2. Call Graph Construction Algorithm

```rust
pub struct CallGraph {
    /// Function name → CallGraphNode
    nodes: HashMap<String, CallGraphNode>,
    
    /// Topological order for bottom-up analysis
    analysis_order: Vec<String>,
}

pub struct CallGraphNode {
    pub function_name: String,
    pub callers: Vec<String>,
    pub callees: Vec<CallSite>,
    pub summary: Option<FunctionSummary>,
}

pub struct CallSite {
    pub callee: String,
    pub arguments: Vec<MirOperand>,
    pub return_destination: Option<MirPlace>,
    pub location: Location,
}

impl CallGraph {
    pub fn from_mir_package(package: &MirPackage) -> Result<Self> {
        // 1. Build nodes for all functions
        // 2. Extract function calls from MIR
        // 3. Compute strongly connected components (for recursion)
        // 4. Compute topological order (bottom-up)
        todo!()
    }
    
    pub fn get_analysis_order(&self) -> &[String] {
        // Return functions in bottom-up order
        &self.analysis_order
    }
}
```

### 3. Inter-Procedural Taint Analysis

```rust
pub struct InterProceduralTaintAnalysis {
    /// Function summaries computed so far
    summaries: HashMap<String, FunctionSummary>,
    
    /// Call graph
    call_graph: CallGraph,
    
    /// Intra-procedural analyzer (Phase 2)
    intra_analyzer: TaintAnalysis,
}

impl InterProceduralTaintAnalysis {
    pub fn analyze(&mut self, package: &MirPackage) -> Result<Vec<TaintFlow>> {
        let mut findings = Vec::new();
        
        // Bottom-up analysis: analyze callees before callers
        for function_name in self.call_graph.get_analysis_order() {
            let summary = self.analyze_function(function_name)?;
            self.summaries.insert(function_name.clone(), summary);
        }
        
        // Now do top-down pass to find complete taint flows
        for function in &package.functions {
            let flows = self.find_inter_procedural_flows(&function)?;
            findings.extend(flows);
        }
        
        Ok(findings)
    }
    
    fn analyze_function(&mut self, name: &str) -> Result<FunctionSummary> {
        // 1. Get function MIR
        // 2. Run intra-procedural analysis (Phase 2)
        // 3. For each function call, consult callee summary
        // 4. Propagate taint through call sites
        // 5. Build summary for this function
        todo!()
    }
    
    fn find_inter_procedural_flows(&self, function: &MirFunction) 
        -> Result<Vec<TaintFlow>> 
    {
        // 1. Start from sources in this function
        // 2. Follow taint through local variables
        // 3. When taint reaches function call:
        //    - Consult callee summary
        //    - Check if tainted param flows to sink in callee
        //    - Or if tainted param returns and flows further
        // 4. Build complete path from source to sink
        todo!()
    }
}
```

### 4. Context-Sensitive Analysis

To maintain 0% FP rate, we need context sensitivity:

```rust
pub struct AnalysisContext {
    /// Call stack (for context sensitivity)
    call_stack: Vec<CallSite>,
    
    /// Taint state at this context
    taint_state: HashMap<MirLocal, TaintInfo>,
    
    /// Maximum depth (to prevent infinite recursion)
    max_depth: usize,
}

impl AnalysisContext {
    pub fn push_call(&mut self, call_site: CallSite) -> bool {
        if self.call_stack.len() >= self.max_depth {
            return false;  // Depth limit reached
        }
        self.call_stack.push(call_site);
        true
    }
    
    pub fn is_recursive(&self, function: &str) -> bool {
        self.call_stack.iter()
            .any(|cs| cs.callee == function)
    }
}
```

## Implementation Plan

### Phase 3.1: Foundation (Week 1-2)
- [ ] Implement CallGraph construction from MIR
- [ ] Design FunctionSummary data structures
- [ ] Add tests for call graph with simple examples
- [ ] Handle direct function calls only

**Deliverable:** Basic call graph that can identify function calls in MIR

### Phase 3.2: Function Summaries (Week 3-4)
- [ ] Implement summary generation for leaf functions (no callees)
- [ ] Track parameter → return taint flows
- [ ] Track parameter → sink flows
- [ ] Add summary caching and serialization

**Deliverable:** Summaries for functions that don't call other functions

### Phase 3.3: Inter-Procedural Propagation (Week 5-6)
- [ ] Implement bottom-up analysis
- [ ] Propagate taint through call sites
- [ ] Handle parameter passing (by value, by reference)
- [ ] Add test cases with 2-level call chains

**Deliverable:** Detect vulnerabilities across 2 function calls

### Phase 3.4: Context Sensitivity (Week 7-8)
- [ ] Add call stack tracking
- [ ] Implement context-sensitive analysis
- [ ] Handle recursion with depth limits
- [ ] Optimize for performance

**Deliverable:** Accurate analysis with multiple call sites

### Phase 3.5: Advanced Features (Week 9-10)
- [ ] Support closures and function pointers
- [ ] Handle trait method calls (dynamic dispatch)
- [ ] Support async functions and futures
- [ ] Integration testing with real projects

**Deliverable:** Production-ready inter-procedural analysis

### Phase 3.6: Evaluation & Refinement (Week 11-12)
- [ ] Measure FP rate on test suite + InfluxDB
- [ ] Performance benchmarks
- [ ] Compare with Phase 2 results
- [ ] Document findings and update ROADMAP

**Deliverable:** Phase 3 complete, 0% FP rate maintained

## Test Strategy

### Unit Tests

```rust
#[test]
fn test_two_level_call_chain() {
    // Source in main, sink in helper
    let code = r#"
        fn source() -> String {
            std::env::args().nth(1).unwrap()
        }
        
        fn sink(cmd: &str) {
            Command::new("sh").arg("-c").arg(cmd).spawn();
        }
        
        fn main() {
            let input = source();
            sink(&input);  // Should detect flow
        }
    "#;
    
    let findings = analyze(code);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].source_type, SourceType::Environment);
}

#[test]
fn test_sanitization_in_helper() {
    // Sanitization in separate function
    let code = r#"
        fn sanitize(s: &str) -> String {
            s.parse::<i32>()
                .ok()
                .map(|n| n.to_string())
                .unwrap_or_default()
        }
        
        fn main() {
            let input = std::env::args().nth(1).unwrap();
            let safe = sanitize(&input);
            Command::new("sh").arg("-c").arg(&safe).spawn();
        }
    "#;
    
    let findings = analyze(code);
    assert_eq!(findings.len(), 0);  // Should be sanitized
}

#[test]
fn test_context_sensitive() {
    // Same function called with different arguments
    let code = r#"
        fn process(data: &str) {
            Command::new("sh").arg("-c").arg(data).spawn();
        }
        
        fn main() {
            let tainted = std::env::args().nth(1).unwrap();
            let safe = "echo hello";
            
            process(&tainted);  // Vulnerable
            process(safe);      // Safe
        }
    "#;
    
    let findings = analyze(code);
    assert_eq!(findings.len(), 1);  // Only the tainted call
}
```

### Integration Tests

1. **Existing Test Suite:** All Phase 2 tests must continue to pass
2. **InfluxDB Re-analysis:** Findings should improve (more TPs, still 0 FPs)
3. **Benchmark Suite:** Create 20 inter-procedural test cases
4. **Performance:** Analysis time should scale sub-linearly with call depth

## Performance Considerations

### Scalability Challenges

- **Call Graph Size:** O(N) for N functions, but edges can be O(N²)
- **Summary Computation:** Each function analyzed once (bottom-up)
- **Context Sensitivity:** Exponential worst-case, need heuristics
- **Recursion:** Need cycle detection and widening

### Optimization Strategies

1. **Caching:** Store computed summaries, invalidate on changes
2. **Pruning:** Skip functions that can't affect taint (no sources/sinks)
3. **Incremental:** Only re-analyze affected functions on code changes
4. **Depth Limits:** Cap context sensitivity at 3-5 levels
5. **Parallel:** Analyze independent call graph components in parallel

### Target Performance

- **Small projects (<100 functions):** <1 minute
- **Medium projects (100-1000 functions):** <10 minutes
- **Large projects (1000+ functions):** <60 minutes

## Challenges & Risks

### Technical Challenges

1. **Trait Method Resolution**
   - Dynamic dispatch makes callee unknown statically
   - Need type information from HIR or trait bounds
   - May require conservative approximation

2. **Closures & Function Pointers**
   - Closures can capture variables from outer scope
   - Function pointers have unknown targets
   - Need escape analysis or conservative handling

3. **Async/Await**
   - Futures passed across function boundaries
   - Executors and spawned tasks complicate analysis
   - Need to model async runtime behavior

4. **Aliasing & Mutable References**
   - `&mut` parameters can cause bidirectional flows
   - Ownership transfer vs. borrowing semantics
   - Rust's borrow checker helps but need careful modeling

### Risk Mitigation

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| FP rate increases | High | Medium | Extensive testing, conservative approximations |
| Performance degrades | Medium | High | Profiling, optimization, caching |
| Complex trait dispatch | Medium | High | Start with simple cases, expand gradually |
| Recursion handling | Medium | Low | Cycle detection, depth limits |

## Success Criteria

### Mandatory (Must Have)

- [ ] ✅ **0% False Positive Rate** on test suite + InfluxDB
- [ ] Detect at least 50% more true positives than Phase 2
- [ ] Analysis completes in <10 minutes for medium projects
- [ ] All Phase 2 tests still pass
- [ ] Call graph construction for 100% of functions

### Desired (Should Have)

- [ ] Context sensitivity with depth ≥ 3
- [ ] Support for closures and basic trait calls
- [ ] Incremental analysis for faster re-runs
- [ ] Performance profiling and optimization
- [ ] Summary serialization for caching

### Stretch Goals (Nice to Have)

- [ ] Full async/await support
- [ ] Complex trait resolution via HIR
- [ ] Parallel analysis of independent components
- [ ] Interactive visualization of taint flows
- [ ] Integration with IDE (VS Code extension)

## Timeline

| Phase | Duration | Key Milestone |
|-------|----------|---------------|
| 3.1 Foundation | 2 weeks | Call graph construction |
| 3.2 Summaries | 2 weeks | Leaf function summaries |
| 3.3 Propagation | 2 weeks | 2-level flow detection |
| 3.4 Context | 2 weeks | Context-sensitive analysis |
| 3.5 Advanced | 2 weeks | Closures, traits, async |
| 3.6 Evaluation | 2 weeks | Testing, optimization |
| **Total** | **12 weeks** | **Phase 3 Complete** |

## Related Work

### Academic Research

1. **FlowDroid** (Android taint analysis)
   - Context-sensitive, field-sensitive, flow-sensitive
   - On-demand call graph construction
   - Applicable techniques for Rust

2. **TAJ** (Java taint analysis)
   - Summary-based inter-procedural analysis
   - Efficient handling of large programs
   - Good model for our approach

3. **IFDS/IDE Framework**
   - General framework for data flow analysis
   - Proven theoretical foundation
   - Could formalize our approach

### Rust Static Analysis Tools

1. **MIRAI** (Facebook)
   - Abstract interpretation for Rust
   - Interprocedural but heavyweight
   - Complementary approach

2. **Rudra** (Memory safety)
   - Focuses on unsafe code
   - Different domain but similar MIR analysis
   - Good reference for implementation

## Next Steps

1. **Create Phase 3 Branch:** `git checkout -b phase3-interprocedural`
2. **Set Up Test Suite:** Create `examples/interprocedural/` with test cases
3. **Implement CallGraph:** Start with Phase 3.1
4. **Weekly Progress Reviews:** Document findings and challenges
5. **Maintain Documentation:** Update this document as design evolves

## References

- [Phase 2 Results](./phase2-final-results.md)
- [ROADMAP](./ROADMAP.md)
- [Real-World Testing](./real-world-testing-influxdb.md)
- [MIR Documentation](https://rustc-dev-guide.rust-lang.org/mir/index.html)
- [FlowDroid Paper](https://www.bodden.de/pubs/far+14flowdroid.pdf)

---

**Document Version:** 1.0  
**Last Updated:** November 10, 2025  
**Author:** Rust-Cola Development Team  
**Status:** Ready for Implementation
