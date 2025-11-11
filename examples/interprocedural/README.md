# Phase 3: Inter-Procedural Taint Analysis

**Status:** 🚧 Planning & Design  
**Started:** November 10, 2025  
**Expected Completion:** February 2026 (12 weeks)

## Overview

Phase 3 extends Rust-Cola's taint tracking to follow data flows across function boundaries. This enables detection of vulnerabilities where tainted data passes through multiple functions before reaching a sink.

## Current Capabilities (Phase 2)

✅ **Intra-procedural taint analysis** (within single functions)  
✅ **0% false positive rate** on test suite + InfluxDB  
✅ **Dataflow-based sanitization** detection  
✅ **Control-flow-based sanitization** detection  

## Phase 3 Goals

### Primary Objectives

1. **Inter-procedural taint tracking**
   - Follow taint through function calls
   - Track parameter → return flows
   - Handle mutable references

2. **Maintain 0% FP rate**
   - Conservative analysis where needed
   - Precise modeling of Rust semantics
   - Extensive testing

3. **Context sensitivity**
   - Distinguish different call sites
   - Handle recursion safely
   - Efficient analysis

### Success Metrics

- **False Positive Rate:** 0% (maintained)
- **True Positive Increase:** ≥50% more than Phase 2
- **Performance:** <10 minutes for medium projects (100-1000 functions)
- **Coverage:** Detect all test cases in `examples/interprocedural/`

## Architecture

```
Call Graph Construction
         ↓
Function Summarization (bottom-up)
         ↓
Inter-procedural Dataflow
         ↓
Path Validation (reuse Phase 2 CFG)
         ↓
Findings Report
```

## Test Cases

See `examples/interprocedural/src/lib.rs` for 17 test cases covering:

- **Basic flows:** 2-level, 3-level function chains
- **Sanitization:** Helper functions, validation checks
- **Parameters:** By value, by reference, mutable
- **Control flow:** Branching, context sensitivity
- **Advanced:** Closures, traits, async (Phase 3.5)

### Expected Results

- **11 vulnerable** patterns (should detect)
- **3 safe** patterns (should NOT flag)
- **0 false positives** (never flag safe code)

## Implementation Phases

### Phase 3.1: Foundation (Weeks 1-2)
- Call graph construction from MIR
- Basic function call identification
- Test infrastructure

### Phase 3.2: Function Summaries (Weeks 3-4)
- Summary data structures
- Leaf function analysis
- Parameter taint tracking

### Phase 3.3: Inter-procedural Propagation (Weeks 5-6)
- Bottom-up analysis
- Call site propagation
- 2-level flow detection

### Phase 3.4: Context Sensitivity (Weeks 7-8)
- Call stack tracking
- Recursion handling
- Performance optimization

### Phase 3.5: Advanced Features (Weeks 9-10)
- Closures and function pointers
- Trait method resolution
- Async/await support

### Phase 3.6: Evaluation (Weeks 11-12)
- Comprehensive testing
- InfluxDB re-analysis
- Performance benchmarking
- Documentation

## Getting Started

### Prerequisites

```bash
# Ensure you have Phase 2 working
cd /Users/peteralbert/Projects/Rust-cola
cargo test --package mir-extractor

# Build the test suite
cd examples/interprocedural
cargo build
```

### Running Tests

```bash
# Phase 2 baseline (should find 0 inter-procedural issues)
cargo-cola --crate-path examples/interprocedural

# After Phase 3 implementation:
# Should find 11 vulnerable patterns, 0 false positives
```

### Development Workflow

1. **Create feature branch:**
   ```bash
   git checkout -b phase3-interprocedural
   ```

2. **Implement a sub-phase:**
   ```bash
   # Edit mir-extractor/src/interprocedural.rs
   # Add tests
   cargo test
   ```

3. **Test on real code:**
   ```bash
   cargo-cola --crate-path examples/interprocedural
   ```

4. **Commit progress:**
   ```bash
   git commit -m "Phase 3.X: Description"
   ```

## Key Challenges

### Technical Challenges

1. **Trait Method Resolution**
   - Dynamic dispatch complicates call graph
   - May need conservative over-approximation
   - Consider using HIR for type information

2. **Closures**
   - Capture environment variables
   - Can be passed as parameters
   - Need escape analysis

3. **Async/Await**
   - Futures passed across boundaries
   - Executor scheduling
   - State machine transformations

4. **Performance**
   - Call graph can be large
   - Context sensitivity is expensive
   - Need caching and optimization

### Mitigation Strategies

- Start with simple cases (direct calls)
- Add complexity gradually
- Benchmark at each phase
- Use profiling to identify bottlenecks
- Implement caching early

## Resources

### Documentation

- [Design Document](../docs/phase3-interprocedural-design.md) - Detailed technical design
- [Phase 2 Results](../docs/phase2-final-results.md) - Baseline performance
- [ROADMAP](../docs/ROADMAP.md) - Overall project plan

### Academic Papers

- **FlowDroid:** Context-sensitive taint analysis for Android
- **TAJ:** Summary-based inter-procedural analysis for Java
- **IFDS/IDE:** Framework for inter-procedural dataflow

### Rust Resources

- [MIR Documentation](https://rustc-dev-guide.rust-lang.org/mir/index.html)
- [MIRAI](https://github.com/facebookexperimental/MIRAI) - Facebook's Rust analyzer
- [Rudra](https://github.com/sslab-gatech/Rudra) - Memory safety analyzer

## Progress Tracking

### Completed ✅

- [x] Phase 3 design document
- [x] Test case suite (17 cases)
- [x] Example crate structure
- [x] Expected results defined

### In Progress 🚧

- [ ] Phase 3.1: Call graph construction

### Planned 📋

- [ ] Phase 3.2: Function summaries
- [ ] Phase 3.3: Inter-procedural propagation
- [ ] Phase 3.4: Context sensitivity
- [ ] Phase 3.5: Advanced features
- [ ] Phase 3.6: Evaluation

## Contact & Collaboration

This is an open-source project. Contributions welcome!

- **Repository:** https://github.com/Opus-the-penguin/Rust-cola
- **Issues:** GitHub Issues for bug reports and feature requests
- **Discussions:** GitHub Discussions for design questions

## License

Same as main project (see LICENSE file in repository root)

---

**Last Updated:** November 10, 2025  
**Next Review:** Start of Phase 3.1 implementation
