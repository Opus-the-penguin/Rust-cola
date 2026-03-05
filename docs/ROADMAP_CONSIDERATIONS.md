# Roadmap Considerations

> **Working Document**: Research directions and experimental ideas for rust-cola development.

rust-cola is a **research tool** for exploring static analysis techniques on Rust's MIR representation. The focus is on advancing the state of taint tracking, dataflow analysis, and vulnerability detection in Rust codebases—not on production deployment or enterprise workflows.

---

## Guard Detection Research

The taint tracker identifies data flow from sources to sinks but may miss validation/bounds checks along the path. This is a fundamental challenge in static analysis: distinguishing true vulnerabilities from guarded code paths.

### Current State (v1.0.1)

- LLM prompt includes Step 0.5 with guard detection guidance
- Rule-specific guard patterns provided per finding type
- Per-finding hints assist human analysis

### Research Directions

#### 1. Semantic Guard Pattern Recognition
Explore detecting guard patterns semantically rather than syntactically:
- Identify min/max/clamp calls and their effect on value ranges
- Track "sanitized" state propagation through the taint lattice
- Investigate abstract interpretation for bound inference

#### 2. Constant Propagation for Allocation Bounds
Research correlating `MAX_*`, `LIMIT_*` constants with allocation findings:
- Determine when allocation sizes derive from bounded fields
- Explore inter-procedural constant propagation through constructors
- Study how schema constraints bound values at type boundaries

#### 3. Validation Function Discovery
Investigate techniques for automatically identifying validation functions:
- Entry-point guards that check invariants before processing
- Constructor validation that establishes field constraints
- Parse/deserialize guards that reject malformed input

#### 4. Context Window Optimization
Experiment with optimal context extraction for LLM analysis:
- Trade-offs between context size and analysis accuracy
- Pre-filtering findings with detected guards
- Minimal context that preserves guard detection capability

---

## Confidence Calibration Research

### Current State
- Categorical confidence levels (High/Medium/Low)
- Confidence assigned per-rule, not per-finding

### Research Questions

#### 1. Evidence-Based Confidence
How should confidence correlate with evidence quality?
- What MIR patterns predict true positives?
- Can confidence be learned from labeled datasets?
- How do pattern matches compare to dataflow evidence?

#### 2. Reachability-Aware Scoring
How does call-graph position affect vulnerability likelihood?
- Public API entry points vs. internal-only paths
- Library code vs. binary code considerations
- Dead code detection and its impact on prioritization

---

## Analysis Technique Experiments

### Current Capabilities
- MIR-level taint tracking
- Inter-procedural analysis (limited depth)
- Pattern-based vulnerability detection

### Experimental Directions

#### 1. Incremental Analysis
Explore incremental re-analysis for iterative research workflows:
- Function-level change detection
- Taint summary caching across runs

#### 2. Multi-Threading & Parallelization
Investigate parallel analysis strategies for large crates and project-level scans:
- Per-function or per-module parallel taint analysis
- Concurrent MIR extraction across workspace crates
- Thread-safe taint summary merging
- Work-stealing schedulers for load balancing
- Benchmarking scaling characteristics (core count vs. analysis time)

#### 3. Hybrid Analysis
Investigate combining static analysis with other techniques:
- **Cargo-fuzz integration**: Leverage LLVM libFuzzer via cargo-fuzz for reachability validation and input generation
  - Use static analysis to identify fuzz-worthy entry points
  - Generate fuzz harnesses from taint paths
  - Correlate fuzzer-discovered crashes with static findings
- **Symbolic execution with constraint solvers**: Integrate SMT solvers (Z3, CVC5) for path feasibility analysis
  - Encode path conditions from MIR control flow
  - Prove/disprove reachability of vulnerable sinks
  - Reason about integer bounds to eliminate false positives
- LLM-assisted code understanding

#### 4. Cross-Crate Analysis
Research challenges in analyzing crate dependencies:
- Taint propagation across crate boundaries
- Trait-based polymorphism handling
- Generic instantiation enumeration

---

## Rule Authoring Research

### Pattern Language Design
- What DSL abstractions simplify rule development?
- Trade-offs between expressiveness and performance
- Composable rule primitives

### Query Language / Engine (CodeQL-style)
Investigate a declarative query language for expressing vulnerability patterns:
- SQL-like or Datalog-based syntax for querying MIR/CFG structures
- Composable predicates for taint sources, sinks, and sanitizers
- Integration with existing rule definitions
- Query optimization for large codebases
- Potential inspiration: CodeQL, Semgrep, tree-sitter queries

### Empirical Rule Evaluation
- Methodology for measuring precision/recall on labeled datasets
- Mutation testing for assessing rule coverage
- False positive/negative characterization

### Rules Iteration via LLM Feedback
Leverage LLM analysis of real-world targets to iteratively refine rule logic:
- Collect LLM verdicts (true positive, false positive, guard detected) from production scans
- Identify systematic false positive patterns requiring rule refinement
- Use feedback to tune confidence thresholds and guard detection heuristics
- Build labeled datasets from LLM-assisted triage for regression testing
- Track rule precision/recall trends over time across target repositories

---

## Benchmarking & Evaluation

### Dataset Curation
- Collecting labeled vulnerability datasets for Rust
- Synthetic vulnerable code generation
- Real-world vulnerability case studies

### Metrics
- Precision/recall on curated benchmarks
- Analysis time vs. codebase size scaling
- Comparison with other Rust analysis tools

---

## Custom LLM Training & Hosting

### Organization-Specific Model Fine-Tuning
Explore training/hosting a local LLM specialized for codebase-specific analysis:
- Fine-tune on InfluxDB codebase, historical issues, and security advisories
- Train on internal bug tracker data (false positives, true positives, triage decisions)
- Incorporate domain knowledge (time-series databases, query engines, storage layers)
- Local hosting for data privacy and reduced latency

### Training Data Sources
- Historical security issues and CVEs
- Code review comments and PR discussions
- Internal documentation and architecture decisions
- Existing triage verdicts from rust-cola scans

### Deployment Considerations
- Model quantization for resource-efficient hosting
- Inference latency vs. analysis depth trade-offs
- Hybrid approach: local model for fast triage, cloud model for deep analysis

---

## Notes

- **Focus**: Guard detection is the primary research priority—directly impacts false positive rates
- **Approach**: Experimental, iterative—not production-hardened
- **Contributions**: Findings may inform future static analysis research for Rust
