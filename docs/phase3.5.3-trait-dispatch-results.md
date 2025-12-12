# Phase 3.5.3: Trait Method Dispatch Support

## Overview
This phase focused on enabling inter-procedural taint analysis to propagate through dynamic dispatch calls (`dyn Trait`). Previously, the analysis would stop at trait method calls because the concrete implementation could not be resolved from the MIR alone.

## Implementation Details

### 1. Call Graph Resolution
We enhanced the `CallGraph` construction in `interprocedural.rs` to resolve ambiguous calls.
- **Heuristic Resolution:** When a call target cannot be resolved directly (e.g., `<dyn Trait>::method`), we now look up potential candidates using a short-name map of all functions in the package.
- **Resolved Targets:** The `CallSite` struct was updated to include `resolved_targets: Vec<String>`, storing all potential concrete implementations for a call.

### 2. Summary Propagation
The inter-procedural analysis was updated to utilize the resolved targets.
- **Summary Merging:** When analyzing a function, if a call site has multiple resolved targets, we merge the summaries of all targets. This ensures that if *any* implementation is vulnerable or propagates taint, the analysis considers it.
- **Name Cleaning:** We improved the summary lookup in `path_sensitive.rs` to strip MIR artifacts (like `move`, `copy`, `const`) from function names, ensuring reliable matching.

### 3. Internal Vulnerability Tracking
We introduced a new mechanism to track functions that contain a complete vulnerability (source -> sink) internally, which is common in top-level functions or test cases.
- **`has_internal_vulnerability`:** Added a flag to `FunctionSummary`.
- **Path-Sensitive Detection:** The `from_mir_function` method now runs path-sensitive analysis to detect internal flows and sets this flag.
- **Flow Reporting:** `detect_inter_procedural_flows` was updated to report flows for functions with internal vulnerabilities, even if they don't return tainted data.

## Verification
We created a new test suite `tests/test_advanced_rules.rs` with a specific test case `test_trait_method`.
- **Scenario:** A `ShellExecutor` struct implements an `Executor` trait with an `execute` method that performs a command injection. The test creates a `Box<dyn Executor>` and calls `execute` with tainted data.
- **Result:** The analysis successfully resolves the `execute` call to `ShellExecutor::execute`, retrieves its summary (which indicates a sink), and reports a vulnerability.

## Next Steps
- **Closures:** Further refine closure analysis (Phase 3.5.2) to handle more complex capture scenarios.
- **Async/Await:** Improve support for async function state machines (Phase 3.5.4).
