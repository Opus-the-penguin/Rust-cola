# cargo-cola v1.x Roadmap

**Start Date:** December 2025  
**Current Version:** 1.0.0  
**Target Version:** 1.x (multiple releases)

---

## Vision

Transform cargo-cola from a scan-and-prompt tool into a **fully autonomous security analysis platform** with integrated AI, specialized agents, and a user-friendly interface that anyone can use - from security engineers to project managers.

---

## Phase Overview

| Phase | Name | Description | Priority |
|-------|------|-------------|----------|
| 1 | **Local LLM Integration** | Eliminate manual LLM step with embedded Code Llama | P0 |
| 2A | **Scanner Agent Pipeline** | Decompose analyzer: Source → Compiler → Rules → IPA → Findings | P0 |
| 2B | **LLM Agent Pipeline** | Specialized AI agents: Precision → Exploit → Severity → Remediation → Report | P0 |
| 3 | **Rules Refresh** | Precision/recall tuning + new rules expansion | P1 |
| 4 | **User Interface** | Simple UI for non-technical users | P1 |
| — | *Developer Workflows* | *IDE, CI/CD integration (v2.x)* | *Future* |
| — | *RustyCode* | *Proprietary synthetic training data (v2.x)* | *Future* |

---

## Phase 1: Local LLM Integration

### Problem
Currently, cargo-cola generates artifacts (`out/cola/`) but requires manual intervention:
1. User runs `cargo-cola --crate-path .`
2. User opens `llm-prompt.md`
3. User manually copies to ChatGPT/Claude
4. User reads response and creates report

This friction prevents adoption and automation.

### Solution
Embed a local LLM (Code Llama or similar) that automatically processes findings and generates the final report.

### Technical Approach

| Option | Model | Size | Pros | Cons |
|--------|-------|------|------|------|
| **A. Ollama integration** | Code Llama 7B/13B | 4-8GB | Easy setup, user's machine | Requires Ollama installed |
| **B. llama.cpp embedded** | Code Llama 7B | 4GB | Zero dependencies, portable | Larger binary, complex build |
| **C. ONNX Runtime** | Fine-tuned model | 2-4GB | Optimized inference | Model training required |

**Recommended:** Start with **Option A (Ollama)** for rapid iteration, move to **Option B** for distribution.

### Implementation Tasks

- [ ] Add `--local-llm` flag to enable local LLM processing
- [ ] Detect/install Ollama automatically (or prompt user)
- [ ] Pull Code Llama model on first run
- [ ] Stream LLM output to terminal during analysis
- [ ] Generate `report.md` automatically (not just `llm-prompt.md`)
- [ ] Support offline mode (no internet required after model download)
- [ ] Benchmark: target <2 min for full analysis + report on typical crate

### User Experience (After)
```bash
cargo-cola --crate-path /path/to/project
# ... scanning ...
# ... AI analysis (local) ...
# ✅ Report generated: out/cola/report.md
```

One command. No manual steps. No API keys.

---

## Phase 2: Agent Architecture

The agent architecture encompasses two distinct pipelines:
1. **Scanner Agents** - Decomposed security analysis (code → raw findings)
2. **LLM Agents** - Post-scan analysis and reporting (raw findings → final report)

### 2A: Scanner Agent Pipeline

The security analyzer itself can be decomposed into discrete phases, each with focused responsibilities. Some phases are purely deterministic (no LLM), while others may optionally engage an LLM for error recovery.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SCANNER AGENT PIPELINE                                │
│                                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐  │
│  │   SOURCE     │   │   COMPILER   │   │    RULES     │   │     IPA      │  │
│  │   AGENT      │ → │    AGENT     │ → │    ENGINE    │ → │    ENGINE    │  │
│  │              │   │              │   │    AGENT     │   │    AGENT     │  │
│  │ • Clone repo │   │ • Build crate│   │              │   │              │  │
│  │ • Resolve    │   │ • Extract AST│   │ • Pattern    │   │ • Taint      │  │
│  │   dependencies│  │ • Extract MIR│   │   matching   │   │   tracking   │  │
│  │ • Workspace  │   │ • Handle     │   │ • Type-based │   │ • Source →   │  │
│  │   detection  │   │   errors     │   │   rules      │   │   Sink       │  │
│  │              │   │              │   │ • MIR rules  │   │ • Injection  │  │
│  │ [No LLM]     │   │ [LLM: debug] │   │              │   │   detection  │  │
│  │              │   │              │   │ [No LLM]     │   │              │  │
│  └──────────────┘   └──────────────┘   └──────────────┘   │ [No LLM]     │  │
│         ↓                  ↓                  ↓           └──────────────┘  │
│    source files      MIR + metadata     pattern findings         ↓          │
│                                                            taint findings   │
│                                                                  ↓          │
│                      ┌──────────────────────────────────────────────────┐   │
│                      │              FINDINGS SYNTHESIZER                │   │
│                      │                                                  │   │
│                      │  • Merge pattern + taint findings                │   │
│                      │  • Deduplicate overlapping detections            │   │
│                      │  • Generate raw-findings.json                    │   │
│                      │  • Generate LLM prompt for next pipeline         │   │
│                      │                                                  │   │
│                      │  [No LLM]                                        │   │
│                      └──────────────────────────────────────────────────┘   │
│                                           ↓                                  │
│                                  raw-findings.json                          │
│                                  llm-prompt.md                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                        ↓
                            (LLM Agent Pipeline - 2B)
```

#### Scanner Agent 1: Source Agent
**Purpose:** Acquire and prepare source code for analysis

**Responsibilities:**
- Clone repository or accept local path
- Detect Cargo workspace structure
- Resolve dependencies (fetch crates.io deps)
- Identify analysis targets (which crates to scan)
- Handle monorepo structures

**LLM Integration:** None (deterministic)

**Output:** Prepared workspace with resolved dependencies

#### Scanner Agent 2: Compiler Agent  
**Purpose:** Build crate and extract intermediate representations

**Responsibilities:**
- Invoke `cargo build` with appropriate flags
- Extract AST (Abstract Syntax Tree)
- Extract MIR (Mid-level Intermediate Representation)
- Extract type information and trait bounds
- Handle compilation errors gracefully

**LLM Integration:** Optional - engage LLM to diagnose and suggest fixes for:
- Missing dependencies
- Feature flag issues
- Incompatible toolchain versions
- Platform-specific compilation failures

**Output:** MIR dump + type metadata + AST for all crates

#### Scanner Agent 3: Rules Engine Agent
**Purpose:** Execute pattern-based vulnerability detection

**Responsibilities:**
- Load and validate rule definitions (126+ rules)
- Execute pattern matching rules against AST
- Execute MIR-based rules for dataflow analysis
- Execute type-system rules (trait bounds, generics)
- Apply rule-specific filters to reduce false positives

**LLM Integration:** None (deterministic rule execution)

**Output:** Pattern-based findings with evidence

#### Scanner Agent 4: IPA (Inter-Procedural Analysis) Engine Agent
**Purpose:** Detect vulnerabilities requiring cross-function analysis

**Responsibilities:**
- Build call graph across crate boundaries
- Implement taint propagation infrastructure
- Track data flow from sources to sinks
- Detect injection vulnerabilities (SQL, command, path traversal)
- Detect SSRF, TOCTOU, and other flow-sensitive bugs
- Handle async/await control flow

**LLM Integration:** None (deterministic dataflow analysis)

**Output:** Taint-based findings with source→sink traces

#### Scanner Agent 5: Findings Synthesizer
**Purpose:** Merge and prepare findings for LLM analysis

**Responsibilities:**
- Merge pattern findings + taint findings
- Deduplicate overlapping detections
- Enrich findings with source context (surrounding code)
- Generate `raw-findings.json` (structured data)
- Generate `llm-prompt.md` (human-readable for LLM consumption)
- Calculate scan metadata (timing, coverage, etc.)

**LLM Integration:** None (deterministic)

**Output:** `raw-findings.json` + `llm-prompt.md` → feeds into LLM Agent Pipeline

---

### 2B: LLM Agent Pipeline

### Problem
The current LLM prompt asks one model to do everything:
- Validate findings (precision)
- Assess exploitability
- Rank severity
- Suggest remediations
- Format report

This is suboptimal - different tasks benefit from different prompting strategies and potentially different models.

### Solution
Decompose into specialized agents with focused responsibilities:

```
┌─────────────────────────────────────────────────────────────────┐
│                      cargo-cola scan                             │
│                           ↓                                      │
│                   raw-findings.json                              │
│                           ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                   AGENT PIPELINE                            │ │
│  │                                                             │ │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │ │
│  │  │  PRECISION  │ →  │EXPLOITABIL- │ →  │  SEVERITY   │     │ │
│  │  │   AGENT     │    │ ITY AGENT   │    │   AGENT     │     │ │
│  │  │             │    │             │    │             │     │ │
│  │  │ • Prune FPs │    │ • PoC code  │    │ • Context   │     │ │
│  │  │ • Validate  │    │ • Attack    │    │ • Controls  │     │ │
│  │  │ • Confidence│    │   vectors   │    │ • Priority  │     │ │
│  │  └─────────────┘    └─────────────┘    └─────────────┘     │ │
│  │         ↓                                    ↓              │ │
│  │  ┌─────────────┐                      ┌─────────────┐      │ │
│  │  │ REMEDIATION │                      │   REPORT    │      │ │
│  │  │   AGENT     │ ──────────────────→  │  GENERATOR  │      │ │
│  │  │             │                      │             │      │ │
│  │  │ • Fix code  │                      │ • Executive │      │ │
│  │  │ • Patterns  │                      │   summary   │      │ │
│  │  │ • Examples  │                      │ • Details   │      │ │
│  │  └─────────────┘                      └─────────────┘      │ │
│  │                                              ↓              │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                           ↓                                      │
│                      report.md                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Agent Specifications

#### Agent 1: Precision Agent
**Purpose:** Prune false positives, validate true positives

**Input:** Raw findings + source context  
**Output:** Validated findings with confidence scores

**Prompt Strategy:**
- Show finding + evidence + surrounding code
- Ask: "Is this a real vulnerability or false positive? Why?"
- Structured output: `{finding_id, verdict: TP|FP|NEEDS_REVIEW, reasoning}`

#### Agent 2: Exploitability Agent
**Purpose:** Assess real-world exploitability, generate PoC concepts

**Input:** Validated findings  
**Output:** Exploitability assessment + attack scenarios

**Prompt Strategy:**
- For each TP finding, analyze attack surface
- Consider: authentication, input validation, network exposure
- Generate conceptual PoC or attack steps
- Output: `{finding_id, exploitable: YES|NO|CONDITIONAL, attack_scenario, poc_concept}`

#### Agent 3: Severity Agent
**Purpose:** Contextual severity ranking with business impact

**Input:** Validated findings + exploitability + crate metadata  
**Output:** Prioritized findings with severity justification

**Prompt Strategy:**
- Consider: CVSS base score, exploitability, blast radius, data sensitivity
- Factor in mitigating controls visible in code
- Output: `{finding_id, severity: CRITICAL|HIGH|MEDIUM|LOW|INFO, reasoning, priority_rank}`

#### Agent 4: Remediation Agent
**Purpose:** Generate actionable fix suggestions with code

**Input:** Validated findings + original code  
**Output:** Fix suggestions with code snippets

**Prompt Strategy:**
- Analyze vulnerable pattern
- Generate idiomatic Rust fix
- Provide before/after code comparison
- Output: `{finding_id, fix_description, code_before, code_after, references}`

#### Agent 5: Report Generator
**Purpose:** Synthesize all agent outputs into polished report

**Input:** All agent outputs + scan metadata  
**Output:** Final `report.md`

**Report Sections:**
1. Executive Summary (for managers)
2. Critical Findings (immediate action)
3. Detailed Findings (for developers)
4. Remediation Roadmap (prioritized fixes)
5. Appendix (methodology, scan metadata)

### Implementation Tasks

- [ ] Design agent interface/trait (`Agent { fn analyze(&self, input) -> output }`)
- [ ] Implement each agent with specialized prompts
- [ ] Create agent pipeline orchestrator
- [ ] Support parallel agent execution where possible
- [ ] Add `--agents` flag to enable agent pipeline (default: on with local LLM)
- [ ] Persist intermediate agent outputs for debugging
- [ ] Benchmark: agents should complete in <3 min total

---

## Phase 3: Rules Refresh

### Sub-Phase 3A: Precision & Recall Tuning

**Goal:** Review all 126 rules for precision and recall improvements.

**Process:**
1. For each rule, collect corpus of TP and FP examples
2. Analyze FP patterns and implement filters
3. Analyze FN patterns (missed vulns) and expand detection
4. Document expected precision/recall for each rule

**Priority Rules (High FP from v1.0 analysis):**
- RUSTCOLA075 (cleartext logging) - 35 findings, ~80% FP
- RUSTCOLA123 (unwrap in hot path) - 38 findings, ~60% FP
- RUSTCOLA122 (async drop) - 12 findings, ~80% FP
- RUSTCOLA044 (timing attack) - needs auth context awareness

**Deliverables:**
- [ ] Rule precision/recall matrix
- [ ] Tuned implementations for high-FP rules
- [ ] Test cases for each rule (TP and TN examples)

### Sub-Phase 3B: Rules Expansion Research

**Goal:** Identify and implement new rules from real-world vulnerabilities.

**Research Sources:**
1. **RustSec Advisory Database** - https://rustsec.org/advisories/
2. **GitHub Security Advisories** - Rust-tagged CVEs
3. **Rust Security Response WG** - https://www.rust-lang.org/governance/wgs/security-response
4. **cve.mitre.org** - Rust-related CVEs
5. **HackerOne/Bugcrowd** - Public Rust vulnerability disclosures
6. **Academic papers** - Rust security research (RustBelt, etc.)
7. **Crate audits** - cargo-crev, cargo-vet findings

**Research Process:**
1. Scrape/collect vulnerability reports
2. Categorize by vulnerability class
3. Identify patterns not covered by existing rules
4. Design new rule with test cases
5. Implement and validate

**Potential New Rule Categories:**
- Cryptographic misuse patterns (beyond weak hashes)
- Async/await edge cases
- Unsafe block patterns
- Macro hygiene issues
- Type confusion via generics
- Memory layout assumptions

**Deliverables:**
- [ ] Vulnerability research database
- [ ] New rule proposals with evidence
- [ ] Implemented new rules (target: 20-30 new rules)
- [ ] Updated rule count: 150+ rules

---

## Phase 4: User Interface

### Problem
Current interface requires command-line expertise:
```bash
cargo-cola --crate-path /path/to/project --out-dir ./results
```

This excludes:
- Executives wanting security posture overview
- Project managers tracking security debt
- Developers unfamiliar with CLI tools

### Solution
Simple graphical interface for launching scans and viewing reports.

### Options

| Option | Technology | Pros | Cons |
|--------|------------|------|------|
| **A. Web UI** | Rust + HTML/JS | Cross-platform, familiar | Requires server |
| **B. Desktop App** | Tauri (Rust + WebView) | Native feel, no server | Build complexity |
| **C. TUI** | Ratatui | Terminal-native, lightweight | Still CLI |

**Recommended:** **Option B (Tauri)** - native app, single binary, uses Rust.

### UI Mockup

```
┌─────────────────────────────────────────────────────────────┐
│  🦀 cargo-cola                                    ─ □ ✕    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │  Project Path:  /Users/dev/my-rust-project     [📁] │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                                                     │   │
│   │              [ 🔍 Start Security Scan ]             │   │
│   │                                                     │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                             │
│   ─────────────────────────────────────────────────────     │
│                                                             │
│   Recent Scans:                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ 📊 my-rust-project    Dec 24, 2025   3 Critical     │   │
│   │ 📊 another-crate      Dec 23, 2025   0 Critical ✅  │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Tasks

- [ ] Create Tauri project scaffold
- [ ] Design scan configuration UI
- [ ] Implement progress indicator during scan
- [ ] Report viewer with finding details
- [ ] Finding filtering/sorting
- [ ] Export to PDF/HTML
- [ ] Auto-update mechanism

---

## Future (v2.x)

Deferred to v2.x release cycle:

- **IDE Integration** - VS Code extension, IntelliJ plugin
- **CI/CD Integration** - GitHub Actions, GitLab CI, Jenkins
- **Baseline Diffing** - Only show new findings since last scan
- **Team Features** - Shared findings database, assignment, tracking
- **Compliance Mapping** - Map findings to SOC2, ISO27001, etc.
- **RustyCode Training Data** - Proprietary synthetic dataset for LLM fine-tuning

---

## RustyCode: Proprietary Training Data

**Target: v2.x**

RustyCode is proprietary synthetic training data designed to fine-tune the built-in LLM for Rust-specific security analysis.

### Motivation

General-purpose LLMs lack deep understanding of:
- Rust's ownership/borrowing model and its security implications
- Unsafe code patterns and their exploitation vectors
- Rust-specific vulnerability classes (transmute misuse, FFI boundary issues, etc.)
- Context-aware severity assessment for Rust codebases

### Dataset Categories

1. **Vulnerable Code Samples**
   - Synthetic examples of each vulnerability class cargo-cola detects
   - Real-world-inspired patterns (anonymized/synthesized from public advisories)
   - Edge cases and subtle variations

2. **Fix Demonstrations**
   - Before/after pairs showing proper remediation
   - Multiple fix strategies per vulnerability type
   - Idiomatic Rust patterns

3. **Reasoning Traces**
   - Step-by-step analysis of why code is vulnerable
   - Exploitation scenario narratives
   - False positive reasoning (why similar code is safe)

4. **Severity Calibration**
   - Examples with ground-truth severity labels
   - Context factors that affect severity (public API, unsafe block, etc.)
   - CVSS-like scoring rationale

### Generation Strategy

```
Phase 1: Seed Examples
├── Extract patterns from cargo-cola's 126+ rules
├── Generate variations using templates
└── Validate with cargo-cola itself (self-consistency)

Phase 2: Advisory Mining
├── Parse RustSec advisories
├── Synthesize similar-but-distinct examples
└── Generate fix demonstrations

Phase 3: Adversarial Examples
├── Create near-miss false positives
├── Generate obfuscated vulnerable patterns
└── Test LLM discrimination ability

Phase 4: Reasoning Annotation
├── Add chain-of-thought explanations
├── Include severity justifications
└── Document exploitation scenarios
```

### Quality Assurance

- All synthetic code must compile (or fail compilation in expected ways)
- Vulnerable examples must trigger cargo-cola detection
- Fixed examples must pass cargo-cola cleanly
- Human review of reasoning traces for accuracy

### Intellectual Property

RustyCode is proprietary training data, providing competitive advantage:
- Not derived from copyrighted codebases
- Synthesized specifically for cargo-cola's rule set
- Enables fine-tuned model to outperform general LLMs on Rust security

---

## Success Metrics

| Metric | v1.0 Baseline | v1.x Target |
|--------|---------------|-------------|
| Manual steps to get report | 4+ | 1 |
| Time to actionable report | 10+ min | <3 min |
| Precision (after AI) | ~60% | >90% |
| Rules count | 126 | 150+ |
| User expertise required | CLI + LLM | Click button |

---

## Timeline (Tentative)

| Phase | Target | Duration |
|-------|--------|----------|
| Phase 1: Local LLM | Q1 2026 | 4-6 weeks |
| Phase 2: Agents | Q1-Q2 2026 | 6-8 weeks |
| Phase 3: Rules | Q2 2026 | 4-6 weeks |
| Phase 4: UI | Q2-Q3 2026 | 4-6 weeks |
| v1.x Release | Q3 2026 | — |

---

## Open Questions

1. **LLM Model Selection:** Code Llama 7B vs 13B vs 34B? Trade-off: quality vs speed vs memory.
2. **Agent Orchestration:** Sequential vs parallel? How to handle agent disagreements?
3. **UI Framework:** Tauri vs Electron vs web-only?
4. **Distribution:** Single binary with embedded model, or separate model download?
5. **Licensing:** Keep open source or commercial license for advanced features?

---

## References

- [Ollama](https://ollama.ai/) - Local LLM runtime
- [llama.cpp](https://github.com/ggerganov/llama.cpp) - Efficient LLM inference
- [Tauri](https://tauri.app/) - Rust desktop app framework
- [RustSec](https://rustsec.org/) - Rust security advisories
- [Code Llama](https://ai.meta.com/blog/code-llama-large-language-model-coding/) - Meta's code-focused LLM
