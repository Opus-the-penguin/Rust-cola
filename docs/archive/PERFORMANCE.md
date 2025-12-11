# Performance Benchmarks

This document tracks Rust-cola's performance characteristics and regression testing.

## Benchmark Setup

### Hardware
- **Machine**: (To be recorded on first run)
- **CPU**: (To be recorded)
- **RAM**: (To be recorded)
- **OS**: macOS/Linux/Windows

### Methodology

We benchmark three key metrics:

1. **MIR Extraction** - Time to extract MIR from source code
2. **Rule Analysis** - Time to run all 31 rules on extracted MIR
3. **End-to-End** - Total time from source to findings

### Test Crates

| Crate | Size | Lines of Code | Description |
|-------|------|---------------|-------------|
| `examples/simple` | Tiny | ~50 | Baseline - minimal crate |
| `examples/hir-typeck-repro` | Small | ~150 | Example with type system features |

*Note: Additional representative crates will be added (serde, tokio-light, etc.)*

## Running Benchmarks

### Quick Baseline
```bash
cargo bench -p mir-extractor --bench analysis_performance
```

### Full Suite
```bash
# Run all benchmarks with detailed output
cargo bench -p mir-extractor --bench analysis_performance -- --verbose

# Save baseline for comparison
cargo bench -p mir-extractor --bench analysis_performance -- --save-baseline main

# Compare against baseline
cargo bench -p mir-extractor --bench analysis_performance -- --baseline main
```

### CI Integration
```bash
# Fast check (smaller sample size)
cargo bench -p mir-extractor --bench analysis_performance -- --quick
```

## Baseline Results

### Version 0.1.0 (31 Rules) - November 4, 2025

**Hardware**: Apple Silicon Mac (M-series)
**Benchmark Date**: January 2025

#### MIR Extraction
| Crate | Mean | Notes |
|-------|------|-------|
| simple | 75.2 ms | Tiny baseline crate |
| hir-typeck-repro | 111.9 ms | Small example crate |

#### Rule Analysis (31 rules)
| Crate | Mean | Notes |
|-------|------|-------|
| simple | 655.9 μs | 0.66 ms - analysis only |
| hir-typeck-repro | 50.1 ms | Pre-extracted MIR |

#### End-to-End
| Crate | Mean | Notes |
|-------|------|-------|
| simple | 77.3 ms | Extract + analyze (31 rules) |
| hir-typeck-repro | 164.5 ms | Full pipeline |

**Key Insights**:
- MIR extraction dominates performance (~97% of time for simple crate)
- Rule analysis overhead is minimal (~0.7 ms for tiny crate, 50 ms for small)
- Analysis scales sublinearly with crate size
- End-to-end performance well within acceptable thresholds

## Performance Targets

### Acceptable Thresholds
- **MIR Extraction**: < 2s for small crates, < 10s for medium
- **Rule Analysis**: < 100ms for small crates, < 1s for medium
- **End-to-End**: < 3s for small crates, < 15s for medium

### Regression Detection
- **Warning**: > 10% slowdown from baseline
- **Failure**: > 25% slowdown from baseline

## Optimization Notes

### Cache Performance
The MIR cache significantly improves repeat analysis:
- **First run**: Full MIR extraction + analysis
- **Cached run**: Skip extraction if source unchanged
- **Cache hit rate**: Target > 90% in typical development

### Rule Complexity
Current rules by complexity:

- **O(n)** Simple pattern matching: 28 rules
- **O(n²)** Proximity analysis: 2 rules (RUSTCOLA024, RUSTCOLA031)
- **O(n³)** Dataflow tracking: 1 rule (RUSTCOLA027)

### Known Bottlenecks
1. **MIR Extraction**: External rustc invocation (unavoidable in current architecture)
2. **String Operations**: Heavy use of `.contains()` and regex patterns
3. **JSON Serialization**: SARIF output generation

## Historical Performance

### Rule Count vs Performance
| Date | Rules | Simple (E2E) | hir-typeck-repro (E2E) | Notes |
|------|-------|--------------|------------------------|-------|
| 2025-01 | 31 | 77.3 ms | 164.5 ms | Initial baseline with criterion benchmarks |

*Track as new rules are added to detect performance regressions*

## Future Improvements

### Short Term
- [ ] Add medium-sized benchmark crates (serde, tokio-mini)
- [ ] Profile individual rules to identify slowest patterns
- [ ] Implement parallel rule execution

### Long Term
- [ ] In-process rustc_interface for faster MIR extraction
- [ ] Incremental analysis (only changed functions)
- [ ] WASM compilation for rule execution

## Profiling

### CPU Profiling
```bash
# Using cargo-flamegraph
cargo flamegraph --bench analysis_performance

# Using perf (Linux)
perf record cargo bench --bench analysis_performance
perf report
```

### Memory Profiling
```bash
# Using valgrind (Linux)
valgrind --tool=massif cargo bench --bench analysis_performance

# Using Instruments (macOS)
instruments -t "Allocations" cargo bench --bench analysis_performance
```

## CI Performance Gates

### GitHub Actions Configuration

```yaml
- name: Performance Regression Check
  run: |
    cargo bench --bench analysis_performance -- --save-baseline pr
    cargo bench --bench analysis_performance -- --baseline main
```

*Exit code 1 if > 25% regression detected*

## Contributing

When adding new rules:
1. Run benchmarks before and after implementation
2. Document performance impact if > 5% slowdown
3. Consider optimization if single rule adds > 50ms to analysis

---

**Last Updated**: November 4, 2025
**Benchmark Version**: 0.1.0
**Active Rules**: 31
