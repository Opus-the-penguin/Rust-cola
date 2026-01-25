use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mir_extractor::{extract_with_cache, CacheConfig, RuleEngine};
use std::path::PathBuf;
use std::time::Duration;

/// Representative crates for benchmarking
const BENCHMARK_CRATES: &[(&str, &str)] = &[
    ("simple", "../examples/simple"), // Tiny (baseline)
    ("hir-typeck-repro", "../examples/hir-typeck-repro"), // Small
                                      // Add more crates here as needed
];

fn benchmark_mir_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("mir-extraction");
    group.sample_size(10); // Smaller sample for longer operations
    group.measurement_time(Duration::from_secs(30));

    for (name, path) in BENCHMARK_CRATES {
        let crate_path = PathBuf::from(path);

        group.bench_with_input(BenchmarkId::new("extract", name), &crate_path, |b, path| {
            b.iter(|| {
                let cache_config = CacheConfig {
                    enabled: false,
                    directory: PathBuf::from("target/bench-cache"),
                    clear: true,
                };

                let (package, _status) =
                    extract_with_cache(black_box(path), black_box(&cache_config))
                        .expect("MIR extraction failed");
                package
            });
        });
    }

    group.finish();
}

fn benchmark_rule_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule-analysis");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    for (name, path) in BENCHMARK_CRATES {
        let crate_path = PathBuf::from(path);

        // Pre-extract MIR for this benchmark
        let cache_config = CacheConfig {
            enabled: false,
            directory: PathBuf::from("target/bench-cache"),
            clear: true,
        };

        let (package, _status) = match extract_with_cache(&crate_path, &cache_config) {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Failed to extract MIR for {}: {}", name, e);
                continue;
            }
        };

        group.bench_with_input(
            BenchmarkId::new("analyze-all-rules", name),
            &package,
            |b, pkg| {
                b.iter(|| {
                    let engine = RuleEngine::with_builtin_rules();
                    engine.run(black_box(pkg))
                });
            },
        );
    }

    group.finish();
}

fn benchmark_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end-to-end");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    for (name, path) in BENCHMARK_CRATES {
        let crate_path = PathBuf::from(path);

        group.bench_with_input(
            BenchmarkId::new("extract-and-analyze", name),
            &crate_path,
            |b, path| {
                b.iter(|| {
                    let cache_config = CacheConfig {
                        enabled: false,
                        directory: PathBuf::from("target/bench-cache"),
                        clear: true,
                    };

                    let (package, _status) =
                        extract_with_cache(black_box(path), black_box(&cache_config))
                            .expect("MIR extraction failed");

                    let engine = RuleEngine::with_builtin_rules();
                    engine.run(black_box(&package))
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_mir_extraction,
    benchmark_rule_analysis,
    benchmark_end_to_end
);
criterion_main!(benches);
