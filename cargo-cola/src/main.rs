#![cfg_attr(feature = "hir-driver", feature(rustc_private))]

use anyhow::{anyhow, Context, Result};
use cargo_metadata::MetadataCommand;
use clap::{builder::BoolishValueParser, ArgAction, Parser};
#[cfg(not(feature = "hir-driver"))]
use mir_extractor::extract_with_cache;
use mir_extractor::{
    analyze_with_engine, load_cached_analysis, sarif_report, store_cached_analysis,
    write_findings_json, write_mir_json, write_sarif_json, AnalysisResult, CacheConfig,
    CacheMissReason, CacheStatus, Finding, MirPackage, RuleEngine, SourceSpan,
};
#[cfg(feature = "hir-driver")]
use mir_extractor::{extract_with_cache_full_opts, HirOptions, HirPackage};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

/// cargo-cola: orchestrates MIR extraction, prototype analyses, and output formatting.
#[derive(Parser, Debug)]
#[command(version, about = "Rust-cola static analysis prototype")]
struct Args {
    /// Path to the crate or workspace to analyze
    #[arg(long, default_value = ".")]
    crate_path: PathBuf,

    /// Directory where analysis artifacts are written
    #[arg(long, default_value = "out/cola")]
    out_dir: PathBuf,

    /// Optional path for the MIR JSON output (defaults to <out_dir>/mir.json)
    #[arg(long)]
    mir_json: Option<PathBuf>,

    /// Optional path for the findings JSON output (defaults to <out_dir>/findings.json)
    #[arg(long)]
    findings_json: Option<PathBuf>,

    /// Optional path to emit SARIF 2.1.0 output (defaults to <out_dir>/cola.sarif if not provided)
    #[arg(long)]
    sarif: Option<PathBuf>,

    /// Exit with code 1 when findings are produced (default true).
    #[arg(long, value_parser = BoolishValueParser::new())]
    fail_on_findings: Option<bool>,

    /// One or more YAML rulepacks to include (repeat the flag to load multiple files)
    #[arg(long = "rulepack", action = ArgAction::Append)]
    rulepack: Vec<PathBuf>,

    /// Experimental: register WASM rule modules (repeatable)
    #[arg(long = "wasm-rule", action = ArgAction::Append)]
    wasm_rule: Vec<PathBuf>,

    /// Enable the MIR cache (default true)
    #[arg(long, value_parser = BoolishValueParser::new())]
    cache: Option<bool>,

    /// Clear cached MIR before running
    #[arg(long = "clear-cache", action = ArgAction::SetTrue)]
    clear_cache: bool,

    #[cfg(feature = "hir-driver")]
    /// Optional path to emit HIR JSON (single crate -> file, workspace -> directory)
    #[arg(long)]
    hir_json: Option<PathBuf>,

    #[cfg(feature = "hir-driver")]
    /// Control whether HIR snapshots are persisted alongside MIR cache entries (default true)
    #[arg(long, value_parser = BoolishValueParser::new())]
    hir_cache: Option<bool>,
}

struct PackageOutput {
    package: MirPackage,
    analysis: AnalysisResult,
    sarif: Value,
    #[cfg(feature = "hir-driver")]
    hir: Option<HirPackage>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    fs::create_dir_all(&args.out_dir).context("create analysis output directory")?;

    let fail_on_findings = args.fail_on_findings.unwrap_or(true);
    let cache_enabled = args.cache.unwrap_or(true);

    let (crate_roots, workspace_root) =
        resolve_crate_roots(&args.crate_path).with_context(|| {
            format!(
                "determine workspace members for {}",
                args.crate_path.display()
            )
        })?;

    if crate_roots.is_empty() {
        return Err(anyhow!(
            "no crates discovered at {}",
            args.crate_path.display()
        ));
    }

    let cache_dir = args.out_dir.join("cache");
    let cache_template = CacheConfig {
        enabled: cache_enabled,
        directory: cache_dir,
        clear: args.clear_cache,
    };

    #[cfg(feature = "hir-driver")]
    let mut hir_options = HirOptions::default();
    #[cfg(feature = "hir-driver")]
    if let Some(cache_override) = args.hir_cache {
        hir_options.cache = cache_override;
    }

    let mut engine = RuleEngine::with_builtin_rules();

    if !args.rulepack.is_empty() {
        println!(
            "Loading rulepacks: {}",
            args.rulepack
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        for pack in &args.rulepack {
            engine
                .load_rulepack(pack)
                .with_context(|| format!("load rulepack from {}", pack.display()))?;
        }
    }

    if !args.wasm_rule.is_empty() {
        println!(
            "Registering WASM rule modules (experimental): {}",
            args.wasm_rule
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        for module in &args.wasm_rule {
            engine
                .load_wasm_module(module)
                .with_context(|| format!("register wasm rule module from {}", module.display()))?;
        }
    }

    let mut package_outputs = Vec::new();

    for crate_root in crate_roots {
        println!("Analyzing crate at {}", crate_root.display());

        let cache_config = cache_template.clone();

        #[cfg(feature = "hir-driver")]
        let (artifacts, cache_status) =
            extract_with_cache_full_opts(&crate_root, &cache_config, &hir_options)?;
        #[cfg(feature = "hir-driver")]
        let package = artifacts.mir.clone();

        #[cfg(not(feature = "hir-driver"))]
        let (package, cache_status) = extract_with_cache(&crate_root, &cache_config)?;

        match &cache_status {
            CacheStatus::Hit(meta) => {
                println!(
                    "Cache hit (fingerprint {}) covering {} functions",
                    meta.crate_fingerprint,
                    meta.function_fingerprints.len()
                );
            }
            CacheStatus::Miss { metadata, reason } => {
                let reason_text = match reason {
                    CacheMissReason::NotFound => "no cache entry".to_string(),
                    CacheMissReason::Cleared => "cache cleared by user".to_string(),
                    CacheMissReason::Invalid(msg) => format!("cache invalid: {msg}"),
                };
                println!(
                    "Cache miss ({reason_text}); computed fingerprint {} ({} functions)",
                    metadata.crate_fingerprint,
                    metadata.function_fingerprints.len()
                );
            }
            CacheStatus::Disabled => {
                println!("Cache disabled; extracting MIR directly.");
            }
        }

        #[cfg(feature = "hir-driver")]
        let hir_payload = artifacts.hir.clone();

        let cached_analysis = load_cached_analysis(&cache_config, &cache_status, &engine)?;

        let analysis = if let Some(analysis) = cached_analysis {
            println!("Using cached analysis results.");
            analysis
        } else {
            let fresh = analyze_with_engine(&engine, &package);
            store_cached_analysis(&cache_config, &cache_status, &engine, &fresh)?;
            fresh
        };

        println!(
            "crate {}: processed {} functions, {} findings",
            package.crate_name,
            package.functions.len(),
            analysis.findings.len()
        );

        let sarif = sarif_report(&package, &analysis);
        package_outputs.push(PackageOutput {
            package,
            analysis,
            sarif,
            #[cfg(feature = "hir-driver")]
            hir: hir_payload,
        });
    }

    let mir_json_path = args
        .mir_json
        .clone()
        .unwrap_or_else(|| args.out_dir.join("mir.json"));
    let findings_path = args
        .findings_json
        .clone()
        .unwrap_or_else(|| args.out_dir.join("findings.json"));
    let sarif_path = args
        .sarif
        .clone()
        .unwrap_or_else(|| args.out_dir.join("cola.sarif"));

    if package_outputs.len() == 1 {
        let output = &package_outputs[0];
        write_mir_json(&mir_json_path, &output.package)?;
        write_findings_json(&findings_path, &output.analysis.findings)?;
        write_sarif_json(&sarif_path, &output.sarif)?;

        #[cfg(feature = "hir-driver")]
        let mut hir_summary_path: Option<PathBuf> = None;
        #[cfg(feature = "hir-driver")]
        if let Some(hir_path) = args.hir_json.clone() {
            if let Some(hir_package) = &output.hir {
                mir_extractor::write_hir_json(&hir_path, hir_package)?;
                hir_summary_path = Some(hir_path);
            } else {
                eprintln!(
                    "cargo-cola: HIR capture disabled or unavailable; skipping write to {}",
                    hir_path.display()
                );
            }
        }
        #[cfg(not(feature = "hir-driver"))]
        let hir_summary_path: Option<PathBuf> = None;

        print_summary_single(
            &mir_json_path,
            &findings_path,
            &sarif_path,
            output.package.functions.len(),
            &output.analysis.findings,
            &output.analysis.rules,
            hir_summary_path.as_deref(),
        );

        if output.analysis.findings.is_empty() {
            println!("No findings — great job!");
            return Ok(());
        }

        if fail_on_findings {
            std::process::exit(1);
        }

        return Ok(());
    }

    let total_functions: usize = package_outputs
        .iter()
        .map(|output| output.package.functions.len())
        .sum();

    let mut aggregated_findings: Vec<Finding> = Vec::new();
    let mut aggregated_rules = Vec::new();
    let mut seen_rule_ids = HashSet::new();
    let mut sarif_reports = Vec::new();
    let mut packages = Vec::new();

    for output in &package_outputs {
        aggregated_findings.extend(output.analysis.findings.clone());
        for rule in &output.analysis.rules {
            if seen_rule_ids.insert(rule.id.clone()) {
                aggregated_rules.push(rule.clone());
            }
        }
        sarif_reports.push(output.sarif.clone());
        packages.push(output.package.clone());
    }

    let aggregated_sarif = merge_sarif_reports(&sarif_reports)?;

    write_workspace_mir_json(&mir_json_path, &workspace_root, &packages)?;
    write_findings_json(&findings_path, &aggregated_findings)?;
    write_sarif_json(&sarif_path, &aggregated_sarif)?;

    #[cfg(feature = "hir-driver")]
    let mut hir_summary_dir: Option<PathBuf> = None;
    #[cfg(feature = "hir-driver")]
    if let Some(hir_base) = args.hir_json.clone() {
        if package_outputs.len() > 1 {
            if hir_base.extension().is_some() {
                return Err(anyhow!(
                    "--hir-json must point to a directory when analyzing multiple crates"
                ));
            }
            fs::create_dir_all(&hir_base).context("create HIR output directory")?;
            for output in &package_outputs {
                if let Some(hir_package) = &output.hir {
                    let file_path =
                        hir_base.join(format!("{}.hir.json", output.package.crate_name));
                    mir_extractor::write_hir_json(&file_path, hir_package)?;
                } else {
                    eprintln!(
                        "cargo-cola: no HIR captured for crate {}; skipping serialization",
                        output.package.crate_name
                    );
                }
            }
            hir_summary_dir = Some(hir_base);
        }
    }

    println!(
        "Analysis complete across {} crates: {} functions processed, {} findings.",
        package_outputs.len(),
        total_functions,
        aggregated_findings.len()
    );
    println!("- MIR JSON: {}", mir_json_path.display());
    println!("- Findings JSON: {}", findings_path.display());
    println!("- SARIF: {}", sarif_path.display());
    #[cfg(feature = "hir-driver")]
    if let Some(dir) = hir_summary_dir {
        println!("- HIR JSON dir: {} (one file per crate)", dir.display());
    }

    if let Some(rendered) = format_findings_output(&aggregated_findings, &aggregated_rules) {
        print!("{}", rendered);
    }

    if aggregated_findings.is_empty() {
        println!("No findings — great job!");
        return Ok(());
    }

    if fail_on_findings {
        std::process::exit(1);
    }

    Ok(())
}

fn print_summary_single(
    mir_path: &Path,
    findings_path: &Path,
    sarif_path: &Path,
    function_count: usize,
    findings: &[Finding],
    rules: &[mir_extractor::RuleMetadata],
    hir_path: Option<&Path>,
) {
    println!(
        "Analysis complete: {} functions processed, {} findings.",
        function_count,
        findings.len()
    );
    println!("- MIR JSON: {}", mir_path.display());
    println!("- Findings JSON: {}", findings_path.display());
    println!("- SARIF: {}", sarif_path.display());
    if let Some(path) = hir_path {
        println!("- HIR JSON: {}", path.display());
    }

    if let Some(rendered) = format_findings_output(findings, rules) {
        print!("{}", rendered);
    }
}

fn format_findings_output(
    findings: &[Finding],
    rules: &[mir_extractor::RuleMetadata],
) -> Option<String> {
    if findings.is_empty() {
        return None;
    }

    use std::fmt::Write as _;

    let mut buffer = String::new();
    let _ = writeln!(&mut buffer, "Findings:");

    for finding in findings {
        let rule_name = rules
            .iter()
            .find(|rule| rule.id == finding.rule_id)
            .map(|rule| rule.name.as_str())
            .unwrap_or("unknown-rule");
        let location_display = finding
            .span
            .as_ref()
            .map(|span| format_span(span))
            .unwrap_or_else(|| finding.function.clone());
        let _ = writeln!(
            &mut buffer,
            "- [{}|{}|{:?}] {} @ {}",
            finding.rule_id, rule_name, finding.severity, finding.message, location_display
        );

        let _ = writeln!(&mut buffer, "    function: {}", finding.function_signature);

        for evidence in &finding.evidence {
            let _ = writeln!(&mut buffer, "    evidence: {}", evidence.trim());
        }
    }

    Some(buffer)
}

fn format_span(span: &SourceSpan) -> String {
    let path = Path::new(&span.file);
    let display = path.display();

    if span.start_line == span.end_line {
        if span.start_column == span.end_column {
            format!("{}:{}:{}", display, span.start_line, span.start_column)
        } else {
            format!(
                "{}:{}:{}-{}",
                display, span.start_line, span.start_column, span.end_column
            )
        }
    } else {
        format!(
            "{}:{}:{}-{}:{}",
            display, span.start_line, span.start_column, span.end_line, span.end_column
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_span_displays_single_line_range() {
        let span = SourceSpan {
            file: "C:/workspace/demo/src/lib.rs".to_string(),
            start_line: 10,
            start_column: 5,
            end_line: 10,
            end_column: 17,
        };

        assert_eq!(format_span(&span), "C:/workspace/demo/src/lib.rs:10:5-17");
    }

    #[test]
    fn format_span_displays_multi_line_range() {
        let span = SourceSpan {
            file: "C:/workspace/demo/src/lib.rs".to_string(),
            start_line: 3,
            start_column: 1,
            end_line: 5,
            end_column: 8,
        };

        assert_eq!(format_span(&span), "C:/workspace/demo/src/lib.rs:3:1-5:8");
    }

    #[test]
    fn format_findings_output_includes_span_location() {
        let rules = vec![mir_extractor::RuleMetadata {
            id: "TEST001".to_string(),
            name: "demo-rule".to_string(),
            short_description: "demo short".to_string(),
            full_description: "demo full".to_string(),
            help_uri: None,
            default_severity: mir_extractor::Severity::Medium,
            origin: mir_extractor::RuleOrigin::BuiltIn,
        }];

        let findings = vec![Finding {
            rule_id: "TEST001".to_string(),
            rule_name: "demo-rule".to_string(),
            severity: mir_extractor::Severity::Medium,
            message: "Example finding".to_string(),
            function: "demo::example".to_string(),
            function_signature: "fn demo::example()".to_string(),
            evidence: vec!["evidence line".to_string()],
            span: Some(SourceSpan {
                file: "C:/workspace/demo/src/lib.rs".to_string(),
                start_line: 8,
                start_column: 1,
                end_line: 8,
                end_column: 4,
            }),
        }];

        let rendered = format_findings_output(&findings, &rules).expect("should render output");
        assert!(rendered.contains("Findings:"));
        assert!(rendered.contains("- [TEST001|demo-rule|"));
        assert!(rendered.contains("@ C:/workspace/demo/src/lib.rs:8:1-4"));
        assert!(rendered.contains("function: fn demo::example()"));
        assert!(rendered.contains("evidence: evidence line"));
    }

    #[test]
    fn format_findings_output_returns_none_for_empty_list() {
        let rules = Vec::new();
        assert!(format_findings_output(&[], &rules).is_none());
    }
}

fn resolve_crate_roots(path: &Path) -> Result<(Vec<PathBuf>, PathBuf)> {
    let canonical = if path.exists() {
        fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    };

    let mut cmd = MetadataCommand::new();
    if canonical.is_file() {
        cmd.manifest_path(&canonical);
    } else {
        cmd.current_dir(&canonical);
    }
    cmd.no_deps();

    let metadata = cmd.exec().context("fetch cargo metadata")?;
    let workspace_root = metadata.workspace_root.clone().into_std_path_buf();

    if let Some(pkg) = metadata.root_package() {
        let manifest_path = pkg.manifest_path.clone().into_std_path_buf();
        let crate_root = manifest_path
            .parent()
            .ok_or_else(|| anyhow!("package manifest has no parent directory"))?
            .to_path_buf();
        return Ok((vec![crate_root], workspace_root));
    }

    let member_ids: HashSet<_> = metadata.workspace_members.into_iter().collect();
    let mut members = Vec::new();

    for pkg in metadata.packages {
        if !member_ids.contains(&pkg.id) {
            continue;
        }

        let manifest_path = pkg.manifest_path.clone();
        let crate_root = manifest_path
            .parent()
            .ok_or_else(|| anyhow!("workspace package {} has no parent", pkg.name))?
            .to_path_buf()
            .into_std_path_buf();
        members.push((pkg.name.clone(), crate_root));
    }

    members.sort_by(|a, b| a.0.cmp(&b.0));
    let crate_roots = members.into_iter().map(|(_, path)| path).collect();

    Ok((crate_roots, workspace_root))
}

fn write_workspace_mir_json(
    path: &Path,
    workspace_root: &Path,
    packages: &[MirPackage],
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create parent directories for workspace MIR JSON")?;
    }

    let mut file = File::create(path).context("create workspace MIR JSON file")?;
    let payload = json!({
        "workspace_root": workspace_root.to_string_lossy(),
        "packages": packages,
    });
    serde_json::to_writer_pretty(&mut file, &payload)
        .context("serialize workspace MIR packages to JSON")?;
    file.write_all(b"\n").ok();
    Ok(())
}

fn merge_sarif_reports(reports: &[Value]) -> Result<Value> {
    if reports.is_empty() {
        return Ok(json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": []
        }));
    }

    let mut all_rules = Vec::new();
    let mut seen_rules = HashSet::new();
    let mut all_results = Vec::new();
    let mut all_invocations = Vec::new();
    let mut all_artifacts = Vec::new();

    for sarif in reports {
        let runs = sarif
            .get("runs")
            .and_then(|value| value.as_array())
            .ok_or_else(|| anyhow!("SARIF report missing runs array"))?;
        let run = runs
            .get(0)
            .ok_or_else(|| anyhow!("SARIF report missing primary run"))?;

        if let Some(rules) = run
            .get("tool")
            .and_then(|tool| tool.get("driver"))
            .and_then(|driver| driver.get("rules"))
            .and_then(|value| value.as_array())
        {
            for rule in rules {
                if let Some(id) = rule.get("id").and_then(|value| value.as_str()) {
                    if seen_rules.insert(id.to_string()) {
                        all_rules.push(rule.clone());
                    }
                }
            }
        }

        if let Some(results) = run.get("results").and_then(|value| value.as_array()) {
            all_results.extend(results.iter().cloned());
        }

        if let Some(invocations) = run.get("invocations").and_then(|value| value.as_array()) {
            all_invocations.extend(invocations.iter().cloned());
        }

        if let Some(artifacts) = run.get("artifacts").and_then(|value| value.as_array()) {
            all_artifacts.extend(artifacts.iter().cloned());
        }
    }

    let base_run = reports[0]
        .get("runs")
        .and_then(|value| value.as_array())
        .and_then(|runs| runs.get(0))
        .cloned()
        .ok_or_else(|| anyhow!("SARIF report missing base run"))?;

    let mut merged_run = base_run;
    merged_run["results"] = Value::Array(all_results);

    let rules_value = Value::Array(all_rules);
    match merged_run.get_mut("tool") {
        Some(tool) => {
            let driver = tool
                .get_mut("driver")
                .and_then(|driver| driver.as_object_mut())
                .map(|driver| {
                    if !driver.contains_key("name") {
                        driver.insert("name".to_string(), json!("rust-cola"));
                    }
                    if !driver.contains_key("informationUri") {
                        driver.insert(
                            "informationUri".to_string(),
                            json!("https://github.com/your-org/rust-cola"),
                        );
                    }
                    if !driver.contains_key("version") {
                        driver.insert("version".to_string(), json!(env!("CARGO_PKG_VERSION")));
                    }
                    driver
                });

            if let Some(driver) = driver {
                driver.insert("rules".to_string(), rules_value);
            } else {
                tool["driver"] = json!({
                    "name": "rust-cola",
                    "informationUri": "https://github.com/your-org/rust-cola",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules_value,
                });
            }
        }
        None => {
            merged_run["tool"] = json!({
                "driver": {
                    "name": "rust-cola",
                    "informationUri": "https://github.com/your-org/rust-cola",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules_value,
                }
            });
        }
    }

    merged_run["invocations"] = Value::Array(all_invocations);
    merged_run["artifacts"] = Value::Array(all_artifacts);

    let schema = "https://json.schemastore.org/sarif-2.1.0.json";
    let version = "2.1.0";

    Ok(json!({
        "$schema": schema,
        "version": version,
        "runs": [merged_run],
    }))
}
