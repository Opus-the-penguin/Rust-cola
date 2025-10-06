use anyhow::{anyhow, Context, Result};
use cargo_metadata::MetadataCommand;
use clap::{builder::BoolishValueParser, ArgAction, Parser};
use mir_extractor::{
    analyze_with_engine, extract_with_cache, load_cached_analysis, sarif_report,
    store_cached_analysis, write_findings_json, write_mir_json, write_sarif_json, AnalysisResult,
    CacheConfig, CacheMissReason, CacheStatus, Finding, MirPackage, RuleEngine,
};
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
}

struct PackageOutput {
    package: MirPackage,
    analysis: AnalysisResult,
    sarif: Value,
}

fn main() -> Result<()> {
    let args = Args::parse();

    fs::create_dir_all(&args.out_dir).context("create analysis output directory")?;

    let fail_on_findings = args.fail_on_findings.unwrap_or(true);
    let cache_enabled = args.cache.unwrap_or(true);

    let (crate_roots, workspace_root) = resolve_crate_roots(&args.crate_path)
        .with_context(|| {
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

        print_summary_single(
            &mir_json_path,
            &findings_path,
            &sarif_path,
            output.package.functions.len(),
            &output.analysis.findings,
            &output.analysis.rules,
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

    println!(
        "Analysis complete across {} crates: {} functions processed, {} findings.",
        package_outputs.len(),
        total_functions,
        aggregated_findings.len()
    );
    println!("- MIR JSON: {}", mir_json_path.display());
    println!("- Findings JSON: {}", findings_path.display());
    println!("- SARIF: {}", sarif_path.display());

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
) {
    println!(
        "Analysis complete: {} functions processed, {} findings.",
        function_count,
        findings.len()
    );
    println!("- MIR JSON: {}", mir_path.display());
    println!("- Findings JSON: {}", findings_path.display());
    println!("- SARIF: {}", sarif_path.display());

    if findings.is_empty() {
        return;
    }

    println!("Findings:");
    for finding in findings {
        let rule_name = rules
            .iter()
            .find(|rule| rule.id == finding.rule_id)
            .map(|rule| rule.name.as_str())
            .unwrap_or("unknown-rule");
        println!(
            "- [{}|{}|{:?}] {}",
            finding.rule_id, rule_name, finding.severity, finding.message
        );
        for evidence in &finding.evidence {
            println!("    evidence: {}", evidence.trim());
        }
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

fn write_workspace_mir_json(path: &Path, workspace_root: &Path, packages: &[MirPackage]) -> Result<()> {
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

    if let Some(tool) = merged_run.get_mut("tool") {
        if let Some(driver) = tool.get_mut("driver") {
            driver["rules"] = Value::Array(all_rules);
        }
    }

    merged_run["invocations"] = Value::Array(all_invocations);
    merged_run["artifacts"] = Value::Array(all_artifacts);

    let schema = reports[0]
        .get("$schema")
        .cloned()
        .unwrap_or_else(|| Value::String("https://json.schemastore.org/sarif-2.1.0.json".to_string()));
    let version = reports[0]
        .get("version")
        .cloned()
        .unwrap_or_else(|| Value::String("2.1.0".to_string()));

    Ok(json!({
        "$schema": schema,
        "version": version,
        "runs": [merged_run],
    }))
}
