use anyhow::{Context, Result};
use clap::{builder::BoolishValueParser, ArgAction, Parser};
use mir_extractor::{
    analyze_with_engine, extract_with_cache, load_cached_analysis, sarif_report,
    store_cached_analysis, write_findings_json, write_mir_json, write_sarif_json, CacheConfig,
    CacheMissReason, CacheStatus, RuleEngine,
};
use std::fs;
use std::path::PathBuf;

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

fn main() -> Result<()> {
    let args = Args::parse();

    fs::create_dir_all(&args.out_dir).context("create analysis output directory")?;

    let fail_on_findings = args.fail_on_findings.unwrap_or(true);
    let cache_enabled = args.cache.unwrap_or(true);

    println!("Analyzing crate at {}", args.crate_path.display());

    let cache_dir = args.out_dir.join("cache");
    let cache_config = CacheConfig {
        enabled: cache_enabled,
        directory: cache_dir.clone(),
        clear: args.clear_cache,
    };

    let (package, cache_status) = extract_with_cache(&args.crate_path, &cache_config)?;

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

    let mir_json_path = args
        .mir_json
        .clone()
        .unwrap_or_else(|| args.out_dir.join("mir.json"));
    write_mir_json(&mir_json_path, &package)?;

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

    let cached_analysis = load_cached_analysis(&cache_config, &cache_status, &engine)?;

    let analysis = if let Some(analysis) = cached_analysis {
        println!("Using cached analysis results.");
        analysis
    } else {
        let fresh = analyze_with_engine(&engine, &package);
        store_cached_analysis(&cache_config, &cache_status, &engine, &fresh)?;
        fresh
    };
    let findings_path = args
        .findings_json
        .clone()
        .unwrap_or_else(|| args.out_dir.join("findings.json"));
    write_findings_json(&findings_path, &analysis.findings)?;

    let sarif_path = args
        .sarif
        .clone()
        .unwrap_or_else(|| args.out_dir.join("cola.sarif"));
    let sarif = sarif_report(&package, &analysis);
    write_sarif_json(&sarif_path, &sarif)?;

    println!(
        "Analysis complete: {} functions processed, {} findings.",
        package.functions.len(),
        analysis.findings.len()
    );
    println!("- MIR JSON: {}", mir_json_path.display());
    println!("- Findings JSON: {}", findings_path.display());
    println!("- SARIF: {}", sarif_path.display());

    if analysis.findings.is_empty() {
        println!("No findings — great job!");
        return Ok(());
    }

    println!("Findings:");
    for finding in &analysis.findings {
        let rule_name = analysis
            .rules
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

    if fail_on_findings {
        std::process::exit(1);
    }

    Ok(())
}
