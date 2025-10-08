#![cfg_attr(feature = "hir-driver", feature(rustc_private))]

#[cfg(feature = "hir-driver")]
extern crate rustc_driver;
#[cfg(feature = "hir-driver")]
extern crate rustc_hir;
#[cfg(feature = "hir-driver")]
extern crate rustc_interface;
#[cfg(feature = "hir-driver")]
extern crate rustc_middle;
#[cfg(feature = "hir-driver")]
extern crate rustc_session;
#[cfg(feature = "hir-driver")]
extern crate rustc_span;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
#[cfg(not(feature = "hir-driver"))]
use mir_extractor::extract_with_cache;
#[cfg(feature = "hir-driver")]
use mir_extractor::extract_with_cache_full;
use mir_extractor::{analyze_with_engine, CacheConfig, CacheMissReason, CacheStatus, RuleEngine};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    /// Path to the crate to extract MIR from
    #[arg(long, default_value = ".")]
    crate_path: PathBuf,

    /// Output directory where artifacts (mir.json, findings.json, sarif.json) are written
    #[arg(long, default_value = "out/mir")]
    out_dir: PathBuf,

    /// Optional path to write the structured MIR JSON (defaults to <out_dir>/mir.json)
    #[arg(long)]
    mir_json: Option<PathBuf>,

    /// Optional path to write findings JSON (defaults to <out_dir>/findings.json)
    #[arg(long)]
    findings_json: Option<PathBuf>,

    /// Optional path to write SARIF output; skipped if omitted
    #[arg(long)]
    sarif: Option<PathBuf>,

    /// One or more YAML rulepacks to include (repeatable)
    #[arg(long = "rulepack", action = ArgAction::Append)]
    rulepack: Vec<PathBuf>,

    /// Experimental: register WASM rule modules (repeatable)
    #[arg(long = "wasm-rule", action = ArgAction::Append)]
    wasm_rule: Vec<PathBuf>,

    /// Enable the MIR cache (default true)
    #[arg(long, value_parser = clap::builder::BoolishValueParser::new())]
    cache: Option<bool>,

    /// Clear cached MIR before running
    #[arg(long = "clear-cache", action = ArgAction::SetTrue)]
    clear_cache: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out_dir)?;

    let cache_enabled = args.cache.unwrap_or(true);
    let cache_dir = args.out_dir.join("cache");
    let cache_config = CacheConfig {
        enabled: cache_enabled,
        directory: cache_dir.clone(),
        clear: args.clear_cache,
    };

    println!("Extracting MIR from {}", args.crate_path.display());

    #[cfg(feature = "hir-driver")]
    let (artifacts, cache_status) = extract_with_cache_full(&args.crate_path, &cache_config)?;
    #[cfg(feature = "hir-driver")]
    let package = artifacts.mir.clone();

    #[cfg(not(feature = "hir-driver"))]
    let (package, cache_status) = extract_with_cache(&args.crate_path, &cache_config)?;

    match cache_status {
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
        .unwrap_or_else(|| args.out_dir.join("mir.json"));
    mir_extractor::write_mir_json(&mir_json_path, &package)?;

    #[cfg(feature = "hir-driver")]
    if let Some(hir_package) = &artifacts.hir {
        let hir_json_path = args.out_dir.join("hir.json");
        mir_extractor::write_hir_json(&hir_json_path, hir_package)?;
        println!(
            "Captured HIR snapshot for {} -> {}",
            hir_package.crate_name,
            hir_json_path.display()
        );
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

    let analysis = analyze_with_engine(&engine, &package);
    let findings_json_path = args
        .findings_json
        .unwrap_or_else(|| args.out_dir.join("findings.json"));
    mir_extractor::write_findings_json(&findings_json_path, &analysis.findings)?;

    if let Some(sarif_path) = args.sarif {
        let sarif = mir_extractor::sarif_report(&package, &analysis);
        mir_extractor::write_sarif_json(sarif_path, &sarif)?;
    }

    println!(
        "Extracted {} MIR functions; wrote JSON to {}",
        package.functions.len(),
        mir_json_path.display()
    );

    if analysis.findings.is_empty() {
        println!("No high-confidence findings detected.");
    } else {
        println!("{} finding(s) detected:", analysis.findings.len());
        for finding in &analysis.findings {
            println!("- [{}] {}", finding.rule_id, finding.message);
        }
    }

    Ok(())
}
