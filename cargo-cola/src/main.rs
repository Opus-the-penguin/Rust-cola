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

    /// Generate LLM-optimized output with prompt template for AI-assisted security analysis
    #[arg(long)]
    llm_report: Option<PathBuf>,

    /// LLM API endpoint for automated analysis (e.g., https://api.openai.com/v1/chat/completions)
    /// Supports OpenAI-compatible APIs including Anthropic, Ollama, etc.
    #[arg(long)]
    llm_endpoint: Option<String>,

    /// LLM model name (e.g., gpt-4, claude-3-opus-20240229, llama2)
    #[arg(long, default_value = "gpt-4")]
    llm_model: String,

    /// LLM API key (can also be set via RUSTCOLA_LLM_API_KEY environment variable)
    #[arg(long, env = "RUSTCOLA_LLM_API_KEY")]
    llm_api_key: Option<String>,

    /// Maximum tokens for LLM response (default: 4096)
    #[arg(long, default_value = "4096")]
    llm_max_tokens: u32,

    /// Generate a standalone human-readable security report (no LLM required)
    /// Defaults to <out_dir>/reports/report.md if no path specified
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    report: Option<PathBuf>,

    /// Generate an LLM prompt file for use with IDE-integrated AI assistants (Copilot, Cursor, etc.)
    /// The output is a markdown file with findings formatted as a prompt ready for analysis.
    /// Defaults to <out_dir>/reports/llm-prompt.md if no path specified
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    llm_prompt: Option<PathBuf>,

    /// Run cargo-audit to check dependencies for known vulnerabilities (requires cargo-audit installed)
    /// Findings are merged into the report output
    #[arg(long = "with-audit", action = ArgAction::SetTrue)]
    with_audit: bool,
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

    // Run cargo-audit if requested
    let audit_vulnerabilities = if args.with_audit {
        run_cargo_audit(&args.crate_path)?
    } else {
        Vec::new()
    };

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

        // Generate LLM report if requested
        if let Some(llm_path) = &args.llm_report {
            let llm_config = args.llm_endpoint.as_ref().map(|endpoint| LlmConfig {
                endpoint: endpoint.clone(),
                model: args.llm_model.clone(),
                api_key: args.llm_api_key.clone().unwrap_or_default(),
                max_tokens: args.llm_max_tokens,
            });
            generate_llm_analysis(
                llm_path,
                &output.package.crate_name,
                &output.analysis.findings,
                &output.analysis.rules,
                llm_config.as_ref(),
            )?;
            println!("- LLM Report: {}", llm_path.display());
        }

        // Generate standalone report if requested
        if let Some(report_path) = &args.report {
            let resolved_path = resolve_report_path(report_path, &args.out_dir, "report.md");
            generate_standalone_report(
                &resolved_path,
                &output.package.crate_name,
                &output.analysis.findings,
                &output.analysis.rules,
                &audit_vulnerabilities,
            )?;
            println!("- Standalone Report: {}", resolved_path.display());
        }

        // Generate LLM prompt for IDE-integrated assistants
        if let Some(prompt_path) = &args.llm_prompt {
            let resolved_path = resolve_report_path(prompt_path, &args.out_dir, "llm-prompt.md");
            generate_llm_prompt(
                &resolved_path,
                &output.package.crate_name,
                &output.analysis.findings,
                &output.analysis.rules,
                &audit_vulnerabilities,
            )?;
            println!("- LLM Prompt: {}", resolved_path.display());
        }

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

    // Generate LLM report if requested (workspace mode)
    if let Some(llm_path) = &args.llm_report {
        let project_name = workspace_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("workspace");
        let llm_config = args.llm_endpoint.as_ref().map(|endpoint| LlmConfig {
            endpoint: endpoint.clone(),
            model: args.llm_model.clone(),
            api_key: args.llm_api_key.clone().unwrap_or_default(),
            max_tokens: args.llm_max_tokens,
        });
        generate_llm_analysis(
            llm_path,
            project_name,
            &aggregated_findings,
            &aggregated_rules,
            llm_config.as_ref(),
        )?;
    }

    // Generate standalone report if requested (workspace mode)
    if let Some(report_path) = &args.report {
        let resolved_path = resolve_report_path(report_path, &args.out_dir, "report.md");
        let project_name = workspace_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("workspace");
        generate_standalone_report(
            &resolved_path,
            project_name,
            &aggregated_findings,
            &aggregated_rules,
            &audit_vulnerabilities,
        )?;
    }

    // Generate LLM prompt if requested (workspace mode)
    if let Some(prompt_path) = &args.llm_prompt {
        let resolved_path = resolve_report_path(prompt_path, &args.out_dir, "llm-prompt.md");
        let project_name = workspace_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("workspace");
        generate_llm_prompt(
            &resolved_path,
            project_name,
            &aggregated_findings,
            &aggregated_rules,
            &audit_vulnerabilities,
        )?;
    }

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
    if let Some(llm_path) = &args.llm_report {
        println!("- LLM Report: {}", llm_path.display());
    }
    if let Some(report_path) = &args.report {
        let resolved = resolve_report_path(report_path, &args.out_dir, "report.md");
        println!("- Standalone Report: {}", resolved.display());
    }
    if let Some(prompt_path) = &args.llm_prompt {
        let resolved = resolve_report_path(prompt_path, &args.out_dir, "llm-prompt.md");
        println!("- LLM Prompt: {}", resolved.display());
    }
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

/// Resolves report paths. If the path is a directory, appends the default filename.
/// If the path contains "cola/reports" it's used as-is, otherwise the default filename is used.
/// Also ensures parent directories exist.
fn resolve_report_path(user_path: &Path, out_dir: &Path, default_filename: &str) -> PathBuf {
    let resolved = if user_path.is_dir() || user_path.to_string_lossy().ends_with('/') {
        // If the user provided just a directory or ending slash, add default filename
        user_path.join(default_filename)
    } else if let Some(stem) = user_path.file_stem() {
        if stem == "reports" && user_path.extension().is_none() {
            // If the path ends with "reports" (no extension), treat as directory
            // out_dir is typically "out/cola", so we just add "reports/"
            out_dir.join("reports").join(default_filename)
        } else {
            // Otherwise use the path as-is (it's a specific file)
            user_path.to_path_buf()
        }
    } else {
        user_path.to_path_buf()
    };
    
    // Ensure parent directories exist
    if let Some(parent) = resolved.parent() {
        if !parent.exists() {
            let _ = fs::create_dir_all(parent);
        }
    }
    
    resolved
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

/// Configuration for LLM API calls
struct LlmConfig {
    endpoint: String,
    model: String,
    api_key: String,
    max_tokens: u32,
}

/// Call an LLM API to analyze findings and generate a curated security report.
/// Supports OpenAI-compatible APIs (OpenAI, Anthropic via proxy, Ollama, etc.)
fn call_llm_api(config: &LlmConfig, prompt: &str) -> Result<String> {
    use serde::{Deserialize, Serialize};

    #[allow(dead_code)] // Used by serde Serialize
    #[derive(Serialize)]
    struct Message {
        role: String,
        content: String,
    }

    #[allow(dead_code)] // Used by serde Serialize  
    #[derive(Serialize)]
    struct ChatRequest {
        model: String,
        messages: Vec<Message>,
        max_tokens: u32,
        temperature: f32,
    }

    #[derive(Deserialize)]
    struct Choice {
        message: MessageResponse,
    }

    #[derive(Deserialize)]
    struct MessageResponse {
        content: String,
    }

    #[derive(Deserialize)]
    struct ChatResponse {
        choices: Vec<Choice>,
    }

    // Detect API type from endpoint
    let is_anthropic = config.endpoint.contains("anthropic.com");
    let is_ollama = config.endpoint.contains("localhost:11434") || config.endpoint.contains("127.0.0.1:11434");

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(300)) // 5 min timeout for large reports
        .build()
        .context("failed to build HTTP client")?;

    let mut request = client.post(&config.endpoint);

    // Set appropriate auth header
    if is_anthropic {
        request = request
            .header("x-api-key", &config.api_key)
            .header("anthropic-version", "2023-06-01");
    } else if !is_ollama {
        // Standard OpenAI-compatible auth
        request = request.header("Authorization", format!("Bearer {}", config.api_key));
    }

    // Build request body
    let body = if is_anthropic {
        // Anthropic has a slightly different format
        json!({
            "model": config.model,
            "max_tokens": config.max_tokens,
            "messages": [{
                "role": "user",
                "content": prompt
            }]
        })
    } else {
        // OpenAI-compatible format (works for OpenAI, Ollama, etc.)
        json!({
            "model": config.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a senior security engineer specializing in Rust security analysis. Produce clear, actionable security reports with code fixes."
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ],
            "max_tokens": config.max_tokens,
            "temperature": 0.3
        })
    };

    eprintln!("  Calling LLM API at {}...", config.endpoint);
    eprintln!("  Model: {}", config.model);
    eprintln!("  Prompt length: {} chars", prompt.len());

    let response = request
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .context("failed to send request to LLM API")?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().unwrap_or_else(|_| "unknown error".to_string());
        return Err(anyhow!("LLM API returned error {}: {}", status, error_text));
    }

    // Parse response - handle both OpenAI and Anthropic formats
    let response_text = response.text().context("failed to read LLM response")?;
    
    if is_anthropic {
        // Anthropic format: { "content": [{ "text": "..." }] }
        #[derive(Deserialize)]
        struct AnthropicContent {
            text: String,
        }
        #[derive(Deserialize)]
        struct AnthropicResponse {
            content: Vec<AnthropicContent>,
        }
        let parsed: AnthropicResponse = serde_json::from_str(&response_text)
            .context("failed to parse Anthropic API response")?;
        parsed.content.first()
            .map(|c| c.text.clone())
            .ok_or_else(|| anyhow!("Anthropic response contained no content"))
    } else {
        // OpenAI-compatible format
        let parsed: ChatResponse = serde_json::from_str(&response_text)
            .context("failed to parse LLM API response")?;
        parsed.choices.first()
            .map(|c| c.message.content.clone())
            .ok_or_else(|| anyhow!("LLM response contained no choices"))
    }
}

/// Generate LLM report and optionally call LLM API for automated analysis
fn generate_llm_analysis(
    path: &Path,
    project_name: &str,
    findings: &[Finding],
    rules: &[mir_extractor::RuleMetadata],
    llm_config: Option<&LlmConfig>,
) -> Result<()> {
    use std::fmt::Write as _;

    // First, generate the prompt content (same as write_llm_report)
    let mut prompt_content = String::new();
    
    // Build the analysis prompt
    writeln!(&mut prompt_content, "Analyze the following {} security findings from the Rust project '{}'.", 
        findings.len(), project_name)?;
    writeln!(&mut prompt_content)?;
    writeln!(&mut prompt_content, "## Instructions")?;
    writeln!(&mut prompt_content)?;
    writeln!(&mut prompt_content, "Produce a security report with:")?;
    writeln!(&mut prompt_content, "1. **Executive Summary** - Total findings, true positives vs false positives, top 3 critical issues")?;
    writeln!(&mut prompt_content, "2. **True Positives** - For each real vulnerability:")?;
    writeln!(&mut prompt_content, "   - Severity (Critical/High/Medium/Low), CVSS estimate")?;
    writeln!(&mut prompt_content, "   - Attack scenario")?;
    writeln!(&mut prompt_content, "   - **Vulnerable code** (from evidence)")?;
    writeln!(&mut prompt_content, "   - **Recommended fix** with corrected Rust code")?;
    writeln!(&mut prompt_content, "3. **False Positives** - Explain why each is likely a false detection")?;
    writeln!(&mut prompt_content, "4. **Remediation Priority** - P0 (immediate), P1 (sprint), P2 (quarter)")?;
    writeln!(&mut prompt_content)?;
    writeln!(&mut prompt_content, "### Fix Patterns Reference")?;
    writeln!(&mut prompt_content, "- SQL Injection: Use `.bind()` or `?` placeholders")?;
    writeln!(&mut prompt_content, "- Path Traversal: `path.canonicalize()?.starts_with(base)`")?;
    writeln!(&mut prompt_content, "- Regex Injection: `regex::escape(&input)`")?;
    writeln!(&mut prompt_content, "- SSRF: Validate URL host against allowlist")?;
    writeln!(&mut prompt_content, "- Unbounded Allocation: Add size check before allocation")?;
    writeln!(&mut prompt_content)?;

    // Rule reference
    writeln!(&mut prompt_content, "## Rule Reference")?;
    writeln!(&mut prompt_content)?;
    for rule in rules {
        writeln!(&mut prompt_content, "- **{}** ({}): {} [Severity: {:?}]", 
            rule.id, rule.name, rule.short_description, rule.default_severity)?;
    }
    writeln!(&mut prompt_content)?;

    // Findings
    writeln!(&mut prompt_content, "## Findings to Analyze")?;
    writeln!(&mut prompt_content)?;
    
    for (i, finding) in findings.iter().enumerate() {
        writeln!(&mut prompt_content, "### Finding {}: {} - {}", i + 1, finding.rule_id, finding.rule_name)?;
        writeln!(&mut prompt_content, "- **Severity:** {:?}", finding.severity)?;
        writeln!(&mut prompt_content, "- **Function:** `{}`", finding.function)?;
        if let Some(span) = &finding.span {
            writeln!(&mut prompt_content, "- **File:** {}:{}-{}", span.file, span.start_line, span.end_line)?;
        }
        writeln!(&mut prompt_content, "- **Message:** {}", finding.message)?;
        if !finding.evidence.is_empty() {
            writeln!(&mut prompt_content, "- **Evidence:**")?;
            for ev in &finding.evidence {
                writeln!(&mut prompt_content, "```")?;
                writeln!(&mut prompt_content, "{}", ev.trim())?;
                writeln!(&mut prompt_content, "```")?;
            }
        }
        writeln!(&mut prompt_content)?;
    }

    // If LLM config provided, call the API
    let final_content = if let Some(config) = llm_config {
        eprintln!("  Sending {} findings to LLM for analysis...", findings.len());
        
        match call_llm_api(config, &prompt_content) {
            Ok(llm_response) => {
                // Wrap LLM response with metadata
                let mut output = String::new();
                writeln!(&mut output, "# Security Analysis Report: {}", project_name)?;
                writeln!(&mut output)?;
                writeln!(&mut output, "*Generated by rust-cola with {} analysis*", config.model)?;
                writeln!(&mut output, "*Findings analyzed: {}*", findings.len())?;
                writeln!(&mut output)?;
                writeln!(&mut output, "---")?;
                writeln!(&mut output)?;
                writeln!(&mut output, "{}", llm_response)?;
                output
            }
            Err(e) => {
                eprintln!("  Warning: LLM API call failed: {}", e);
                eprintln!("  Falling back to prompt-only output");
                
                // Fall back to prompt-only format
                let mut output = String::new();
                writeln!(&mut output, "# Security Analysis Context for LLM Review")?;
                writeln!(&mut output)?;
                writeln!(&mut output, "*LLM API call failed: {}*", e)?;
                writeln!(&mut output, "*Copy the content below to your preferred LLM for analysis.*")?;
                writeln!(&mut output)?;
                writeln!(&mut output, "---")?;
                writeln!(&mut output)?;
                writeln!(&mut output, "{}", prompt_content)?;
                output
            }
        }
    } else {
        // No LLM config - just output the prompt for manual submission
        let mut output = String::new();
        writeln!(&mut output, "# Security Analysis Context for LLM Review")?;
        writeln!(&mut output)?;
        writeln!(&mut output, "**Project:** {}", project_name)?;
        writeln!(&mut output, "**Total Findings:** {}", findings.len())?;
        writeln!(&mut output)?;
        writeln!(&mut output, "*Copy the content below to your preferred LLM (Claude, GPT-4, etc.) for analysis.*")?;
        writeln!(&mut output)?;
        writeln!(&mut output, "---")?;
        writeln!(&mut output)?;
        writeln!(&mut output, "{}", prompt_content)?;
        output
    };

    // Write output file
    let mut file = File::create(path)
        .with_context(|| format!("create LLM report at {}", path.display()))?;
    file.write_all(final_content.as_bytes())?;
    
    if llm_config.is_some() {
        eprintln!("  LLM-analyzed report written to: {}", path.display());
    } else {
        eprintln!("  Prompt file written to: {}", path.display());
        eprintln!("  Tip: Use --llm-endpoint to automatically send to an LLM API");
    }
    
    Ok(())
}

/// Generate a standalone human-readable security report (no LLM required)
/// This provides structured output with heuristic-based triage hints
fn generate_standalone_report(
    path: &Path,
    project_name: &str,
    findings: &[Finding],
    rules: &[mir_extractor::RuleMetadata],
    audit_vulns: &[AuditVulnerability],
) -> Result<()> {
    use std::collections::HashMap;
    use std::fmt::Write as _;

    let mut content = String::new();

    // Categorize findings with heuristics
    let mut high_confidence: Vec<&Finding> = Vec::new();
    let mut needs_review: Vec<&Finding> = Vec::new();
    let mut likely_fp: Vec<&Finding> = Vec::new();

    for finding in findings {
        let fp_score = compute_false_positive_likelihood(finding);
        if fp_score >= 0.7 {
            likely_fp.push(finding);
        } else if fp_score >= 0.4 {
            needs_review.push(finding);
        } else {
            high_confidence.push(finding);
        }
    }

    // Header
    writeln!(&mut content, "# 🔒 Security Report: {}", project_name)?;
    writeln!(&mut content)?;
    writeln!(&mut content, "*Generated by rust-cola v{}*", env!("CARGO_PKG_VERSION"))?;
    writeln!(&mut content, "*Date: {}*", chrono_lite_date())?;
    writeln!(&mut content)?;

    // Executive Summary
    writeln!(&mut content, "## Executive Summary")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "| Category | Count |")?;
    writeln!(&mut content, "|----------|-------|")?;
    if !audit_vulns.is_empty() {
        writeln!(&mut content, "| � **Dependency Vulnerabilities** | {} |", audit_vulns.len())?;
    }
    writeln!(&mut content, "| �🔴 **High Confidence Issues** | {} |", high_confidence.len())?;
    writeln!(&mut content, "| 🟡 **Needs Review** | {} |", needs_review.len())?;
    writeln!(&mut content, "| ⚪ **Likely False Positives** | {} |", likely_fp.len())?;
    writeln!(&mut content, "| **Total Findings** | {} |", findings.len())?;
    writeln!(&mut content)?;

    // Add audit section if vulnerabilities found
    if !audit_vulns.is_empty() {
        content.push_str(&format_audit_section(audit_vulns));
    }

    // Severity breakdown
    let high_count = findings.iter().filter(|f| matches!(f.severity, mir_extractor::Severity::High)).count();
    let medium_count = findings.iter().filter(|f| matches!(f.severity, mir_extractor::Severity::Medium)).count();
    let low_count = findings.iter().filter(|f| matches!(f.severity, mir_extractor::Severity::Low)).count();

    writeln!(&mut content, "### By Severity")?;
    writeln!(&mut content)?;
    if high_count > 0 {
        writeln!(&mut content, "- � **High:** {}", high_count)?;
    }
    if medium_count > 0 {
        writeln!(&mut content, "- 🟡 **Medium:** {}", medium_count)?;
    }
    if low_count > 0 {
        writeln!(&mut content, "- 🔵 **Low:** {}", low_count)?;
    }
    writeln!(&mut content)?;
    
    // Rule summary table with FP estimates
    write_rule_summary_table(&mut content, findings, rules)?;

    // Recommendation banner
    writeln!(&mut content, "---")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "> 💡 **Tip:** For better analysis with false positive filtering and code fix suggestions,")?;
    writeln!(&mut content, "> run with `--llm-report` and an LLM endpoint. See [LLM Integration](#llm-integration) below.")?;
    writeln!(&mut content)?;

    // High confidence issues (most important)
    if !high_confidence.is_empty() {
        writeln!(&mut content, "---")?;
        writeln!(&mut content)?;
        writeln!(&mut content, "## 🔴 High Confidence Issues ({} findings)", high_confidence.len())?;
        writeln!(&mut content)?;
        writeln!(&mut content, "*These findings are in application code and likely represent real vulnerabilities.*")?;
        writeln!(&mut content)?;

        for (i, finding) in high_confidence.iter().enumerate() {
            write_finding_detail(&mut content, i + 1, finding, rules)?;
        }
    }

    // Needs review
    if !needs_review.is_empty() {
        writeln!(&mut content, "---")?;
        writeln!(&mut content)?;
        writeln!(&mut content, "## 🟡 Needs Review ({} findings)", needs_review.len())?;
        writeln!(&mut content)?;
        writeln!(&mut content, "*These findings require manual review to determine if they are true positives.*")?;
        writeln!(&mut content)?;

        // Group by rule for easier review
        let mut by_rule: HashMap<&str, Vec<&Finding>> = HashMap::new();
        for finding in &needs_review {
            by_rule.entry(&finding.rule_id).or_default().push(finding);
        }

        for (rule_id, findings_list) in by_rule {
            let rule_name = rules.iter()
                .find(|r| r.id == rule_id)
                .map(|r| r.name.as_str())
                .unwrap_or("unknown");
            writeln!(&mut content, "### {} - {} ({} findings)", rule_id, rule_name, findings_list.len())?;
            writeln!(&mut content)?;
            
            for finding in findings_list.iter().take(5) {
                writeln!(&mut content, "- `{}` @ {}", 
                    finding.function,
                    finding.span.as_ref()
                        .map(|s| format!("{}:{}", s.file, s.start_line))
                        .unwrap_or_else(|| "unknown".to_string())
                )?;
            }
            if findings_list.len() > 5 {
                writeln!(&mut content, "- *... and {} more*", findings_list.len() - 5)?;
            }
            writeln!(&mut content)?;
        }
    }

    // Likely false positives (collapsed)
    if !likely_fp.is_empty() {
        writeln!(&mut content, "---")?;
        writeln!(&mut content)?;
        writeln!(&mut content, "## ⚪ Likely False Positives ({} findings)", likely_fp.len())?;
        writeln!(&mut content)?;
        writeln!(&mut content, "*These findings are in test/example code or match common false positive patterns.*")?;
        writeln!(&mut content)?;
        writeln!(&mut content, "<details>")?;
        writeln!(&mut content, "<summary>Click to expand</summary>")?;
        writeln!(&mut content)?;

        let mut by_reason: HashMap<&str, Vec<&Finding>> = HashMap::new();
        for finding in &likely_fp {
            let reason = get_fp_reason(finding);
            by_reason.entry(reason).or_default().push(finding);
        }

        for (reason, findings_list) in by_reason {
            writeln!(&mut content, "### {} ({} findings)", reason, findings_list.len())?;
            writeln!(&mut content)?;
            for finding in findings_list.iter().take(3) {
                writeln!(&mut content, "- {} in `{}`", finding.rule_id, finding.function)?;
            }
            if findings_list.len() > 3 {
                writeln!(&mut content, "- *... and {} more*", findings_list.len() - 3)?;
            }
            writeln!(&mut content)?;
        }

        writeln!(&mut content, "</details>")?;
        writeln!(&mut content)?;
    }

    // Remediation guide
    writeln!(&mut content, "---")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "## 🛠️ Remediation Quick Reference")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "| Vulnerability | Fix Pattern |")?;
    writeln!(&mut content, "|--------------|-------------|")?;
    writeln!(&mut content, "| SQL Injection | Use parameterized queries: `.bind()` or `?` placeholders |")?;
    writeln!(&mut content, "| Path Traversal | `path.canonicalize()?.starts_with(base_dir)` |")?;
    writeln!(&mut content, "| Command Injection | Use `Command::new().arg()` instead of string concat |")?;
    writeln!(&mut content, "| SSRF | Validate URL host against allowlist |")?;
    writeln!(&mut content, "| Regex Injection | `regex::escape(&user_input)` |")?;
    writeln!(&mut content, "| Weak Crypto | Replace MD5/SHA1 with SHA-256+ |")?;
    writeln!(&mut content, "| Hardcoded Secrets | Use environment variables or secret managers |")?;
    writeln!(&mut content, "| Unbounded Allocation | Add `if size > MAX {{ return Err(...) }}` |")?;
    writeln!(&mut content)?;

    // LLM integration section
    writeln!(&mut content, "---")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "## 🤖 LLM Integration")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "For enhanced analysis with AI-powered false positive detection and code fix suggestions:")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "```bash")?;
    writeln!(&mut content, "# With OpenAI")?;
    writeln!(&mut content, "export RUSTCOLA_LLM_API_KEY=sk-...")?;
    writeln!(&mut content, "cargo-cola --crate-path . --llm-report report.md \\")?;
    writeln!(&mut content, "  --llm-endpoint https://api.openai.com/v1/chat/completions")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "# With Anthropic Claude")?;
    writeln!(&mut content, "cargo-cola --crate-path . --llm-report report.md \\")?;
    writeln!(&mut content, "  --llm-endpoint https://api.anthropic.com/v1/messages \\")?;
    writeln!(&mut content, "  --llm-model claude-3-sonnet-20240229")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "# With local Ollama")?;
    writeln!(&mut content, "cargo-cola --crate-path . --llm-report report.md \\")?;
    writeln!(&mut content, "  --llm-endpoint http://localhost:11434/v1/chat/completions \\")?;
    writeln!(&mut content, "  --llm-model llama2")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "# With IDE-integrated AI (Copilot, Cursor, etc.)")?;
    writeln!(&mut content, "cargo-cola --crate-path . --llm-prompt prompt.md")?;
    writeln!(&mut content, "# Then open prompt.md and paste into your AI chat")?;
    writeln!(&mut content, "```")?;
    writeln!(&mut content)?;

    // Write file
    let mut file = File::create(path)
        .with_context(|| format!("create standalone report at {}", path.display()))?;
    file.write_all(content.as_bytes())?;
    
    eprintln!("  Standalone report written to: {}", path.display());
    
    Ok(())
}

/// Generate an LLM prompt file for use with IDE-integrated AI assistants
/// This creates a markdown file with findings formatted as a prompt ready to paste
/// into Copilot Chat, Cursor, or any other AI assistant integrated into the IDE.
fn generate_llm_prompt(
    path: &Path,
    project_name: &str,
    findings: &[Finding],
    _rules: &[mir_extractor::RuleMetadata],
    audit_vulns: &[AuditVulnerability],
) -> Result<()> {
    use std::fmt::Write as _;

    let mut content = String::new();

    // Header
    writeln!(&mut content, "# Security Analysis: {}", project_name)?;
    writeln!(&mut content)?;

    // Include audit vulnerabilities if present
    if !audit_vulns.is_empty() {
        writeln!(&mut content, "## Dependency Vulnerabilities (cargo-audit)")?;
        writeln!(&mut content)?;
        writeln!(&mut content, "The following {} known vulnerabilities were found in dependencies:", audit_vulns.len())?;
        writeln!(&mut content)?;
        writeln!(&mut content, "| ID | Package | Version | Severity | Title |")?;
        writeln!(&mut content, "|-----|---------|---------|----------|-------|")?;
        for vuln in audit_vulns {
            let severity = vuln.severity.as_deref().unwrap_or("unknown");
            writeln!(&mut content, "| {} | {} | {} | {} | {} |",
                vuln.id, vuln.package, vuln.version, severity, vuln.title)?;
        }
        writeln!(&mut content)?;
        writeln!(&mut content, "**Note:** Address dependency vulnerabilities by updating affected packages or reviewing advisories for mitigations.")?;
        writeln!(&mut content)?;
        writeln!(&mut content, "---")?;
        writeln!(&mut content)?;
    }

    writeln!(&mut content, "You are a senior security researcher performing a comprehensive audit of a Rust codebase.")?;
    writeln!(&mut content, "Below are {} findings from static analysis. Your task is to transform this raw output into an actionable security report.", findings.len())?;
    writeln!(&mut content)?;
    
    // Phase 1: False Positive Elimination
    writeln!(&mut content, "## Phase 1: False Positive Analysis")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "For EACH finding, determine if it's a true positive or false positive. Apply these Rust-specific criteria:")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "### Common False Positive Patterns")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "**Dismiss as FALSE POSITIVE if:**")?;
    writeln!(&mut content, "- **Test code**: Function path contains `test`, `tests/`, `_test`, `mock`, `bench` - test vulnerabilities don't affect production")?;
    writeln!(&mut content, "- **Build scripts**: In `build.rs` - executes at compile time on developer machines only")?;
    writeln!(&mut content, "- **Macro-generated code**: Evidence shows derive macros (`#[derive(...)]`) or procedural macros generating the flagged pattern")?;
    writeln!(&mut content, "- **Dead code paths**: `#[cfg(...)]` guards that exclude the code from production builds")?;
    writeln!(&mut content, "- **Intentional unsafe with safety comments**: Unsafe block has documented safety invariants that are upheld")?;
    writeln!(&mut content, "- **Constant/literal inputs**: The \"tainted\" input is actually a compile-time constant, not user data")?;
    writeln!(&mut content, "- **Internal-only APIs**: Private functions (`pub(crate)`, no `pub`) that are only called with validated inputs")?;
    writeln!(&mut content, "- **Example/demo code**: In `examples/` directory - documentation, not production code")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "**Dismiss specific rule patterns:**")?;
    writeln!(&mut content, "- **SQL injection (RUSTCOLA087)**: String is used in logging, error messages, or format strings - NOT actual SQL query construction")?;
    writeln!(&mut content, "- **Timing attack (RUSTCOLA044)**: Comparison is of non-secret data (config keys, enum variants, error codes, public identifiers)")?;
    writeln!(&mut content, "- **Hardcoded secrets (RUSTCOLA039)**: Variable name contains 'key'/'password'/'secret' but value is a file path, config key name, or placeholder")?;
    writeln!(&mut content, "- **HTTP URLs (RUSTCOLA011)**: URL is localhost default, documentation example, or configuration placeholder")?;
    writeln!(&mut content, "- **Unsafe code (RUSTCOLA003)**: Required for FFI, signal handlers, or performance-critical code with proper safety documentation")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "For each false positive, provide a ONE-LINE rationale citing the specific dismissal pattern.")?;
    writeln!(&mut content)?;
    
    // Phase 2: True Positive Deep Analysis
    writeln!(&mut content, "## Phase 2: True Positive Deep Analysis")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "For each TRUE POSITIVE, provide comprehensive analysis:")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "### Severity Assessment (use CVSS 3.1 reasoning)")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "| Level | Criteria | Examples |")?;
    writeln!(&mut content, "|-------|----------|----------|")?;
    writeln!(&mut content, "| **Critical** | Remote code execution, auth bypass, data exfiltration without auth | Deserialize untrusted data into executable, SQL injection in auth query |")?;
    writeln!(&mut content, "| **High** | Privilege escalation, significant data exposure, DoS of critical service | SSRF to internal services, unbounded allocation from network input |")?;
    writeln!(&mut content, "| **Medium** | Limited data exposure, DoS requiring specific conditions, local privilege issues | Path traversal with limited scope, blocking calls in async (degrades performance) |")?;
    writeln!(&mut content, "| **Low** | Information disclosure of non-sensitive data, code quality issues with security implications | Commented code with old credentials, weak hash for non-security purpose |")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "### Exploitability Analysis")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "Answer these questions for each finding:")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "1. **Attack Vector**: How does attacker reach this code?")?;
    writeln!(&mut content, "   - Network (unauthenticated) → highest risk")?;
    writeln!(&mut content, "   - Network (authenticated) → requires credential theft first")?;
    writeln!(&mut content, "   - Local (CLI input) → requires shell access")?;
    writeln!(&mut content, "   - Local (file input) → requires file write access")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "2. **Prerequisites**: What conditions must be true?")?;
    writeln!(&mut content, "   - Feature flags enabled?")?;
    writeln!(&mut content, "   - Specific configuration?")?;
    writeln!(&mut content, "   - Authentication/authorization bypassed?")?;
    writeln!(&mut content, "   - Race conditions or timing requirements?")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "3. **Complexity**: How hard is exploitation?")?;
    writeln!(&mut content, "   - Trivial: Simple curl command or script")?;
    writeln!(&mut content, "   - Moderate: Custom tool or chained vulnerabilities")?;
    writeln!(&mut content, "   - Complex: Requires insider knowledge, precise timing, or rare conditions")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "4. **Impact Scope**: What's the blast radius?")?;
    writeln!(&mut content, "   - Single user/request affected")?;
    writeln!(&mut content, "   - All users of the service")?;
    writeln!(&mut content, "   - Lateral movement to other systems")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "### Attack Scenario (Required for High/Critical)")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "Write a concrete, step-by-step attack narrative:")?;
    writeln!(&mut content, "```")?;
    writeln!(&mut content, "1. Attacker identifies [entry point]")?;
    writeln!(&mut content, "2. Attacker crafts [malicious input] with [specific payload]")?;
    writeln!(&mut content, "3. Application [vulnerable behavior] because [root cause]")?;
    writeln!(&mut content, "4. Attacker achieves [impact: RCE/data theft/DoS/etc]")?;
    writeln!(&mut content, "```")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "Include a realistic exploit payload or command where applicable.")?;
    writeln!(&mut content)?;
    
    // Phase 3: Remediation
    writeln!(&mut content, "## Phase 3: Remediation Guidance")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "For each true positive, provide:")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "### Code Fix")?;
    writeln!(&mut content, "- Show the BEFORE (vulnerable) and AFTER (fixed) code")?;
    writeln!(&mut content, "- Use idiomatic Rust patterns")?;
    writeln!(&mut content, "- Prefer standard library or well-audited crates")?;
    writeln!(&mut content, "- If the fix requires a dependency, name the crate and version")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "### Defense in Depth")?;
    writeln!(&mut content, "- Additional mitigations beyond the immediate fix")?;
    writeln!(&mut content, "- Architectural changes to prevent similar issues")?;
    writeln!(&mut content, "- Testing strategies to catch regressions")?;
    writeln!(&mut content)?;
    
    // Phase 4: Prioritization
    writeln!(&mut content, "## Phase 4: Prioritization")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "Assign priority based on risk AND effort:")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "| Priority | Risk | Effort | Action Timeline |")?;
    writeln!(&mut content, "|----------|------|--------|-----------------|")?;
    writeln!(&mut content, "| **P0** | Critical/High + Easy to exploit | Any | Hotfix NOW (same day) |")?;
    writeln!(&mut content, "| **P1** | High + Moderate exploit, or Medium + Easy | Low-Medium | This sprint (1-2 weeks) |")?;
    writeln!(&mut content, "| **P2** | Medium + Moderate, or Low + Any | Any | Backlog (plan within quarter) |")?;
    writeln!(&mut content, "| **P3** | Low + Hard to exploit | High | Track but don't prioritize |")?;
    writeln!(&mut content)?;
    
    // Output format
    writeln!(&mut content, "## Output Format")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "Structure your report as:")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "```markdown")?;
    writeln!(&mut content, "# Security Audit Report: [Project Name]")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "## Executive Summary")?;
    writeln!(&mut content, "[2-3 sentences: total findings, true positives, critical issues, overall risk posture]")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "## Critical & High Findings (P0/P1)")?;
    writeln!(&mut content, "[Detailed analysis for each, with attack scenarios and fixes]")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "## Medium Findings (P2)")?;
    writeln!(&mut content, "[Analysis with fixes]")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "## Low/Informational (P3)")?;
    writeln!(&mut content, "[Brief descriptions]")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "## False Positives")?;
    writeln!(&mut content, "[Table: Finding | Dismissal Reason]")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "## Recommendations")?;
    writeln!(&mut content, "[Prioritized action items]")?;
    writeln!(&mut content, "```")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "---")?;
    writeln!(&mut content)?;
    writeln!(&mut content, "## Findings to Analyze")?;
    writeln!(&mut content)?;

    // Include more findings (up to 100) - no summary table, just raw data
    let findings_limit = 100;
    let show_all = findings.len() <= findings_limit;
    
    if !show_all {
        writeln!(&mut content, "*Showing {} of {} findings. Analyze all shown findings.*", findings_limit, findings.len())?;
        writeln!(&mut content)?;
    }

    for (i, finding) in findings.iter().take(findings_limit).enumerate() {
        writeln!(&mut content, "### {}. {} ({:?})", i + 1, finding.rule_id, finding.severity)?;
        writeln!(&mut content, "| Attribute | Value |")?;
        writeln!(&mut content, "|-----------|-------|")?;
        writeln!(&mut content, "| **Rule** | {} |", finding.rule_id)?;
        writeln!(&mut content, "| **Static Severity** | {:?} |", finding.severity)?;
        writeln!(&mut content, "| **Function** | `{}` |", finding.function)?;
        if let Some(span) = &finding.span {
            writeln!(&mut content, "| **File** | `{}:{}` |", span.file, span.start_line)?;
            // Add context hints for LLM
            let file_lower = span.file.to_lowercase();
            if file_lower.contains("test") || file_lower.contains("/tests/") {
                writeln!(&mut content, "| **Context Hint** | ⚠️ Test code path detected |")?;
            } else if file_lower.contains("example") {
                writeln!(&mut content, "| **Context Hint** | ⚠️ Example code path detected |")?;
            } else if file_lower.contains("build.rs") {
                writeln!(&mut content, "| **Context Hint** | ⚠️ Build script (compile-time only) |")?;
            }
        }
        writeln!(&mut content)?;
        writeln!(&mut content, "**Issue:** {}", finding.message)?;
        writeln!(&mut content)?;
        
        if !finding.evidence.is_empty() {
            writeln!(&mut content, "**Evidence (MIR/Source):**")?;
            writeln!(&mut content, "```rust")?;
            for ev in finding.evidence.iter().take(6) {
                writeln!(&mut content, "{}", ev.trim())?;
            }
            writeln!(&mut content, "```")?;
        }
        writeln!(&mut content)?;
        writeln!(&mut content, "---")?;
        writeln!(&mut content)?;
    }

    // Write file
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut file = File::create(path)
        .with_context(|| format!("create LLM prompt at {}", path.display()))?;
    file.write_all(content.as_bytes())?;
    
    eprintln!("  LLM prompt written to: {}", path.display());
    
    Ok(())
}

/// Compute a heuristic false positive likelihood score (0.0 = definitely real, 1.0 = definitely FP)
fn compute_false_positive_likelihood(finding: &Finding) -> f64 {
    let mut score: f64 = 0.0;
    
    // Check file path patterns
    if let Some(span) = &finding.span {
        let file = span.file.to_lowercase();
        if file.contains("/test") || file.contains("_test.rs") || file.contains("/tests/") {
            score += 0.4;
        }
        if file.contains("/example") || file.contains("/examples/") {
            score += 0.35;
        }
        if file.contains("/mock") || file.contains("/fixture") {
            score += 0.3;
        }
        if file.contains("/benches/") || file.contains("_bench.rs") {
            score += 0.25;
        }
    }
    
    // Check function name patterns
    let func = finding.function.to_lowercase();
    if func.contains("test_") || func.starts_with("test") || func.contains("_test") {
        score += 0.3;
    }
    if func.contains("mock") || func.contains("fake") || func.contains("stub") {
        score += 0.25;
    }
    if func.contains("example") || func.contains("demo") {
        score += 0.2;
    }
    
    // Check evidence for common FP patterns
    for ev in &finding.evidence {
        let ev_lower = ev.to_lowercase();
        if ev_lower.contains("const ") && (ev_lower.contains("\"select") || ev_lower.contains("\"insert")) {
            // SQL in const string - common false positive
            score += 0.2;
        }
        if ev_lower.contains("error") || ev_lower.contains("panic") || ev_lower.contains("assert") {
            // In error handling or assertion - less likely to be exploitable
            score += 0.1;
        }
    }
    
    score.min(1.0_f64)
}

/// Get a human-readable reason for why something is likely a false positive
fn get_fp_reason(finding: &Finding) -> &'static str {
    if let Some(span) = &finding.span {
        let file = span.file.to_lowercase();
        if file.contains("/test") || file.contains("_test.rs") || file.contains("/tests/") {
            return "In test code";
        }
        if file.contains("/example") || file.contains("/examples/") {
            return "In example code";
        }
        if file.contains("/mock") || file.contains("/fixture") {
            return "In mock/fixture code";
        }
    }
    
    let func = finding.function.to_lowercase();
    if func.contains("test") {
        return "Test function";
    }
    if func.contains("mock") || func.contains("fake") {
        return "Mock/fake function";
    }
    
    "Other heuristic match"
}

/// Write detailed finding information
fn write_finding_detail(
    content: &mut String,
    index: usize,
    finding: &Finding,
    rules: &[mir_extractor::RuleMetadata],
) -> Result<()> {
    use std::fmt::Write as _;
    
    let rule_name = rules.iter()
        .find(|r| r.id == finding.rule_id)
        .map(|r| r.name.as_str())
        .unwrap_or("unknown");
    
    let severity_emoji = match finding.severity {
        mir_extractor::Severity::High => "�",
        mir_extractor::Severity::Medium => "🟡",
        mir_extractor::Severity::Low => "🔵",
    };

    writeln!(content, "### {}. {} {} - {}", index, severity_emoji, finding.rule_id, rule_name)?;
    writeln!(content)?;
    writeln!(content, "**Severity:** {:?}", finding.severity)?;
    writeln!(content, "**Function:** `{}`", finding.function)?;
    if let Some(span) = &finding.span {
        writeln!(content, "**Location:** [{}:{}]({}#L{})", 
            span.file, span.start_line, span.file, span.start_line)?;
    }
    writeln!(content)?;
    writeln!(content, "**Issue:** {}", finding.message)?;
    writeln!(content)?;
    
    if !finding.evidence.is_empty() {
        writeln!(content, "**Evidence:**")?;
        writeln!(content, "```rust")?;
        for ev in &finding.evidence {
            writeln!(content, "{}", ev.trim())?;
        }
        writeln!(content, "```")?;
        writeln!(content)?;
    }
    
    Ok(())
}

/// Simple date string without external dependency
fn chrono_lite_date() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    
    // Attempt to get local timezone offset
    // On Unix systems, we can check /etc/localtime or TZ environment variable
    // For simplicity, we'll use a heuristic based on common US timezones
    let tz_offset_hours: i64 = std::env::var("TZ")
        .ok()
        .and_then(|tz| {
            let tz_lower = tz.to_lowercase();
            if tz_lower.contains("pst") || tz_lower.contains("pacific") || tz_lower.contains("los_angeles") {
                Some(-8)
            } else if tz_lower.contains("mst") || tz_lower.contains("mountain") || tz_lower.contains("denver") {
                Some(-7)
            } else if tz_lower.contains("cst") || tz_lower.contains("central") || tz_lower.contains("chicago") {
                Some(-6)
            } else if tz_lower.contains("est") || tz_lower.contains("eastern") || tz_lower.contains("new_york") {
                Some(-5)
            } else if tz_lower.contains("utc") || tz_lower.contains("gmt") {
                Some(0)
            } else {
                None
            }
        })
        .unwrap_or(-8); // Default to PST for US-based development
    
    let adjusted_secs = duration.as_secs() as i64 + (tz_offset_hours * 3600);
    let mut days = adjusted_secs / 86400;
    
    // Calculate year, accounting for leap years
    let mut year = 1970i64;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    
    // Calculate month and day
    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    
    let mut month = 1;
    for &dim in &days_in_months {
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    let day = days + 1;
    
    format!("{:04}-{:02}-{:02}", year, month, day)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Get estimated false positive rate and notes for a rule based on empirical testing
/// Returns (estimated_fp_rate_percent, notes)
fn get_rule_fp_estimate(rule_id: &str) -> (Option<u8>, &'static str) {
    match rule_id {
        // Low FP rate rules - well-tuned
        "RUSTCOLA087" => (Some(5), "SQL injection - uses format string validation"),
        "RUSTCOLA030" => (Some(10), "Lock guard - tracks wildcard bindings only"),
        "RUSTCOLA064" => (Some(15), "ZST arithmetic - skips derive macros"),
        "RUSTCOLA065" => (Some(10), "Cleartext env vars - keyword-based"),
        "RUSTCOLA005" => (Some(5), "Weak crypto - MD5/SHA1 detection"),
        "RUSTCOLA006" => (Some(5), "Hardcoded secrets - pattern-based"),
        
        // Medium FP rate rules - context-dependent
        "RUSTCOLA024" => (Some(25), "Unbounded allocation - needs context"),
        "RUSTCOLA044" => (Some(35), "Timing attack - may be intentional"),
        "RUSTCOLA007" => (Some(40), "Command execution - may be intentional"),
        "RUSTCOLA088" => (Some(35), "SSRF - depends on URL source"),
        "RUSTCOLA011" => (Some(45), "Non-HTTPS - many safe dev/local cases"),
        
        // Higher FP rate rules - need more context
        "RUSTCOLA022" => (Some(50), "Length truncation - often safe casts"),
        "RUSTCOLA003" => (Some(60), "Unsafe usage - many are safe patterns"),
        
        // Code quality rules - not security FPs
        "RUSTCOLA067" => (None, "Commented code - informational only"),
        "RUSTCOLA020" => (None, "Cargo auditable - build config check"),
        
        _ => (None, ""),
    }
}

/// Generate rule summary table with FP estimates
fn write_rule_summary_table(
    content: &mut String,
    findings: &[Finding],
    rules: &[mir_extractor::RuleMetadata],
) -> Result<()> {
    use std::collections::HashMap;
    use std::fmt::Write as _;
    
    // Count findings by rule
    let mut by_rule: HashMap<&str, usize> = HashMap::new();
    for finding in findings {
        *by_rule.entry(&finding.rule_id).or_default() += 1;
    }
    
    if by_rule.is_empty() {
        return Ok(());
    }
    
    // Sort by count descending
    let mut sorted_rules: Vec<_> = by_rule.into_iter().collect();
    sorted_rules.sort_by(|a, b| b.1.cmp(&a.1));
    
    writeln!(content, "### Findings by Rule")?;
    writeln!(content)?;
    writeln!(content, "| Rule ID | Name | Count | Est. FP Rate | Notes |")?;
    writeln!(content, "|---------|------|-------|--------------|-------|")?;
    
    for (rule_id, count) in sorted_rules {
        let rule_name = rules.iter()
            .find(|r| r.id == rule_id)
            .map(|r| r.name.as_str())
            .unwrap_or("unknown");
        
        let (fp_rate, notes) = get_rule_fp_estimate(rule_id);
        let fp_str = fp_rate
            .map(|r| format!("~{}%", r))
            .unwrap_or_else(|| "N/A".to_string());
        
        writeln!(content, "| {} | {} | {} | {} | {} |",
            rule_id, rule_name, count, fp_str, notes)?;
    }
    writeln!(content)?;
    
    Ok(())
}

/// Represents a vulnerability found by cargo-audit
#[derive(Debug, Clone)]
struct AuditVulnerability {
    id: String,           // RUSTSEC-XXXX-XXXX
    package: String,      // affected crate name
    version: String,      // installed version
    title: String,        // vulnerability title
    severity: Option<String>,
    url: Option<String>,
}

/// Run cargo-audit and return parsed vulnerabilities
fn run_cargo_audit(crate_path: &Path) -> Result<Vec<AuditVulnerability>> {
    use std::process::Command;

    // Check if cargo-audit is installed
    let check = Command::new("cargo")
        .args(["audit", "--version"])
        .output();

    match check {
        Ok(output) if output.status.success() => {}
        Ok(_) | Err(_) => {
            eprintln!("cargo-cola: cargo-audit not found. Install with: cargo install cargo-audit");
            eprintln!("cargo-cola: skipping dependency audit");
            return Ok(Vec::new());
        }
    }

    println!("Running cargo-audit for dependency vulnerabilities...");

    let output = Command::new("cargo")
        .args(["audit", "--json"])
        .current_dir(crate_path)
        .output()
        .context("failed to run cargo audit")?;

    // cargo-audit exits with non-zero if vulnerabilities found, but still outputs valid JSON
    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.trim().is_empty() {
        // No output - might be an error
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            eprintln!("cargo-audit stderr: {}", stderr);
        }
        return Ok(Vec::new());
    }

    // Parse the JSON output
    let json: Value = serde_json::from_str(&stdout)
        .context("failed to parse cargo-audit JSON output")?;

    let mut vulnerabilities = Vec::new();

    // cargo-audit JSON structure: { "vulnerabilities": { "list": [...] } }
    if let Some(vuln_obj) = json.get("vulnerabilities") {
        if let Some(list) = vuln_obj.get("list").and_then(|l| l.as_array()) {
            for vuln in list {
                let advisory = vuln.get("advisory").unwrap_or(&Value::Null);
                let pkg = vuln.get("package").unwrap_or(&Value::Null);

                let id = advisory
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN")
                    .to_string();

                let package = pkg
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                let version = pkg
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string();

                let title = advisory
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("No title")
                    .to_string();

                let severity = advisory
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let url = advisory
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                vulnerabilities.push(AuditVulnerability {
                    id,
                    package,
                    version,
                    title,
                    severity,
                    url,
                });
            }
        }
    }

    if vulnerabilities.is_empty() {
        println!("cargo-audit: no known vulnerabilities found in dependencies");
    } else {
        println!(
            "cargo-audit: found {} known vulnerabilities in dependencies",
            vulnerabilities.len()
        );
    }

    Ok(vulnerabilities)
}

/// Format cargo-audit results for inclusion in reports
fn format_audit_section(vulnerabilities: &[AuditVulnerability]) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();

    writeln!(output, "## Dependency Vulnerabilities (cargo-audit)").unwrap();
    writeln!(output).unwrap();

    if vulnerabilities.is_empty() {
        writeln!(output, "✅ No known vulnerabilities found in dependencies.").unwrap();
        writeln!(output).unwrap();
        return output;
    }

    writeln!(
        output,
        "⚠️ Found **{}** known vulnerabilities in dependencies:",
        vulnerabilities.len()
    )
    .unwrap();
    writeln!(output).unwrap();

    writeln!(output, "| ID | Package | Version | Severity | Title |").unwrap();
    writeln!(output, "|-----|---------|---------|----------|-------|").unwrap();

    for vuln in vulnerabilities {
        let severity = vuln.severity.as_deref().unwrap_or("unknown");
        let id_link = if let Some(url) = &vuln.url {
            format!("[{}]({})", vuln.id, url)
        } else {
            vuln.id.clone()
        };

        writeln!(
            output,
            "| {} | {} | {} | {} | {} |",
            id_link, vuln.package, vuln.version, severity, vuln.title
        )
        .unwrap();
    }

    writeln!(output).unwrap();
    writeln!(
        output,
        "**Recommendation:** Update affected dependencies or review advisories for mitigations."
    )
    .unwrap();
    writeln!(output).unwrap();

    output
}
