#![cfg_attr(feature = "hir-driver", feature(rustc_private))]

use anyhow::{anyhow, Context, Result};
use cargo_metadata::MetadataCommand;
use chrono::Local;
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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

mod suppression;

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

    /// Optional path for the raw findings JSON output (defaults to <out_dir>/raw-findings.json)
    #[arg(long)]
    findings_json: Option<PathBuf>,

    /// Optional path to emit raw SARIF 2.1.0 output (defaults to <out_dir>/raw-findings.sarif if not provided)
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
    /// Optional path to emit HIR JSON (defaults to <out_dir>/hir.json)
    #[arg(long)]
    hir_json: Option<PathBuf>,

    #[cfg(feature = "hir-driver")]
    /// Suppress HIR JSON output (default: HIR is generated when hir-driver feature is enabled)
    #[arg(long = "no-hir", action = ArgAction::SetTrue)]
    no_hir: bool,

    #[cfg(feature = "hir-driver")]
    /// Control whether HIR snapshots are persisted alongside MIR cache entries (default true)
    #[arg(long, value_parser = BoolishValueParser::new())]
    hir_cache: Option<bool>,

    /// Optional path to emit AST JSON (defaults to <out_dir>/ast.json)
    #[arg(long)]
    ast_json: Option<PathBuf>,

    /// Suppress AST JSON output (default: AST is generated)
    #[arg(long = "no-ast", action = ArgAction::SetTrue)]
    no_ast: bool,

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

    /// Temperature for LLM responses (0.0 = deterministic)
    #[arg(long, default_value = "0.0")]
    llm_temperature: f32,

    /// Generate a standalone raw human-readable security report (no LLM required)
    /// Defaults to <out_dir>/reports/raw-report.md if no path specified
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    report: Option<PathBuf>,

    /// Suppress standalone report generation
    #[arg(long = "no-report", action = ArgAction::SetTrue)]
    no_report: bool,

    /// Custom path for LLM prompt file (defaults to <out_dir>/llm-prompt.md)
    /// Alias: --output-for-llm
    #[arg(long, visible_alias = "output-for-llm")]
    llm_prompt: Option<PathBuf>,

    /// Suppress LLM prompt generation (default: LLM prompt is generated)
    #[arg(long = "no-llm-prompt", action = ArgAction::SetTrue)]
    no_llm_prompt: bool,

    /// Run cargo-audit to check dependencies for known vulnerabilities (requires cargo-audit installed)
    /// Findings are merged into the report output
    #[arg(long = "with-audit", action = ArgAction::SetTrue)]
    with_audit: bool,

    /// v1.0.1: Exclude test code from analysis (files in tests/, test modules, #[cfg(test)])
    /// Default: true - test code is excluded to reduce noise
    #[arg(long, value_parser = BoolishValueParser::new(), default_value = "true")]
    exclude_tests: Option<bool>,

    /// v1.0.1: Exclude example code from analysis (files in examples/)
    /// Default: true - example code is excluded
    #[arg(long, value_parser = BoolishValueParser::new(), default_value = "true")]
    exclude_examples: Option<bool>,

    /// v1.0.1: Exclude benchmark code from analysis (files in benches/)
    /// Default: true - benchmark code is excluded
    #[arg(long, value_parser = BoolishValueParser::new(), default_value = "true")]
    exclude_benches: Option<bool>,

    /// Path to cargo-cola configuration file (YAML format)
    /// See examples/cargo-cola.yaml for available options
    #[arg(long)]
    config: Option<PathBuf>,

    /// List all available rules (built-ins plus loaded rulepacks) and exit
    #[arg(long = "rules", action = ArgAction::SetTrue)]
    list_rules: bool,
}

/// Configuration file format for cargo-cola
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct ColaConfig {
    /// Inter-procedural analysis settings
    analysis: mir_extractor::interprocedural::IpaConfig,
    /// Rule profile: strict, balanced (default), or permissive
    profile: RuleProfile,
}

/// Rule profile controls which findings are included in the output
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RuleProfile {
    /// All findings, no filtering - for thorough security audits
    Strict,
    /// Default: Filter out low-confidence, low-severity findings
    Balanced,
    /// Only high-confidence, high-severity findings - for CI pipelines
    Permissive,
}

impl Default for RuleProfile {
    fn default() -> Self {
        RuleProfile::Balanced
    }
}

impl RuleProfile {
    /// Returns true if finding should be included based on profile
    fn should_include(&self, finding: &mir_extractor::Finding) -> bool {
        use mir_extractor::{Confidence, Severity};
        match self {
            RuleProfile::Strict => true, // Include everything
            RuleProfile::Balanced => {
                // Exclude low-confidence + low-severity combo
                !(finding.confidence == Confidence::Low && finding.severity == Severity::Low)
            }
            RuleProfile::Permissive => {
                // Only high-confidence OR high/critical severity
                finding.confidence == Confidence::High || finding.severity >= Severity::High
            }
        }
    }
}

struct PackageOutput {
    package: MirPackage,
    analysis: AnalysisResult,
    sarif: Value,
    #[cfg(feature = "hir-driver")]
    hir: Option<HirPackage>,
}

#[derive(Clone)]
struct ScanConfigSnapshot {
    entries: Vec<ScanConfigEntry>,
}

impl ScanConfigSnapshot {
    fn entries(&self) -> &[ScanConfigEntry] {
        &self.entries
    }
}

#[derive(Clone)]
struct ScanConfigEntry {
    flag: &'static str,
    value: String,
    source: ConfigValueSource,
}

impl ScanConfigEntry {
    fn new(flag: &'static str, value: String, source: ConfigValueSource) -> Self {
        Self {
            flag,
            value,
            source,
        }
    }
}

#[derive(Clone, Copy)]
enum ConfigValueSource {
    Default,
    User,
}

impl ConfigValueSource {
    fn label(&self) -> &'static str {
        match self {
            ConfigValueSource::Default => "default",
            ConfigValueSource::User => "user",
        }
    }
}

fn build_scan_config_snapshot(
    args: &Args,
    fail_on_findings: bool,
    cache_enabled: bool,
) -> ScanConfigSnapshot {
    let mut entries = Vec::new();
    let default_crate = PathBuf::from(".");
    let default_out_dir = PathBuf::from("out/cola");

    let crate_source = if args.crate_path == default_crate {
        ConfigValueSource::Default
    } else {
        ConfigValueSource::User
    };
    entries.push(ScanConfigEntry::new(
        "--crate-path",
        args.crate_path.display().to_string(),
        crate_source,
    ));

    let out_dir_source = if args.out_dir == default_out_dir {
        ConfigValueSource::Default
    } else {
        ConfigValueSource::User
    };
    entries.push(ScanConfigEntry::new(
        "--out-dir",
        args.out_dir.display().to_string(),
        out_dir_source,
    ));

    let (mir_json_value, mir_json_source) = describe_optional_path(
        &args.mir_json,
        format!("auto ({})", args.out_dir.join("mir.json").display()),
    );
    entries.push(ScanConfigEntry::new(
        "--mir-json",
        mir_json_value,
        mir_json_source,
    ));

    let (findings_value, findings_source) = describe_optional_path(
        &args.findings_json,
        format!(
            "auto ({})",
            args.out_dir.join("raw-findings.json").display()
        ),
    );
    entries.push(ScanConfigEntry::new(
        "--findings-json",
        findings_value,
        findings_source,
    ));

    let (sarif_value, sarif_source) = describe_optional_path(
        &args.sarif,
        format!(
            "auto ({})",
            args.out_dir.join("raw-findings.sarif").display()
        ),
    );
    entries.push(ScanConfigEntry::new("--sarif", sarif_value, sarif_source));

    let fail_source = if args.fail_on_findings.is_some() {
        ConfigValueSource::User
    } else {
        ConfigValueSource::Default
    };
    entries.push(ScanConfigEntry::new(
        "--fail-on-findings",
        fail_on_findings.to_string(),
        fail_source,
    ));

    let cache_source = if args.cache.is_some() {
        ConfigValueSource::User
    } else {
        ConfigValueSource::Default
    };
    entries.push(ScanConfigEntry::new(
        "--cache",
        cache_enabled.to_string(),
        cache_source,
    ));

    entries.push(ScanConfigEntry::new(
        "--clear-cache",
        args.clear_cache.to_string(),
        if args.clear_cache {
            ConfigValueSource::User
        } else {
            ConfigValueSource::Default
        },
    ));

    let (rulepack_value, rulepack_source) = if args.rulepack.is_empty() {
        ("none".to_string(), ConfigValueSource::Default)
    } else {
        (
            args.rulepack
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            ConfigValueSource::User,
        )
    };
    entries.push(ScanConfigEntry::new(
        "--rulepack",
        rulepack_value,
        rulepack_source,
    ));

    let (wasm_rule_value, wasm_rule_source) = if args.wasm_rule.is_empty() {
        ("none".to_string(), ConfigValueSource::Default)
    } else {
        (
            args.wasm_rule
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            ConfigValueSource::User,
        )
    };
    entries.push(ScanConfigEntry::new(
        "--wasm-rule",
        wasm_rule_value,
        wasm_rule_source,
    ));

    let (config_value, config_source) = match &args.config {
        Some(path) => (path.display().to_string(), ConfigValueSource::User),
        None => ("unset (default)".to_string(), ConfigValueSource::Default),
    };
    entries.push(ScanConfigEntry::new(
        "--config",
        config_value,
        config_source,
    ));

    entries.push(ScanConfigEntry::new(
        "--with-audit",
        args.with_audit.to_string(),
        if args.with_audit {
            ConfigValueSource::User
        } else {
            ConfigValueSource::Default
        },
    ));

    entries.push(ScanConfigEntry::new(
        "--no-ast",
        args.no_ast.to_string(),
        if args.no_ast {
            ConfigValueSource::User
        } else {
            ConfigValueSource::Default
        },
    ));

    let (ast_json_value, ast_json_source) = if args.no_ast {
        ("disabled (--no-ast)".to_string(), ConfigValueSource::User)
    } else {
        describe_optional_path(
            &args.ast_json,
            format!("auto ({})", args.out_dir.join("ast.json").display()),
        )
    };
    entries.push(ScanConfigEntry::new(
        "--ast-json",
        ast_json_value,
        ast_json_source,
    ));

    let (report_value, report_source) = if args.no_report {
        (
            "disabled (--no-report)".to_string(),
            ConfigValueSource::User,
        )
    } else {
        describe_optional_path(
            &args.report,
            format!("auto ({})", args.out_dir.join("raw-report.md").display()),
        )
    };
    entries.push(ScanConfigEntry::new(
        "--report",
        report_value,
        report_source,
    ));
    entries.push(ScanConfigEntry::new(
        "--no-report",
        args.no_report.to_string(),
        if args.no_report {
            ConfigValueSource::User
        } else {
            ConfigValueSource::Default
        },
    ));

    let (llm_prompt_value, llm_prompt_source) = if args.no_llm_prompt {
        (
            "disabled (--no-llm-prompt)".to_string(),
            ConfigValueSource::User,
        )
    } else {
        describe_optional_path(
            &args.llm_prompt,
            format!("auto ({})", args.out_dir.join("llm-prompt.md").display()),
        )
    };
    entries.push(ScanConfigEntry::new(
        "--llm-prompt",
        llm_prompt_value,
        llm_prompt_source,
    ));
    entries.push(ScanConfigEntry::new(
        "--no-llm-prompt",
        args.no_llm_prompt.to_string(),
        if args.no_llm_prompt {
            ConfigValueSource::User
        } else {
            ConfigValueSource::Default
        },
    ));

    let (llm_report_value, llm_report_source) =
        describe_optional_path(&args.llm_report, "not requested (default)".to_string());
    entries.push(ScanConfigEntry::new(
        "--llm-report",
        llm_report_value,
        llm_report_source,
    ));

    let (llm_endpoint_value, llm_endpoint_source) = match &args.llm_endpoint {
        Some(endpoint) => (endpoint.clone(), ConfigValueSource::User),
        None => ("unset (default)".to_string(), ConfigValueSource::Default),
    };
    entries.push(ScanConfigEntry::new(
        "--llm-endpoint",
        llm_endpoint_value,
        llm_endpoint_source,
    ));

    let llm_model_source = if args.llm_model == "gpt-4" {
        ConfigValueSource::Default
    } else {
        ConfigValueSource::User
    };
    entries.push(ScanConfigEntry::new(
        "--llm-model",
        args.llm_model.clone(),
        llm_model_source,
    ));

    let llm_max_tokens_source = if args.llm_max_tokens == 4096 {
        ConfigValueSource::Default
    } else {
        ConfigValueSource::User
    };
    entries.push(ScanConfigEntry::new(
        "--llm-max-tokens",
        args.llm_max_tokens.to_string(),
        llm_max_tokens_source,
    ));

    let llm_temperature_source = if (args.llm_temperature - 0.0).abs() < f32::EPSILON {
        ConfigValueSource::Default
    } else {
        ConfigValueSource::User
    };
    entries.push(ScanConfigEntry::new(
        "--llm-temperature",
        format!("{:.2}", args.llm_temperature),
        llm_temperature_source,
    ));

    let (llm_api_key_value, llm_api_key_source) = match &args.llm_api_key {
        Some(_) => ("<redacted>".to_string(), ConfigValueSource::User),
        None => (
            "not provided (default)".to_string(),
            ConfigValueSource::Default,
        ),
    };
    entries.push(ScanConfigEntry::new(
        "--llm-api-key",
        llm_api_key_value,
        llm_api_key_source,
    ));

    entries.push(ScanConfigEntry::new(
        "--list-rules",
        args.list_rules.to_string(),
        if args.list_rules {
            ConfigValueSource::User
        } else {
            ConfigValueSource::Default
        },
    ));

    ScanConfigSnapshot { entries }
}

fn describe_optional_path(
    option: &Option<PathBuf>,
    default_desc: String,
) -> (String, ConfigValueSource) {
    match option {
        Some(path) if path.as_os_str().is_empty() => (default_desc, ConfigValueSource::User),
        Some(path) => (path.display().to_string(), ConfigValueSource::User),
        None => (default_desc, ConfigValueSource::Default),
    }
}

fn resolve_output_path(
    user_path: Option<PathBuf>,
    out_dir: &Path,
    base_name: &str,
    timestamp: &str,
) -> PathBuf {
    let path = match user_path {
        Some(p) if p.as_os_str().is_empty() => None,
        Some(p) => Some(p),
        None => None,
    };

    if let Some(p) = path {
        return p;
    }

    let default_path = out_dir.join(base_name);
    if default_path.exists() {
        let stem = Path::new(base_name).file_stem().unwrap().to_str().unwrap();
        let ext = Path::new(base_name).extension().unwrap().to_str().unwrap();
        out_dir.join(format!("{}_{}.{}", stem, timestamp, ext))
    } else {
        default_path
    }
}

fn main() -> Result<()> {
    // Initialize memory profiler (enabled with RUSTCOLA_MEMORY_PROFILE=1)
    mir_extractor::memory_profiler::init();

    let args = Args::parse();
    let timestamp = Local::now().format("%Y%m%d-%H%M%S").to_string();

    fs::create_dir_all(&args.out_dir).context("create analysis output directory")?;

    let fail_on_findings = args.fail_on_findings.unwrap_or(true);
    let cache_enabled = args.cache.unwrap_or(true);
    let scan_config_snapshot = build_scan_config_snapshot(&args, fail_on_findings, cache_enabled);

    // Load configuration file if specified
    let cola_config: ColaConfig = if let Some(config_path) = &args.config {
        let config_contents = fs::read_to_string(config_path)
            .with_context(|| format!("read config file {}", config_path.display()))?;
        serde_yaml::from_str(&config_contents)
            .with_context(|| format!("parse config file {}", config_path.display()))?
    } else {
        ColaConfig::default()
    };

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
    engine.set_ipa_config(cola_config.analysis.clone());

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

    if args.list_rules {
        print_rules_inventory(&engine);
        return Ok(());
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

        let mut analysis = if let Some(analysis) = cached_analysis {
            println!("Using cached analysis results.");
            analysis
        } else {
            let fresh = analyze_with_engine(&engine, &package);
            store_cached_analysis(&cache_config, &cache_status, &engine, &fresh)?;
            fresh
        };

        // Filter suppressed findings
        suppression::filter_suppressed_findings(
            &mut analysis.findings,
            &crate_root,
            &engine.suppressions,
        );

        // Apply rule profile filtering
        let pre_filter_count = analysis.findings.len();
        analysis
            .findings
            .retain(|f| cola_config.profile.should_include(f));
        if analysis.findings.len() < pre_filter_count {
            println!(
                "  profile {:?}: filtered {} → {} findings",
                cola_config.profile,
                pre_filter_count,
                analysis.findings.len()
            );
        }

        // v1.0.1: Filter findings from test/example/bench code based on CLI flags
        let exclude_tests = args.exclude_tests.unwrap_or(true);
        let exclude_examples = args.exclude_examples.unwrap_or(true);
        let exclude_benches = args.exclude_benches.unwrap_or(true);

        if exclude_tests || exclude_examples || exclude_benches {
            let pre_exclude_count = analysis.findings.len();
            analysis.findings.retain(|finding| {
                // Check if finding is from test/example/bench code
                // Look up the function in the package to check its code type
                if let Some(func) = package.functions.iter().find(|f| f.name == finding.function) {
                    if exclude_tests && func.is_test_code() {
                        return false;
                    }
                    if exclude_examples && func.is_example_code() {
                        return false;
                    }
                    if exclude_benches && func.is_bench_code() {
                        return false;
                    }
                }
                true
            });

            if analysis.findings.len() < pre_exclude_count {
                println!(
                    "  test/example/bench exclusion: filtered {} → {} findings",
                    pre_exclude_count,
                    analysis.findings.len()
                );
            }
        }

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

    let mir_json_path =
        resolve_output_path(args.mir_json.clone(), &args.out_dir, "mir.json", &timestamp);
    let findings_path = resolve_output_path(
        args.findings_json.clone(),
        &args.out_dir,
        "raw-findings.json",
        &timestamp,
    );
    let sarif_path = resolve_output_path(
        args.sarif.clone(),
        &args.out_dir,
        "raw-findings.sarif",
        &timestamp,
    );

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
                temperature: args.llm_temperature,
            });
            generate_llm_analysis(
                llm_path,
                &output.package.crate_name,
                &output.analysis.findings,
                &output.analysis.rules,
                &audit_vulnerabilities,
                llm_config.as_ref(),
                &scan_config_snapshot,
            )?;
            println!("- LLM Report: {}", llm_path.display());
        }

        // Generate standalone report (automatic unless --no-report, or if explicitly requested with path)
        let report_summary_path: Option<PathBuf> = if !args.no_report || args.report.is_some() {
            let resolved_path = resolve_output_path(
                args.report.clone(),
                &args.out_dir,
                "raw-report.md",
                &timestamp,
            );
            generate_standalone_report(
                &resolved_path,
                &output.package.crate_name,
                &output.analysis.findings,
                &output.analysis.rules,
                &audit_vulnerabilities,
            )?;
            Some(resolved_path)
        } else {
            None
        };

        // Generate LLM prompt (automatic unless --no-llm-prompt)
        let llm_prompt_summary_path: Option<PathBuf> = if !args.no_llm_prompt {
            let prompt_path = resolve_output_path(
                args.llm_prompt.clone(),
                &args.out_dir,
                "llm-prompt.md",
                &timestamp,
            );
            generate_llm_prompt(
                &prompt_path,
                &output.package.crate_name,
                &output.analysis.findings,
                &output.analysis.rules,
                &audit_vulnerabilities,
                &scan_config_snapshot,
            )?;
            Some(prompt_path)
        } else {
            None
        };

        #[cfg(feature = "hir-driver")]
        let mut hir_summary_path: Option<PathBuf> = None;
        #[cfg(feature = "hir-driver")]
        if !args.no_hir {
            let hir_path =
                resolve_output_path(args.hir_json.clone(), &args.out_dir, "hir.json", &timestamp);
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

        // Write AST JSON (automatic unless --no-ast)
        let ast_summary_path: Option<PathBuf> = if !args.no_ast {
            let ast_path =
                resolve_output_path(args.ast_json.clone(), &args.out_dir, "ast.json", &timestamp);
            let crate_root = PathBuf::from(&output.package.crate_root);
            if let Ok(ast_package) = collect_ast_package(&crate_root, &output.package.crate_name) {
                write_ast_json(&ast_path, &ast_package)?;
                Some(ast_path)
            } else {
                None
            }
        } else {
            None
        };

        // Write manifest.json
        write_manifest(
            &args.out_dir,
            &output.package.crate_name,
            output.package.functions.len(),
            output.analysis.findings.len(),
            &mir_json_path,
            &findings_path,
            &sarif_path,
            ast_summary_path.as_deref(),
            hir_summary_path.as_deref(),
            llm_prompt_summary_path.as_deref(),
            report_summary_path.as_deref(),
        )?;

        print_summary_single(
            &mir_json_path,
            &findings_path,
            &sarif_path,
            output.package.functions.len(),
            &output.analysis.findings,
            &output.analysis.rules,
            hir_summary_path.as_deref(),
            ast_summary_path.as_deref(),
            report_summary_path.as_deref(),
            llm_prompt_summary_path.as_deref(),
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

    // Write AST JSON (workspace mode - automatic unless --no-ast)
    let workspace_ast_path: Option<PathBuf> = if !args.no_ast {
        let ast_path =
            resolve_output_path(args.ast_json.clone(), &args.out_dir, "ast.json", &timestamp);
        let mut ast_packages = Vec::new();
        for output in &package_outputs {
            let crate_root = PathBuf::from(&output.package.crate_root);
            if let Ok(ast_package) = collect_ast_package(&crate_root, &output.package.crate_name) {
                ast_packages.push(ast_package);
            }
        }
        if !ast_packages.is_empty() {
            let workspace_ast = WorkspaceAst {
                workspace_root: workspace_root.display().to_string(),
                packages: ast_packages,
            };
            write_workspace_ast_json(&ast_path, &workspace_ast)?;
            println!("- AST JSON: {}", ast_path.display());
            Some(ast_path)
        } else {
            None
        }
    } else {
        None
    };

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
            temperature: args.llm_temperature,
        });
        generate_llm_analysis(
            llm_path,
            project_name,
            &aggregated_findings,
            &aggregated_rules,
            &audit_vulnerabilities,
            llm_config.as_ref(),
            &scan_config_snapshot,
        )?;
        println!("- LLM Report: {}", llm_path.display());
    }

    // Generate standalone report (automatic unless --no-report) (workspace mode)
    let project_name = workspace_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("workspace");

    let workspace_report_path: Option<PathBuf> = if !args.no_report || args.report.is_some() {
        let resolved_path = resolve_output_path(
            args.report.clone(),
            &args.out_dir,
            "raw-report.md",
            &timestamp,
        );
        generate_standalone_report(
            &resolved_path,
            project_name,
            &aggregated_findings,
            &aggregated_rules,
            &audit_vulnerabilities,
        )?;
        println!("- Report: {}", resolved_path.display());
        Some(resolved_path)
    } else {
        None
    };

    // Generate LLM prompt (automatic unless --no-llm-prompt) (workspace mode)
    let workspace_llm_prompt_path: Option<PathBuf> = if !args.no_llm_prompt {
        let prompt_path = resolve_output_path(
            args.llm_prompt.clone(),
            &args.out_dir,
            "llm-prompt.md",
            &timestamp,
        );
        generate_llm_prompt(
            &prompt_path,
            project_name,
            &aggregated_findings,
            &aggregated_rules,
            &audit_vulnerabilities,
            &scan_config_snapshot,
        )?;
        println!("- LLM Prompt: {}", prompt_path.display());
        Some(prompt_path)
    } else {
        None
    };

    // Write HIR JSON (workspace mode - automatic when hir-driver feature is enabled)
    #[cfg(feature = "hir-driver")]
    let hir_summary_path: Option<PathBuf> = {
        // For workspaces, create a combined HIR file similar to AST
        let hir_path =
            resolve_output_path(args.hir_json.clone(), &args.out_dir, "hir.json", &timestamp);

        let mut hir_packages = Vec::new();
        for output in &package_outputs {
            if let Some(hir_package) = &output.hir {
                hir_packages.push(hir_package.clone());
            }
        }

        if !hir_packages.is_empty() {
            // Write combined HIR as array of packages
            let combined = serde_json::json!({
                "workspace_root": workspace_root.display().to_string(),
                "packages": hir_packages
            });
            let json =
                serde_json::to_string_pretty(&combined).context("serialize workspace HIR")?;
            fs::write(&hir_path, json)
                .with_context(|| format!("write workspace HIR to {}", hir_path.display()))?;
            println!("- HIR JSON: {}", hir_path.display());
            Some(hir_path)
        } else {
            eprintln!("cargo-cola: no HIR captured for any crates in workspace");
            None
        }
    };
    #[cfg(not(feature = "hir-driver"))]
    let hir_summary_path: Option<PathBuf> = None;

    // Write manifest.json (workspace mode)
    write_manifest(
        &args.out_dir,
        project_name,
        total_functions,
        aggregated_findings.len(),
        &mir_json_path,
        &findings_path,
        &sarif_path,
        workspace_ast_path.as_deref(),
        hir_summary_path.as_deref(),
        workspace_llm_prompt_path.as_deref(),
        workspace_report_path.as_deref(),
    )?;

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
        let resolved = resolve_report_path(report_path, &args.out_dir, "raw-report.md");
        println!("- Standalone Report: {}", resolved.display());
    }
    if let Some(prompt_path) = &args.llm_prompt {
        let resolved = resolve_report_path(prompt_path, &args.out_dir, "llm-prompt.md");
        println!("- LLM Prompt: {}", resolved.display());
    }

    if let Some(rendered) = format_findings_output(&aggregated_findings, &aggregated_rules) {
        print!("{}", rendered);
    }

    if aggregated_findings.is_empty() {
        println!("No findings — great job!");
        mir_extractor::memory_profiler::final_report();
        return Ok(());
    }

    mir_extractor::memory_profiler::final_report();

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
    ast_path: Option<&Path>,
    report_path: Option<&Path>,
    llm_prompt_path: Option<&Path>,
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
    if let Some(path) = ast_path {
        println!("- AST JSON: {}", path.display());
    }
    if let Some(path) = report_path {
        println!("- Report: {}", path.display());
    }
    if let Some(path) = llm_prompt_path {
        println!("- LLM Prompt: {}", path.display());
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
            cwe_ids: Vec::new(),
            fix_suggestion: None,
            exploitability: mir_extractor::Exploitability::default(),
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
            ..Default::default()
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

    // If there's a root package (single crate, not workspace), use it
    if let Some(pkg) = metadata.root_package() {
        let manifest_path = pkg.manifest_path.clone().into_std_path_buf();
        let crate_root = manifest_path
            .parent()
            .ok_or_else(|| anyhow!("package manifest has no parent directory"))?
            .to_path_buf();
        return Ok((vec![crate_root], workspace_root));
    }

    // For workspaces: check if the user specified a path to a specific member
    // If so, only scan that member, not the entire workspace
    let member_ids: HashSet<_> = metadata.workspace_members.iter().cloned().collect();
    let mut members = Vec::new();

    for pkg in &metadata.packages {
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

    // Check if the user-specified path matches a specific workspace member
    // If so, only scan that member instead of the entire workspace
    let user_canonical = fs::canonicalize(&canonical).unwrap_or_else(|_| canonical.clone());
    let matching_member: Vec<_> = members
        .iter()
        .filter(|(_, member_path)| {
            let member_canonical =
                fs::canonicalize(member_path).unwrap_or_else(|_| member_path.clone());
            member_canonical == user_canonical || user_canonical.starts_with(&member_canonical)
        })
        .cloned()
        .collect();

    if matching_member.len() == 1 {
        // User pointed to a specific workspace member - only scan that one
        let crate_roots = matching_member.into_iter().map(|(_, path)| path).collect();
        return Ok((crate_roots, workspace_root));
    }

    // No specific member matched - scan all workspace members
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
    temperature: f32,
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
    let is_ollama =
        config.endpoint.contains("localhost:11434") || config.endpoint.contains("127.0.0.1:11434");

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
            "temperature": config.temperature,
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
            "temperature": config.temperature
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
        let error_text = response
            .text()
            .unwrap_or_else(|_| "unknown error".to_string());
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
        parsed
            .content
            .first()
            .map(|c| c.text.clone())
            .ok_or_else(|| anyhow!("Anthropic response contained no content"))
    } else {
        // OpenAI-compatible format
        let parsed: ChatResponse =
            serde_json::from_str(&response_text).context("failed to parse LLM API response")?;
        parsed
            .choices
            .first()
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
    audit_vulns: &[AuditVulnerability],
    llm_config: Option<&LlmConfig>,
    scan_config: &ScanConfigSnapshot,
) -> Result<()> {
    use std::fmt::Write as _;

    let prompt_content = build_llm_prompt_content(
        project_name,
        findings,
        audit_vulns,
        None,
        false,
        Some(rules),
        Some(scan_config),
    )?;

    // If LLM config provided, call the API
    let final_content = if let Some(config) = llm_config {
        eprintln!(
            "  Sending {} findings to LLM for analysis...",
            findings.len()
        );

        match call_llm_api(config, &prompt_content) {
            Ok(llm_response) => {
                // Wrap LLM response with metadata
                let mut output = String::new();
                writeln!(&mut output, "# Security Analysis Report: {}", project_name)?;
                writeln!(&mut output)?;
                writeln!(
                    &mut output,
                    "*Generated by rust-cola with {} analysis*",
                    config.model
                )?;
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
                writeln!(
                    &mut output,
                    "*Copy the content below to your preferred LLM for analysis.*"
                )?;
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
        writeln!(
            &mut output,
            "*Copy the content below to your preferred LLM (Claude, GPT-4, etc.) for analysis.*"
        )?;
        writeln!(&mut output)?;
        writeln!(&mut output, "---")?;
        writeln!(&mut output)?;
        writeln!(&mut output, "{}", prompt_content)?;
        output
    };

    // Write output file
    let mut file =
        File::create(path).with_context(|| format!("create LLM report at {}", path.display()))?;
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
    writeln!(content, "# Security Report: {}", project_name)?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "Generated by rust-cola v{}",
        env!("CARGO_PKG_VERSION")
    )?;
    writeln!(content, "Date: {}", chrono_lite_date())?;
    writeln!(&mut content)?;

    // Executive Summary
    writeln!(content, "## Executive Summary")?;
    writeln!(&mut content)?;
    writeln!(content, "| Category | Count |")?;
    writeln!(content, "|----------|-------|")?;
    if !audit_vulns.is_empty() {
        writeln!(
            content,
            "| Dependency Vulnerabilities | {} |",
            audit_vulns.len()
        )?;
    }
    writeln!(
        content,
        "| High Confidence Issues | {} |",
        high_confidence.len()
    )?;
    writeln!(content, "| Needs Review | {} |", needs_review.len())?;
    writeln!(content, "| Likely False Positives | {} |", likely_fp.len())?;
    writeln!(content, "| Total Findings | {} |", findings.len())?;
    writeln!(&mut content)?;

    // Add audit section if vulnerabilities found
    if !audit_vulns.is_empty() {
        content.push_str(&format_audit_section(audit_vulns));
    }

    // Severity breakdown
    let high_count = findings
        .iter()
        .filter(|f| matches!(f.severity, mir_extractor::Severity::High))
        .count();
    let medium_count = findings
        .iter()
        .filter(|f| matches!(f.severity, mir_extractor::Severity::Medium))
        .count();
    let low_count = findings
        .iter()
        .filter(|f| matches!(f.severity, mir_extractor::Severity::Low))
        .count();
    let critical_count = findings
        .iter()
        .filter(|f| matches!(f.severity, mir_extractor::Severity::Critical))
        .count();

    writeln!(content, "### By Severity")?;
    writeln!(&mut content)?;
    if critical_count > 0 {
        writeln!(content, "- Critical: {}", critical_count)?;
    }
    if high_count > 0 {
        writeln!(content, "- High: {}", high_count)?;
    }
    if medium_count > 0 {
        writeln!(content, "- Medium: {}", medium_count)?;
    }
    if low_count > 0 {
        writeln!(content, "- Low: {}", low_count)?;
    }
    writeln!(&mut content)?;

    // Priority classification
    writeln!(content, "### Remediation Priority")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "- P0 (immediate): {} critical/high in production code",
        high_confidence
            .iter()
            .filter(|f| matches!(
                f.severity,
                mir_extractor::Severity::Critical | mir_extractor::Severity::High
            ))
            .count()
    )?;
    writeln!(
        content,
        "- P1 (this sprint): {} medium in production code",
        high_confidence
            .iter()
            .filter(|f| matches!(f.severity, mir_extractor::Severity::Medium))
            .count()
    )?;
    writeln!(
        content,
        "- P2 (backlog): {} low priority or needs review",
        high_confidence
            .iter()
            .filter(|f| matches!(f.severity, mir_extractor::Severity::Low))
            .count()
            + needs_review.len()
    )?;
    writeln!(&mut content)?;

    // Rule summary table with FP estimates
    write_rule_summary_table(&mut content, findings, rules)?;

    // High confidence issues (most important)
    if !high_confidence.is_empty() {
        writeln!(content, "---")?;
        writeln!(&mut content)?;
        writeln!(
            content,
            "## High Confidence Issues ({} findings)",
            high_confidence.len()
        )?;
        writeln!(&mut content)?;
        writeln!(
            content,
            "These findings are in application code and likely represent real vulnerabilities."
        )?;
        writeln!(&mut content)?;

        for (i, finding) in high_confidence.iter().enumerate() {
            write_finding_detail(&mut content, i + 1, finding, rules)?;
        }
    }

    // Needs review
    if !needs_review.is_empty() {
        writeln!(content, "---")?;
        writeln!(&mut content)?;
        writeln!(content, "## Needs Review ({} findings)", needs_review.len())?;
        writeln!(&mut content)?;
        writeln!(
            content,
            "These findings require manual review to determine if they are true positives."
        )?;
        writeln!(&mut content)?;

        // Group by rule for easier review
        let mut by_rule: HashMap<&str, Vec<&Finding>> = HashMap::new();
        for finding in &needs_review {
            by_rule.entry(&finding.rule_id).or_default().push(finding);
        }

        for (rule_id, findings_list) in by_rule {
            let rule_name = rules
                .iter()
                .find(|r| r.id == rule_id)
                .map(|r| r.name.as_str())
                .unwrap_or("unknown");
            writeln!(
                content,
                "### {} - {} ({} findings)",
                rule_id,
                rule_name,
                findings_list.len()
            )?;
            writeln!(&mut content)?;

            for finding in findings_list.iter().take(5) {
                writeln!(
                    content,
                    "- {} @ {}",
                    finding.function,
                    finding
                        .span
                        .as_ref()
                        .map(|s| format!("{}:{}", s.file, s.start_line))
                        .unwrap_or_else(|| "unknown".to_string())
                )?;
            }
            if findings_list.len() > 5 {
                writeln!(content, "- ... and {} more", findings_list.len() - 5)?;
            }
            writeln!(&mut content)?;
        }
    }

    // Likely false positives (collapsed)
    if !likely_fp.is_empty() {
        writeln!(content, "---")?;
        writeln!(&mut content)?;
        writeln!(
            content,
            "## Likely False Positives ({} findings)",
            likely_fp.len()
        )?;
        writeln!(&mut content)?;
        writeln!(
            content,
            "These findings are in test/example code or match common false positive patterns."
        )?;
        writeln!(&mut content)?;
        writeln!(content, "<details>")?;
        writeln!(content, "<summary>Click to expand</summary>")?;
        writeln!(&mut content)?;

        let mut by_reason: HashMap<&str, Vec<&Finding>> = HashMap::new();
        for finding in &likely_fp {
            let reason = get_fp_reason(finding);
            by_reason.entry(reason).or_default().push(finding);
        }

        for (reason, findings_list) in by_reason {
            writeln!(content, "### {} ({} findings)", reason, findings_list.len())?;
            writeln!(&mut content)?;
            for finding in findings_list.iter().take(3) {
                writeln!(content, "- {} in {}", finding.rule_id, finding.function)?;
            }
            if findings_list.len() > 3 {
                writeln!(content, "- ... and {} more", findings_list.len() - 3)?;
            }
            writeln!(&mut content)?;
        }

        writeln!(content, "</details>")?;
        writeln!(&mut content)?;
    }

    // Remediation guide
    writeln!(content, "---")?;
    writeln!(&mut content)?;
    writeln!(content, "## Remediation Reference")?;
    writeln!(&mut content)?;
    writeln!(content, "| Vulnerability | Fix |")?;
    writeln!(content, "|---------------|-----|")?;
    writeln!(
        content,
        "| SQL Injection | Use parameterized queries with .bind() or ? placeholders |"
    )?;
    writeln!(
        content,
        "| Path Traversal | Canonicalize and validate: path.canonicalize()?.starts_with(base) |"
    )?;
    writeln!(
        content,
        "| Command Injection | Use Command::new().arg() instead of string concatenation |"
    )?;
    writeln!(content, "| SSRF | Validate URL host against allowlist |")?;
    writeln!(
        content,
        "| Regex Injection | Escape user input: regex::escape(&input) |"
    )?;
    writeln!(
        content,
        "| Weak Crypto | Replace MD5/SHA1 with SHA-256 or stronger |"
    )?;
    writeln!(
        content,
        "| Hardcoded Secrets | Use environment variables or secret managers |"
    )?;
    writeln!(
        content,
        "| Unbounded Allocation | Validate size: if size > MAX then return error |"
    )?;
    writeln!(&mut content)?;

    // LLM note (brief)
    writeln!(content, "---")?;
    writeln!(&mut content)?;
    writeln!(content, "## LLM-Enhanced Analysis")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "For false positive filtering and detailed fix suggestions, run with --llm-prompt"
    )?;
    writeln!(
        content,
        "and submit the generated prompt to an LLM (Claude, GPT-4, etc.)."
    )?;
    writeln!(&mut content)?;

    // Write file
    let mut file = File::create(path)
        .with_context(|| format!("create standalone report at {}", path.display()))?;
    file.write_all(content.as_bytes())?;

    eprintln!("  Standalone report written to: {}", path.display());

    Ok(())
}

/// Build the canonical LLM prompt content shared by manual and automated workflows.
fn build_llm_prompt_content(
    project_name: &str,
    findings: &[Finding],
    audit_vulns: &[AuditVulnerability],
    prompt_path: Option<&Path>,
    include_save_instructions: bool,
    rule_reference: Option<&[mir_extractor::RuleMetadata]>,
    scan_config: Option<&ScanConfigSnapshot>,
) -> Result<String> {
    use std::fmt::Write as _;

    let mut content = String::new();

    // Get current date
    let date_str = chrono::Local::now().format("%Y-%m-%d").to_string();

    // ===== HEADER =====
    writeln!(content, "# Security Analysis Request: {}", project_name)?;
    writeln!(
        content,
        "**Analysis Date:** {} | **Tool:** Rust-COLA v1.0 | **Findings:** {}",
        date_str,
        findings.len()
    )?;
    writeln!(&mut content)?;

    if findings.is_empty() {
        writeln!(
            content,
            "> No findings were reported. If you're craving a little chaos, re-run cargo-cola with `--llm-temperature 0.4` (default 0.0) to let the LLM riff more freely."
        )?;
        writeln!(&mut content)?;
    }

    if let Some(config) = scan_config {
        writeln!(content, "## Scan Configuration")?;
        writeln!(&mut content)?;
        writeln!(
            content,
            "Cargo-cola executed with the following CLI flags. **Reproduce this table in your final report**, calling out whether each value is a default or an explicit override."
        )?;
        writeln!(&mut content)?;
        writeln!(content, "| Flag | Value | Source |")?;
        writeln!(content, "|------|-------|--------|")?;
        for entry in config.entries() {
            writeln!(
                content,
                "| {} | {} | {} |",
                entry.flag,
                escape_markdown_pipes(&entry.value),
                entry.source.label()
            )?;
        }
        writeln!(&mut content)?;
    }

    // ===== SAVE INSTRUCTIONS =====
    if include_save_instructions {
        let prompt_dir_display = prompt_path
            .and_then(|p| p.parent())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| ".".to_string());
        let report_dir_display = prompt_path
            .and_then(|p| p.parent())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "out/cola".to_string());
        writeln!(content, "> **Save Instructions:** After analysis, save the generated report as `security-report.md`")?;
        writeln!(
            content,
            "> in the same directory as this prompt file (`{}`), or use the automated option:",
            prompt_dir_display
        )?;
        writeln!(content, "> ```")?;
        writeln!(
            content,
            "> cargo-cola --crate-path <PROJECT> --llm-report {}/security-report.md",
            report_dir_display
        )?;
        writeln!(content, "> ```")?;
        writeln!(&mut content)?;
    }

    // ===== ROLE & OBJECTIVE =====
    writeln!(content, "## Your Role")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "You are a senior application security engineer performing a security assessment."
    )?;
    writeln!(content, "Your goal is to transform these static analysis findings into an **actionable, executive-ready security report**.")?;
    writeln!(&mut content)?;
    writeln!(content, "The report will be reviewed by:")?;
    writeln!(
        content,
        "- **Security team**: Need technical details and remediation code"
    )?;
    writeln!(
        content,
        "- **Engineering leads**: Need priority and effort estimates"
    )?;
    writeln!(
        content,
        "- **Leadership**: Need executive summary and risk posture"
    )?;
    writeln!(&mut content)?;

    // ===== SOURCE VERIFICATION (STEP 0) =====
    writeln!(content, "---")?;
    writeln!(content, "## Step 0: Source Verification (MANDATORY)")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "⚠️ **CRITICAL: You MUST read the actual source file before analyzing ANY finding.**"
    )?;
    writeln!(&mut content)?;
    writeln!(content, "### Why This Matters")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "Static analysis tools report line numbers and patterns, but:"
    )?;
    writeln!(
        content,
        "- The reported line may have changed since analysis"
    )?;
    writeln!(
        content,
        "- Evidence snippets may be MIR, not the real source"
    )?;
    writeln!(
        content,
        "- Context around the line is essential for accurate assessment"
    )?;
    writeln!(&mut content)?;
    writeln!(content, "### Verification Checklist")?;
    writeln!(&mut content)?;
    writeln!(content, "For EVERY finding you keep in the report:")?;
    writeln!(&mut content)?;
    writeln!(content, "| Step | Action | If You Cannot Complete |")?;
    writeln!(content, "|------|--------|------------------------|")?;
    writeln!(content, "| **1. Read the file** | Fetch the actual source at the reported lines | Mark finding as UNVERIFIED |")?;
    writeln!(content, "| **2. Confirm the pattern** | Ensure the vulnerable construct truly exists | Dismiss as false positive |")?;
    writeln!(content, "| **3. Check context** | Read 20-50 surrounding lines for guards/sanitizers | Note mitigations found |")?;
    writeln!(content, "| **4. Trace call chain** | Verify the entry point reaches this code | Downgrade reachability if uncertain |")?;
    writeln!(&mut content)?;
    writeln!(content, "### Before analyzing anything else:")?;
    writeln!(&mut content)?;
    writeln!(content, "1. Cross-check every file + line reference against the entries in **Findings to Analyze**.")?;
    writeln!(content, "2. Only quote code that appears in the provided Evidence blocks or verified source reads. Do **not** invent or reformat snippets.")?;
    writeln!(content, "3. If a file path, line number, or snippet cannot be matched verbatim to the prompt or verified source, exclude the finding (note it as dismissed for lack of evidence).")?;
    writeln!(&mut content)?;
    writeln!(content, "### NEVER Do This")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "❌ **NEVER synthesize or guess what code looks like**"
    )?;
    writeln!(
        content,
        "❌ **NEVER copy code snippets from tool output without verification**"
    )?;
    writeln!(
        content,
        "❌ **NEVER write `Vulnerable Code` sections without reading the actual file**"
    )?;
    writeln!(
        content,
        "❌ **NEVER invent variable names, function signatures, or code patterns**"
    )?;
    writeln!(&mut content)?;
    writeln!(content, "### Required Evidence Format")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "When showing vulnerable code, include verification:"
    )?;
    writeln!(content, "```")?;
    writeln!(
        content,
        "**Verified Source** (read from `src/handler.rs` lines 145-152):"
    )?;
    writeln!(content, "```rust")?;
    writeln!(content, "// ACTUAL CODE from source file")?;
    writeln!(content, "```")?;
    writeln!(content, "```")?;
    writeln!(&mut content)?;
    writeln!(content, "This verification step prevents hallucinated file paths and keeps conclusions grounded in static analysis output plus real source context.")?;

    // ===== PRUNING INSTRUCTIONS (MANDATORY - FIRST) =====
    writeln!(content, "---")?;
    writeln!(content, "## Step 1: Aggressive Pruning")?;
    writeln!(&mut content)?;
    writeln!(content, "After verifying findings exist, **prune false positives aggressively**. A concise report with real issues is more valuable than a comprehensive report with noise.")?;
    writeln!(&mut content)?;
    writeln!(content, "### Automatic False Positive Criteria")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "**Dismiss immediately** (with brief evidence citation) if ANY of these apply:"
    )?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "| Criterion | How to Identify | Example Evidence |"
    )?;
    writeln!(
        content,
        "|-----------|-----------------|------------------|"
    )?;
    writeln!(content, "| **Test Code** | Path contains `/tests/`, `/test_`, `_test.rs`, `#[test]`, `#[cfg(test)]` | \"File: src/tests/db_test.rs\" |")?;
    writeln!(content, "| **Example/Demo Code** | Path contains `/examples/`, `/demo/`, `/sample/` | \"File: examples/basic_usage.rs\" |")?;
    writeln!(content, "| **Benchmark Code** | Path contains `/benches/`, `_bench.rs` | \"File: benches/perf.rs\" |")?;
    writeln!(content, "| **Build Scripts** | File is `build.rs` (unless executing external commands) | \"File: build.rs\" |")?;
    writeln!(content, "| **Compile-time Constants** | Value is string literal, `const`, or `static` with no runtime input | \"const QUERY: &str = ...\" |")?;
    writeln!(content, "| **Dead Code** | Function is never called, behind `#[cfg(feature = \"...\")]` that's disabled | \"No callers found\" |")?;
    writeln!(content, "| **Documented Unsafe** | Has `// SAFETY:` comment explaining why it's safe | \"SAFETY: bounds checked above\" |")?;
    writeln!(&mut content)?;
    writeln!(content, "### Lower Priority (Keep but Deprioritize)")?;
    writeln!(&mut content)?;
    writeln!(content, "Move to **Low/P3** (not dismissed) if:")?;
    writeln!(
        content,
        "- Requires authenticated access AND has rate limiting"
    )?;
    writeln!(
        content,
        "- Impact limited to self-DoS (user can only crash their own request)"
    )?;
    writeln!(
        content,
        "- Defense-in-depth issue where primary controls exist"
    )?;
    writeln!(&mut content)?;
    writeln!(content, "### Pruning Output")?;
    writeln!(&mut content)?;
    writeln!(content, "After pruning, report: \"Pruned X of Y findings as false positives. Z findings require analysis.\"")?;
    writeln!(&mut content)?;

    // ===== REACHABILITY CLASSIFICATION =====
    writeln!(content, "---")?;
    writeln!(content, "## Step 2: Reachability Analysis")?;
    writeln!(&mut content)?;
    writeln!(content, "For each remaining finding, classify reachability. This determines if a vulnerability is exploitable or theoretical.")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "| Reachability | Definition | Severity Impact | Action |"
    )?;
    writeln!(
        content,
        "|--------------|------------|-----------------|--------|"
    )?;
    writeln!(content, "| **EXPOSED** | Direct path from untrusted input (HTTP handler params, CLI args, stdin, file upload) | Full severity | Immediate fix required |")?;
    writeln!(content, "| **INDIRECT** | Reachable via call chain from entry point; may have intermediate processing | -1 severity level if sanitized | Trace the call chain |")?;
    writeln!(content, "| **AUTHENTICATED** | Behind authentication/authorization checks | -1 severity level | Note auth requirements |")?;
    writeln!(content, "| **INTERNAL** | Only callable from trusted internal code, not exposed to users | -2 severity levels (min: Low) | Defense-in-depth fix |")?;
    writeln!(content, "| **CONFIG-DRIVEN** | Input comes from config files, env vars at startup | Context-dependent | Assess config access model |")?;
    writeln!(&mut content)?;
    writeln!(content, "### Reachability Evidence Required")?;
    writeln!(&mut content)?;
    writeln!(content, "For EXPOSED/INDIRECT findings, show the path:")?;
    writeln!(content, "```")?;
    writeln!(content, "Entry: POST /api/users (handler: create_user)")?;
    writeln!(content, "  → calls validate_input(body.name)")?;
    writeln!(
        content,
        "  → calls db::insert_user(name)  // ← vulnerable sink"
    )?;
    writeln!(
        content,
        "Taint: body.name flows to SQL query without parameterization"
    )?;
    writeln!(content, "```")?;
    writeln!(&mut content)?;

    // ===== MANDATORY AUTHENTICATION VERIFICATION =====
    writeln!(
        content,
        "### ⚠️ MANDATORY: Authentication Verification Checklist"
    )?;
    writeln!(&mut content)?;
    writeln!(content, "**Before classifying ANY finding as AUTHENTICATED, you MUST verify ALL of the following:**")?;
    writeln!(&mut content)?;
    writeln!(content, "| Check | How to Verify | If Uncertain |")?;
    writeln!(content, "|-------|---------------|--------------|")?;
    writeln!(content, "| **1. Auth middleware exists** | Search for `auth`, `authenticate`, `authorize`, `bearer`, `token` in HTTP handler chain | Assume EXPOSED |")?;
    writeln!(content, "| **2. Auth is mandatory** | Check for `--without-auth`, `--no-auth`, `DISABLE_AUTH` flags/env vars | Assume EXPOSED (worst-case) |")?;
    writeln!(content, "| **3. Endpoint is protected** | Verify endpoint is NOT in any auth bypass list (`public_routes`, `skip_auth`, etc.) | Assume EXPOSED |")?;
    writeln!(content, "| **4. Auth cannot be bypassed** | Check for debug modes, test modes, or feature flags that disable auth | Note as CONFIG-DEPENDENT |")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "**Required Evidence Format for AUTHENTICATED classification:**"
    )?;
    writeln!(content, "```")?;
    writeln!(content, "Authentication Status: AUTHENTICATED")?;
    writeln!(content, "Evidence:")?;
    writeln!(
        content,
        "  - Middleware: `AuthMiddleware` applied at router level (src/http.rs:45)"
    )?;
    writeln!(content, "  - No bypass flags found for this endpoint")?;
    writeln!(content, "  - Endpoint NOT in public_routes list")?;
    writeln!(
        content,
        "  - Auth required by default (--without-auth flag exists but disabled by default)"
    )?;
    writeln!(
        content,
        "Caveat: Exploitable if server started with --without-auth flag"
    )?;
    writeln!(content, "```")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "**If auth can be disabled via config, state BOTH scenarios:**"
    )?;
    writeln!(content, "> \"Reachability: EXPOSED when `--without-auth` is used; AUTHENTICATED in default configuration.\"")?;
    writeln!(
        content,
        "> \"Severity assessment uses worst-case (EXPOSED) for final rating.\""
    )?;
    writeln!(&mut content)?;

    // ===== IMPACT TAXONOMY =====
    writeln!(content, "---")?;
    writeln!(content, "## Step 3: Impact Classification")?;
    writeln!(&mut content)?;
    writeln!(content, "Classify each true positive by impact type:")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "| Impact Type | Code | Description | Typical Severity |"
    )?;
    writeln!(
        content,
        "|-------------|------|-------------|------------------|"
    )?;
    writeln!(
        content,
        "| **Remote Code Execution** | RCE | Attacker executes arbitrary code | Critical |"
    )?;
    writeln!(
        content,
        "| **Authentication Bypass** | AUTH | Circumvent login/access controls | Critical |"
    )?;
    writeln!(content, "| **Memory Corruption** | MEM | Use-after-free, buffer overflow, undefined behavior | Critical |")?;
    writeln!(
        content,
        "| **SQL/Command Injection** | INJ | Execute arbitrary queries/commands | Critical-High |"
    )?;
    writeln!(
        content,
        "| **Privilege Escalation** | PRIV | Gain elevated permissions | High |"
    )?;
    writeln!(
        content,
        "| **Sensitive Data Exposure** | DATA | Leak credentials, PII, secrets | High |"
    )?;
    writeln!(
        content,
        "| **Path Traversal** | PATH | Access files outside intended directory | High-Medium |"
    )?;
    writeln!(content, "| **Server-Side Request Forgery** | SSRF | Make server fetch attacker-controlled URLs | High-Medium |")?;
    writeln!(
        content,
        "| **Denial of Service** | DOS | Crash, hang, or resource exhaust | Medium |"
    )?;
    writeln!(
        content,
        "| **Data Integrity** | INTEG | Unauthorized data modification | Medium |"
    )?;
    writeln!(
        content,
        "| **Information Disclosure** | INFO | Leak non-sensitive internal details | Low |"
    )?;
    writeln!(
        content,
        "| **Code Quality** | QUAL | Maintainability, not security-exploitable | Low |"
    )?;
    writeln!(&mut content)?;

    // ===== CONTEXTUAL SEVERITY MODEL =====
    writeln!(content, "---")?;
    writeln!(content, "## Step 4: Contextual Severity Rating")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "Use this model instead of raw CVSS. Final severity considers reachability and context."
    )?;
    writeln!(&mut content)?;
    writeln!(content, "```")?;
    writeln!(
        content,
        "Final Severity = Base Severity + Reachability Modifier + Context Modifier"
    )?;
    writeln!(content, "```")?;
    writeln!(&mut content)?;
    writeln!(content, "### Base Severity (from Impact Type)")?;
    writeln!(&mut content)?;
    writeln!(content, "| Base | Impact Types |")?;
    writeln!(content, "|------|-------------|")?;
    writeln!(
        content,
        "| Critical | RCE, AUTH bypass, MEM corruption with control |"
    )?;
    writeln!(
        content,
        "| High | INJ (SQL/Cmd), PRIV escalation, DATA exposure (credentials/PII) |"
    )?;
    writeln!(
        content,
        "| Medium | SSRF, PATH traversal, DOS, DATA exposure (non-sensitive) |"
    )?;
    writeln!(content, "| Low | INFO disclosure, QUAL issues |")?;
    writeln!(&mut content)?;
    writeln!(content, "### Reachability Modifier")?;
    writeln!(&mut content)?;
    writeln!(content, "| Reachability | Modifier |")?;
    writeln!(content, "|--------------|----------|")?;
    writeln!(content, "| EXPOSED | No change |")?;
    writeln!(content, "| INDIRECT (no sanitization) | No change |")?;
    writeln!(content, "| INDIRECT (partial sanitization) | -1 level |")?;
    writeln!(content, "| AUTHENTICATED | -1 level |")?;
    writeln!(content, "| INTERNAL only | -2 levels (min: Low) |")?;
    writeln!(content, "| CONFIG-DRIVEN (trusted source) | -2 levels |")?;
    writeln!(&mut content)?;
    writeln!(content, "### Context Modifiers")?;
    writeln!(&mut content)?;
    writeln!(content, "| Context | Modifier |")?;
    writeln!(content, "|---------|----------|")?;
    writeln!(content, "| Rate limiting present | -1 level for DOS |")?;
    writeln!(
        content,
        "| Input validation exists (but incomplete) | Note in analysis |"
    )?;
    writeln!(
        content,
        "| Defense-in-depth (other controls exist) | Note, don't reduce |"
    )?;
    writeln!(
        content,
        "| Rust's borrow checker prevents exploitation | Can dismiss if proven |"
    )?;
    writeln!(&mut content)?;

    // ===== REMEDIATION REQUIREMENTS =====
    writeln!(content, "---")?;
    writeln!(content, "## Step 5: Remediation with Code")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "For each true positive, provide **concrete code fixes**:"
    )?;
    writeln!(&mut content)?;
    writeln!(content, "### Required Format")?;
    writeln!(&mut content)?;
    writeln!(content, "````markdown")?;
    writeln!(content, "#### Remediation")?;
    writeln!(&mut content)?;
    writeln!(content, "**Vulnerable Code:**")?;
    writeln!(content, "```rust")?;
    writeln!(
        content,
        "// Current: SQL injection via string interpolation"
    )?;
    writeln!(
        content,
        "let query = format!(\"SELECT * FROM users WHERE id = {{}}\", user_id);"
    )?;
    writeln!(content, "conn.execute(&query)?;")?;
    writeln!(content, "```")?;
    writeln!(&mut content)?;
    writeln!(content, "**Fixed Code:**")?;
    writeln!(content, "```rust")?;
    writeln!(content, "// Fixed: Parameterized query prevents injection")?;
    writeln!(
        content,
        "sqlx::query(\"SELECT * FROM users WHERE id = $1\")"
    )?;
    writeln!(content, "    .bind(user_id)")?;
    writeln!(content, "    .fetch_one(&pool)")?;
    writeln!(content, "    .await?;")?;
    writeln!(content, "```")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "**Recommended Libraries:** `sqlx` with compile-time query checking"
    )?;
    writeln!(content, "**Effort Estimate:** ~2 hours (includes testing)")?;
    writeln!(content, "**Breaking Changes:** None - same return type")?;
    writeln!(content, "````")?;
    writeln!(&mut content)?;
    writeln!(content, "### Remediation Quality Checklist")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "- [ ] **SOURCE VERIFIED**: Code snippet was read from actual source file, not synthesized"
    )?;
    writeln!(
        content,
        "- [ ] **LINE CONFIRMED**: The reported line number matches the vulnerable pattern"
    )?;
    writeln!(content, "- [ ] Code compiles (valid Rust syntax)")?;
    writeln!(content, "- [ ] Uses idiomatic Rust patterns")?;
    writeln!(
        content,
        "- [ ] Recommends well-maintained crates (check if unsure)"
    )?;
    writeln!(content, "- [ ] Includes error handling")?;
    writeln!(content, "- [ ] Notes any API/behavior changes")?;
    writeln!(&mut content)?;

    // ===== OUTPUT FORMAT (ENTERPRISE) =====
    writeln!(content, "---")?;
    writeln!(content, "## Required Output Format")?;
    writeln!(&mut content)?;
    writeln!(content, "Generate the report in this exact structure:")?;
    writeln!(content, "- Include a **Scan Configuration** section (Flag, Value, Source) ahead of the Findings Overview, using the values provided above.")?;
    writeln!(&mut content)?;
    writeln!(content, "> Do not create new findings, functions, files, or line numbers beyond what is present in the Findings table. If information is missing, state 'Insufficient data in prompt' instead of guessing.")?;
    writeln!(&mut content)?;
    writeln!(content, "````markdown")?;
    writeln!(content, "# Security Assessment Report: {}", project_name)?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "**Date:** {} | **Assessed By:** AI-Assisted Analysis | **Tool:** Rust-COLA v1.0",
        date_str
    )?;
    writeln!(&mut content)?;
    writeln!(content, "---")?;
    writeln!(&mut content)?;
    writeln!(content, "## Executive Summary")?;
    writeln!(&mut content)?;
    writeln!(content, "**Risk Rating:** [CRITICAL | HIGH | MEDIUM | LOW]")?;
    writeln!(&mut content)?;
    writeln!(content, "[2-3 sentence summary for leadership. State the most important finding and recommended immediate action.]")?;
    writeln!(&mut content)?;
    writeln!(content, "### Findings Overview")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "| Severity | Count | Exploitable | Requires Immediate Action |"
    )?;
    writeln!(
        content,
        "|----------|-------|-------------|---------------------------|"
    )?;
    writeln!(content, "| Critical | X | X | Yes |")?;
    writeln!(content, "| High | X | X | Yes - within 1 sprint |")?;
    writeln!(content, "| Medium | X | X | Within 30 days |")?;
    writeln!(content, "| Low | X | - | Backlog |")?;
    writeln!(content, "| **Total** | X | X | |")?;
    writeln!(&mut content)?;
    writeln!(content, "### Key Findings")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "1. **[Most critical finding]** - [one-line description]"
    )?;
    writeln!(content, "2. **[Second priority]** - [one-line description]")?;
    writeln!(content, "3. **[Third priority]** - [one-line description]")?;
    writeln!(&mut content)?;
    writeln!(content, "---")?;
    writeln!(&mut content)?;
    writeln!(content, "## Critical & High Severity Findings")?;
    writeln!(&mut content)?;
    writeln!(content, "### [RULE_ID]: [Title]")?;
    writeln!(&mut content)?;
    writeln!(content, "| Attribute | Value |")?;
    writeln!(content, "|-----------|-------|")?;
    writeln!(content, "| **Severity** | Critical/High |")?;
    writeln!(content, "| **Impact Type** | [RCE/AUTH/INJ/etc.] |")?;
    writeln!(content, "| **Reachability** | [EXPOSED/INDIRECT/etc.] |")?;
    writeln!(content, "| **Location** | `file.rs:line` |")?;
    writeln!(content, "| **Exploitability** | [Proven/Likely/Possible] |")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "**Description:** [What the vulnerability is and why it matters]"
    )?;
    writeln!(&mut content)?;
    writeln!(content, "**Attack Path:**")?;
    writeln!(content, "```")?;
    writeln!(content, "Entry: [entry point]")?;
    writeln!(content, "  → [call chain]")?;
    writeln!(content, "  → [vulnerable sink]")?;
    writeln!(content, "```")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "**Business Impact:** [What an attacker could achieve]"
    )?;
    writeln!(&mut content)?;
    writeln!(content, "#### Remediation")?;
    writeln!(&mut content)?;
    writeln!(content, "**Vulnerable Code:**")?;
    writeln!(content, "```rust")?;
    writeln!(content, "[exact vulnerable code]")?;
    writeln!(content, "```")?;
    writeln!(&mut content)?;
    writeln!(content, "**Fixed Code:**")?;
    writeln!(content, "```rust")?;
    writeln!(content, "[corrected code with comments]")?;
    writeln!(content, "```")?;
    writeln!(&mut content)?;
    writeln!(content, "**Effort:** [X hours] | **Priority:** P0/P1")?;
    writeln!(&mut content)?;
    writeln!(content, "---")?;
    writeln!(&mut content)?;
    writeln!(content, "## Medium Severity Findings")?;
    writeln!(&mut content)?;
    writeln!(content, "[Same format as above, can be more condensed]")?;
    writeln!(&mut content)?;
    writeln!(content, "---")?;
    writeln!(&mut content)?;
    writeln!(content, "## Low Severity Findings")?;
    writeln!(&mut content)?;
    writeln!(content, "| ID | Finding | Location | Impact | Effort |")?;
    writeln!(content, "|----|---------|----------|--------|--------|")?;
    writeln!(
        content,
        "| RUSTCOLAXX | [description] | file.rs:line | [impact] | [X hours] |"
    )?;
    writeln!(&mut content)?;
    writeln!(content, "---")?;
    writeln!(&mut content)?;
    writeln!(content, "## Remediation Roadmap")?;
    writeln!(&mut content)?;
    writeln!(content, "| Priority | Finding | Effort | Target |")?;
    writeln!(content, "|----------|---------|--------|--------|")?;
    writeln!(
        content,
        "| **P0** (Immediate) | [finding] | [hours] | Before next deploy |"
    )?;
    writeln!(
        content,
        "| **P1** (Sprint) | [finding] | [hours] | This sprint |"
    )?;
    writeln!(
        content,
        "| **P2** (30 days) | [finding] | [hours] | This month |"
    )?;
    writeln!(
        content,
        "| **P3** (Backlog) | [finding] | [hours] | When convenient |"
    )?;
    writeln!(&mut content)?;
    writeln!(content, "---")?;
    writeln!(&mut content)?;
    writeln!(content, "## Appendix A: False Positives Dismissed")?;
    writeln!(&mut content)?;
    writeln!(content, "| Finding | Reason | Evidence |")?;
    writeln!(content, "|---------|--------|----------|")?;
    writeln!(
        content,
        "| [RULE_ID] | [Test code/Constant/etc.] | [file path or code quote] |"
    )?;
    writeln!(&mut content)?;
    writeln!(content, "---")?;
    writeln!(&mut content)?;
    writeln!(content, "## Appendix B: Methodology")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "This assessment was performed using Rust-COLA static analysis on MIR (Mid-level IR),"
    )?;
    writeln!(content, "followed by AI-assisted triage for false positive elimination and exploitability analysis.")?;
    writeln!(content, "````")?;
    writeln!(&mut content)?;

    if let Some(rules) = rule_reference {
        if !rules.is_empty() {
            writeln!(content, "---")?;
            writeln!(content, "## Rule Reference")?;
            writeln!(&mut content)?;
            for rule in rules {
                writeln!(
                    content,
                    "- **{}** ({}): {} [Severity: {:?}]",
                    rule.id, rule.name, rule.short_description, rule.default_severity
                )?;
            }
            writeln!(&mut content)?;
        }
    }

    // ===== DEPENDENCY VULNERABILITIES (if any) =====
    if !audit_vulns.is_empty() {
        writeln!(content, "---")?;
        writeln!(content, "## Dependency Vulnerabilities (cargo-audit)")?;
        writeln!(&mut content)?;
        writeln!(
            content,
            "Include these in your report under a \"Dependency Vulnerabilities\" section:"
        )?;
        writeln!(&mut content)?;
        writeln!(
            content,
            "| Advisory | Package | Version | Severity | Title |"
        )?;
        writeln!(
            content,
            "|----------|---------|---------|----------|-------|"
        )?;
        for vuln in audit_vulns {
            let severity = vuln.severity.as_deref().unwrap_or("unknown");
            writeln!(
                content,
                "| {} | {} | {} | {} | {} |",
                vuln.id, vuln.package, vuln.version, severity, vuln.title
            )?;
        }
        writeln!(&mut content)?;
    }

    // ===== FINDINGS DATA =====
    writeln!(content, "---")?;
    writeln!(content, "## Findings to Analyze")?;
    writeln!(&mut content)?;

    let findings_limit = 100;
    let show_all = findings.len() <= findings_limit;

    if !show_all {
        writeln!(
            content,
            "⚠️ *Showing {} of {} findings. Focus on highest severity first.*",
            findings_limit,
            findings.len()
        )?;
        writeln!(&mut content)?;
    }

    writeln!(content, "Total findings: **{}**", findings.len())?;
    writeln!(&mut content)?;

    // Group findings by severity for better organization
    let critical_high: Vec<_> = findings
        .iter()
        .filter(|f| {
            matches!(
                f.severity,
                mir_extractor::Severity::Critical | mir_extractor::Severity::High
            )
        })
        .collect();
    let medium: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.severity, mir_extractor::Severity::Medium))
        .collect();
    let low_info: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.severity, mir_extractor::Severity::Low))
        .collect();

    writeln!(content, "- Critical/High: {}", critical_high.len())?;
    writeln!(content, "- Medium: {}", medium.len())?;
    writeln!(content, "- Low/Info: {}", low_info.len())?;
    writeln!(&mut content)?;

    // Output findings
    for (i, finding) in findings.iter().take(findings_limit).enumerate() {
        writeln!(
            content,
            "### Finding {}: {} ({:?})",
            i + 1,
            finding.rule_id,
            finding.severity
        )?;
        writeln!(&mut content)?;
        writeln!(content, "| Attribute | Value |")?;
        writeln!(content, "|-----------|-------|")?;
        writeln!(content, "| **Rule ID** | {} |", finding.rule_id)?;
        writeln!(content, "| **Severity** | {:?} |", finding.severity)?;
        writeln!(content, "| **Function** | `{}` |", finding.function)?;
        if let Some(span) = &finding.span {
            writeln!(
                content,
                "| **Location** | `{}:{}` |",
                span.file, span.start_line
            )?;

            // Add context hints for pruning
            let file_lower = span.file.to_lowercase();
            if file_lower.contains("test") || file_lower.contains("/tests/") {
                writeln!(
                    content,
                    "| **Context** | ⚠️ Test code - likely false positive |"
                )?;
            } else if file_lower.contains("example") || file_lower.contains("/examples/") {
                writeln!(
                    content,
                    "| **Context** | ⚠️ Example code - likely false positive |"
                )?;
            } else if file_lower.contains("bench") || file_lower.contains("/benches/") {
                writeln!(
                    content,
                    "| **Context** | ⚠️ Benchmark code - likely false positive |"
                )?;
            } else if span.file.ends_with("build.rs") {
                writeln!(
                    content,
                    "| **Context** | Build script - assess if running external commands |"
                )?;
            }
        }
        writeln!(&mut content)?;
        writeln!(content, "**Issue:** {}", finding.message)?;
        writeln!(&mut content)?;

        if !finding.evidence.is_empty() {
            writeln!(content, "**Evidence:**")?;
            writeln!(content, "```rust")?;
            for ev in finding.evidence.iter().take(8) {
                writeln!(content, "{}", ev.trim())?;
            }
            writeln!(content, "```")?;
        }
        writeln!(&mut content)?;
        writeln!(content, "---")?;
        writeln!(&mut content)?;
    }

    // ===== OUTPUT VERIFICATION =====
    writeln!(content, "## Step 6: Output Verification")?;
    writeln!(&mut content)?;
    writeln!(content, "Before delivering the report:")?;
    writeln!(
        content,
        "- Re-read your draft and highlight every code/file reference."
    )?;
    writeln!(content, "- Confirm each path + line exists in the Findings table and the quoted snippet matches the provided Evidence block exactly (no invention or rewording).")?;
    writeln!(content, "- Ensure every Exploitable/Not exploitable statement agrees with the reachability table created in Step 2.")?;
    writeln!(content, "- If any reference cannot be tied back to the static findings, replace it with `Unknown – not present in static findings` and explain the gap instead of speculating.")?;
    writeln!(&mut content)?;

    // ===== FINAL REMINDERS =====
    writeln!(content, "## Final Checklist")?;
    writeln!(&mut content)?;
    writeln!(content, "Before submitting your report, verify:")?;
    writeln!(&mut content)?;
    writeln!(
        content,
        "- [ ] **CRITICAL: Every code snippet was read from actual source files, NOT synthesized**"
    )?;
    writeln!(content, "- [ ] **CRITICAL: Line numbers verified against source - finding exists at reported location**")?;
    writeln!(
        content,
        "- [ ] All test/example/benchmark code findings dismissed with evidence"
    )?;
    writeln!(
        content,
        "- [ ] Each true positive has reachability classification"
    )?;
    writeln!(content, "- [ ] **CRITICAL: Each AUTHENTICATED claim has evidence (middleware location, no bypass flags)**")?;
    writeln!(
        content,
        "- [ ] **CRITICAL: Auth bypass flags (--without-auth, etc.) documented if they exist**"
    )?;
    writeln!(
        content,
        "- [ ] Each true positive has impact type (RCE/INJ/DOS/etc.)"
    )?;
    writeln!(
        content,
        "- [ ] Severity reflects reachability, not just base CVSS"
    )?;
    writeln!(content, "- [ ] Remediation includes compilable code fixes")?;
    writeln!(content, "- [ ] Executive summary is 2-3 sentences max")?;
    writeln!(
        content,
        "- [ ] Roadmap has clear priorities and effort estimates"
    )?;
    writeln!(&mut content)?;

    Ok(content)
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
    scan_config: &ScanConfigSnapshot,
) -> Result<()> {
    let content = build_llm_prompt_content(
        project_name,
        findings,
        audit_vulns,
        Some(path),
        true,
        None,
        Some(scan_config),
    )?;

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut file =
        File::create(path).with_context(|| format!("create LLM prompt at {}", path.display()))?;
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
        if file.contains("/example") {
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
        if ev_lower.contains("const ")
            && (ev_lower.contains("\"select") || ev_lower.contains("\"insert"))
        {
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
        if file.contains("/example") {
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

    let rule = rules.iter().find(|r| r.id == finding.rule_id);
    let rule_name = rule.map(|r| r.name.as_str()).unwrap_or("unknown");

    writeln!(
        content,
        "### {}. {} - {} [{:?}]",
        index, finding.rule_id, rule_name, finding.severity
    )?;
    writeln!(content)?;

    // Location
    if let Some(span) = &finding.span {
        writeln!(content, "**Location:** {}:{}", span.file, span.start_line)?;
    }
    writeln!(content, "**Function:** {}", finding.function)?;

    // CWE if available
    if !finding.cwe_ids.is_empty() {
        writeln!(content, "**CWE:** {}", finding.cwe_ids.join(", "))?;
    }

    // Confidence
    writeln!(content, "**Confidence:** {:?}", finding.confidence)?;
    writeln!(content)?;

    writeln!(content, "**Issue:** {}", finding.message)?;
    writeln!(content)?;

    // Fix suggestion if available
    if let Some(fix) = &finding.fix_suggestion {
        writeln!(content, "**Fix:** {}", fix)?;
        writeln!(content)?;
    }

    // Evidence (simplified)
    if !finding.evidence.is_empty() {
        writeln!(content, "**Evidence:**")?;
        writeln!(content, "```")?;
        for ev in finding.evidence.iter().take(4) {
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
            if tz_lower.contains("pst")
                || tz_lower.contains("pacific")
                || tz_lower.contains("los_angeles")
            {
                Some(-8)
            } else if tz_lower.contains("mst")
                || tz_lower.contains("mountain")
                || tz_lower.contains("denver")
            {
                Some(-7)
            } else if tz_lower.contains("cst")
                || tz_lower.contains("central")
                || tz_lower.contains("chicago")
            {
                Some(-6)
            } else if tz_lower.contains("est")
                || tz_lower.contains("eastern")
                || tz_lower.contains("new_york")
            {
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
        let rule_name = rules
            .iter()
            .find(|r| r.id == rule_id)
            .map(|r| r.name.as_str())
            .unwrap_or("unknown");

        let (fp_rate, notes) = get_rule_fp_estimate(rule_id);
        let fp_str = fp_rate
            .map(|r| format!("~{}%", r))
            .unwrap_or_else(|| "N/A".to_string());

        writeln!(
            content,
            "| {} | {} | {} | {} | {} |",
            rule_id, rule_name, count, fp_str, notes
        )?;
    }
    writeln!(content)?;

    Ok(())
}

/// Represents a vulnerability found by cargo-audit
#[derive(Debug, Clone)]
struct AuditVulnerability {
    id: String,      // RUSTSEC-XXXX-XXXX
    package: String, // affected crate name
    version: String, // installed version
    title: String,   // vulnerability title
    severity: Option<String>,
    url: Option<String>,
}

/// Run cargo-audit and return parsed vulnerabilities
fn run_cargo_audit(crate_path: &Path) -> Result<Vec<AuditVulnerability>> {
    use std::process::Command;

    // Check if cargo-audit is installed
    let check = Command::new("cargo").args(["audit", "--version"]).output();

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
    let json: Value =
        serde_json::from_str(&stdout).context("failed to parse cargo-audit JSON output")?;

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

// ============================================================================
// AST Extraction and Output
// ============================================================================

/// Represents the AST for an entire workspace (multiple crates)
#[derive(Clone, Debug, Serialize)]
struct WorkspaceAst {
    workspace_root: String,
    packages: Vec<AstPackage>,
}

/// Represents the AST package for a crate
#[derive(Clone, Debug, Serialize)]
struct AstPackage {
    crate_name: String,
    files: Vec<AstFile>,
}

/// Represents a single source file's AST
#[derive(Clone, Debug, Serialize)]
struct AstFile {
    path: String,
    items: Vec<AstItem>,
}

/// Simplified AST item representation
#[derive(Clone, Debug, Serialize)]
struct AstItem {
    kind: String,
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    visibility: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    attributes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
}

/// Collect AST from all source files in a crate
fn collect_ast_package(crate_root: &Path, crate_name: &str) -> Result<AstPackage> {
    use walkdir::WalkDir;

    let mut files = Vec::new();

    for entry in WalkDir::new(crate_root)
        .into_iter()
        .filter_entry(|e| {
            let file_name = e.file_name().to_string_lossy();
            !file_name.starts_with('.') && file_name != "target" && file_name != "out"
        })
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            if let Some(ext) = entry.path().extension() {
                if ext == "rs" {
                    if let Ok(ast_file) = parse_ast_file(entry.path(), crate_root) {
                        files.push(ast_file);
                    }
                }
            }
        }
    }

    Ok(AstPackage {
        crate_name: crate_name.to_string(),
        files,
    })
}

/// Parse a single source file into AST items
fn parse_ast_file(path: &Path, crate_root: &Path) -> Result<AstFile> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;

    let syntax =
        syn::parse_file(&content).with_context(|| format!("Failed to parse {}", path.display()))?;

    let relative_path = path
        .strip_prefix(crate_root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();

    let items: Vec<AstItem> = syntax
        .items
        .iter()
        .filter_map(|item| extract_ast_item(item))
        .collect();

    Ok(AstFile {
        path: relative_path,
        items,
    })
}

/// Extract simplified AST item information
fn extract_ast_item(item: &syn::Item) -> Option<AstItem> {
    use syn::*;

    let (kind, name, visibility, signature) = match item {
        Item::Fn(f) => (
            "function".to_string(),
            Some(f.sig.ident.to_string()),
            Some(vis_to_string(&f.vis)),
            Some(format!("fn {}({})", f.sig.ident, format_fn_args(&f.sig))),
        ),
        Item::Struct(s) => (
            "struct".to_string(),
            Some(s.ident.to_string()),
            Some(vis_to_string(&s.vis)),
            None,
        ),
        Item::Enum(e) => (
            "enum".to_string(),
            Some(e.ident.to_string()),
            Some(vis_to_string(&e.vis)),
            None,
        ),
        Item::Trait(t) => (
            "trait".to_string(),
            Some(t.ident.to_string()),
            Some(vis_to_string(&t.vis)),
            None,
        ),
        Item::Impl(i) => (
            "impl".to_string(),
            i.trait_.as_ref().map(|(_, path, _)| {
                path.segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default()
            }),
            None,
            Some(format!("impl {}", type_to_string(&i.self_ty))),
        ),
        Item::Mod(m) => (
            "mod".to_string(),
            Some(m.ident.to_string()),
            Some(vis_to_string(&m.vis)),
            None,
        ),
        Item::Use(u) => ("use".to_string(), None, Some(vis_to_string(&u.vis)), None),
        Item::Const(c) => (
            "const".to_string(),
            Some(c.ident.to_string()),
            Some(vis_to_string(&c.vis)),
            None,
        ),
        Item::Static(s) => (
            "static".to_string(),
            Some(s.ident.to_string()),
            Some(vis_to_string(&s.vis)),
            None,
        ),
        Item::Type(t) => (
            "type".to_string(),
            Some(t.ident.to_string()),
            Some(vis_to_string(&t.vis)),
            None,
        ),
        Item::Macro(m) => (
            "macro".to_string(),
            m.ident.as_ref().map(|i| i.to_string()),
            None,
            None,
        ),
        _ => return None,
    };

    let attributes: Vec<String> = match item {
        Item::Fn(f) => extract_attrs(&f.attrs),
        Item::Struct(s) => extract_attrs(&s.attrs),
        Item::Enum(e) => extract_attrs(&e.attrs),
        Item::Trait(t) => extract_attrs(&t.attrs),
        Item::Impl(i) => extract_attrs(&i.attrs),
        Item::Mod(m) => extract_attrs(&m.attrs),
        _ => Vec::new(),
    };

    Some(AstItem {
        kind,
        name,
        visibility,
        attributes,
        signature,
    })
}

fn vis_to_string(vis: &syn::Visibility) -> String {
    match vis {
        syn::Visibility::Public(_) => "pub".to_string(),
        syn::Visibility::Restricted(r) => format!("pub({})", quote::quote!(#r).to_string()),
        syn::Visibility::Inherited => "private".to_string(),
    }
}

fn format_fn_args(sig: &syn::Signature) -> String {
    sig.inputs
        .iter()
        .map(|arg| match arg {
            syn::FnArg::Receiver(r) => if r.reference.is_some() {
                if r.mutability.is_some() {
                    "&mut self"
                } else {
                    "&self"
                }
            } else {
                "self"
            }
            .to_string(),
            syn::FnArg::Typed(t) => {
                format!("{}: {}", quote::quote!(#t.pat), quote::quote!(#t.ty))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn type_to_string(ty: &syn::Type) -> String {
    quote::quote!(#ty).to_string()
}

fn extract_attrs(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter_map(|attr| attr.path().get_ident().map(|i| i.to_string()))
        .collect()
}

/// Write AST package to JSON file
fn write_ast_json(path: &Path, ast_package: &AstPackage) -> Result<()> {
    let json = serde_json::to_string_pretty(ast_package).context("serialize AST package")?;
    fs::write(path, json).with_context(|| format!("write AST JSON to {}", path.display()))?;
    Ok(())
}

/// Write workspace AST (multiple crates) to JSON file
fn write_workspace_ast_json(path: &Path, workspace_ast: &WorkspaceAst) -> Result<()> {
    let json = serde_json::to_string_pretty(workspace_ast).context("serialize workspace AST")?;
    fs::write(path, json)
        .with_context(|| format!("write workspace AST JSON to {}", path.display()))?;
    Ok(())
}

/// Manifest describing all generated artifacts from a scan
#[derive(Clone, Debug, Serialize)]
struct Manifest {
    /// Rust-cola version
    version: String,
    /// Timestamp of scan completion (ISO 8601)
    timestamp: String,
    /// Target crate or workspace path
    target: String,
    /// Number of functions analyzed
    functions_analyzed: usize,
    /// Number of findings
    findings_count: usize,
    /// Generated artifact paths (relative to out_dir)
    artifacts: ManifestArtifacts,
}

#[derive(Clone, Debug, Serialize)]
struct ManifestArtifacts {
    mir_json: String,
    findings_json: String,
    sarif: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ast_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hir_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    llm_prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<String>,
}

/// Write manifest.json describing all generated artifacts
fn write_manifest(
    out_dir: &Path,
    target: &str,
    functions_analyzed: usize,
    findings_count: usize,
    mir_json: &Path,
    findings_json: &Path,
    sarif: &Path,
    ast_json: Option<&Path>,
    hir_json: Option<&Path>,
    llm_prompt: Option<&Path>,
    report: Option<&Path>,
) -> Result<()> {
    let manifest = Manifest {
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        target: target.to_string(),
        functions_analyzed,
        findings_count,
        artifacts: ManifestArtifacts {
            mir_json: path_to_relative(mir_json, out_dir),
            findings_json: path_to_relative(findings_json, out_dir),
            sarif: path_to_relative(sarif, out_dir),
            ast_json: ast_json.map(|p| path_to_relative(p, out_dir)),
            hir_json: hir_json.map(|p| path_to_relative(p, out_dir)),
            llm_prompt: llm_prompt.map(|p| path_to_relative(p, out_dir)),
            report: report.map(|p| path_to_relative(p, out_dir)),
        },
    };

    let manifest_path = out_dir.join("manifest.json");
    let json = serde_json::to_string_pretty(&manifest).context("serialize manifest")?;
    fs::write(&manifest_path, json)
        .with_context(|| format!("write manifest to {}", manifest_path.display()))?;
    Ok(())
}

/// Convert absolute path to relative (from out_dir), or filename if outside
fn path_to_relative(path: &Path, out_dir: &Path) -> String {
    path.strip_prefix(out_dir)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| {
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        })
}

fn print_rules_inventory(engine: &RuleEngine) {
    let mut metadata = engine.rule_metadata();
    metadata.sort_by(|a, b| a.id.cmp(&b.id));

    println!(
        "cargo-cola ships with {} available rules (built-ins plus loaded rulepacks).",
        metadata.len()
    );
    println!("| ID | Name | Severity | Description |");
    println!("|-----|------|----------|-------------|");

    for meta in metadata {
        println!(
            "| {} | {} | {:?} | {} |",
            meta.id,
            meta.name,
            meta.default_severity,
            escape_markdown_pipes(&meta.short_description)
        );
    }
}

fn escape_markdown_pipes(text: &str) -> String {
    text.replace('|', "\\|")
}
