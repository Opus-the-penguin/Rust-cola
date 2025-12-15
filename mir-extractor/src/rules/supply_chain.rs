//! Supply chain security rules.
//!
//! Rules detecting supply chain vulnerabilities:
//! - RUSTSEC advisory dependencies
//! - Yanked crate versions
//! - Cargo auditable metadata
//! - Proc-macro side effects

use crate::{Finding, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};
use semver::{Version, VersionReq};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

use super::utils::filter_entry;

// ============================================================================
// RUSTCOLA018: RUSTSEC Unsound Dependency Rule
// ============================================================================

struct UnsoundAdvisory {
    crate_name: &'static str,
    version_req: &'static str,
    advisory_id: &'static str,
    summary: &'static str,
}

/// Detects dependencies with known RUSTSEC advisories.
pub struct RustsecUnsoundDependencyRule {
    metadata: RuleMetadata,
}

impl RustsecUnsoundDependencyRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA018".to_string(),
                name: "rustsec-unsound-dependency".to_string(),
                short_description: "Dependency has known RUSTSEC advisory".to_string(),
                full_description: "Detects dependencies that have known soundness issues documented in RUSTSEC advisories.".to_string(),
                help_uri: Some("https://rustsec.org/".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn advisories() -> &'static [UnsoundAdvisory] {
        &[
            UnsoundAdvisory {
                crate_name: "arrayvec",
                version_req: "<= 0.4.10",
                advisory_id: "RUSTSEC-2018-0001",
                summary: "arrayvec::ArrayVec::insert can cause memory corruption",
            },
            UnsoundAdvisory {
                crate_name: "time",
                version_req: "< 0.2.23",
                advisory_id: "RUSTSEC-2020-0071",
                summary: "Potential segfault in localtime_r",
            },
            UnsoundAdvisory {
                crate_name: "crossbeam-deque",
                version_req: "< 0.7.4",
                advisory_id: "RUSTSEC-2021-0093",
                summary: "Race condition may result in double-free",
            },
            UnsoundAdvisory {
                crate_name: "owning_ref",
                version_req: "< 0.4.2",
                advisory_id: "RUSTSEC-2022-0044",
                summary: "Unsound StableAddress impl",
            },
            UnsoundAdvisory {
                crate_name: "smallvec",
                version_req: "< 1.10.0",
                advisory_id: "RUSTSEC-2021-0009",
                summary: "SmallVec::insert_many can cause memory exposure",
            },
            UnsoundAdvisory {
                crate_name: "fixedbitset",
                version_req: "< 0.4.0",
                advisory_id: "RUSTSEC-2019-0003",
                summary: "FixedBitSet::insert unsound aliasing",
            },
        ]
    }

    fn advisory_matches(advisory: &UnsoundAdvisory, version: &Version) -> bool {
        VersionReq::parse(advisory.version_req)
            .ok()
            .map(|req| req.matches(version))
            .unwrap_or(false)
    }
}

impl Rule for RustsecUnsoundDependencyRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        let crate_root = Path::new(&package.crate_root);
        let lock_path = crate_root.join("Cargo.lock");

        if !lock_path.exists() {
            return findings;
        }

        let Ok(contents) = fs::read_to_string(&lock_path) else {
            return findings;
        };

        let Ok(doc) = toml::from_str::<toml::Value>(&contents) else {
            return findings;
        };

        let Some(packages) = doc.get("package").and_then(|value| value.as_array()) else {
            return findings;
        };

        let relative_lock = lock_path
            .strip_prefix(crate_root)
            .unwrap_or(&lock_path)
            .to_string_lossy()
            .replace('\\', "/");

        let mut emitted = HashSet::new();

        for pkg in packages {
            let Some(name) = pkg.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(version_str) = pkg.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            let Ok(version) = Version::parse(version_str) else {
                continue;
            };

            for advisory in Self::advisories() {
                if advisory.crate_name != name {
                    continue;
                }

                if !Self::advisory_matches(advisory, &version) {
                    continue;
                }

                let key = (
                    name.to_string(),
                    version_str.to_string(),
                    advisory.advisory_id,
                );
                if !emitted.insert(key) {
                    continue;
                }

                let evidence = vec![format!(
                    "{} {} matches {} ({})",
                    name, version_str, advisory.advisory_id, advisory.summary
                )];

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Dependency '{}' v{} is flagged unsound by advisory {}",
                        name, version_str, advisory.advisory_id
                    ),
                    function: relative_lock.clone(),
                    function_signature: format!("{} {}", name, version_str),
                    evidence,
                    span: None,
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA019: Yanked Crate Rule
// ============================================================================

struct YankedRelease {
    crate_name: &'static str,
    version: &'static str,
    reason: &'static str,
}

/// Detects dependencies pinned to yanked versions.
pub struct YankedCrateRule {
    metadata: RuleMetadata,
}

impl YankedCrateRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA019".to_string(),
                name: "yanked-crate-version".to_string(),
                short_description: "Dependency references a yanked crate version".to_string(),
                full_description: "Highlights crates pinned to versions that have been yanked from crates.io.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/cargo/reference/publishing.html#removing-a-version".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn releases() -> &'static [YankedRelease] {
        &[
            YankedRelease {
                crate_name: "memoffset",
                version: "0.5.6",
                reason: "Yanked due to soundness issue (RUSTSEC-2021-0119)",
            },
            YankedRelease {
                crate_name: "chrono",
                version: "0.4.19",
                reason: "Yanked pending security fixes",
            },
        ]
    }
}

impl Rule for YankedCrateRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        let crate_root = Path::new(&package.crate_root);
        let lock_path = crate_root.join("Cargo.lock");

        if !lock_path.exists() {
            return findings;
        }

        let Ok(contents) = fs::read_to_string(&lock_path) else {
            return findings;
        };

        let Ok(doc) = toml::from_str::<toml::Value>(&contents) else {
            return findings;
        };

        let Some(packages) = doc.get("package").and_then(|value| value.as_array()) else {
            return findings;
        };

        let relative_lock = lock_path
            .strip_prefix(crate_root)
            .unwrap_or(&lock_path)
            .to_string_lossy()
            .replace('\\', "/");

        let mut emitted = HashSet::new();

        for pkg in packages {
            let Some(name) = pkg.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(version) = pkg.get("version").and_then(|v| v.as_str()) else {
                continue;
            };

            for release in Self::releases() {
                if release.crate_name != name || release.version != version {
                    continue;
                }

                if !emitted.insert((name.to_string(), version.to_string())) {
                    continue;
                }

                let evidence = vec![format!("{}: {}", release.crate_name, release.reason)];

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Dependency '{}' v{} has been yanked: {}",
                        name, version, release.reason
                    ),
                    function: relative_lock.clone(),
                    function_signature: format!("{} {}", name, version),
                    evidence,
                    span: None,
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA020: Cargo Auditable Metadata Rule
// ============================================================================

/// Detects binary crates missing cargo-auditable metadata.
pub struct CargoAuditableMetadataRule {
    metadata: RuleMetadata,
}

impl CargoAuditableMetadataRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA020".to_string(),
                name: "cargo-auditable-metadata".to_string(),
                short_description: "Binary crate missing cargo auditable metadata".to_string(),
                full_description: "Detects binary crates that do not integrate cargo auditable metadata, encouraging projects to embed supply-chain provenance in release artifacts.".to_string(),
                help_uri: Some("https://github.com/rust-secure-code/cargo-auditable".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn read_manifest(crate_root: &Path) -> Option<toml::Value> {
        let manifest_path = crate_root.join("Cargo.toml");
        let contents = fs::read_to_string(manifest_path).ok()?;
        toml::from_str::<toml::Value>(&contents).ok()
    }

    fn is_workspace(manifest: &toml::Value) -> bool {
        manifest.get("workspace").is_some() && manifest.get("package").is_none()
    }

    fn is_binary_crate(manifest: &toml::Value, crate_root: &Path) -> bool {
        if Self::is_workspace(manifest) {
            return false;
        }

        if manifest
            .get("bin")
            .and_then(|value| value.as_array())
            .map(|arr| !arr.is_empty())
            .unwrap_or(false)
        {
            return true;
        }

        let src_main = crate_root.join("src").join("main.rs");
        if src_main.exists() {
            return true;
        }

        let bin_dir = crate_root.join("src").join("bin");
        if let Ok(entries) = fs::read_dir(&bin_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && path
                        .extension()
                        .and_then(OsStr::to_str)
                        .map_or(false, |ext| ext.eq_ignore_ascii_case("rs"))
                {
                    return true;
                }

                if path.is_dir() && path.join("main.rs").exists() {
                    return true;
                }
            }
        }

        false
    }

    fn metadata_skip(manifest: &toml::Value) -> bool {
        manifest
            .get("package")
            .and_then(|pkg| pkg.get("metadata"))
            .and_then(|metadata| match metadata {
                toml::Value::Table(table) => table.get("rust-cola"),
                _ => None,
            })
            .and_then(|rust_cola| match rust_cola {
                toml::Value::Table(table) => table.get("skip_auditable_check"),
                _ => None,
            })
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
    }

    fn has_auditable_markers(manifest: &toml::Value) -> bool {
        let marker_keys = ["auditable", "cargo-auditable"];

        let dep_tables = [
            manifest.get("dependencies"),
            manifest.get("dev-dependencies"),
            manifest.get("build-dependencies"),
        ];

        if dep_tables.iter().any(|value| match value {
            Some(toml::Value::Table(table)) => table
                .keys()
                .any(|key| marker_keys.iter().any(|mk| key.contains(mk))),
            _ => false,
        }) {
            return true;
        }

        if manifest
            .get("package")
            .and_then(|pkg| pkg.get("metadata"))
            .and_then(|metadata| match metadata {
                toml::Value::Table(table) => Some(table),
                _ => None,
            })
            .map(|metadata_table| {
                metadata_table.keys().any(|key| marker_keys.iter().any(|mk| key.contains(mk)))
                    || metadata_table.values().any(|value| matches!(value, toml::Value::Table(inner) if inner.keys().any(|k| k.contains("auditable"))))
            })
            .unwrap_or(false)
        {
            return true;
        }

        if let Some(toml::Value::Table(features)) = manifest.get("features") {
            if features.iter().any(|(key, value)| {
                key.contains("auditable")
                    || matches!(value, toml::Value::Array(items) if items.iter().any(|item| item.as_str().map_or(false, |s| s.contains("auditable"))))
            }) {
                return true;
            }
        }

        false
    }

    fn lockfile_mentions_auditable(crate_root: &Path) -> bool {
        let lock_path = crate_root.join("Cargo.lock");
        let Ok(contents) = fs::read_to_string(lock_path) else {
            return false;
        };

        contents.to_lowercase().contains("auditable")
    }

    fn ci_mentions_cargo_auditable(crate_root: &Path) -> bool {
        const MAX_ANCESTOR_SEARCH: usize = 5;

        for ancestor in crate_root.ancestors().take(MAX_ANCESTOR_SEARCH) {
            if Self::ci_markers_within(ancestor) {
                return true;
            }
        }

        false
    }

    fn ci_markers_within(base: &Path) -> bool {
        let search_dirs = [".github", ".gitlab", "ci", "scripts"];
        for dir in &search_dirs {
            let path = base.join(dir);
            if !path.exists() {
                continue;
            }

            for entry in WalkDir::new(&path)
                .max_depth(6)
                .into_iter()
                .filter_entry(|e| {
                    // Allow root entry
                    if e.depth() == 0 {
                        return true;
                    }
                    let name = e.file_name().to_string_lossy();
                    // Only filter out specific directories that aren't CI-related
                    if e.file_type().is_dir() {
                        return !matches!(name.as_ref(), "target" | ".git" | ".cola-cache" | "out" | "node_modules");
                    }
                    true
                })
            {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                if !entry.file_type().is_file() {
                    continue;
                }

                if let Ok(metadata) = entry.metadata() {
                    if metadata.len() > 512 * 1024 {
                        continue;
                    }
                }

                if fs::read_to_string(entry.path())
                    .map(|contents| contents.to_lowercase().contains("cargo auditable"))
                    .unwrap_or(false)
                {
                    return true;
                }
            }
        }

        let marker_files = ["Makefile", "makefile", "Justfile", "justfile"];
        for file in &marker_files {
            let path = base.join(file);
            if !path.exists() {
                continue;
            }

            if fs::read_to_string(&path)
                .map(|contents| contents.to_lowercase().contains("cargo auditable"))
                .unwrap_or(false)
            {
                return true;
            }
        }

        false
    }
}

impl Rule for CargoAuditableMetadataRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        let crate_root = Path::new(&package.crate_root);

        let Some(manifest) = Self::read_manifest(crate_root) else {
            return findings;
        };

        if !Self::is_binary_crate(&manifest, crate_root) {
            return findings;
        }

        if Self::metadata_skip(&manifest) {
            return findings;
        }

        if Self::has_auditable_markers(&manifest)
            || Self::lockfile_mentions_auditable(crate_root)
            || Self::ci_mentions_cargo_auditable(crate_root)
        {
            return findings;
        }

        let package_name = manifest
            .get("package")
            .and_then(|pkg| pkg.get("name"))
            .and_then(|name| name.as_str())
            .unwrap_or(&package.crate_name);

        let mut evidence = Vec::new();
        if crate_root.join("src").join("main.rs").exists() {
            evidence.push("Found src/main.rs binary entry point".to_string());
        }

        if crate_root.join("src").join("bin").exists() {
            evidence.push("Found src/bin directory indicating additional binaries".to_string());
        }

        if manifest
            .get("bin")
            .and_then(|value| value.as_array())
            .map(|arr| !arr.is_empty())
            .unwrap_or(false)
        {
            evidence.push("Cargo.toml defines [[bin]] targets".to_string());
        }

        evidence.push(
            "No cargo auditable dependency, metadata, lockfile entry, or CI integration detected"
                .to_string(),
        );

        let manifest_path = crate_root.join("Cargo.toml");
        let relative_manifest = manifest_path
            .strip_prefix(crate_root)
            .unwrap_or(&manifest_path)
            .to_string_lossy()
            .replace('\\', "/");

        findings.push(Finding {
            rule_id: self.metadata.id.clone(),
            rule_name: self.metadata.name.clone(),
            severity: self.metadata.default_severity,
            message: format!(
                "Binary crate '{}' is missing cargo auditable metadata; consider integrating cargo auditable builds",
                package_name
            ),
            function: relative_manifest,
            function_signature: package_name.to_string(),
            evidence,
            span: None,
        });

        findings
    }
}

// ============================================================================
// RUSTCOLA102: Proc-Macro Side Effects Rule
// ============================================================================

/// Detects proc-macro crates with potential side effects (filesystem, network access).
/// 
/// Proc-macros run at compile time with full system access. Malicious or compromised
/// proc-macros can exfiltrate data, download payloads, or modify the build.
pub struct ProcMacroSideEffectsRule {
    metadata: RuleMetadata,
}

impl ProcMacroSideEffectsRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA102".to_string(),
                name: "proc-macro-side-effects".to_string(),
                short_description: "Proc-macro with suspicious side effects".to_string(),
                full_description: "Detects proc-macro crates that use filesystem, network, or \
                    process APIs. Proc-macros execute at compile time with full system access, \
                    making them a supply chain attack vector. Patterns include: std::fs, \
                    std::net, std::process::Command, reqwest, and similar.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/reference/procedural-macros.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Suspicious patterns for proc-macros
    fn suspicious_patterns() -> &'static [(&'static str, &'static str)] {
        &[
            ("std::fs::", "filesystem access in proc-macro"),
            ("std::net::", "network access in proc-macro"),
            ("std::process::Command", "process spawning in proc-macro"),
            ("tokio::", "async runtime in proc-macro (unusual)"),
            ("reqwest::", "HTTP client in proc-macro"),
            ("hyper::", "HTTP library in proc-macro"),
            ("curl::", "curl bindings in proc-macro"),
            ("attohttpc::", "HTTP client in proc-macro"),
            ("ureq::", "HTTP client in proc-macro"),
            ("env!(", "environment variable access (may leak secrets)"),
            ("include_bytes!", "includes external file at compile time"),
            ("include_str!", "includes external file at compile time"),
        ]
    }
}

impl Rule for ProcMacroSideEffectsRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let crate_root = Path::new(&package.crate_root);

        if !crate_root.exists() {
            return findings;
        }

        // Check if this is a proc-macro crate
        let cargo_toml = crate_root.join("Cargo.toml");
        if !cargo_toml.exists() {
            return findings;
        }

        let cargo_content = match std::fs::read_to_string(&cargo_toml) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        // Only analyze proc-macro crates
        let is_proc_macro = cargo_content.contains("proc-macro = true") 
            || cargo_content.contains("proc_macro = true");
        
        if !is_proc_macro {
            return findings;
        }

        // Scan source files for suspicious patterns
        for entry in WalkDir::new(crate_root)
            .into_iter()
            .filter_entry(|e| filter_entry(e))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            if path.extension() != Some(std::ffi::OsStr::new("rs")) {
                continue;
            }

            let rel_path = path
                .strip_prefix(crate_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let lines: Vec<&str> = content.lines().collect();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                for (pattern, description) in Self::suspicious_patterns() {
                    if trimmed.contains(pattern) {
                        let location = format!("{}:{}", rel_path, idx + 1);

                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: format!(
                                "Suspicious {} in proc-macro crate. Proc-macros execute at \
                                compile time with full system access. This could be a supply \
                                chain attack vector. Review carefully.",
                                description
                            ),
                            function: location,
                            function_signature: String::new(),
                            evidence: vec![trimmed.to_string()],
                            span: None,
                        });
                    }
                }
            }
        }

        findings
    }
}

/// Register all supply chain rules with the rule engine.
pub fn register_supply_chain_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(RustsecUnsoundDependencyRule::new()));
    engine.register_rule(Box::new(YankedCrateRule::new()));
    engine.register_rule(Box::new(CargoAuditableMetadataRule::new()));
    engine.register_rule(Box::new(ProcMacroSideEffectsRule::new()));
}
