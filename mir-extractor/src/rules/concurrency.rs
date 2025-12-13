//! Concurrency safety rules.
//!
//! Rules detecting concurrency issues:
//! - Mutex guard held across await (RUSTCOLA094)
//! - Blocking operations in async context (RUSTCOLA037, RUSTCOLA093)
//! - Unsafe Send/Sync bounds (RUSTCOLA015)
//! - Non-thread-safe test patterns (RUSTCOLA074)

use crate::{Finding, MirFunction, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};
use super::filter_entry;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

// ============================================================================
// RUSTCOLA074: Non-Thread-Safe Test Rule
// ============================================================================

/// Detects test functions that use non-thread-safe types like Rc, RefCell,
/// Cell, or raw pointers in ways that could cause issues when tests run in parallel.
pub struct NonThreadSafeTestRule {
    metadata: RuleMetadata,
}

impl NonThreadSafeTestRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA074".to_string(),
                name: "non-thread-safe-test".to_string(),
                short_description: "Test function uses non-thread-safe types".to_string(),
                full_description: "Detects test functions that use non-thread-safe types like Rc, RefCell, \
                    Cell, or raw pointers in ways that could cause issues when tests run in parallel. \
                    The Rust test framework runs tests concurrently by default, and using !Send or !Sync \
                    types with shared state (like static variables) can lead to data races or undefined \
                    behavior. Consider using thread-safe alternatives (Arc, Mutex, AtomicCell) or marking \
                    tests that require serialization with #[serial].".to_string(),
                help_uri: Some("https://doc.rust-lang.org/book/ch16-04-extensible-concurrency-sync-and-send.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Non-Send/Sync type patterns
    fn non_thread_safe_patterns() -> &'static [&'static str] {
        &[
            "Rc<",
            "Rc::",
            "RefCell<",
            "RefCell::",
            "Cell<",
            "Cell::",
            "UnsafeCell<",
            "UnsafeCell::",
            "*const ",
            "*mut ",
        ]
    }

    /// Check if function name indicates it's a test
    fn is_test_function(name: &str, signature: &str) -> bool {
        let looks_like_test_name = name.contains("::test_") || 
            name.starts_with("test_") ||
            name.contains("::tests::") ||
            name.ends_with("_test");

        let no_params = signature.contains("fn()") || 
            signature.contains("fn ()") ||
            (signature.contains('(') && signature.contains("()"));

        looks_like_test_name && no_params
    }

    /// Check if function body uses non-thread-safe types
    fn uses_non_thread_safe_types(body: &[String]) -> Vec<String> {
        let mut evidence = Vec::new();
        let patterns = Self::non_thread_safe_patterns();

        for line in body {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }

            for pattern in patterns {
                if trimmed.contains(pattern) {
                    evidence.push(trimmed.to_string());
                    break;
                }
            }
        }

        evidence
    }

    /// Check if test accesses static/global state
    fn accesses_static_state(body: &[String]) -> bool {
        body.iter().any(|line| {
            let trimmed = line.trim();
            trimmed.contains("static ") ||
            trimmed.contains("lazy_static!") ||
            trimmed.contains("thread_local!") ||
            trimmed.contains("GLOBAL") ||
            trimmed.contains("STATE")
        })
    }
}

impl Rule for NonThreadSafeTestRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if !Self::is_test_function(&function.name, &function.signature) {
                continue;
            }

            let non_thread_safe_usage = Self::uses_non_thread_safe_types(&function.body);
            
            if !non_thread_safe_usage.is_empty() {
                let severity = if Self::accesses_static_state(&function.body) {
                    Severity::High
                } else {
                    self.metadata.default_severity
                };

                let limited_evidence: Vec<_> = non_thread_safe_usage.into_iter().take(5).collect();

                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity,
                    message: format!(
                        "Test function `{}` uses non-thread-safe types (Rc, RefCell, Cell, raw pointers). \
                        Tests run in parallel by default; consider using thread-safe alternatives or #[serial].",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: limited_evidence,
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA037: Blocking Sleep in Async Rule
// ============================================================================

/// Detects std::thread::sleep and other blocking sleep calls inside async functions.
pub struct BlockingSleepInAsyncRule {
    metadata: RuleMetadata,
}

impl BlockingSleepInAsyncRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA037".to_string(),
                name: "blocking-sleep-in-async".to_string(),
                short_description: "Blocking sleep in async function".to_string(),
                full_description: "Detects std::thread::sleep and other blocking sleep calls inside async functions. \
                    Blocking sleep in async contexts can stall the executor and prevent other tasks from running, \
                    potentially causing denial-of-service. Use async sleep (tokio::time::sleep, async_std::task::sleep, etc.) instead.".to_string(),
                help_uri: Some("https://www.jetbrains.com/help/inspectopedia/RsSleepInsideAsyncFunction.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn blocking_sleep_patterns() -> &'static [&'static str] {
        &[
            "std::thread::sleep",
            "thread::sleep",
            "::thread::sleep",
        ]
    }
}

impl Rule for BlockingSleepInAsyncRule {
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
            if path.extension() != Some(OsStr::new("rs")) {
                continue;
            }

            let rel_path = path
                .strip_prefix(crate_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let lines: Vec<&str> = content.lines().collect();

            let mut in_async_fn = false;
            let mut async_fn_start = 0;
            let mut brace_depth = 0;
            let mut async_fn_name = String::new();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("async fn ") {
                    in_async_fn = true;
                    async_fn_start = idx;
                    brace_depth = 0;

                    if let Some(fn_pos) = trimmed.find("fn ") {
                        let after_fn = &trimmed[fn_pos + 3..];
                        if let Some(paren_pos) = after_fn.find('(') {
                            async_fn_name = after_fn[..paren_pos].trim().to_string();
                        }
                    }
                }

                if in_async_fn {
                    brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                    for pattern in Self::blocking_sleep_patterns() {
                        if trimmed.contains(pattern) {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Blocking sleep in async function `{}` can stall executor",
                                    async_fn_name
                                ),
                                function: location,
                                function_signature: async_fn_name.clone(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                            });
                        }
                    }

                    if brace_depth <= 0 && idx > async_fn_start {
                        in_async_fn = false;
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA093: Blocking Operations in Async Rule
// ============================================================================

/// Detects blocking operations inside async functions that can stall the async executor.
pub struct BlockingOpsInAsyncRule {
    metadata: RuleMetadata,
}

impl BlockingOpsInAsyncRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA093".to_string(),
                name: "blocking-ops-in-async".to_string(),
                short_description: "Blocking operation in async function".to_string(),
                full_description: "Detects blocking operations inside async functions that can stall the async executor. \
                    This includes std::sync::Mutex::lock(), std::fs::* operations, std::net::* operations, and blocking I/O. \
                    These operations block the current thread, preventing the async runtime from executing other tasks. \
                    Use async alternatives (tokio::sync::Mutex, tokio::fs, tokio::net) or wrap blocking ops in spawn_blocking/block_in_place.".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Blocking patterns to detect with their categories
    fn blocking_patterns() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            // Pattern, Category, Recommendation
            (".lock().unwrap()", "sync_mutex", "Use tokio::sync::Mutex::lock().await instead"),
            (".lock().expect(", "sync_mutex", "Use tokio::sync::Mutex::lock().await instead"),
            ("mutex.lock()", "sync_mutex", "Use tokio::sync::Mutex::lock().await instead"),
            ("fs::read_to_string(", "blocking_fs", "Use tokio::fs::read_to_string().await instead"),
            ("fs::read(", "blocking_fs", "Use tokio::fs::read().await instead"),
            ("fs::write(", "blocking_fs", "Use tokio::fs::write().await instead"),
            ("fs::remove_file(", "blocking_fs", "Use tokio::fs::remove_file().await instead"),
            ("fs::create_dir(", "blocking_fs", "Use tokio::fs::create_dir().await instead"),
            ("fs::create_dir_all(", "blocking_fs", "Use tokio::fs::create_dir_all().await instead"),
            ("fs::metadata(", "blocking_fs", "Use tokio::fs::metadata().await instead"),
            ("fs::File::open(", "blocking_fs", "Use tokio::fs::File::open().await instead"),
            ("fs::File::create(", "blocking_fs", "Use tokio::fs::File::create().await instead"),
            ("File::open(", "blocking_fs", "Use tokio::fs::File::open().await instead"),
            ("File::create(", "blocking_fs", "Use tokio::fs::File::create().await instead"),
            ("TcpStream::connect(", "blocking_net", "Use tokio::net::TcpStream::connect().await instead"),
            ("TcpListener::bind(", "blocking_net", "Use tokio::net::TcpListener::bind().await instead"),
            ("UdpSocket::bind(", "blocking_net", "Use tokio::net::UdpSocket::bind().await instead"),
            ("stdin().read_line(", "blocking_io", "Use tokio::io::stdin() with AsyncBufReadExt instead"),
            ("stdin().read(", "blocking_io", "Use tokio::io::stdin() with AsyncReadExt instead"),
            ("reqwest::blocking::", "blocking_http", "Use reqwest async API (reqwest::get, Client::new()) instead"),
        ]
    }

    /// Patterns that indicate the blocking op is wrapped safely
    fn safe_wrappers() -> &'static [&'static str] {
        &[
            "spawn_blocking",
            "block_in_place",
            "tokio::task::spawn_blocking",
            "tokio::task::block_in_place",
            "actix_web::web::block",
        ]
    }
}

impl Rule for BlockingOpsInAsyncRule {
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
            if path.extension() != Some(OsStr::new("rs")) {
                continue;
            }

            let rel_path = path
                .strip_prefix(crate_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let lines: Vec<&str> = content.lines().collect();

            let mut in_async_fn = false;
            let mut async_fn_start = 0;
            let mut brace_depth = 0;
            let mut async_fn_name = String::new();
            let mut in_safe_wrapper = false;
            let mut safe_wrapper_depth = 0;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("async fn ") || trimmed.contains("async move") {
                    if trimmed.contains("async fn ") {
                        in_async_fn = true;
                        async_fn_start = idx;
                        brace_depth = 0;

                        if let Some(fn_pos) = trimmed.find("fn ") {
                            let after_fn = &trimmed[fn_pos + 3..];
                            if let Some(paren_pos) = after_fn.find('(') {
                                async_fn_name = after_fn[..paren_pos].trim().to_string();
                            }
                        }
                    }
                }

                if in_async_fn {
                    for wrapper in Self::safe_wrappers() {
                        if trimmed.contains(wrapper) {
                            in_safe_wrapper = true;
                            safe_wrapper_depth = brace_depth;
                        }
                    }

                    brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                    if in_safe_wrapper && brace_depth <= safe_wrapper_depth {
                        in_safe_wrapper = false;
                    }

                    if in_safe_wrapper {
                        if brace_depth <= 0 && idx > async_fn_start {
                            in_async_fn = false;
                        }
                        continue;
                    }

                    for (pattern, category, recommendation) in Self::blocking_patterns() {
                        if trimmed.contains(pattern) {
                            if trimmed.contains(".await") || trimmed.contains("tokio::") {
                                continue;
                            }
                            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                                continue;
                            }

                            let fn_content: String = lines[async_fn_start..=idx]
                                .iter()
                                .copied()
                                .collect::<Vec<&str>>()
                                .join("\n");
                            if fn_content.contains("tokio::sync::Mutex") && pattern.contains(".lock") {
                                continue;
                            }

                            let location = format!("{}:{}", rel_path, idx + 1);
                            let message = match category {
                                "sync_mutex" => format!(
                                    "Blocking std::sync::Mutex in async function `{}`. {}",
                                    async_fn_name, recommendation
                                ),
                                "blocking_fs" => format!(
                                    "Blocking filesystem operation in async function `{}`. {}",
                                    async_fn_name, recommendation
                                ),
                                "blocking_net" => format!(
                                    "Blocking network operation in async function `{}`. {}",
                                    async_fn_name, recommendation
                                ),
                                "blocking_io" => format!(
                                    "Blocking I/O in async function `{}`. {}",
                                    async_fn_name, recommendation
                                ),
                                "blocking_http" => format!(
                                    "Blocking HTTP client in async function `{}`. {}",
                                    async_fn_name, recommendation
                                ),
                                _ => format!(
                                    "Blocking operation in async function `{}`",
                                    async_fn_name
                                ),
                            };

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message,
                                function: location,
                                function_signature: async_fn_name.clone(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                            });
                        }
                    }

                    if brace_depth <= 0 && idx > async_fn_start {
                        in_async_fn = false;
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA094: Mutex Guard Across Await Rule
// ============================================================================

/// Detects MutexGuard/RwLockGuard held across await points which can cause deadlocks.
pub struct MutexGuardAcrossAwaitRule {
    metadata: RuleMetadata,
}

impl MutexGuardAcrossAwaitRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA094".to_string(),
                name: "mutex-guard-across-await".to_string(),
                short_description: "MutexGuard held across await point".to_string(),
                full_description: "Holding a std::sync::MutexGuard or RwLockGuard across an .await point can cause deadlocks. \
                    When the async task yields, another task on the same thread may try to acquire the same lock, \
                    leading to deadlock. Use tokio::sync::Mutex or drop the guard before awaiting.".to_string(),
                help_uri: Some("https://rust-lang.github.io/rust-clippy/master/index.html#await_holding_lock".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn guard_patterns() -> &'static [(&'static str, &'static str)] {
        &[
            (".lock().unwrap()", "MutexGuard"),
            (".lock().expect(", "MutexGuard"),
            (".lock()?", "MutexGuard"),
            (".read().unwrap()", "RwLockReadGuard"),
            (".read().expect(", "RwLockReadGuard"),
            (".read()?", "RwLockReadGuard"),
            (".write().unwrap()", "RwLockWriteGuard"),
            (".write().expect(", "RwLockWriteGuard"),
            (".write()?", "RwLockWriteGuard"),
        ]
    }

    fn safe_guard_patterns() -> &'static [&'static str] {
        &[
            "tokio::sync::Mutex",
            "tokio::sync::RwLock",
            "async_std::sync::Mutex",
            "async_std::sync::RwLock",
            "futures::lock::Mutex",
        ]
    }
}

impl Rule for MutexGuardAcrossAwaitRule {
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
            if path.extension() != Some(OsStr::new("rs")) {
                continue;
            }

            let rel_path = path
                .strip_prefix(crate_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let lines: Vec<&str> = content.lines().collect();

            let mut in_async_fn = false;
            let mut async_fn_start = 0;
            let mut brace_depth = 0;
            let mut async_fn_name = String::new();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.contains("async fn ") || trimmed.contains("async move") {
                    if trimmed.contains("async fn ") {
                        in_async_fn = true;
                        async_fn_start = idx;
                        brace_depth = 0;

                        if let Some(fn_pos) = trimmed.find("fn ") {
                            let after_fn = &trimmed[fn_pos + 3..];
                            if let Some(paren_pos) = after_fn.find('(') {
                                async_fn_name = after_fn[..paren_pos].trim().to_string();
                            }
                        }
                    }
                }

                if in_async_fn {
                    brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                    for (pattern, guard_type) in Self::guard_patterns() {
                        if trimmed.contains(pattern) {
                            if trimmed.contains(".await") {
                                continue;
                            }
                            if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("/*") {
                                continue;
                            }

                            let fn_content: String = lines[async_fn_start..=std::cmp::min(idx + 50, lines.len() - 1)]
                                .iter()
                                .copied()
                                .collect::<Vec<&str>>()
                                .join("\n");

                            let uses_async_mutex = Self::safe_guard_patterns()
                                .iter()
                                .any(|p| fn_content.contains(p));
                            if uses_async_mutex {
                                continue;
                            }

                            let mut inner_brace_depth = 0;
                            let mut has_await_after = false;
                            let mut await_line = 0;

                            for (later_idx, later_line) in lines[idx..].iter().enumerate() {
                                let later_trimmed = later_line.trim();
                                inner_brace_depth += later_trimmed.chars().filter(|&c| c == '{').count() as i32;
                                inner_brace_depth -= later_trimmed.chars().filter(|&c| c == '}').count() as i32;

                                if later_trimmed.contains("drop(") {
                                    break;
                                }

                                if later_idx > 0 && later_trimmed.contains(".await") {
                                    has_await_after = true;
                                    await_line = idx + later_idx + 1;
                                    break;
                                }

                                if inner_brace_depth < 0 {
                                    break;
                                }

                                if later_idx > 30 {
                                    break;
                                }
                            }

                            if has_await_after {
                                let location = format!("{}:{}", rel_path, idx + 1);
                                findings.push(Finding {
                                    rule_id: self.metadata.id.clone(),
                                    rule_name: self.metadata.name.clone(),
                                    severity: self.metadata.default_severity,
                                    message: format!(
                                        "{} held across .await in async function `{}` (line {}). \
                                        This can cause deadlocks. Drop the guard before awaiting or use tokio::sync::Mutex.",
                                        guard_type, async_fn_name, await_line
                                    ),
                                    function: location,
                                    function_signature: async_fn_name.clone(),
                                    evidence: vec![trimmed.to_string()],
                                    span: None,
                                });
                            }
                        }
                    }

                    if brace_depth <= 0 && idx > async_fn_start {
                        in_async_fn = false;
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// Registration
// ============================================================================

/// Register all concurrency rules with the rule engine.
pub fn register_concurrency_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(NonThreadSafeTestRule::new()));
    engine.register_rule(Box::new(BlockingSleepInAsyncRule::new()));
    engine.register_rule(Box::new(BlockingOpsInAsyncRule::new()));
    engine.register_rule(Box::new(MutexGuardAcrossAwaitRule::new()));
}
