//! Concurrency safety rules.
//!
//! Rules detecting concurrency issues:
//! - Mutex guard held across await (RUSTCOLA094)
//! - Blocking operations in async context (RUSTCOLA037, RUSTCOLA093)
//! - Unsafe Send/Sync bounds (RUSTCOLA015)
//! - Non-thread-safe test patterns (RUSTCOLA074)
//! - Underscore lock guard (RUSTCOLA030)
//! - Broadcast unsync payload (RUSTCOLA023)
//! - Panic in Drop (RUSTCOLA040)
//! - Unwrap in Poll (RUSTCOLA041)

use crate::detect_broadcast_unsync_payloads;
use crate::{Finding, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity};
use super::filter_entry;
use super::utils::{StringLiteralState, strip_string_literals};
use std::collections::HashSet;
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
// RUSTCOLA030: Underscore Lock Guard Rule
// ============================================================================

/// Detects lock guards assigned to `_`, which immediately drops the guard.
pub struct UnderscoreLockGuardRule {
    metadata: RuleMetadata,
}

impl UnderscoreLockGuardRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA030".to_string(),
                name: "underscore-lock-guard".to_string(),
                short_description: "Lock guard immediately discarded via underscore binding".to_string(),
                full_description: "Detects lock guards (Mutex::lock, RwLock::read/write, etc.) assigned to `_`, which immediately drops the guard and releases the lock before the critical section executes, creating race conditions.".to_string(),
                help_uri: Some("https://rust-lang.github.io/rust-clippy/master/index.html#/let_underscore_lock".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn lock_method_patterns() -> &'static [&'static str] {
        &[
            "::lock(",
            "::read(",
            "::write(",
            "::try_lock(",
            "::try_read(",
            "::try_write(",
            "::blocking_lock(",
            "::blocking_read(",
            "::blocking_write(",
        ]
    }
}

impl Rule for UnderscoreLockGuardRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            // Step 1: Collect all MIR variables that have debug mappings
            // Variables with debug mappings are named bindings like "let guard = ..." or "let _guard = ..."
            // Variables WITHOUT debug mappings are wildcard patterns like "let _ = ..."
            let mut named_vars: HashSet<String> = HashSet::new();
            
            for line in &function.body {
                let trimmed = line.trim();
                // Pattern: "debug VAR_NAME => _N;"
                if trimmed.starts_with("debug ") && trimmed.contains(" => ") {
                    // Extract the _N part (MIR variable)
                    if let Some(arrow_pos) = trimmed.find(" => ") {
                        let var_part = trimmed[arrow_pos + 4..].trim().trim_end_matches(';').trim();
                        if var_part.starts_with('_') && var_part.chars().nth(1).map_or(false, |c| c.is_ascii_digit()) {
                            named_vars.insert(var_part.to_string());
                        }
                    }
                }
            }
            
            let body_lines: Vec<&str> = function.body.iter().map(|s| s.as_str()).collect();
            
            // Step 2: Find lock acquisitions and trace to guard type
            // Track: lock_result -> guard_var (via unwrap/expect) -> drop
            for (i, line) in body_lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Check if the RHS contains a lock acquisition
                let has_lock_call = Self::lock_method_patterns()
                    .iter()
                    .any(|pattern| trimmed.contains(pattern));

                if !has_lock_call {
                    continue;
                }
                
                // Parse the assignment: "_N = ..."
                if !trimmed.contains(" = ") {
                    continue;
                }
                
                let lock_result_var = trimmed.split(" = ").next()
                    .map(|s| s.trim())
                    .unwrap_or("");
                
                // Skip if not a MIR variable (_N format)
                if !lock_result_var.starts_with('_') || !lock_result_var.chars().nth(1).map_or(false, |c| c.is_ascii_digit()) {
                    continue;
                }
                
                // Case 1: Direct drop of lock result (no unwrap)
                // Pattern: _N = mutex.lock() then drop(_N)
                let drop_pattern = format!("drop({})", lock_result_var);
                let has_direct_drop = body_lines.iter().skip(i + 1).take(15)
                    .any(|future_line| future_line.trim().starts_with(&drop_pattern));
                
                if has_direct_drop && !named_vars.contains(lock_result_var) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "Lock guard assigned to `_` in `{}`, immediately releasing the lock",
                            function.name
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: function.span.clone(),
                    });
                    continue;
                }
                
                // Case 2: Unwrap then drop
                // Pattern: _N = mutex.lock() then _M = ...unwrap(move _N) then drop(_M)
                let unwrap_source_pattern = format!("(move {})", lock_result_var);
                for future_line in body_lines.iter().skip(i + 1).take(15) {
                    let future_trimmed = future_line.trim();
                    
                    // Look for unwrap/expect of the lock result
                    if (future_trimmed.contains("unwrap") || future_trimmed.contains("expect")) 
                        && future_trimmed.contains(&unwrap_source_pattern)
                        && future_trimmed.contains(" = ") 
                    {
                        let guard_var = future_trimmed.split(" = ").next()
                            .map(|s| s.trim())
                            .unwrap_or("");
                        
                        // Check if guard_var is unnamed and immediately dropped
                        if guard_var.starts_with('_') 
                            && guard_var.chars().nth(1).map_or(false, |c| c.is_ascii_digit())
                            && !named_vars.contains(guard_var) 
                        {
                            let guard_drop_pattern = format!("drop({})", guard_var);
                            let has_guard_drop = body_lines.iter()
                                .any(|line| line.trim().starts_with(&guard_drop_pattern));
                            
                            if has_guard_drop {
                                findings.push(Finding {
                                    rule_id: self.metadata.id.clone(),
                                    rule_name: self.metadata.name.clone(),
                                    severity: self.metadata.default_severity,
                                    message: format!(
                                        "Lock guard assigned to `_` in `{}`, immediately releasing the lock",
                                        function.name
                                    ),
                                    function: function.name.clone(),
                                    function_signature: function.signature.clone(),
                                    evidence: vec![trimmed.to_string(), future_trimmed.to_string()],
                                    span: function.span.clone(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA023: Broadcast Unsync Payload Rule
// ============================================================================

/// Detects tokio broadcast channels with !Sync payloads.
pub struct BroadcastUnsyncPayloadRule {
    metadata: RuleMetadata,
}

impl BroadcastUnsyncPayloadRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA023".to_string(),
                name: "tokio-broadcast-unsync-payload".to_string(),
                short_description: "Tokio broadcast carries !Sync payload".to_string(),
                full_description: "Warns when `tokio::sync::broadcast` channels are instantiated for types like `Rc`/`RefCell` that are not Sync, enabling unsound clones to cross thread boundaries. See RUSTSEC-2025-0023 for details.".to_string(),
                help_uri: Some("https://rustsec.org/advisories/RUSTSEC-2025-0023.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for BroadcastUnsyncPayloadRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            let usages = detect_broadcast_unsync_payloads(function);

            for usage in usages {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Broadcast channel instantiated with !Sync payload in `{}`",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: vec![usage.line.clone()],
                    span: function.span.clone(),
                });
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA040: Panic In Drop Rule
// ============================================================================

/// Detects panic!, unwrap(), or expect() in Drop implementations.
pub struct PanicInDropRule {
    metadata: RuleMetadata,
}

impl PanicInDropRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA040".to_string(),
                name: "panic-in-drop".to_string(),
                short_description: "panic! or unwrap in Drop implementation".to_string(),
                full_description: "Detects panic!, unwrap(), or expect() calls inside Drop trait implementations. Panicking during stack unwinding causes the process to abort, which can mask the original error and make debugging difficult. Drop implementations should handle errors gracefully or use logging instead of panicking.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/nomicon/exception-safety.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn panic_patterns() -> &'static [&'static str] {
        &[
            "panic!",
            ".unwrap()",
            ".expect(",
            "unreachable!",
            "unimplemented!",
            "todo!",
        ]
    }
}

impl Rule for PanicInDropRule {
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

            // Track Drop implementation boundaries
            let mut in_drop_impl = false;
            let mut drop_impl_start = 0;
            let mut brace_depth = 0;
            let mut drop_type_name = String::new();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Detect Drop impl start
                if trimmed.contains("impl") && trimmed.contains("Drop") && trimmed.contains("for") {
                    in_drop_impl = true;
                    drop_impl_start = idx;
                    brace_depth = 0;

                    // Extract type name
                    if let Some(for_pos) = trimmed.find("for ") {
                        let after_for = &trimmed[for_pos + 4..];
                        if let Some(space_pos) = after_for.find(|c: char| c.is_whitespace() || c == '{') {
                            drop_type_name = after_for[..space_pos].trim().to_string();
                        } else {
                            drop_type_name = after_for.trim().to_string();
                        }
                    }
                }

                if in_drop_impl {
                    brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                    // Check for panic patterns
                    for pattern in Self::panic_patterns() {
                        if trimmed.contains(pattern) {
                            // Skip commented lines
                            if !trimmed.starts_with("//") {
                                let location = format!("{}:{}", rel_path, idx + 1);

                                findings.push(Finding {
                                    rule_id: self.metadata.id.clone(),
                                    rule_name: self.metadata.name.clone(),
                                    severity: self.metadata.default_severity,
                                    message: format!(
                                        "Panic in Drop implementation for `{}` can cause abort during unwinding",
                                        drop_type_name
                                    ),
                                    function: location,
                                    function_signature: drop_type_name.clone(),
                                    evidence: vec![trimmed.to_string()],
                                    span: None,
                                });
                            }
                        }
                    }

                    // If brace depth returns to 0, we've exited the Drop impl
                    if brace_depth <= 0 && idx > drop_impl_start {
                        in_drop_impl = false;
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA041: Unwrap In Poll Rule
// ============================================================================

/// Detects unwrap(), expect(), or panic! in Future::poll implementations.
pub struct UnwrapInPollRule {
    metadata: RuleMetadata,
}

impl UnwrapInPollRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA041".to_string(),
                name: "unwrap-in-poll".to_string(),
                short_description: "unwrap or panic in Future::poll implementation".to_string(),
                full_description: "Detects unwrap(), expect(), or panic! calls inside Future::poll implementations. Panicking in poll() can stall async executors, cause runtime hangs, and make debugging async code difficult. Poll implementations should propagate errors using Poll::Ready(Err(...)) or use defensive patterns like match/if-let.".to_string(),
                help_uri: Some("https://rust-lang.github.io/async-book/02_execution/03_wakeups.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn panic_patterns() -> &'static [&'static str] {
        &[
            "panic!",
            ".unwrap()",
            ".expect(",
            "unreachable!",
            "unimplemented!",
            "todo!",
        ]
    }
}

impl Rule for UnwrapInPollRule {
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

            // Track Future impl and poll method boundaries
            let mut in_future_impl = false;
            let mut in_poll_method = false;
            let mut poll_start = 0;
            let mut brace_depth = 0;
            let mut impl_brace_depth = 0;
            let mut future_type_name = String::new();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                // Detect Future impl start
                if !in_future_impl && trimmed.contains("impl") && trimmed.contains("Future") && trimmed.contains("for") {
                    in_future_impl = true;
                    impl_brace_depth = 0;

                    // Extract type name
                    if let Some(for_pos) = trimmed.find("for ") {
                        let after_for = &trimmed[for_pos + 4..];
                        if let Some(space_pos) = after_for.find(|c: char| c.is_whitespace() || c == '{') {
                            future_type_name = after_for[..space_pos].trim().to_string();
                        } else {
                            future_type_name = after_for.trim().to_string();
                        }
                    }
                }

                if in_future_impl {
                    impl_brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    impl_brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                    // Detect poll method start
                    if !in_poll_method && (trimmed.contains("fn poll") || trimmed.contains("fn poll(")) {
                        in_poll_method = true;
                        poll_start = idx;
                        brace_depth = 0;
                    }

                    if in_poll_method {
                        brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                        brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                        // Check for panic patterns
                        for pattern in Self::panic_patterns() {
                            if trimmed.contains(pattern) {
                                // Skip commented lines
                                if !trimmed.starts_with("//") {
                                    let location = format!("{}:{}", rel_path, idx + 1);

                                    findings.push(Finding {
                                        rule_id: self.metadata.id.clone(),
                                        rule_name: self.metadata.name.clone(),
                                        severity: self.metadata.default_severity,
                                        message: format!(
                                            "Panic in Future::poll for `{}` can stall async executor",
                                            future_type_name
                                        ),
                                        function: location,
                                        function_signature: future_type_name.clone(),
                                        evidence: vec![trimmed.to_string()],
                                        span: None,
                                    });
                                }
                            }
                        }

                        // If brace depth returns to 0, we've exited the poll method
                        if brace_depth <= 0 && idx > poll_start {
                            in_poll_method = false;
                        }
                    }

                    // If impl brace depth returns to 0, we've exited the Future impl
                    if impl_brace_depth <= 0 && idx > 0 {
                        in_future_impl = false;
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA015: Unsafe Send/Sync Bounds
// ============================================================================

/// Detects unsafe implementations of Send/Sync for generic types that do not
/// constrain their generic parameters, which can reintroduce thread-safety bugs.
pub struct UnsafeSendSyncBoundsRule {
    metadata: RuleMetadata,
}

impl UnsafeSendSyncBoundsRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA015".to_string(),
                name: "unsafe-send-sync-bounds".to_string(),
                short_description: "Unsafe Send/Sync impl without generic bounds".to_string(),
                full_description: "Detects unsafe implementations of Send/Sync for generic types that do not constrain their generic parameters, which can reintroduce thread-safety bugs.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    fn has_required_bounds(block_text: &str, trait_name: &str) -> bool {
        let trait_marker = format!(" {trait_name} for");
        let Some(for_idx) = block_text.find(&trait_marker) else {
            return true;
        };
        let before_for = &block_text[..for_idx];
        let Some((generics_text, generic_names)) = Self::extract_generic_params(before_for) else {
            return true;
        };

        if generic_names.is_empty() {
            return true;
        }

        let generic_set: HashSet<String> = generic_names.iter().cloned().collect();
        let mut satisfied: HashSet<String> = HashSet::new();

        for (name, bounds) in Self::parse_inline_bounds(&generics_text) {
            if !generic_set.contains(&name) {
                continue;
            }

            if bounds
                .iter()
                .any(|bound| Self::bound_matches_trait(bound, trait_name))
            {
                satisfied.insert(name.clone());
            }
        }

        if let Some(where_clauses) = Self::extract_where_clauses(block_text) {
            for (name, bounds) in where_clauses {
                if !generic_set.contains(&name) {
                    continue;
                }

                if bounds
                    .iter()
                    .any(|bound| Self::bound_matches_trait(bound, trait_name))
                {
                    satisfied.insert(name);
                }
            }
        }

        generic_names
            .into_iter()
            .all(|name| satisfied.contains(&name))
    }

    fn extract_generic_params(before_for: &str) -> Option<(String, Vec<String>)> {
        let start = before_for.find('<')?;
        let end_offset = before_for[start..].find('>')?;
        let generics_text = before_for[start + 1..start + end_offset].trim().to_string();

        let mut names = Vec::new();
        for param in generics_text.split(',') {
            if let Some(name) = Self::normalize_generic_name(param) {
                names.push(name);
            }
        }

        Some((generics_text, names))
    }

    fn parse_inline_bounds(generics_text: &str) -> Vec<(String, Vec<String>)> {
        generics_text
            .split(',')
            .filter_map(|param| {
                let Some(name) = Self::normalize_generic_name(param) else {
                    return None;
                };

                let trimmed = param.trim();
                let mut parts = trimmed.splitn(2, ':');
                parts.next()?;
                let bounds = parts
                    .next()
                    .map(|rest| Self::split_bounds(rest))
                    .unwrap_or_default();

                Some((name, bounds))
            })
            .collect()
    }

    fn normalize_generic_name(token: &str) -> Option<String> {
        let token = token.trim();
        if token.is_empty() {
            return None;
        }

        if token.starts_with("const ") {
            return None;
        }

        if token.starts_with('\'') {
            return None;
        }

        let ident = token
            .split(|c: char| c == ':' || c == '=' || c.is_whitespace())
            .next()
            .unwrap_or("")
            .trim();

        if ident.is_empty() {
            None
        } else {
            Some(ident.to_string())
        }
    }

    fn extract_where_clauses(block_text: &str) -> Option<Vec<(String, Vec<String>)>> {
        let where_idx = block_text.find(" where ")?;
        let after_where = &block_text[where_idx + " where ".len()..];
        let end_idx = after_where
            .find('{')
            .or_else(|| after_where.find(';'))
            .unwrap_or(after_where.len());
        let clauses = after_where[..end_idx].trim();
        if clauses.is_empty() {
            return Some(Vec::new());
        }

        let mut result = Vec::new();
        for predicate in clauses.split(',') {
            let pred = predicate.trim();
            if pred.is_empty() {
                continue;
            }

            let mut parts = pred.splitn(2, ':');
            let ident = parts.next().unwrap_or("").trim();
            if ident.is_empty() {
                continue;
            }

            let bounds = parts
                .next()
                .map(|rest| Self::split_bounds(rest))
                .unwrap_or_default();
            result.push((ident.to_string(), bounds));
        }

        Some(result)
    }

    fn split_bounds(bounds: &str) -> Vec<String> {
        bounds
            .split('+')
            .map(|part| {
                part.trim()
                    .trim_start_matches('?')
                    .trim_start_matches("~const ")
                    .trim_end_matches(|c| matches!(c, ',' | '{' | ';'))
                    .to_string()
            })
            .filter(|part| !part.is_empty())
            .collect()
    }

    fn scan_string_state(
        state: StringLiteralState,
        line: &str,
    ) -> (bool, String, StringLiteralState) {
        let (sanitized, state_after) = strip_string_literals(state, line);
        let has_impl = sanitized.contains("unsafe impl")
            && (sanitized.contains(" Send for") || sanitized.contains(" Sync for"));
        (has_impl, sanitized, state_after)
    }

    fn bound_matches_trait(bound: &str, trait_name: &str) -> bool {
        let normalized = bound.trim();
        if normalized.is_empty() {
            return false;
        }

        let normalized = normalized
            .trim_start_matches("dyn ")
            .trim_start_matches("impl ");

        if normalized == trait_name {
            return true;
        }

        if normalized.ends_with(trait_name)
            && normalized
                .trim_end_matches(trait_name)
                .trim_end()
                .ends_with("::")
        {
            return true;
        }

        if let Some(start) = normalized.find('<') {
            let (path, generics) = normalized.split_at(start);
            if Self::bound_matches_trait(path.trim_end_matches('<'), trait_name) {
                return generics
                    .trim_matches(|c| c == '<' || c == '>')
                    .split(',')
                    .any(|part| Self::bound_matches_trait(part, trait_name));
            }
        }

        if let Some(idx) = normalized.find('<') {
            let inner = normalized[idx + 1..].trim_end_matches('>').trim();
            if inner.starts_with("*const") || inner.starts_with("*mut") || inner.starts_with('&') {
                return true;
            }
        }

        let tokens: Vec<_> = normalized
            .split(|c: char| c == ':' || c == '+' || c == ',' || c.is_whitespace())
            .filter(|token| !token.is_empty())
            .collect();

        if tokens.iter().any(|token| token == &trait_name) {
            return true;
        }

        if trait_name == "Send"
            && tokens
                .iter()
                .any(|token| *token == "Sync" || token.ends_with("::Sync"))
        {
            return true;
        }

        if trait_name == "Sync"
            && tokens
                .iter()
                .any(|token| *token == "Send" || token.ends_with("::Send"))
        {
            return true;
        }

        false
    }
}

impl Rule for UnsafeSendSyncBoundsRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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

            if entry.path().extension().and_then(OsStr::to_str) != Some("rs") {
                continue;
            }

            let Ok(source) = fs::read_to_string(entry.path()) else {
                continue;
            };

            let rel_path = entry
                .path()
                .strip_prefix(crate_root)
                .unwrap_or_else(|_| entry.path())
                .to_string_lossy()
                .replace('\\', "/");

            let lines: Vec<&str> = source.lines().collect();
            let mut idx = 0usize;
            let mut string_state = StringLiteralState::default();

            while idx < lines.len() {
                let line = lines[idx];
                let (has_impl, sanitized_line, mut state_after_line) =
                    Self::scan_string_state(string_state, line);
                let trimmed_sanitized = sanitized_line.trim();

                if !has_impl {
                    string_state = state_after_line;
                    idx += 1;
                    continue;
                }

                let mut block_lines = Vec::new();
                let trimmed_first = line.trim();
                if !trimmed_first.is_empty() {
                    block_lines.push(trimmed_first.to_string());
                }

                let mut block_complete =
                    trimmed_sanitized.contains('{') || trimmed_sanitized.ends_with(';');

                let mut j = idx;
                while !block_complete && j + 1 < lines.len() {
                    let next_line = lines[j + 1];
                    let (next_has_impl, next_sanitized, next_state) =
                        Self::scan_string_state(state_after_line, next_line);
                    let trimmed_original = next_line.trim();
                    let trimmed_sanitized_next = next_sanitized.trim();
                    let mut appended = false;

                    if !trimmed_original.is_empty() {
                        block_lines.push(trimmed_original.to_string());
                        appended = true;
                    }

                    state_after_line = next_state;
                    block_complete = trimmed_sanitized_next.contains('{')
                        || trimmed_sanitized_next.ends_with(';');

                    if next_has_impl {
                        if appended {
                            block_lines.pop();
                        }
                        break;
                    }

                    j += 1;
                }

                let block_text = block_lines.join(" ");
                let trait_name = if block_text.contains(" Send for") {
                    "Send"
                } else if block_text.contains(" Sync for") {
                    "Sync"
                } else {
                    string_state = state_after_line;
                    idx = j + 1;
                    continue;
                };

                if !Self::has_required_bounds(&block_text, trait_name) {
                    let location = format!("{}:{}", rel_path, idx + 1);
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!("Unsafe impl of {trait_name} without generic bounds"),
                        function: location,
                        function_signature: block_lines
                            .first()
                            .cloned()
                            .unwrap_or_else(|| trait_name.to_string()),
                        evidence: block_lines.clone(),
                        span: None,
                    });
                }

                string_state = state_after_line;
                idx = j + 1;
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA115: Non-Cancellation-Safe Select Rule
// ============================================================================

/// Detects use of potentially non-cancellation-safe futures in select! macro.
/// 
/// When using `select!`, if a branch is not chosen, its future is dropped.
/// If that future has made partial progress (e.g., partially read from a channel),
/// that progress is lost. This can lead to data loss or unexpected behavior.
pub struct NonCancellationSafeSelectRule {
    metadata: RuleMetadata,
}

impl NonCancellationSafeSelectRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA115".to_string(),
                name: "non-cancellation-safe-select".to_string(),
                short_description: "Potentially non-cancellation-safe future in select!".to_string(),
                full_description: "Detects use of potentially non-cancellation-safe futures in select! macro. \
                    When using tokio::select!, futures::select!, or similar macros, if a branch is not chosen, \
                    its future is dropped. If the future has made partial progress (e.g., started reading from \
                    a buffered stream), that progress is lost. Common non-cancellation-safe patterns include: \
                    - read_line() / read_until() on buffered streams \
                    - recv_many() on channels \
                    - Futures that modify internal state before awaiting \
                    Consider using cancellation-safe alternatives or restructuring the code.".to_string(),
                help_uri: Some("https://docs.rs/tokio/latest/tokio/macro.select.html#cancellation-safety".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Patterns that are known to be non-cancellation-safe
    fn non_cancellation_safe_patterns() -> &'static [(&'static str, &'static str)] {
        &[
            ("read_line(", "BufRead::read_line is not cancellation safe - partial reads are lost"),
            ("read_until(", "BufRead::read_until is not cancellation safe - partial reads are lost"),
            ("read_exact(", "read_exact is not cancellation safe - partial reads are lost"),
            ("recv_many(", "recv_many is not cancellation safe - some messages may be lost"),
            ("read_to_end(", "read_to_end is not cancellation safe - partial reads are lost"),
            ("read_to_string(", "read_to_string is not cancellation safe - partial reads are lost"),
            ("copy(", "io::copy is not cancellation safe - partial copy progress is lost"),
            ("copy_buf(", "io::copy_buf is not cancellation safe - partial copy progress is lost"),
        ]
    }
    
    /// Patterns that indicate we're in a select! context
    fn select_macro_patterns() -> &'static [&'static str] {
        &[
            "select!",
            "tokio::select!",
            "futures::select!",
            "futures_util::select!",
        ]
    }
}

impl Rule for NonCancellationSafeSelectRule {
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

            // Look for select! macro usage
            let mut in_select = false;
            let mut select_start_line = 0;
            let mut brace_depth = 0;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Check for select! macro start
                for pattern in Self::select_macro_patterns() {
                    if trimmed.contains(pattern) && !in_select {
                        in_select = true;
                        select_start_line = idx;
                        brace_depth = 0;
                    }
                }

                if in_select {
                    brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                    // Check for non-cancellation-safe patterns within select!
                    for (pattern, reason) in Self::non_cancellation_safe_patterns() {
                        if trimmed.contains(pattern) {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Non-cancellation-safe operation `{}` used in select! macro. {}",
                                    pattern.trim_end_matches('('),
                                    reason
                                ),
                                function: location,
                                function_signature: String::new(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                            });
                        }
                    }

                    // End of select! macro
                    if brace_depth <= 0 && idx > select_start_line {
                        in_select = false;
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA111: Missing Sync Bound on Clone Rule
// ============================================================================

/// Detects concurrent data structures that clone values without requiring Sync bound.
/// 
/// This pattern was found in tokio broadcast channels (RUSTSEC-2025-0023) where
/// cloning a value in a concurrent context without `Sync` bound can cause data races.
/// When multiple threads clone the same inner value simultaneously without synchronization,
/// undefined behavior can occur.
pub struct MissingSyncBoundOnCloneRule {
    metadata: RuleMetadata,
}

impl MissingSyncBoundOnCloneRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA111".to_string(),
                name: "missing-sync-bound-on-clone".to_string(),
                short_description: "Clone in concurrent context without Sync bound".to_string(),
                full_description: "Detects implementations that clone values in concurrent contexts \
                    without requiring the `Sync` trait bound. This pattern was found in tokio's \
                    broadcast channel (RUSTSEC-2025-0023) where concurrent cloning without Sync \
                    can cause data races. Channels and shared data structures that clone inner \
                    values should require `T: Clone + Send + Sync` instead of just `T: Clone + Send`.".to_string(),
                help_uri: Some("https://rustsec.org/advisories/RUSTSEC-2025-0023.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for MissingSyncBoundOnCloneRule {
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

            // Track impl blocks that use Clone + Send but not Sync
            // and also use unsafe impl Sync or have channel-like names
            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Pattern 1: unsafe impl Sync for types that clone without Sync bound
                if trimmed.contains("unsafe impl") && trimmed.contains("Sync") {
                    // Check if this might be a channel or shared structure
                    let is_channel_like = trimmed.contains("Sender") 
                        || trimmed.contains("Receiver")
                        || trimmed.contains("Channel")
                        || trimmed.contains("Broadcast")
                        || trimmed.contains("Queue")
                        || trimmed.contains("Buffer");
                    
                    if is_channel_like {
                        // Look for Clone + Send without Sync in nearby context
                        let context_start = idx.saturating_sub(20);
                        let context_end = (idx + 20).min(lines.len());
                        
                        let has_clone_send = lines[context_start..context_end].iter()
                            .any(|l| l.contains("Clone") && l.contains("Send"));
                        let has_sync_bound = lines[context_start..context_end].iter()
                            .any(|l| l.contains(": Sync") || l.contains("+ Sync"));
                        
                        if has_clone_send && !has_sync_bound {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: "unsafe impl Sync for channel-like type with Clone + Send \
                                    but no Sync bound. This may allow data races when cloning. \
                                    Consider adding `T: Sync` bound.".to_string(),
                                function: location,
                                function_signature: String::new(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                            });
                        }
                    }
                }

                // Pattern 2: impl blocks with Clone + Send but not Sync for channel types
                if trimmed.starts_with("impl") && trimmed.contains("Clone + Send") 
                    && !trimmed.contains("Sync") {
                    let is_channel_like = trimmed.contains("Sender") 
                        || trimmed.contains("Receiver")
                        || trimmed.contains("Channel")
                        || trimmed.contains("Broadcast");
                    
                    if is_channel_like {
                        let location = format!("{}:{}", rel_path, idx + 1);

                        findings.push(Finding {
                            rule_id: self.metadata.id.clone(),
                            rule_name: self.metadata.name.clone(),
                            severity: self.metadata.default_severity,
                            message: "Channel implementation with Clone + Send but missing Sync \
                                bound. Concurrent cloning may cause data races. \
                                Consider `T: Clone + Send + Sync`.".to_string(),
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

// ============================================================================
// RUSTCOLA112: Pin Contract Violation Rule
// ============================================================================

/// Detects potential Pin contract violations through unsplit/reconstruction patterns.
/// 
/// Based on RUSTSEC-2023-0005 where ReadHalf::unsplit could violate Pin contract
/// for !Unpin types. When split IO types are unsplit, pinned data may be moved
/// incorrectly, leading to use-after-free.
pub struct PinContractViolationRule {
    metadata: RuleMetadata,
}

impl PinContractViolationRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA112".to_string(),
                name: "pin-contract-violation".to_string(),
                short_description: "Potential Pin contract violation through unsplit".to_string(),
                full_description: "Detects potential Pin contract violations through unsplit or \
                    reconstruction patterns. When split IO types are recombined using unsplit(), \
                    pinned data for !Unpin types may be moved incorrectly. Also detects unsafe \
                    Pin::new_unchecked followed by potential moves. Based on RUSTSEC-2023-0005.".to_string(),
                help_uri: Some("https://rustsec.org/advisories/RUSTSEC-2023-0005.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for PinContractViolationRule {
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

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Pattern 1: unsplit() calls on IO types
                if trimmed.contains(".unsplit(") {
                    let location = format!("{}:{}", rel_path, idx + 1);

                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: "Use of unsplit() may violate Pin contract for !Unpin types. \
                            When recombining split IO halves, pinned data may be moved incorrectly. \
                            Ensure the underlying type is Unpin or use appropriate synchronization.".to_string(),
                        function: location,
                        function_signature: String::new(),
                        evidence: vec![trimmed.to_string()],
                        span: None,
                    });
                }

                // Pattern 2: Pin::new_unchecked in unsafe blocks
                if trimmed.contains("Pin::new_unchecked") {
                    let location = format!("{}:{}", rel_path, idx + 1);

                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: Severity::Medium,
                        message: "Use of Pin::new_unchecked requires ensuring the pinned value \
                            is never moved. Verify the value is not moved after pinning.".to_string(),
                        function: location,
                        function_signature: String::new(),
                        evidence: vec![trimmed.to_string()],
                        span: None,
                    });
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA113: Oneshot Race After Close Rule
// ============================================================================

/// Detects potential race conditions when using oneshot channels after close().
/// 
/// Based on RUSTSEC-2021-0124 where concurrent close(), send(), and recv()
/// operations on a oneshot channel could cause data races.
pub struct OneshotRaceAfterCloseRule {
    metadata: RuleMetadata,
}

impl OneshotRaceAfterCloseRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA113".to_string(),
                name: "oneshot-race-after-close".to_string(),
                short_description: "Potential race condition with oneshot channel close()".to_string(),
                full_description: "Detects patterns where oneshot::Receiver::close() may be called \
                    concurrently with send() or recv()/await operations. This pattern can cause \
                    data races as the sender and receiver may concurrently access shared memory. \
                    Based on RUSTSEC-2021-0124.".to_string(),
                help_uri: Some("https://rustsec.org/advisories/RUSTSEC-2021-0124.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}

impl Rule for OneshotRaceAfterCloseRule {
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

            // Check if file uses oneshot channels
            if !content.contains("oneshot::") && !content.contains("oneshot::{") {
                continue;
            }

            let lines: Vec<&str> = content.lines().collect();
            let mut has_close_call = false;
            let mut close_line = 0;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Track .close() calls on receivers
                if trimmed.contains(".close()") {
                    has_close_call = true;
                    close_line = idx + 1;
                }

                // If we've seen a close() and see send/recv in spawn context, flag it
                if has_close_call {
                    let in_spawn_context = lines[..idx].iter().rev().take(10)
                        .any(|l| l.contains("spawn") || l.contains("thread::"));
                    
                    if in_spawn_context {
                        if trimmed.contains(".send(") || trimmed.contains(".try_recv(") {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Oneshot channel operation after close() at line {}. \
                                    Concurrent close(), send(), and recv() operations can cause data races. \
                                    Ensure proper synchronization between channel halves.",
                                    close_line
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
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA109: Async-Signal-Unsafe in Handler Rule
// ============================================================================

/// Detects async-signal-unsafe operations inside signal handlers.
/// 
/// Signal handlers have strict requirements about what operations are safe.
/// Many common operations (heap allocation, I/O, locking) are NOT safe in
/// signal handlers and can cause deadlocks or corruption.
pub struct AsyncSignalUnsafeInHandlerRule {
    metadata: RuleMetadata,
}

impl AsyncSignalUnsafeInHandlerRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA109".to_string(),
                name: "async-signal-unsafe-in-handler".to_string(),
                short_description: "Async-signal-unsafe operation in signal handler".to_string(),
                full_description: "Detects async-signal-unsafe operations inside signal handlers. \
                    Signal handlers run asynchronously and interrupt normal execution, so only \
                    'async-signal-safe' functions may be called. Unsafe operations include: \
                    heap allocation (Box, Vec, String, format!), I/O (println!, eprintln!), \
                    locking (Mutex, RwLock), and most standard library functions.".to_string(),
                help_uri: Some("https://man7.org/linux/man-pages/man7/signal-safety.7.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Operations that are NOT async-signal-safe
    fn unsafe_operations() -> &'static [(&'static str, &'static str)] {
        &[
            ("println!", "I/O operations are not async-signal-safe"),
            ("eprintln!", "I/O operations are not async-signal-safe"),
            ("print!", "I/O operations are not async-signal-safe"),
            ("eprint!", "I/O operations are not async-signal-safe"),
            ("format!", "format! allocates memory, not async-signal-safe"),
            ("vec!", "vec! allocates memory, not async-signal-safe"),
            ("Box::new", "Box allocates memory, not async-signal-safe"),
            ("Vec::new", "Vec may allocate, not async-signal-safe"),
            ("String::new", "String may allocate, not async-signal-safe"),
            (".to_string()", "to_string allocates, not async-signal-safe"),
            (".to_owned()", "to_owned allocates, not async-signal-safe"),
            ("Mutex::new", "Creating locks in handlers is dangerous"),
            (".lock()", "Locking is not async-signal-safe"),
            (".read()", "RwLock read is not async-signal-safe"),
            (".write()", "RwLock write is not async-signal-safe"),
            ("std::io::", "Most std::io is not async-signal-safe"),
            ("std::fs::", "File operations are not async-signal-safe"),
        ]
    }
}

impl Rule for AsyncSignalUnsafeInHandlerRule {
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

            // Check if file uses signal handling
            if !content.contains("signal") && !content.contains("Signal") 
                && !content.contains("ctrlc") && !content.contains("SIGINT")
                && !content.contains("SIGTERM") && !content.contains("SIGHUP") {
                continue;
            }

            let lines: Vec<&str> = content.lines().collect();
            let mut in_signal_handler = false;
            let mut handler_start_line = 0;
            let mut brace_depth = 0;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Detect signal handler registration patterns
                let is_handler_start = trimmed.contains("signal::") 
                    || trimmed.contains("ctrlc::set_handler")
                    || trimmed.contains("set_handler")
                    || (trimmed.contains("signal") && trimmed.contains("move ||"))
                    || (trimmed.contains("signal") && trimmed.contains("move |"))
                    || trimmed.contains("SigAction::new");

                if is_handler_start && !in_signal_handler {
                    in_signal_handler = true;
                    handler_start_line = idx;
                    brace_depth = 0;
                }

                if in_signal_handler {
                    brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                    brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                    // Check for unsafe operations within handler
                    for (pattern, reason) in Self::unsafe_operations() {
                        if trimmed.contains(pattern) {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Async-signal-unsafe operation `{}` in signal handler (started at line {}). {}",
                                    pattern, handler_start_line + 1, reason
                                ),
                                function: location,
                                function_signature: String::new(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                            });
                        }
                    }

                    // End of handler closure
                    if brace_depth <= 0 && idx > handler_start_line {
                        in_signal_handler = false;
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
// RUSTCOLA100: OnceCell TOCTOU Race Rule
// ============================================================================

/// Detects potential TOCTOU (Time-of-check to time-of-use) races with OnceCell.
/// 
/// Pattern: Checking OnceCell::get() then calling get_or_init() based on result
/// creates a race window where another thread may initialize between check and use.
pub struct OnceCellTocTouRule {
    metadata: RuleMetadata,
}

impl OnceCellTocTouRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA100".to_string(),
                name: "oncecell-toctou-race".to_string(),
                short_description: "Potential TOCTOU race with OnceCell".to_string(),
                full_description: "Detects patterns where OnceCell::get() is checked before \
                    calling get_or_init(). This creates a TOCTOU race: another thread may \
                    initialize the cell between the check and the use. Use get_or_init() \
                    directly without pre-checking, or use get_or_try_init() for fallible init.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/cell/struct.OnceCell.html".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Patterns that indicate TOCTOU with OnceCell/OnceLock
    fn toctou_patterns() -> &'static [(&'static str, &'static str)] {
        &[
            (".get().is_none()", "checking get().is_none() then initializing"),
            (".get().is_some()", "checking get().is_some() before using"),
            ("if let None = ", "pattern matching None before get_or_init"),
            ("if cell.get() == None", "comparing get() to None"),
            ("match .get() {", "matching on get() result"),
        ]
    }
}

impl Rule for OnceCellTocTouRule {
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

            // Quick check: does file use OnceCell or OnceLock?
            if !content.contains("OnceCell") && !content.contains("OnceLock") 
                && !content.contains("once_cell") {
                continue;
            }

            let lines: Vec<&str> = content.lines().collect();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Check for TOCTOU patterns
                for (pattern, description) in Self::toctou_patterns() {
                    if trimmed.contains(pattern) {
                        // Look ahead for get_or_init within 5 lines
                        let has_init_nearby = lines[idx..].iter().take(5)
                            .any(|l| l.contains("get_or_init") || l.contains("set("));
                        
                        if has_init_nearby {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Potential TOCTOU race: {} followed by initialization. \
                                    Another thread may initialize between check and use. \
                                    Use get_or_init() directly without pre-checking.",
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
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA117: Panic While Holding Lock Rule
// ============================================================================

/// Detects panic-prone operations while holding a MutexGuard or RwLockGuard.
/// 
/// Panicking while holding a lock poisons the mutex, making it permanently
/// unusable for other threads. This can cause cascading failures.
pub struct PanicWhileHoldingLockRule {
    metadata: RuleMetadata,
}

impl PanicWhileHoldingLockRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA117".to_string(),
                name: "panic-while-holding-lock".to_string(),
                short_description: "Potential panic while holding lock".to_string(),
                full_description: "Detects panic-prone operations (unwrap, expect, assert, \
                    indexing) while a MutexGuard or RwLockGuard is held. Panicking while \
                    holding a lock poisons the mutex, making it unusable for other threads \
                    and causing cascading failures.".to_string(),
                help_uri: Some("https://doc.rust-lang.org/std/sync/struct.Mutex.html#poisoning".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Patterns that can cause panics
    fn panic_patterns() -> &'static [&'static str] {
        &[
            ".unwrap()",
            ".expect(",
            "panic!",
            "assert!",
            "assert_eq!",
            "assert_ne!",
            "unreachable!",
            "unimplemented!",
            "todo!",
        ]
    }

    /// Patterns that acquire locks
    fn lock_patterns() -> &'static [&'static str] {
        &[
            ".lock()",
            ".read()",
            ".write()",
            ".try_lock()",
            ".try_read()",
            ".try_write()",
        ]
    }
}

impl Rule for PanicWhileHoldingLockRule {
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

            // Quick check: does file use Mutex or RwLock?
            if !content.contains("Mutex") && !content.contains("RwLock") {
                continue;
            }

            let lines: Vec<&str> = content.lines().collect();
            let mut in_lock_scope = false;
            let mut lock_start_line = 0;
            let mut brace_depth_at_lock = 0;
            let mut current_brace_depth = 0;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Track brace depth
                current_brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                current_brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                // Detect lock acquisition
                for pattern in Self::lock_patterns() {
                    if trimmed.contains(pattern) && trimmed.contains("let ") {
                        in_lock_scope = true;
                        lock_start_line = idx;
                        brace_depth_at_lock = current_brace_depth;
                    }
                }

                // Check for panic patterns while lock is held
                if in_lock_scope {
                    for pattern in Self::panic_patterns() {
                        if trimmed.contains(pattern) {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: self.metadata.default_severity,
                                message: format!(
                                    "Panic-prone operation `{}` while holding lock (acquired at line {}). \
                                    Panicking will poison the mutex, making it unusable. \
                                    Consider using fallible alternatives or dropping the guard first.",
                                    pattern.trim_end_matches('('), lock_start_line + 1
                                ),
                                function: location,
                                function_signature: String::new(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                            });
                        }
                    }

                    // End of lock scope (simplified: when we return to or below the lock depth)
                    if current_brace_depth < brace_depth_at_lock {
                        in_lock_scope = false;
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA119: Closure Escaping References Rule
// ============================================================================

/// Detects closures that capture references and may escape their scope,
/// particularly when passed to spawn/thread functions or stored in 
/// longer-lived contexts.
pub struct ClosureEscapingRefsRule {
    metadata: RuleMetadata,
}

impl ClosureEscapingRefsRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA119".to_string(),
                name: "closure-escaping-refs".to_string(),
                short_description: "Closure may capture escaping references".to_string(),
                full_description: "Detects closures passed to spawn/thread functions that \
                    capture local references. These closures outlive the captured references, \
                    leading to use-after-free. Use move closures or Arc for shared ownership.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Functions that take closures that outlive the current scope
    fn escaping_closure_receivers() -> &'static [&'static str] {
        &[
            "thread::spawn",
            "spawn(",
            "spawn_blocking(",
            "spawn_local(",
            "task::spawn",
            "tokio::spawn",
            "async_std::spawn",
            "rayon::spawn",
            "thread::Builder",
            ".spawn(",
            "std::thread::spawn",
        ]
    }

    /// Patterns indicating a closure captures a reference
    fn ref_capture_patterns() -> &'static [&'static str] {
        &[
            // Non-move closure with explicit ref capture
            "|&",
            "| &",
            // Patterns that suggest borrowing in closure body
            ".as_ref()",
            ".borrow()",
        ]
    }
}

impl Rule for ClosureEscapingRefsRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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

            // Quick check: does file use spawn-like functions?
            let has_spawn = Self::escaping_closure_receivers()
                .iter()
                .any(|p| content.contains(p));
            if !has_spawn {
                continue;
            }

            let lines: Vec<&str> = content.lines().collect();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Check for spawn-like function calls
                for spawn_fn in Self::escaping_closure_receivers() {
                    if trimmed.contains(spawn_fn) {
                        // Check if it's NOT a move closure (which would be safe)
                        let has_closure = trimmed.contains('|');
                        let is_move_closure = trimmed.contains("move |") || 
                                             trimmed.contains("move|");
                        
                        if has_closure && !is_move_closure {
                            // Non-move closure passed to spawn - potential issue
                            let location = format!("{}:{}", rel_path, idx + 1);
                            
                            findings.push(Finding {
                                rule_id: self.metadata.id.clone(),
                                rule_name: self.metadata.name.clone(),
                                severity: Severity::Medium,
                                message: format!(
                                    "Non-move closure passed to '{}'. Closures passed to spawn \
                                    functions must use 'move' to take ownership of captured \
                                    variables, otherwise captured references may dangle. \
                                    Add 'move' keyword: `move |...| {{ ... }}`",
                                    spawn_fn.trim_end_matches('(')
                                ),
                                function: location,
                                function_signature: String::new(),
                                evidence: vec![trimmed.to_string()],
                                span: None,
                            });
                        }

                        // Also check for reference capture patterns even in move closures
                        // (which can still be problematic with explicit &var)
                        if has_closure {
                            for ref_pattern in Self::ref_capture_patterns() {
                                if trimmed.contains(ref_pattern) {
                                    let location = format!("{}:{}", rel_path, idx + 1);
                                    
                                    findings.push(Finding {
                                        rule_id: self.metadata.id.clone(),
                                        rule_name: self.metadata.name.clone(),
                                        severity: Severity::High,
                                        message: format!(
                                            "Closure passed to spawn may capture reference (pattern: '{}'). \
                                            References captured in spawn closures will dangle when the \
                                            spawning function returns. Use Arc or clone the data instead.",
                                            ref_pattern
                                        ),
                                        function: location,
                                        function_signature: String::new(),
                                        evidence: vec![trimmed.to_string()],
                                        span: None,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA121: Executor Starvation Rule
// ============================================================================

/// Detects CPU-bound operations in async functions that may starve the executor.
/// 
/// Long-running synchronous operations in async code block the executor thread,
/// preventing other tasks from making progress. Use spawn_blocking or yield points.
pub struct ExecutorStarvationRule {
    metadata: RuleMetadata,
}

impl ExecutorStarvationRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA121".to_string(),
                name: "executor-starvation".to_string(),
                short_description: "CPU-bound work in async context".to_string(),
                full_description: "Detects CPU-bound operations (tight loops, heavy computation) \
                    in async functions that may starve the executor. Long-running synchronous \
                    work blocks the executor thread. Use tokio::task::spawn_blocking or \
                    add yield points with tokio::task::yield_now().".to_string(),
                help_uri: Some("https://tokio.rs/tokio/topics/bridging".to_string()),
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
            },
        }
    }

    /// Patterns indicating CPU-bound work
    fn cpu_bound_patterns() -> &'static [(&'static str, &'static str)] {
        &[
            // Tight loops without yield
            ("loop {", "CPU-bound loop without yield_now() or await"),
            ("while true", "Infinite loop without yield"),
            ("for _ in 0..", "Large iteration without yield"),
            // Heavy computation patterns
            (".par_iter()", "Rayon parallel iteration blocks executor"),
            // Cryptographic operations
            ("hash(", "Cryptographic hashing is CPU-bound"),
            ("encrypt(", "Encryption is CPU-bound"),
            ("decrypt(", "Decryption is CPU-bound"),
            // Compression
            ("compress(", "Compression is CPU-bound"),
            ("decompress(", "Decompression is CPU-bound"),
            ("GzEncoder", "Gzip encoding is CPU-bound"),
            ("GzDecoder", "Gzip decoding is CPU-bound"),
        ]
    }
}

impl Rule for ExecutorStarvationRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
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

            // Quick check: does file have async functions?
            if !content.contains("async fn") && !content.contains("async move") {
                continue;
            }

            let lines: Vec<&str> = content.lines().collect();
            let mut in_async_fn = false;
            let mut async_fn_name = String::new();
            let mut brace_depth = 0;
            let mut async_start_depth = 0;

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                
                // Skip comments
                if trimmed.starts_with("//") {
                    continue;
                }

                // Track async function entry
                if (trimmed.contains("async fn ") || trimmed.contains("async move")) && !in_async_fn {
                    in_async_fn = true;
                    async_start_depth = brace_depth;
                    // Extract function name
                    if let Some(fn_pos) = trimmed.find("fn ") {
                        let after_fn = &trimmed[fn_pos + 3..];
                        async_fn_name = after_fn.split(|c| c == '(' || c == '<')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string();
                    }
                }

                // Track brace depth
                brace_depth += trimmed.chars().filter(|&c| c == '{').count() as i32;
                brace_depth -= trimmed.chars().filter(|&c| c == '}').count() as i32;

                // Check if we've exited the async function
                if in_async_fn && brace_depth <= async_start_depth && trimmed.contains('}') {
                    in_async_fn = false;
                    async_fn_name.clear();
                }

                // Check for CPU-bound patterns in async context
                if in_async_fn {
                    // Skip if there's already a spawn_blocking nearby
                    if trimmed.contains("spawn_blocking") || trimmed.contains("block_in_place") {
                        continue;
                    }

                    for (pattern, description) in Self::cpu_bound_patterns() {
                        if trimmed.contains(pattern) {
                            // Check if there's an await or yield nearby (within 5 lines)
                            let start_idx = idx.saturating_sub(5);
                            let end_idx = (idx + 5).min(lines.len() - 1);
                            let has_nearby_yield = lines[start_idx..=end_idx]
                                .iter()
                                .any(|l| l.contains(".await") || l.contains("yield_now"));

                            if !has_nearby_yield {
                                let location = format!("{}:{}", rel_path, idx + 1);
                                
                                findings.push(Finding {
                                    rule_id: self.metadata.id.clone(),
                                    rule_name: self.metadata.name.clone(),
                                    severity: self.metadata.default_severity,
                                    message: format!(
                                        "Potential executor starvation in async function '{}': {}. \
                                        Consider using tokio::task::spawn_blocking() for CPU-bound work \
                                        or adding yield points with tokio::task::yield_now().await",
                                        async_fn_name, description
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
    engine.register_rule(Box::new(UnderscoreLockGuardRule::new()));
    engine.register_rule(Box::new(BroadcastUnsyncPayloadRule::new()));
    engine.register_rule(Box::new(PanicInDropRule::new()));
    engine.register_rule(Box::new(UnwrapInPollRule::new()));
    engine.register_rule(Box::new(UnsafeSendSyncBoundsRule::new()));
    engine.register_rule(Box::new(NonCancellationSafeSelectRule::new()));
    engine.register_rule(Box::new(MissingSyncBoundOnCloneRule::new()));
    engine.register_rule(Box::new(PinContractViolationRule::new()));
    engine.register_rule(Box::new(OneshotRaceAfterCloseRule::new()));
    engine.register_rule(Box::new(AsyncSignalUnsafeInHandlerRule::new()));
    engine.register_rule(Box::new(OnceCellTocTouRule::new()));
    engine.register_rule(Box::new(PanicWhileHoldingLockRule::new()));
    engine.register_rule(Box::new(ClosureEscapingRefsRule::new()));
    engine.register_rule(Box::new(ExecutorStarvationRule::new()));
}
