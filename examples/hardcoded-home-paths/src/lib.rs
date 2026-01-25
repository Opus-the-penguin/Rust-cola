// Test suite for RUSTCOLA068: Hard-coded home directory paths
// Tests detection of absolute home directory paths that reduce portability and security
// Hard-coded home paths are problematic because:
// - They break when code runs under different users
// - They expose username information in code
// - They prevent containerization and CI/CD from working
// - They make code non-portable across systems

use std::fs;
use std::path::{Path, PathBuf};

// ==============================================================================
// PROBLEMATIC CASES - Should trigger RUSTCOLA068
// ==============================================================================

/// PROBLEMATIC: Hard-coded Linux/Unix home path
/// NOSEC: Intentional test pattern
pub fn hardcoded_unix_home() -> &'static str {
    "/home/john/config.toml"
}

/// PROBLEMATIC: Hard-coded macOS home path
/// NOSEC: Intentional test pattern
pub fn hardcoded_macos_home() -> &'static str {
    "/Users/jane/Documents/secret.txt"
}

/// PROBLEMATIC: Hard-coded Windows home path (forward slashes)
/// NOSEC: Intentional test pattern
pub fn hardcoded_windows_home_forward() -> &'static str {
    "C:/Users/bob/AppData/config.json"
}

/// PROBLEMATIC: Hard-coded Windows home path (backslashes)
/// NOSEC: Intentional test pattern
pub fn hardcoded_windows_home_back() -> &'static str {
    "C:\\Users\\alice\\Documents\\data.db"
}

/// PROBLEMATIC: Hard-coded Unix tilde expansion with username
/// NOSEC: Intentional test pattern
pub fn hardcoded_tilde_username() -> &'static str {
    "~root/.ssh/id_rsa"
}

/// PROBLEMATIC: Multiple hard-coded paths in same function
/// NOSEC: Intentional test pattern
pub fn multiple_hardcoded_paths() -> Vec<&'static str> {
    vec![
        "/home/developer/projects",
        "/Users/admin/scripts",
        "C:\\Users\\test\\temp",
    ]
}

/// PROBLEMATIC: Hard-coded path used in file operations
/// NOSEC: Intentional test pattern
pub fn file_op_with_hardcoded_path() -> std::io::Result<String> {
    fs::read_to_string("/home/user/important.txt")
}

// ==============================================================================
// SAFE CASES - Should NOT trigger RUSTCOLA068
// ==============================================================================

/// SAFE: Using environment variable for home
pub fn safe_env_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// SAFE: Using std::env::home_dir (deprecated but proper approach)
#[allow(deprecated)]
pub fn safe_home_dir() -> Option<PathBuf> {
    std::env::home_dir()
}

/// SAFE: Using relative path
pub fn safe_relative_path() -> &'static str {
    "./config/settings.toml"
}

/// SAFE: Using current directory marker
pub fn safe_current_dir() -> &'static str {
    "../data/cache.db"
}

/// SAFE: Generic system paths (not user-specific)
pub fn safe_system_paths() -> Vec<&'static str> {
    vec![
        "/etc/config.toml",
        "/var/log/app.log",
        "/tmp/tempfile",
        "C:\\Windows\\System32\\drivers",
        "/usr/local/bin/tool",
    ]
}

/// SAFE: Tilde without username (shell expansion)
pub fn safe_tilde_no_username() -> &'static str {
    "~/.config/app.toml"
}

/// SAFE: Path components that happen to contain user string
pub fn safe_contains_user_word() -> &'static str {
    "/var/lib/users_database/schema.sql"
}

/// SAFE: Using dirs crate pattern (commented example)
pub fn safe_using_dirs_crate() -> PathBuf {
    // In real code: dirs::home_dir().unwrap().join(".config")
    PathBuf::from("/tmp/fallback")
}

/// SAFE: Using path parameter instead of hard-coding
pub fn safe_parameterized(user_path: &Path) -> PathBuf {
    user_path.join("config.toml")
}

/// SAFE: Home path in comments (not executed code)
pub fn safe_comment_mentions_home() {
    // This function used to read from /home/user/old_config
    // but now uses proper environment variables
    let _path = std::env::var("HOME").ok();
}
