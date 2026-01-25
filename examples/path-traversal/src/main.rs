//! Path Traversal Test Cases for RUSTCOLA086
//!
//! This module contains test cases for detecting path traversal vulnerabilities
//! where untrusted input flows to filesystem operations without proper validation.
//!
//! ## Vulnerability Pattern
//!
//! Path traversal occurs when user-controlled input is used to construct file paths
//! without proper validation, allowing attackers to access files outside intended
//! directories using sequences like `../` or absolute paths.
//!
//! ## Detection Approach
//!
//! RUSTCOLA086 uses interprocedural taint tracking:
//! 1. **Sources**: env::var, env::args, stdin, HTTP request parameters
//! 2. **Sinks**: fs::read, fs::write, fs::remove_file, File::open, etc.
//! 3. **Sanitizers**: Path::canonicalize, starts_with validation, path stripping

use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

// ============================================================================
// VULNERABLE PATTERNS - Should trigger RUSTCOLA086
// ============================================================================

/// BAD: Direct use of environment variable as file path
/// Attacker can set FILE_PATH="../../../etc/passwd" to read sensitive files
pub fn bad_env_var_to_read() -> io::Result<String> {
    let file_path = env::var("FILE_PATH").unwrap_or_default();
    fs::read_to_string(&file_path)
}

/// BAD: Command-line argument directly used as file path
/// ./program "../../../etc/passwd" reads arbitrary files
pub fn bad_cli_arg_to_read() -> io::Result<String> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        fs::read_to_string(&args[1])
    } else {
        Ok(String::new())
    }
}

/// BAD: User input from stdin used as file path
pub fn bad_stdin_to_write() -> io::Result<()> {
    let stdin = io::stdin();
    let mut file_path = String::new();
    stdin.lock().read_line(&mut file_path)?;
    let file_path = file_path.trim();

    fs::write(file_path, "malicious content")
}

/// BAD: Path joined with untrusted input (interprocedural)
/// Even with a "safe" base directory, ../.. can escape
pub fn bad_joined_path_to_remove() -> io::Result<()> {
    let base = PathBuf::from("/var/www/uploads");
    let user_filename = env::var("FILENAME").unwrap_or_default();

    // Vulnerable: user can supply "../../etc/passwd" to escape base
    let full_path = base.join(&user_filename);
    fs::remove_file(full_path)
}

/// BAD: Helper function passes taint through
fn get_user_requested_file() -> PathBuf {
    let filename = env::var("REQUESTED_FILE").unwrap_or_default();
    PathBuf::from(filename)
}

pub fn bad_interprocedural_read() -> io::Result<String> {
    let path = get_user_requested_file();
    fs::read_to_string(path)
}

/// BAD: Multiple levels of helper functions
fn get_config_key() -> String {
    env::var("CONFIG_KEY").unwrap_or_default()
}

fn build_config_path() -> PathBuf {
    let key = get_config_key();
    PathBuf::from(format!("/etc/app/{}.conf", key))
}

pub fn bad_deep_interprocedural() -> io::Result<String> {
    let path = build_config_path();
    fs::read_to_string(path)
}

/// BAD: File deletion with user-controlled path
pub fn bad_delete_user_file() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        fs::remove_file(&args[1])?;
    }
    Ok(())
}

/// BAD: Directory operations with user input
pub fn bad_create_user_directory() -> io::Result<()> {
    let dir_name = env::var("NEW_DIR").unwrap_or_default();
    fs::create_dir_all(&dir_name)
}

/// BAD: Copying files with user-controlled destination
pub fn bad_copy_to_user_path() -> io::Result<u64> {
    let dest = env::var("DEST_PATH").unwrap_or_default();
    fs::copy("/tmp/source.txt", &dest)
}

/// BAD: Rename with user-controlled paths
pub fn bad_rename_user_controlled() -> io::Result<()> {
    let old_path = env::var("OLD_PATH").unwrap_or_default();
    let new_path = env::var("NEW_PATH").unwrap_or_default();
    fs::rename(&old_path, &new_path)
}

// ============================================================================
// SAFE PATTERNS - Should NOT trigger RUSTCOLA086
// ============================================================================

/// SAFE: Hardcoded path, no user input
pub fn safe_hardcoded_path() -> io::Result<String> {
    fs::read_to_string("/etc/hostname")
}

/// SAFE: Path validation with canonicalize and starts_with
pub fn safe_canonicalized_path() -> io::Result<String> {
    let base_dir = PathBuf::from("/var/www/uploads").canonicalize()?;
    let user_file = env::var("USER_FILE").unwrap_or_default();

    let requested_path = base_dir.join(&user_file).canonicalize()?;

    // Validate the canonicalized path is within allowed directory
    if !requested_path.starts_with(&base_dir) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "path traversal attempt",
        ));
    }

    fs::read_to_string(requested_path)
}

/// SAFE: Strip dangerous sequences from input
fn sanitize_filename(input: &str) -> String {
    input
        .replace("..", "")
        .replace("/", "")
        .replace("\\", "")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect()
}

pub fn safe_sanitized_filename() -> io::Result<String> {
    let user_input = env::var("FILENAME").unwrap_or_default();
    let safe_name = sanitize_filename(&user_input);

    let path = PathBuf::from("/var/uploads").join(safe_name);
    fs::read_to_string(path)
}

/// SAFE: Allowlist validation
pub fn safe_allowlist_validation() -> io::Result<String> {
    let allowed_files = ["config.json", "settings.yaml", "data.csv"];
    let requested = env::var("FILE").unwrap_or_default();

    if !allowed_files.contains(&requested.as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file not in allowlist",
        ));
    }

    let path = PathBuf::from("/etc/app").join(&requested);
    fs::read_to_string(path)
}

/// SAFE: Check for path components
pub fn safe_no_parent_traversal() -> io::Result<String> {
    let filename = env::var("FILENAME").unwrap_or_default();

    // Reject if contains parent directory references
    if filename.contains("..") || filename.starts_with('/') || filename.contains("\\") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid path characters",
        ));
    }

    let path = PathBuf::from("/data").join(&filename);
    fs::read_to_string(path)
}

/// SAFE: Helper function with validation
fn validate_and_get_path(user_input: &str) -> Option<PathBuf> {
    // Reject suspicious patterns
    if user_input.contains("..") || user_input.starts_with('/') {
        return None;
    }

    // Only allow alphanumeric and safe characters
    if !user_input
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    {
        return None;
    }

    Some(PathBuf::from("/uploads").join(user_input))
}

pub fn safe_validated_helper() -> io::Result<String> {
    let filename = env::var("FILENAME").unwrap_or_default();

    match validate_and_get_path(&filename) {
        Some(path) => fs::read_to_string(path),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid filename",
        )),
    }
}

/// SAFE: Path is relative within known safe directory using strip_prefix
pub fn safe_strip_prefix_check() -> io::Result<String> {
    let base = PathBuf::from("/var/www/public");
    let user_path = env::var("PATH").unwrap_or_default();
    let full_path = base.join(&user_path);

    // Ensure the resolved path is within base directory
    if let Ok(canonical) = full_path.canonicalize() {
        if canonical.strip_prefix(&base).is_ok() {
            return fs::read_to_string(canonical);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "path outside allowed directory",
    ))
}

/// SAFE: UUID-based filename with sanitized prefix selection
pub fn safe_uuid_with_validated_prefix() -> io::Result<()> {
    // Get prefix from env but validate it
    let prefix = env::var("PREFIX").unwrap_or_default();
    let allowed_prefixes = ["temp", "cache", "data"];

    // Validate prefix is in allowlist
    if !allowed_prefixes.contains(&prefix.as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid prefix",
        ));
    }

    let uuid = "550e8400-e29b-41d4-a716-446655440000"; // Would be generated
    let path = format!("/tmp/{}/{}.dat", prefix, uuid);
    fs::write(&path, "data")
}

fn main() {
    println!("Path traversal test cases");
    println!("Run rust-cola to detect vulnerabilities in this file");
}
