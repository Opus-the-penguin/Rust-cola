// Test cases for RUSTCOLA058: Absolute Path in join()
//
// This module tests detection of absolute paths passed to Path::join()
// or PathBuf::push(), which nullifies the base path and can enable
// path traversal attacks.

use std::path::{Path, PathBuf};

// PROBLEMATIC: Unix absolute path in join - nullifies base path
pub fn join_unix_absolute() -> PathBuf {
    let base = Path::new("/var/www/uploads");
    base.join("/etc/passwd") // Ignores base, returns "/etc/passwd"
}

// PROBLEMATIC: Unix absolute path with push
pub fn push_unix_absolute() -> PathBuf {
    let mut path = PathBuf::from("/var/www/uploads");
    path.push("/etc/shadow"); // Replaces entire path with "/etc/shadow"
    path
}

// PROBLEMATIC: Unix home directory
pub fn join_unix_home() -> PathBuf {
    let base = Path::new("/safe/directory");
    base.join("/home/user/.ssh/id_rsa") // Ignores base path
}

// PROBLEMATIC: Unix system directory
pub fn join_unix_system() -> PathBuf {
    let base = Path::new("/app/data");
    base.join("/usr/local/secret") // Ignores base path
}

// PROBLEMATIC: Windows absolute path with drive letter
#[cfg(windows)]
pub fn join_windows_absolute() -> PathBuf {
    let base = Path::new("C:\\Users\\Public");
    base.join("C:\\Windows\\System32\\config\\SAM") // Ignores base
}

// PROBLEMATIC: Windows UNC path
#[cfg(windows)]
pub fn join_windows_unc() -> PathBuf {
    let base = Path::new("C:\\app\\uploads");
    base.join("\\\\server\\share\\secret") // Absolute UNC path
}

// SAFE: Relative path in join
pub fn join_relative_safe() -> PathBuf {
    let base = Path::new("/var/www/uploads");
    base.join("user123/file.txt") // Relative path, properly joined
}

// SAFE: Relative path with subdirectories
pub fn join_relative_subdir() -> PathBuf {
    let base = Path::new("/app/data");
    base.join("subdir/file.dat") // Relative, stays within base
}

// SAFE: Push relative path
pub fn push_relative_safe() -> PathBuf {
    let mut path = PathBuf::from("/var/www");
    path.push("uploads");
    path.push("file.txt"); // All relative additions
    path
}

// SAFE: Join with dot notation (still relative)
pub fn join_dot_notation() -> PathBuf {
    let base = Path::new("/base");
    base.join("./subdir/file") // Relative despite ./
}

// SAFE: Empty or simple filename
pub fn join_filename() -> PathBuf {
    let base = Path::new("/var/log");
    base.join("app.log") // Just a filename
}

// EDGE CASE: Parent directory traversal (different vulnerability)
pub fn join_parent_traversal() -> PathBuf {
    let base = Path::new("/app/uploads");
    base.join("../../../etc/passwd") // Path traversal but not absolute
}
