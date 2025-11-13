// Test cases for RUSTCOLA055: Unix Permissions Not Octal
//
// This module tests detection of Unix file permissions passed as decimal
// literals instead of octal notation, which is confusing and error-prone.

#![cfg(unix)]
use std::fs::{self, DirBuilder, Permissions};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

// PROBLEMATIC: Using decimal 644 (which is actually 0o1204 in octal, not rw-r--r--)
pub fn set_file_permissions_decimal_644(path: &str) -> std::io::Result<()> {
    let perms = Permissions::from_mode(644); // Should be 0o644
    fs::set_permissions(path, perms)
}

// PROBLEMATIC: Using decimal 755 (which is actually 0o1363 in octal, not rwxr-xr-x)
pub fn set_file_permissions_decimal_755(path: &str) -> std::io::Result<()> {
    let perms = Permissions::from_mode(755); // Should be 0o755
    fs::set_permissions(path, perms)
}

// PROBLEMATIC: Using decimal 777 (world-writable, also wrong value)
pub fn create_dir_decimal_777(path: &str) -> std::io::Result<()> {
    DirBuilder::new()
        .mode(777) // Should be 0o777
        .create(path)
}

// PROBLEMATIC: Using decimal 600 (owner read/write only)
pub fn set_private_file_decimal_600(path: &str) -> std::io::Result<()> {
    let perms = Permissions::from_mode(600); // Should be 0o600
    fs::set_permissions(path, perms)
}

// SAFE: Using proper octal notation with 0o prefix
pub fn set_file_permissions_octal_644(path: &str) -> std::io::Result<()> {
    let perms = Permissions::from_mode(0o644); // Correct octal notation
    fs::set_permissions(path, perms)
}

// SAFE: Using proper octal notation for executable
pub fn set_file_permissions_octal_755(path: &str) -> std::io::Result<()> {
    let perms = Permissions::from_mode(0o755); // Correct octal notation
    fs::set_permissions(path, perms)
}

// SAFE: Using proper octal notation for directory
pub fn create_dir_octal_755(path: &str) -> std::io::Result<()> {
    DirBuilder::new()
        .mode(0o755) // Correct octal notation
        .create(path)
}

// SAFE: Using proper octal notation for private file
pub fn set_private_file_octal_600(path: &str) -> std::io::Result<()> {
    let perms = Permissions::from_mode(0o600); // Correct octal notation
    fs::set_permissions(path, perms)
}

// EDGE CASE: Using variable (can't detect statically)
pub fn set_permissions_from_variable(path: &str, mode: u32) -> std::io::Result<()> {
    let perms = Permissions::from_mode(mode);
    fs::set_permissions(path, perms)
}

// EDGE CASE: Hexadecimal notation (less common but valid)
pub fn set_permissions_hex(path: &str) -> std::io::Result<()> {
    let perms = Permissions::from_mode(0x1A4); // 0x1A4 = 0o644 = 420 decimal
    fs::set_permissions(path, perms)
}
