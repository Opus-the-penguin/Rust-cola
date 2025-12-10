//! Test cases for RUSTCOLA097: Network/process access in build scripts
//!
//! Build scripts (build.rs) should not perform network requests or spawn
//! arbitrary processes. This is a supply-chain security risk - malicious
//! dependencies could exfiltrate data or download malware at build time.
//!
//! This file tests SAFE patterns only - the actual PROBLEMATIC patterns are in build.rs
//!
//! Expected: Findings in build.rs, no findings in main.rs

fn main() {
    println!("RUSTCOLA097 test - build script network detection");
}
