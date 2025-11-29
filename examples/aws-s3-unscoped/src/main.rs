//! AWS S3 Unscoped Access Detection Test Cases
//!
//! Tests for RUSTCOLA085: Detecting AWS S3 operations where bucket names,
//! keys, or prefixes come from untrusted sources (env vars, CLI args, etc.)
//! without validation or scoping.

use aws_sdk_s3::Client;
use std::env;

// ============================================================================
// VULNERABLE PATTERNS - Should trigger RUSTCOLA085
// ============================================================================

/// VULNERABLE: Bucket name from environment variable without validation
async fn bad_bucket_from_env(client: &Client) {
    // Untrusted: bucket name directly from env var
    let bucket = env::var("BUCKET_NAME").unwrap();
    
    client
        .list_objects_v2()
        .bucket(&bucket)  // Untrusted bucket name!
        .send()
        .await
        .unwrap();
}

/// VULNERABLE: Key prefix from CLI args without validation
async fn bad_prefix_from_args(client: &Client, args: &[String]) {
    let bucket = "my-safe-bucket";
    // Untrusted: prefix from command line argument
    let prefix = &args[1];
    
    client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(prefix)  // Untrusted prefix - could list any path!
        .send()
        .await
        .unwrap();
}

/// VULNERABLE: Key from user input used in delete operation
async fn bad_delete_untrusted_key(client: &Client) {
    let bucket = "my-bucket";
    // Untrusted: key from env var
    let key = env::var("OBJECT_KEY").unwrap();
    
    client
        .delete_object()
        .bucket(bucket)
        .key(&key)  // Untrusted key - attacker can delete any object!
        .send()
        .await
        .unwrap();
}

/// VULNERABLE: Both bucket and key from untrusted sources
async fn bad_put_object_untrusted(client: &Client, data: &[u8]) {
    // Both from env vars - completely unscoped!
    let bucket = env::var("S3_BUCKET").unwrap();
    let key = env::var("S3_KEY").unwrap();
    
    client
        .put_object()
        .bucket(&bucket)
        .key(&key)
        .body(data.to_vec().into())
        .send()
        .await
        .unwrap();
}

/// VULNERABLE: Wildcard prefix pattern
async fn bad_wildcard_prefix(client: &Client) {
    let bucket = "data-bucket";
    
    // Using wildcard-like prefix that lists everything
    client
        .list_objects_v2()
        .bucket(bucket)
        .prefix("")  // Empty prefix = list all objects
        .send()
        .await
        .unwrap();
}

/// VULNERABLE: Bucket from query parameter (web context simulation)
async fn bad_bucket_from_query(client: &Client, query_params: &std::collections::HashMap<String, String>) {
    // Simulating untrusted web input
    let bucket = query_params.get("bucket").unwrap();
    
    client
        .list_objects_v2()
        .bucket(bucket)
        .send()
        .await
        .unwrap();
}

/// VULNERABLE: Key constructed from multiple untrusted parts
async fn bad_key_concatenation(client: &Client) {
    let bucket = "uploads";
    let user_id = env::var("USER_ID").unwrap();
    let filename = env::var("FILENAME").unwrap();
    
    // Path traversal risk: ../../../sensitive/file
    let key = format!("{}/{}", user_id, filename);
    
    client
        .get_object()
        .bucket(bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
}

/// VULNERABLE: Using args directly in head_object
async fn bad_head_object_from_args(client: &Client) {
    let args: Vec<String> = env::args().collect();
    let bucket = &args[1];
    let key = &args[2];
    
    client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .unwrap();
}

// ============================================================================
// SAFE PATTERNS - Should NOT trigger RUSTCOLA085
// ============================================================================

/// SAFE: Hardcoded bucket and key
async fn safe_hardcoded_values(client: &Client) {
    client
        .list_objects_v2()
        .bucket("my-known-bucket")
        .prefix("safe/prefix/")
        .send()
        .await
        .unwrap();
}

/// SAFE: Bucket from config constant
async fn safe_config_constant(client: &Client) {
    const ALLOWED_BUCKET: &str = "production-bucket";
    const ALLOWED_PREFIX: &str = "uploads/";
    
    client
        .list_objects_v2()
        .bucket(ALLOWED_BUCKET)
        .prefix(ALLOWED_PREFIX)
        .send()
        .await
        .unwrap();
}

/// SAFE: Validated bucket from allowlist
async fn safe_validated_bucket(client: &Client) {
    let bucket = env::var("BUCKET_NAME").unwrap();
    
    // Validation: check against allowlist
    let allowed = ["bucket-a", "bucket-b", "bucket-c"];
    if !allowed.contains(&bucket.as_str()) {
        panic!("Invalid bucket");
    }
    
    client
        .list_objects_v2()
        .bucket(&bucket)
        .send()
        .await
        .unwrap();
}

/// SAFE: Prefix with path traversal prevention
async fn safe_sanitized_prefix(client: &Client) {
    let user_input = env::var("USER_PREFIX").unwrap();
    
    // Sanitization: remove path traversal attempts
    let safe_prefix = user_input
        .replace("..", "")
        .replace("//", "/")
        .trim_start_matches('/')
        .to_string();
    
    // Additional validation
    if safe_prefix.contains("..") || safe_prefix.starts_with('/') {
        panic!("Invalid prefix");
    }
    
    client
        .list_objects_v2()
        .bucket("safe-bucket")
        .prefix(&format!("user-data/{}", safe_prefix))
        .send()
        .await
        .unwrap();
}

/// SAFE: Key scoped to user directory
async fn safe_scoped_key(client: &Client) {
    let user_id = "known-user-123";  // From authenticated session, not raw input
    let filename = env::var("FILENAME").unwrap();
    
    // Safe: scoped to specific user directory with validation
    let safe_filename = filename
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect::<String>();
    
    let key = format!("users/{}/files/{}", user_id, safe_filename);
    
    client
        .get_object()
        .bucket("user-files")
        .key(&key)
        .send()
        .await
        .unwrap();
}

/// SAFE: Using starts_with check for prefix scoping
async fn safe_prefix_scoping(client: &Client) {
    let requested_prefix = env::var("PREFIX").unwrap();
    const ALLOWED_BASE: &str = "public/";
    
    // Ensure prefix is within allowed scope
    if !requested_prefix.starts_with(ALLOWED_BASE) {
        panic!("Access denied: prefix must start with {}", ALLOWED_BASE);
    }
    
    // Additional path traversal check
    if requested_prefix.contains("..") {
        panic!("Invalid prefix");
    }
    
    client
        .list_objects_v2()
        .bucket("data-bucket")
        .prefix(&requested_prefix)
        .send()
        .await
        .unwrap();
}

/// SAFE: Test function - disabled verification expected in tests
#[cfg(test)]
async fn test_list_objects(client: &Client) {
    let bucket = env::var("TEST_BUCKET").unwrap();
    client
        .list_objects_v2()
        .bucket(&bucket)
        .send()
        .await
        .unwrap();
}

// ============================================================================
// EDGE CASES
// ============================================================================

/// EDGE: Bucket from env but only used for read operations
async fn edge_read_only_from_env(client: &Client) {
    let bucket = env::var("READ_BUCKET").unwrap();
    
    // Read-only operation - less severe than delete/put
    let _ = client
        .list_objects_v2()
        .bucket(&bucket)
        .max_keys(10)  // Limited results
        .send()
        .await;
}

/// EDGE: Copy object with mixed sources
async fn edge_copy_mixed_sources(client: &Client) {
    let source_bucket = "trusted-source";
    let dest_bucket = env::var("DEST_BUCKET").unwrap();  // Untrusted!
    let key = "known-file.txt";
    
    client
        .copy_object()
        .copy_source(format!("{}/{}", source_bucket, key))
        .bucket(&dest_bucket)  // Destination bucket from env
        .key(key)
        .send()
        .await
        .unwrap();
}

#[tokio::main]
async fn main() {
    println!("AWS S3 Unscoped Access Test Cases");
    println!("==================================");
    println!();
    println!("VULNERABLE patterns (should trigger RUSTCOLA085):");
    println!("  - bad_bucket_from_env: Bucket name from env var");
    println!("  - bad_prefix_from_args: Key prefix from CLI args");
    println!("  - bad_delete_untrusted_key: Delete with env var key");
    println!("  - bad_put_object_untrusted: Put with env bucket/key");
    println!("  - bad_wildcard_prefix: Empty prefix (lists all)");
    println!("  - bad_bucket_from_query: Bucket from query params");
    println!("  - bad_key_concatenation: Key from concat'd env vars");
    println!("  - bad_head_object_from_args: Head with CLI args");
    println!();
    println!("SAFE patterns (should NOT trigger):");
    println!("  - safe_hardcoded_values: Static bucket/prefix");
    println!("  - safe_config_constant: Const values");
    println!("  - safe_validated_bucket: Allowlist validation");
    println!("  - safe_sanitized_prefix: Path traversal prevention");
    println!("  - safe_scoped_key: User-scoped with sanitization");
    println!("  - safe_prefix_scoping: starts_with validation");
}
