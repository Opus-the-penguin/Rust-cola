// Test suite for RUSTCOLA065: Cleartext environment variable exposure
//
// Setting environment variables with sensitive values in cleartext can expose
// secrets to other processes, child processes, and system logs. Environment
// variables are visible via /proc on Linux and process inspection tools.
//
// This detects env::set_var() with sensitive variable names like:
// - PASSWORD, SECRET, TOKEN, API_KEY, AUTH_TOKEN
// - Database credentials, private keys, etc.

use std::env;

// ===== PROBLEMATIC PATTERNS (8 functions) =====
// These set environment variables with sensitive names

pub fn set_password_env() {
    env::set_var("PASSWORD", "mysecret123"); // NOSEC - Cleartext password in env
}

pub fn set_api_key_env() {
    env::set_var("API_KEY", "sk-1234567890abcdef"); // NOSEC - API key in env
}

pub fn set_secret_token() {
    let token = "ghp_secrettoken123";
    env::set_var("SECRET_TOKEN", token); // NOSEC - Secret token in env
}

pub fn set_db_password() {
    env::set_var("DB_PASSWORD", "dbpass456"); // NOSEC - DB password in env
}

pub fn set_auth_token() {
    env::set_var("AUTH_TOKEN", get_token()); // NOSEC - Auth token in env
}

pub fn set_private_key() {
    env::set_var("PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----"); // NOSEC - Private key in env
}

pub fn set_jwt_secret() {
    env::set_var("JWT_SECRET", "supersecret"); // NOSEC - JWT secret in env
}

pub fn set_access_token() {
    let token = fetch_access_token();
    env::set_var("ACCESS_TOKEN", &token); // NOSEC - Access token in env
}

// ===== SAFE PATTERNS (7 functions) =====
// These either don't use sensitive names or read (not set) env vars

pub fn set_normal_config() {
    env::set_var("LOG_LEVEL", "debug"); // Safe: Non-sensitive config
}

pub fn set_path_var() {
    env::set_var("PATH", "/usr/local/bin"); // Safe: Path is not sensitive
}

pub fn read_password_env() {
    let _password = env::var("PASSWORD"); // Safe: Reading, not setting
}

pub fn set_user_name() {
    env::set_var("USER_NAME", "alice"); // Safe: Username is not a secret
}

pub fn set_port_config() {
    env::set_var("SERVER_PORT", "8080"); // Safe: Port is public config
}

pub fn remove_password_env() {
    env::remove_var("PASSWORD"); // Safe: Removing, not setting
}

pub fn proper_secret_handling() {
    // Safe: Using secure credential storage instead of env vars
    store_in_keyring("PASSWORD", "mysecret");
}

// Helper functions
fn get_token() -> String {
    "token123".to_string()
}

fn fetch_access_token() -> String {
    "access_token_xyz".to_string()
}

fn store_in_keyring(_key: &str, _value: &str) {
    // Mock secure storage
}
