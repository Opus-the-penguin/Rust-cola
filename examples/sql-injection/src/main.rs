//! SQL Injection Test Cases for RUSTCOLA087
//!
//! This module contains test cases for detecting SQL injection vulnerabilities
//! where untrusted input flows to SQL query construction without proper
//! parameterization.
//!
//! ## Vulnerability Pattern
//!
//! SQL injection occurs when user-controlled input is concatenated or formatted
//! directly into SQL query strings instead of using parameterized queries.
//! This allows attackers to modify query logic, bypass authentication, or
//! extract/modify sensitive data.
//!
//! ## Detection Approach
//!
//! RUSTCOLA087 uses interprocedural taint tracking:
//! 1. **Sources**: env::var, env::args, stdin, HTTP request parameters
//! 2. **Sinks**: raw SQL execution (sql_query, execute, query, prepare with string)
//! 3. **Sanitizers**: Parameterized queries, prepared statements with bind params

use std::env;
use std::io::{self, BufRead};

// ============================================================================
// VULNERABLE PATTERNS - Should trigger RUSTCOLA087
// ============================================================================

/// BAD: SQL query built with format! and environment variable
/// Attacker can set USER_ID="1; DROP TABLE users; --" for SQL injection
pub fn bad_format_env_var() -> String {
    let user_id = env::var("USER_ID").unwrap_or_default();
    // Vulnerable: direct string interpolation into SQL
    let query = format!("SELECT * FROM users WHERE id = {}", user_id);
    // Would execute: execute(&query)
    query
}

/// BAD: SQL query built with CLI argument
pub fn bad_format_cli_arg() -> String {
    let args: Vec<String> = env::args().collect();
    let username = args.get(1).cloned().unwrap_or_default();
    // Vulnerable: CLI argument directly in SQL
    let query = format!("SELECT * FROM users WHERE username = '{}'", username);
    query
}

/// BAD: SQL query from stdin input
pub fn bad_stdin_query() -> io::Result<String> {
    let stdin = io::stdin();
    let mut search_term = String::new();
    stdin.lock().read_line(&mut search_term)?;
    let search_term = search_term.trim();
    
    // Vulnerable: stdin input in LIKE clause
    let query = format!("SELECT * FROM products WHERE name LIKE '%{}%'", search_term);
    Ok(query)
}

/// BAD: Concatenation instead of format
pub fn bad_concat_query() -> String {
    let table_name = env::var("TABLE").unwrap_or_default();
    // Vulnerable: string concatenation
    let query = "SELECT * FROM ".to_string() + &table_name + " WHERE active = 1";
    query
}

/// BAD: SQL query with multiple user inputs
pub fn bad_multiple_inputs() -> String {
    let username = env::var("USERNAME").unwrap_or_default();
    let password = env::var("PASSWORD").unwrap_or_default();
    // Vulnerable: classic login bypass - username: "admin' --"
    let query = format!(
        "SELECT * FROM users WHERE username = '{}' AND password = '{}'",
        username, password
    );
    query
}

/// BAD: ORDER BY injection
pub fn bad_order_by_injection() -> String {
    let sort_column = env::var("SORT_BY").unwrap_or_default();
    // Vulnerable: ORDER BY clause injection
    let query = format!("SELECT * FROM products ORDER BY {}", sort_column);
    query
}

/// BAD: INSERT with user data
pub fn bad_insert_injection() -> String {
    let name = env::var("ITEM_NAME").unwrap_or_default();
    let price = env::var("ITEM_PRICE").unwrap_or_default();
    // Vulnerable: INSERT statement with unescaped values
    let query = format!(
        "INSERT INTO products (name, price) VALUES ('{}', {})",
        name, price
    );
    query
}

/// BAD: UPDATE with user data  
pub fn bad_update_injection() -> String {
    let user_id = env::var("USER_ID").unwrap_or_default();
    let new_email = env::var("NEW_EMAIL").unwrap_or_default();
    // Vulnerable: UPDATE with unescaped WHERE clause
    let query = format!(
        "UPDATE users SET email = '{}' WHERE id = {}",
        new_email, user_id
    );
    query
}

/// BAD: DELETE with user input
pub fn bad_delete_injection() -> String {
    let record_id = env::var("RECORD_ID").unwrap_or_default();
    // Vulnerable: DELETE without parameterization
    let query = format!("DELETE FROM records WHERE id = {}", record_id);
    query
}

/// BAD: Interprocedural - helper function returns tainted data
fn get_user_input() -> String {
    env::var("USER_INPUT").unwrap_or_default()
}

pub fn bad_interprocedural_query() -> String {
    let input = get_user_input();
    // Vulnerable: taint flows through helper
    let query = format!("SELECT * FROM data WHERE field = '{}'", input);
    query
}

/// BAD: Deep interprocedural flow
fn get_search_term() -> String {
    env::var("SEARCH").unwrap_or_default()
}

fn build_search_clause() -> String {
    let term = get_search_term();
    format!("name LIKE '%{}%'", term)
}

pub fn bad_deep_interprocedural() -> String {
    let clause = build_search_clause();
    // Vulnerable: taint flows through multiple functions
    let query = format!("SELECT * FROM products WHERE {}", clause);
    query
}

/// BAD: SQL executed via rusqlite-style API
pub fn bad_rusqlite_execute(user_id: &str) -> String {
    // Simulating rusqlite::Connection::execute pattern
    // Vulnerable: user input directly in query string
    let query = format!("UPDATE users SET last_login = NOW() WHERE id = {}", user_id);
    // conn.execute(&query, [])
    query
}

/// BAD: SQL executed via sqlx-style raw query
pub fn bad_sqlx_query_as() -> String {
    let email = env::var("EMAIL").unwrap_or_default();
    // Simulating sqlx::query! or query_as pattern without bind params
    // Vulnerable: string interpolation
    let query = format!("SELECT id, name FROM users WHERE email = '{}'", email);
    // sqlx::query_as::<_, User>(&query).fetch_one(&pool)
    query
}

/// BAD: Diesel raw SQL query
pub fn bad_diesel_sql_query() -> String {
    let category = env::var("CATEGORY").unwrap_or_default();
    // Simulating diesel::sql_query pattern
    // Vulnerable: raw SQL with user input
    let query = format!(
        "SELECT * FROM products WHERE category = '{}' ORDER BY price",
        category
    );
    // diesel::sql_query(&query).load::<Product>(&mut conn)
    query
}

// ============================================================================
// SAFE PATTERNS - Should NOT trigger RUSTCOLA087
// ============================================================================

/// SAFE: Hardcoded query, no user input
pub fn safe_hardcoded_query() -> String {
    let query = "SELECT * FROM users WHERE active = 1".to_string();
    query
}

/// SAFE: Parameterized query placeholder (rusqlite style)
pub fn safe_parameterized_rusqlite() -> (String, String) {
    let user_id = env::var("USER_ID").unwrap_or_default();
    // Safe: using ? placeholder with separate parameter
    let query = "SELECT * FROM users WHERE id = ?".to_string();
    // conn.execute(&query, [&user_id])
    (query, user_id)
}

/// SAFE: Parameterized query with named params (rusqlite style)
pub fn safe_named_params() -> (String, String) {
    let username = env::var("USERNAME").unwrap_or_default();
    // Safe: named parameter :username bound separately
    let query = "SELECT * FROM users WHERE username = :username".to_string();
    // conn.execute(&query, &[(":username", &username)])
    (query, username)
}

/// SAFE: Parameterized query (sqlx style with $1)
pub fn safe_parameterized_sqlx() -> (String, String) {
    let user_id = env::var("USER_ID").unwrap_or_default();
    // Safe: $1 placeholder with bind()
    let query = "SELECT * FROM users WHERE id = $1".to_string();
    // sqlx::query(&query).bind(&user_id).fetch_one(&pool)
    (query, user_id)
}

/// SAFE: Query builder pattern (typically safe)
pub fn safe_query_builder() -> String {
    let _filter_active = env::var("FILTER_ACTIVE").unwrap_or_default();
    // Safe: query builders typically handle escaping
    // QueryBuilder::new().select("*").from("users").where_eq("active", filter_active)
    "SELECT * FROM users WHERE active = ?".to_string()
}

/// SAFE: ORM with type-safe queries (Diesel DSL)
pub fn safe_diesel_dsl() -> String {
    let _user_id = env::var("USER_ID").unwrap_or_default();
    // Safe: Diesel's DSL uses parameterized queries internally
    // users::table.filter(users::id.eq(&user_id)).first::<User>(&mut conn)
    "Diesel DSL query - parameterized internally".to_string()
}

/// SAFE: Allowlist validation for table/column names
pub fn safe_allowlist_table() -> String {
    let table = env::var("TABLE").unwrap_or_default();
    // Safe: validating against allowlist
    let allowed_tables = ["users", "products", "orders"];
    let safe_table = if allowed_tables.contains(&table.as_str()) {
        &table
    } else {
        "users"
    };
    format!("SELECT * FROM {} WHERE active = 1", safe_table)
}

/// SAFE: Integer parsing validation
pub fn safe_integer_validated() -> String {
    let user_id_str = env::var("USER_ID").unwrap_or_default();
    // Safe: parsing to integer prevents SQL injection
    let user_id: i32 = user_id_str.parse().unwrap_or(0);
    format!("SELECT * FROM users WHERE id = {}", user_id)
}

/// SAFE: Regex validation for alphanumeric only
pub fn safe_regex_validated() -> String {
    let column = env::var("SORT_COLUMN").unwrap_or_default();
    // Safe: regex ensures alphanumeric only
    let is_safe = column.chars().all(|c| c.is_alphanumeric() || c == '_');
    let safe_column = if is_safe { &column } else { "id" };
    format!("SELECT * FROM users ORDER BY {}", safe_column)
}

/// SAFE: Escaped string (db-specific escaping)
pub fn safe_escaped_string() -> String {
    let search = env::var("SEARCH").unwrap_or_default();
    // Safe: proper escaping (simulated)
    let escaped = search.replace('\'', "''").replace('\\', "\\\\");
    format!("SELECT * FROM products WHERE name = '{}'", escaped)
}

/// SAFE: Prepared statement pattern
pub fn safe_prepared_statement() -> (String, Vec<String>) {
    let params: Vec<String> = vec![
        env::var("PARAM1").unwrap_or_default(),
        env::var("PARAM2").unwrap_or_default(),
    ];
    // Safe: prepared statement with placeholders
    let query = "SELECT * FROM data WHERE field1 = ? AND field2 = ?".to_string();
    (query, params)
}

// ============================================================================
// Entry point
// ============================================================================

fn main() {
    println!("SQL Injection test cases for RUSTCOLA087");
    println!("Run with: cargo cola --clear-cache");
}
