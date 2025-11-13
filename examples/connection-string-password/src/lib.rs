// PROBLEMATIC: Connection strings with empty or hardcoded passwords

pub fn postgres_empty_password() {
    // PROBLEMATIC: Empty password (user:@host pattern)
    let _conn_str = "postgres://user:@localhost/mydb";
}

pub fn mysql_hardcoded_password() {
    // PROBLEMATIC: Hardcoded password in connection string
    let _conn_str = "mysql://root:password123@localhost:3306/mydb";
}

pub fn redis_hardcoded_password() {
    // PROBLEMATIC: Hardcoded password
    let _conn_str = "redis://:secretpass@localhost:6379";
}

pub fn postgresql_hardcoded_password() {
    // PROBLEMATIC: Hardcoded password with special chars
    let _conn_str = "postgresql://admin:P@ssw0rd!@db.example.com:5432/production";
}

pub fn amqp_empty_password() {
    // PROBLEMATIC: Empty password
    let _conn_str = "amqp://guest:@rabbitmq.local:5672/";
}

pub fn mongodb_hardcoded_password() {
    // PROBLEMATIC: Hardcoded MongoDB password
    let _conn_str = "mongodb://user:mongo123@mongodb.example.com:27017/database";
}

// SAFE: Proper ways to handle connection strings

pub fn postgres_from_env() {
    // SAFE: Loading from environment variable
    let _conn_str = std::env::var("DATABASE_URL").unwrap_or_default();
}

pub fn mysql_constructed_from_env() {
    // SAFE: Building connection string from env vars
    let host = std::env::var("DB_HOST").unwrap_or_else(|_| "localhost".to_string());
    let user = std::env::var("DB_USER").unwrap_or_else(|_| "user".to_string());
    let pass = std::env::var("DB_PASS").unwrap_or_default();
    let _conn_str = format!("mysql://{}:{}@{}/mydb", user, pass, host);
}

pub fn redis_localhost_no_auth() {
    // SAFE: Localhost without authentication (development)
    let _conn_str = "redis://localhost:6379";
}

pub fn postgres_with_port_only() {
    // SAFE: Just host and port, no credentials
    let _conn_str = "postgres://localhost:5432/mydb";
}

pub fn postgres_unix_socket() {
    // SAFE: Unix socket connection (no password needed)
    let _conn_str = "postgres:///var/run/postgresql";
}

pub fn connection_string_const() {
    // SAFE: Using a constant that should be defined elsewhere
    const DATABASE_URL: &str = "postgres://localhost/mydb";
    let _conn_str = DATABASE_URL;
}

pub fn unrelated_string() {
    // SAFE: Not a connection string
    let _s = "This is just a regular string with postgres:// in it as text";
}
