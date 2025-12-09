//! Test cases for RUSTCOLA093: Blocking Operations in Async Context
//!
//! This extends RUSTCOLA037 (blocking-sleep-in-async) to detect a broader range
//! of blocking operations that can stall async executors:
//! - std::sync::Mutex::lock() (blocking, should use tokio::sync::Mutex)
//! - std::fs::* operations (blocking I/O)
//! - std::net::* operations (blocking network)
//! - std::io::stdin/stdout/stderr (blocking console I/O)
//! - reqwest::blocking::* (blocking HTTP client)

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

// ============================================================================
// BAD PATTERNS - Blocking operations in async context
// ============================================================================

/// BAD: std::sync::Mutex::lock() in async function blocks the executor
pub async fn bad_sync_mutex_lock() {
    let mutex = Mutex::new(42);
    let guard = mutex.lock().unwrap();  // BLOCKING!
    println!("Value: {}", *guard);
}

/// BAD: Multiple sync mutex operations
pub async fn bad_multiple_mutex_locks() {
    let m1 = Mutex::new(1);
    let m2 = Mutex::new(2);
    let g1 = m1.lock().unwrap();  // BLOCKING!
    let g2 = m2.lock().unwrap();  // BLOCKING!
    println!("{} {}", *g1, *g2);
}

/// BAD: std::fs::read_to_string in async function
pub async fn bad_fs_read() -> std::io::Result<String> {
    fs::read_to_string("/etc/hosts")  // BLOCKING!
}

/// BAD: std::fs::write in async function
pub async fn bad_fs_write() -> std::io::Result<()> {
    fs::write("/tmp/test.txt", "data")  // BLOCKING!
}

/// BAD: std::fs::read in async function
pub async fn bad_fs_read_bytes() -> std::io::Result<Vec<u8>> {
    fs::read("/etc/hosts")  // BLOCKING!
}

/// BAD: std::fs::remove_file in async function
pub async fn bad_fs_remove() -> std::io::Result<()> {
    fs::remove_file("/tmp/test.txt")  // BLOCKING!
}

/// BAD: std::fs::create_dir_all in async function
pub async fn bad_fs_create_dir() -> std::io::Result<()> {
    fs::create_dir_all("/tmp/test/nested")  // BLOCKING!
}

/// BAD: std::fs::metadata in async function
pub async fn bad_fs_metadata() -> std::io::Result<fs::Metadata> {
    fs::metadata("/etc/hosts")  // BLOCKING!
}

/// BAD: std::fs::copy in async function
pub async fn bad_fs_copy() -> std::io::Result<u64> {
    fs::copy("/etc/hosts", "/tmp/hosts.bak")  // BLOCKING!
}

/// BAD: std::fs::rename in async function
pub async fn bad_fs_rename() -> std::io::Result<()> {
    fs::rename("/tmp/old.txt", "/tmp/new.txt")  // BLOCKING!
}

/// BAD: std::net::TcpStream::connect in async function
pub async fn bad_tcp_connect() -> std::io::Result<TcpStream> {
    TcpStream::connect("127.0.0.1:8080")  // BLOCKING!
}

/// BAD: std::net::TcpListener::bind in async function
pub async fn bad_tcp_bind() -> std::io::Result<TcpListener> {
    TcpListener::bind("127.0.0.1:8080")  // BLOCKING!
}

/// BAD: std::io::stdin().read_line in async function
pub async fn bad_stdin_read() -> std::io::Result<String> {
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer)?;  // BLOCKING!
    Ok(buffer)
}

/// BAD: std::io::stdout().write_all in async function
pub async fn bad_stdout_write() -> std::io::Result<()> {
    std::io::stdout().write_all(b"Hello\n")  // BLOCKING!
}

/// BAD: File::open + read in async function
pub async fn bad_file_open_read() -> std::io::Result<String> {
    let mut file = fs::File::open("/etc/hosts")?;  // BLOCKING!
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;  // BLOCKING!
    Ok(contents)
}

/// BAD: File::create + write in async function
pub async fn bad_file_create_write() -> std::io::Result<()> {
    let mut file = fs::File::create("/tmp/test.txt")?;  // BLOCKING!
    file.write_all(b"Hello")?;  // BLOCKING!
    Ok(())
}

/// BAD: thread::sleep in async (covered by RUSTCOLA037, included for completeness)
pub async fn bad_thread_sleep() {
    std::thread::sleep(Duration::from_secs(1));  // BLOCKING!
}

// ============================================================================
// SAFE PATTERNS - Using async-compatible alternatives
// ============================================================================

/// SAFE: tokio::sync::Mutex is async-aware
pub async fn safe_tokio_mutex() {
    let mutex = tokio::sync::Mutex::new(42);
    let guard = mutex.lock().await;  // Non-blocking!
    println!("Value: {}", *guard);
}

/// SAFE: tokio::fs for async file operations
pub async fn safe_tokio_fs_read() -> std::io::Result<String> {
    tokio::fs::read_to_string("/etc/hosts").await
}

/// SAFE: tokio::fs::write for async file writing
pub async fn safe_tokio_fs_write() -> std::io::Result<()> {
    tokio::fs::write("/tmp/test.txt", "data").await
}

/// SAFE: tokio::net::TcpStream::connect for async networking
pub async fn safe_tokio_tcp_connect() -> std::io::Result<tokio::net::TcpStream> {
    tokio::net::TcpStream::connect("127.0.0.1:8080").await
}

/// SAFE: tokio::net::TcpListener::bind for async networking
pub async fn safe_tokio_tcp_bind() -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind("127.0.0.1:8080").await
}

/// SAFE: tokio::time::sleep for async sleep
pub async fn safe_tokio_sleep() {
    tokio::time::sleep(Duration::from_secs(1)).await;
}

/// SAFE: tokio::io::stdin for async stdin
pub async fn safe_tokio_stdin() -> std::io::Result<String> {
    use tokio::io::AsyncBufReadExt;
    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin);
    let mut buffer = String::new();
    reader.read_line(&mut buffer).await?;
    Ok(buffer)
}

/// SAFE: spawn_blocking for intentional blocking ops
pub async fn safe_spawn_blocking_fs() -> std::io::Result<String> {
    tokio::task::spawn_blocking(|| {
        fs::read_to_string("/etc/hosts")
    }).await.unwrap()
}

/// SAFE: spawn_blocking for sync mutex
pub async fn safe_spawn_blocking_mutex() {
    let mutex = std::sync::Arc::new(Mutex::new(42));
    let m = mutex.clone();
    tokio::task::spawn_blocking(move || {
        let guard = m.lock().unwrap();
        println!("Value: {}", *guard);
    }).await.unwrap();
}

/// SAFE: block_in_place for blocking ops (multi-threaded runtime only)
pub async fn safe_block_in_place_fs() -> std::io::Result<String> {
    tokio::task::block_in_place(|| {
        fs::read_to_string("/etc/hosts")
    })
}

/// SAFE: Sync mutex in non-async function (not our concern)
pub fn sync_function_mutex() {
    let mutex = Mutex::new(42);
    let guard = mutex.lock().unwrap();  // Fine in sync context
    println!("Value: {}", *guard);
}

/// SAFE: Sync fs in non-async function (not our concern)
pub fn sync_function_fs() -> std::io::Result<String> {
    fs::read_to_string("/etc/hosts")  // Fine in sync context
}

fn main() {
    println!("Blocking in Async Context Test Suite");
}
