//! Test cases for RUSTCOLA090: Unbounded read_to_end Detection
//!
//! Detects when read_to_end() or read_to_string() is called on untrusted
//! sources (network streams, stdin, files from user paths) without size limits.
//! This can cause memory exhaustion DoS when attackers send large payloads.
//!
//! Safe patterns: .take(N) to limit bytes, size checks before allocation,
//! chunked reading with limits.

use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;

// ============================================================================
// BAD PATTERNS - Unbounded reads from untrusted sources
// ============================================================================

/// BAD: read_to_end on TcpStream without size limit
fn bad_tcp_read_to_end() -> io::Result<Vec<u8>> {
    let stream = TcpStream::connect("127.0.0.1:8080")?;
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?; // Unbounded!
    Ok(buffer)
}

/// BAD: read_to_string on TcpStream without size limit
fn bad_tcp_read_to_string() -> io::Result<String> {
    let mut stream = TcpStream::connect("127.0.0.1:8080")?;
    let mut content = String::new();
    stream.read_to_string(&mut content)?; // Unbounded!
    Ok(content)
}

/// BAD: read_to_end on stdin without limit
fn bad_stdin_read_to_end() -> io::Result<Vec<u8>> {
    let stdin = io::stdin();
    let mut buffer = Vec::new();
    stdin.lock().read_to_end(&mut buffer)?; // Unbounded!
    Ok(buffer)
}

/// BAD: read_to_string on stdin without limit
fn bad_stdin_read_to_string() -> io::Result<String> {
    let mut stdin = io::stdin();
    let mut content = String::new();
    stdin.read_to_string(&mut content)?; // Unbounded!
    Ok(content)
}

/// BAD: read_to_end on file from user-controlled path
fn bad_file_from_env() -> io::Result<Vec<u8>> {
    let file_path = env::var("INPUT_FILE").unwrap_or_default();
    let mut file = File::open(&file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?; // Unbounded on user-controlled file!
    Ok(buffer)
}

/// BAD: read_to_end on file from CLI argument
fn bad_file_from_args() -> io::Result<Vec<u8>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "No file"));
    }
    let mut file = File::open(&args[1])?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?; // Unbounded!
    Ok(buffer)
}

/// BAD: UnixStream read_to_end without limit
fn bad_unix_stream_read() -> io::Result<Vec<u8>> {
    let mut stream = UnixStream::connect("/tmp/socket.sock")?;
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer)?; // Unbounded!
    Ok(buffer)
}

/// BAD: BufReader wrapping network stream, still unbounded
fn bad_bufreader_tcp() -> io::Result<Vec<u8>> {
    let stream = TcpStream::connect("127.0.0.1:8080")?;
    let mut reader = BufReader::new(stream);
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?; // BufReader doesn't limit!
    Ok(data)
}

/// BAD: Accepted connection read without limit
fn bad_accepted_connection() -> io::Result<Vec<u8>> {
    let listener = TcpListener::bind("127.0.0.1:9000")?;
    let (mut socket, _) = listener.accept()?;
    let mut buffer = Vec::new();
    socket.read_to_end(&mut buffer)?; // Unbounded from client!
    Ok(buffer)
}

/// BAD: read_to_end in loop without per-connection limit
fn bad_server_loop() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:9001")?;
    for stream in listener.incoming() {
        let mut socket = stream?;
        let mut buffer = Vec::new();
        socket.read_to_end(&mut buffer)?; // Each client can exhaust memory
        process_data(&buffer);
    }
    Ok(())
}

fn process_data(_data: &[u8]) {}

// ============================================================================
// SAFE PATTERNS - Bounded reads with size limits
// ============================================================================

/// SAFE: Using take() to limit bytes read
fn safe_tcp_with_take() -> io::Result<Vec<u8>> {
    let stream = TcpStream::connect("127.0.0.1:8080")?;
    let mut reader = stream.take(1024 * 1024); // 1MB limit
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// SAFE: Size check before reading
fn safe_file_with_size_check() -> io::Result<Vec<u8>> {
    let file_path = env::var("INPUT_FILE").unwrap_or_default();
    let metadata = std::fs::metadata(&file_path)?;

    const MAX_SIZE: u64 = 10 * 1024 * 1024; // 10MB
    if metadata.len() > MAX_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "File too large"));
    }

    let mut file = File::open(&file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// SAFE: Chunked reading with limit
fn safe_chunked_read() -> io::Result<Vec<u8>> {
    let stream = TcpStream::connect("127.0.0.1:8080")?;
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();
    let mut total = 0usize;
    const MAX_SIZE: usize = 1024 * 1024;

    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        let len = chunk.len().min(MAX_SIZE - total);
        buffer.extend_from_slice(&chunk[..len]);
        reader.consume(len);
        total += len;
        if total >= MAX_SIZE {
            break;
        }
    }
    Ok(buffer)
}

/// SAFE: Pre-allocated buffer with fixed size
fn safe_fixed_buffer() -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect("127.0.0.1:8080")?;
    let mut buffer = vec![0u8; 4096]; // Fixed size
    let n = stream.read(&mut buffer)?;
    buffer.truncate(n);
    Ok(buffer)
}

/// SAFE: Hardcoded file path (trusted source)
fn safe_hardcoded_file() -> io::Result<Vec<u8>> {
    let mut file = File::open("/etc/hosts")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?; // Known small file
    Ok(buffer)
}

/// SAFE: Reading from internal config (trusted)
fn safe_internal_config() -> io::Result<String> {
    let mut file = File::open("/app/config.json")?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

/// SAFE: bytes() iterator with take limit
fn safe_bytes_with_take() -> io::Result<Vec<u8>> {
    let stream = TcpStream::connect("127.0.0.1:8080")?;
    let bytes: Result<Vec<u8>, _> = stream.bytes().take(1024).collect();
    bytes
}

/// SAFE: Limited stdin with take
fn safe_stdin_with_take() -> io::Result<Vec<u8>> {
    let stdin = io::stdin();
    let mut buffer = Vec::new();
    stdin.lock().take(10000).read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// SAFE: Explicit capacity with with_capacity (shows awareness)
fn safe_with_capacity_limit() -> io::Result<Vec<u8>> {
    let stream = TcpStream::connect("127.0.0.1:8080")?;
    let mut reader = stream.take(8192);
    let mut buffer = Vec::with_capacity(8192);
    reader.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn main() {
    println!("Unbounded Read Detection Test Cases");

    // Safe example
    match safe_hardcoded_file() {
        Ok(data) => println!("Read {} bytes from /etc/hosts", data.len()),
        Err(e) => println!("Error: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_patterns_compile() {
        // Just verify safe patterns compile
        let _ = safe_hardcoded_file();
    }
}
