//! Test cases for RUSTCOLA115: Non-Cancellation-Safe Select
//!
//! This example demonstrates dangerous patterns where non-cancellation-safe
//! futures are used inside select! macros, which can lead to data loss.

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

// ============================================================================
// PROBLEMATIC: Non-cancellation-safe patterns in select!
// ============================================================================

/// PROBLEMATIC: read_line in select! - partial reads are lost on cancellation
async fn bad_read_line_in_select(stream: TcpStream, mut rx: mpsc::Receiver<()>) {
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    loop {
        tokio::select! {
            // This is NOT cancellation-safe! If a partial line was read
            // and then the other branch wins, those bytes are lost.
            line = lines.next_line() => {
                match line {
                    Ok(Some(l)) => println!("Got line: {}", l),
                    Ok(None) => break,
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            _ = rx.recv() => {
                println!("Received shutdown signal");
                break;
            }
        }
    }
}

/// PROBLEMATIC: read_exact in select! - partial reads are lost
async fn bad_read_exact_in_select(stream: TcpStream, mut rx: mpsc::Receiver<()>) {
    use tokio::io::AsyncReadExt;

    let mut stream = stream;
    let mut buffer = [0u8; 1024];

    loop {
        tokio::select! {
            // PROBLEMATIC: read_exact( is not cancellation safe
            result = stream.read_exact(&mut buffer) => {
                match result {
                    Ok(_) => println!("Read buffer"),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        break;
                    }
                }
            }
            _ = rx.recv() => {
                break;
            }
        }
    }
}

/// PROBLEMATIC: recv_many in select! - some messages may be lost
async fn bad_recv_many_in_select(mut rx1: mpsc::Receiver<String>, mut rx2: mpsc::Receiver<()>) {
    let mut buffer = Vec::with_capacity(10);

    loop {
        tokio::select! {
            // PROBLEMATIC: recv_many( is not cancellation safe
            count = rx1.recv_many(&mut buffer, 10) => {
                if count == 0 {
                    break;
                }
                for msg in buffer.drain(..) {
                    println!("Processing: {}", msg);
                }
            }
            _ = rx2.recv() => {
                break;
            }
        }
    }
}

/// PROBLEMATIC: read_to_end in select!
async fn bad_read_to_end_in_select(stream: TcpStream, mut rx: mpsc::Receiver<()>) {
    use tokio::io::AsyncReadExt;

    let mut stream = stream;
    let mut buffer = Vec::new();

    tokio::select! {
        // PROBLEMATIC: read_to_end( is not cancellation safe
        result = stream.read_to_end(&mut buffer) => {
            match result {
                Ok(n) => println!("Read {} bytes", n),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        _ = rx.recv() => {
            println!("Cancelled");
        }
    }
}

/// PROBLEMATIC: copy in select!
async fn bad_copy_in_select(
    mut reader: TcpStream,
    mut writer: tokio::fs::File,
    mut rx: mpsc::Receiver<()>,
) {
    use tokio::io::copy;

    tokio::select! {
        // PROBLEMATIC: copy( is not cancellation safe
        result = copy(&mut reader, &mut writer) => {
            match result {
                Ok(n) => println!("Copied {} bytes", n),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        _ = rx.recv() => {
            println!("Cancelled");
        }
    }
}

// ============================================================================
// SAFE: Cancellation-safe alternatives
// ============================================================================

/// SAFE: Using recv() instead of recv_many() - recv() is cancellation safe
async fn safe_recv_in_select(mut rx1: mpsc::Receiver<String>, mut rx2: mpsc::Receiver<()>) {
    loop {
        tokio::select! {
            // recv() is cancellation-safe - it doesn't start until polled
            // and if dropped, no messages are lost
            msg = rx1.recv() => {
                match msg {
                    Some(m) => println!("Got: {}", m),
                    None => break,
                }
            }
            _ = rx2.recv() => {
                break;
            }
        }
    }
}

/// SAFE: Pre-reading the line outside of select!
async fn safe_read_line_pattern(stream: TcpStream, mut rx: mpsc::Receiver<()>) {
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    loop {
        // Pin the future outside of select so we can resume it
        let next_line = lines.next_line();
        tokio::pin!(next_line);

        tokio::select! {
            // The future is owned and pinned - we can restart if needed
            line = &mut next_line => {
                match line {
                    Ok(Some(l)) => {
                        println!("Got line: {}", l);
                        // Loop continues with a new future
                    }
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        break;
                    }
                }
            }
            _ = rx.recv() => {
                // The pinned future will be dropped, but that's expected
                break;
            }
        }
    }
}

/// SAFE: Using biased select to prefer completing the read
async fn safe_biased_select(stream: TcpStream, mut rx: mpsc::Receiver<()>) {
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    loop {
        tokio::select! {
            biased;

            // By using biased, we ensure the line read completes first
            // if both are ready, reducing (but not eliminating) data loss
            line = lines.next_line() => {
                match line {
                    Ok(Some(l)) => println!("Got line: {}", l),
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        break;
                    }
                }
            }
            _ = rx.recv() => {
                break;
            }
        }
    }
}

fn main() {
    println!("RUSTCOLA115: Non-Cancellation-Safe Select Examples");
    println!("==================================================");
    println!();
    println!("PROBLEMATIC patterns (should trigger warnings):");
    println!("  - read_line() in select!");
    println!("  - read_exact() in select!");
    println!("  - recv_many() in select!");
    println!("  - read_to_end() in select!");
    println!("  - copy() in select!");
    println!();
    println!("SAFE alternatives:");
    println!("  - Use recv() instead of recv_many() (it's cancellation-safe)");
    println!("  - Pin the future outside select! and resume");
    println!("  - Use biased select to prefer completing reads");
}
