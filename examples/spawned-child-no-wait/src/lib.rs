// Test suite for RUSTCOLA067: Spawned child without wait
//
// Based on Clippy's zombie_processes lint. When a process is spawned via
// Command::spawn(), the resulting Child must be waited on via wait() or
// status() to collect its exit status. Failing to wait creates zombie
// processes that consume system resources (PIDs, kernel memory for process
// table entries) until the parent exits.
//
// This is particularly problematic in long-running services that spawn
// many child processes.

use std::process::Command;
use std::io;

// ============================================================================
// PROBLEMATIC: Child spawned but not waited on
// ============================================================================

/// Spawn child and forget - PROBLEMATIC
pub fn spawn_and_forget() -> io::Result<()> {
    Command::new("ls").spawn()?;
    // Child is dropped without wait() - creates zombie
    Ok(())
}

/// Spawn child, store but never wait - PROBLEMATIC
pub fn spawn_stored_no_wait() -> io::Result<()> {
    let _child = Command::new("echo").arg("test").spawn()?;
    // Child dropped at end of scope without wait()
    Ok(())
}

/// Spawn in loop without waiting - PROBLEMATIC
pub fn spawn_loop_no_wait(count: usize) -> io::Result<()> {
    for i in 0..count {
        Command::new("echo").arg(i.to_string()).spawn()?;
        // Each child becomes a zombie
    }
    Ok(())
}

/// Conditional spawn without wait - PROBLEMATIC
pub fn conditional_spawn_no_wait(condition: bool) -> io::Result<()> {
    if condition {
        Command::new("pwd").spawn()?;
        // Zombie if condition is true
    }
    Ok(())
}

/// Multiple commands, one without wait - PROBLEMATIC
pub fn mixed_spawn_one_no_wait() -> io::Result<()> {
    let mut child1 = Command::new("ls").spawn()?;
    child1.wait()?; // This one is OK
    
    Command::new("pwd").spawn()?; // This one creates zombie
    Ok(())
}

/// Spawn and return child - PROBLEMATIC (caller might not wait)
pub fn spawn_and_return() -> io::Result<std::process::Child> {
    Command::new("sleep").arg("1").spawn()
    // Caller responsibility, but often forgotten
}

/// Spawn with error handling but no wait - PROBLEMATIC
pub fn spawn_with_error_handling() -> io::Result<()> {
    match Command::new("ls").spawn() {
        Ok(_child) => {
            // Child not waited on
            println!("Process spawned");
        }
        Err(e) => eprintln!("Failed: {}", e),
    }
    Ok(())
}

// ============================================================================
// SAFE: Proper child process handling
// ============================================================================

/// Spawn and immediately wait - SAFE
pub fn spawn_and_wait() -> io::Result<()> {
    let mut child = Command::new("ls").spawn()?;
    child.wait()?;
    Ok(())
}

/// Spawn and check status - SAFE
pub fn spawn_and_status() -> io::Result<()> {
    let mut child = Command::new("pwd").spawn()?;
    let status = child.wait()?;
    println!("Exit status: {}", status);
    Ok(())
}

/// Spawn in loop with wait - SAFE
pub fn spawn_loop_with_wait(count: usize) -> io::Result<()> {
    for i in 0..count {
        let mut child = Command::new("echo").arg(i.to_string()).spawn()?;
        child.wait()?;
    }
    Ok(())
}

/// Store children and wait later - SAFE
pub fn spawn_store_wait_later() -> io::Result<()> {
    let mut children = Vec::new();
    for i in 0..3 {
        let child = Command::new("echo").arg(i.to_string()).spawn()?;
        children.push(child);
    }
    
    for mut child in children {
        child.wait()?;
    }
    Ok(())
}

/// Conditional spawn with wait - SAFE
pub fn conditional_spawn_with_wait(condition: bool) -> io::Result<()> {
    if condition {
        let mut child = Command::new("pwd").spawn()?;
        child.wait()?;
    }
    Ok(())
}

/// Spawn with wait_with_output - SAFE
pub fn spawn_with_output() -> io::Result<()> {
    let child = Command::new("ls").spawn()?;
    let _output = child.wait_with_output()?;
    Ok(())
}

/// Use Command::output() directly - SAFE
pub fn use_output_directly() -> io::Result<()> {
    let _output = Command::new("pwd").output()?;
    // output() spawns and waits internally
    Ok(())
}

/// Use Command::status() directly - SAFE
pub fn use_status_directly() -> io::Result<()> {
    let _status = Command::new("ls").status()?;
    // status() spawns and waits internally
    Ok(())
}
