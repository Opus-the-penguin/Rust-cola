use std::fs::OpenOptions;
use std::io::Write;

/// BAD: Creates writable file without truncate or append
/// RUSTCOLA032 should flag this
pub fn create_log_file_bad() -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open("app.log")?;
    
    file.write_all(b"New log entry\n")?;
    Ok(())
}

/// GOOD: Uses truncate to clear old content
pub fn create_log_file_with_truncate() -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("app.log")?;
    
    file.write_all(b"New log entry\n")?;
    Ok(())
}

/// GOOD: Uses append mode for logs
pub fn append_log_file() -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open("app.log")?;
    
    file.write_all(b"New log entry\n")?;
    Ok(())
}

/// BAD: Multiline builder pattern without truncate
/// RUSTCOLA032 should flag this
pub fn create_config_file_bad() -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open("/etc/myapp/config.txt")?;
    
    file.write_all(b"admin_password=new_password\n")?;
    Ok(())
}

/// GOOD: Read-only access doesn't need truncate
pub fn read_file() -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = OpenOptions::new()
        .read(true)
        .open("data.bin")?;
    
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// GOOD: Create without write is fine
pub fn create_readonly() -> std::io::Result<()> {
    let _file = OpenOptions::new()
        .create(true)
        .read(true)
        .open("readonly.txt")?;
    
    Ok(())
}
