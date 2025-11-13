# Absolute Path in join() Test Cases

This example demonstrates detection of absolute paths passed to `Path::join()` or `PathBuf::push()`.

## The Problem

When you pass an absolute path to `Path::join()` or `PathBuf::push()`, the absolute path **completely replaces** the base path. This defeats any sanitization or security checks on the base directory.

### How join() Works

```rust
let base = Path::new("/var/www/uploads");

// Relative path - properly joined
base.join("user/file.txt");
// Result: /var/www/uploads/user/file.txt ✓

// Absolute path - BASE IS IGNORED!
base.join("/etc/passwd");
// Result: /etc/passwd ✗ (base path discarded!)
```

## Security Impact

This vulnerability enables **path traversal attacks** by completely bypassing base directory restrictions:

```rust
// Intended: files only in /var/www/uploads/
let base = PathBuf::from("/var/www/uploads");

// Attacker provides: "/etc/passwd"
let user_input = get_user_filename();
let path = base.join(user_input);

// If user_input is "/etc/passwd":
// - Expected: /var/www/uploads/etc/passwd ✓
// - Actual:   /etc/passwd ✗
// - Result:   Read arbitrary system files!
```

## Real-World Scenarios

### 1. File Upload Vulnerability

```rust
// VULNERABLE
fn save_upload(filename: &str, data: &[u8]) -> io::Result<()> {
    let upload_dir = Path::new("/var/www/uploads");
    let path = upload_dir.join(filename);  // If filename is absolute...
    fs::write(path, data)  // ...write anywhere!
}
```

### 2. Log File Injection

```rust
// VULNERABLE  
fn create_log_file(log_name: &str) -> io::Result<File> {
    let log_dir = Path::new("/var/log/app");
    let path = log_dir.join(log_name);  // Attacker provides "/tmp/payload"
    File::create(path)  // Creates file outside log directory!
}
```

### 3. Configuration File Access

```rust
// VULNERABLE
fn load_config(config_name: &str) -> io::Result<String> {
    let config_dir = Path::new("/app/configs");
    let path = config_dir.join(config_name);  // Attacker provides "/etc/shadow"
    fs::read_to_string(path)  // Reads arbitrary files!
}
```

## Platform-Specific Absolute Paths

### Unix/Linux/macOS
- Starts with `/`: `/etc/passwd`, `/home/user`, `/var/log`
- Root always begins with forward slash

### Windows
- Drive letter: `C:\Windows`, `D:\Data`
- UNC paths: `\\server\share\file`
- Both backslash and forward slash work

## Safe Alternatives

### 1. Validate Relative Paths

```rust
fn safe_join(base: &Path, user_path: &str) -> Option<PathBuf> {
    let user = Path::new(user_path);
    
    // Reject absolute paths
    if user.is_absolute() {
        return None;
    }
    
    // Optionally: check for parent directory traversal
    if user.components().any(|c| c == Component::ParentDir) {
        return None;
    }
    
    Some(base.join(user))
}
```

### 2. Canonicalize and Check

```rust
fn safe_join_checked(base: &Path, user_path: &str) -> io::Result<PathBuf> {
    let joined = base.join(user_path);
    let canonical = joined.canonicalize()?;
    
    // Ensure result is still under base directory
    if !canonical.starts_with(base) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Path traversal attempt"
        ));
    }
    
    Ok(canonical)
}
```

### 3. Use File Name Only

```rust
fn safe_join_filename(base: &Path, user_input: &str) -> Option<PathBuf> {
    // Extract just the filename, ignore any path components
    let filename = Path::new(user_input)
        .file_name()?;
    
    Some(base.join(filename))
}
```

## Detection Strategy

RUSTCOLA058 detects:

1. **join() with string literals**: Checks for absolute path patterns in literals
2. **Common absolute prefixes**: Unix (`/etc`, `/usr`, `/var`, `/home`) and Windows (`C:\`, `D:\`)
3. **Path operations**: Flags when join/push methods are used with suspicious paths

## References

- Clippy lint: `join_absolute_paths`
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- OWASP: Path Traversal
