# RUSTCOLA051: Try Operator on io::Result

## Problem

Using the `?` operator directly on `std::io::Result` can lose important error context. IO errors are often generic and don't include information about:

- Which file failed to open
- What operation was being performed
- The full path that was attempted
- Whether it was a read, write, or create operation

This makes debugging production failures much harder, especially in complex applications with many file operations.

## Example

### ❌ Problematic (loses context)

```rust
pub fn read_config_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;  // Error: "No such file or directory"
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}
```

When this fails, you get: `Error: Os { code: 2, kind: NotFound, message: "No such file or directory" }`

But you don't know **which** file wasn't found!

### ✅ Better (adds context)

```rust
pub fn read_config_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)
        .map_err(|e| io::Error::new(
            e.kind(), 
            format!("Failed to open config file {:?}: {}", path, e)
        ))?;
    
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| io::Error::new(
            e.kind(),
            format!("Failed to read config file {:?}: {}", path, e)
        ))?;
    
    Ok(contents)
}
```

Now you get: `Error: Custom { kind: NotFound, error: "Failed to open config file \"/etc/myapp/config.toml\": No such file or directory" }`

Much better for debugging!

### ✅ Even Better (custom error type)

```rust
#[derive(Debug)]
pub enum ConfigError {
    Io { operation: String, path: PathBuf, source: io::Error },
    Parse { message: String },
}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::Io {
            operation: "io operation".to_string(),
            path: PathBuf::new(),
            source: e,
        }
    }
}
```

## Why It Matters

In production systems, you need to know:

1. **Which file** caused the problem
2. **What operation** was attempted
3. **Context** about why the file was being accessed

Without this information, debugging becomes a guessing game.

## Detection

This rule detects functions that:
- Return `io::Result<T>`
- Use the `?` operator to propagate errors
- Don't wrap errors with additional context

## Parity

- Dylint: `try_io_result`
- Clippy: No equivalent (Clippy focuses on correctness, not error ergonomics)

## Severity

**Low** - This is a code quality issue, not a security vulnerability. However, it can make debugging security-relevant failures much harder.
