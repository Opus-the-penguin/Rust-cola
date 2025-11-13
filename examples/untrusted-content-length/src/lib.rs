//! Demonstrates RUSTSEC-2025-0015: Content-Length DoS vulnerability
//! 
//! This example shows how trusting remote Content-Length headers for allocations
//! can lead to denial-of-service attacks.

use bytes::BytesMut;

// ============================================================================
// VULNERABLE PATTERNS - Should trigger RUSTCOLA021
// ============================================================================

/// VULNERABLE: Directly using content_length() for Vec::with_capacity
/// An attacker can send Content-Length: 4294967295 to exhaust memory
pub fn vulnerable_direct_allocation(response: &reqwest::blocking::Response) {
    if let Some(len) = response.content_length() {
        // RUSTCOLA021 should flag this - unbounded allocation from untrusted header
        let _buffer: Vec<u8> = Vec::with_capacity(len as usize);
        // ... read response body ...
    }
}

/// VULNERABLE: Using header lookup with from_static
pub fn vulnerable_header_lookup(response: &reqwest::blocking::Response) {
    use reqwest::header::HeaderName;
    
    if let Some(header_value) = response.headers().get(HeaderName::from_static("content-length")) {
        if let Ok(len_str) = header_value.to_str() {
            if let Ok(len) = len_str.parse::<usize>() {
                // RUSTCOLA021 should flag this - tainted length from header lookup
                let _buffer: Vec<u8> = Vec::with_capacity(len);
                // ... read response body ...
            }
        }
    }
}

/// VULNERABLE: Using CONTENT_LENGTH constant
pub fn vulnerable_content_length_constant(response: &reqwest::blocking::Response) {
    use reqwest::header::CONTENT_LENGTH;
    
    if let Some(header_value) = response.headers().get(CONTENT_LENGTH) {
        if let Ok(len_str) = header_value.to_str() {
            if let Ok(len) = len_str.parse::<usize>() {
                // RUSTCOLA021 should flag this
                let _buffer: Vec<u8> = Vec::with_capacity(len);
                // ... read response body ...
            }
        }
    }
}

/// VULNERABLE: BytesMut::with_capacity (common in async HTTP clients)
pub fn vulnerable_bytes_mut_allocation(response: &reqwest::blocking::Response) {
    if let Some(len) = response.content_length() {
        // RUSTCOLA021 should flag this - BytesMut is also an allocation sink
        let _buffer = BytesMut::with_capacity(len as usize);
        // ... read response body ...
    }
}

/// VULNERABLE: Vec::reserve without bounds
pub fn vulnerable_reserve(response: &reqwest::blocking::Response) {
    let mut buffer: Vec<u8> = Vec::new();
    if let Some(len) = response.content_length() {
        // RUSTCOLA021 should flag this - reserve is also dangerous
        buffer.reserve(len as usize);
        // ... read response body ...
    }
}

/// VULNERABLE: Vec::reserve_exact without bounds
pub fn vulnerable_reserve_exact(response: &reqwest::blocking::Response) {
    let mut buffer: Vec<u8> = Vec::new();
    if let Some(len) = response.content_length() {
        // RUSTCOLA021 should flag this
        buffer.reserve_exact(len as usize);
        // ... read response body ...
    }
}

/// VULNERABLE: Indirect flow through variable
pub fn vulnerable_indirect_flow(response: &reqwest::blocking::Response) {
    if let Some(len) = response.content_length() {
        let capacity = len as usize; // Taint propagates through assignment
        // RUSTCOLA021 should flag this - taint tracked through assignment
        let _buffer: Vec<u8> = Vec::with_capacity(capacity);
        // ... read response body ...
    }
}

// ============================================================================
// SAFE PATTERNS - Should NOT trigger RUSTCOLA021
// ============================================================================

/// SAFE: Using min() to clamp allocation size
pub fn safe_with_min_clamp(response: &reqwest::blocking::Response) {
    const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10 MB limit
    
    if let Some(len) = response.content_length() {
        // Safe: clamped with min()
        let capacity = (len as usize).min(MAX_BUFFER_SIZE);
        let _buffer: Vec<u8> = Vec::with_capacity(capacity);
        // ... read response body safely ...
    }
}

/// SAFE: Using clamp() to enforce bounds
pub fn safe_with_clamp(response: &reqwest::blocking::Response) {
    const MIN_SIZE: usize = 1024;
    const MAX_SIZE: usize = 10 * 1024 * 1024;
    
    if let Some(len) = response.content_length() {
        // Safe: clamped with explicit bounds
        let capacity = (len as usize).clamp(MIN_SIZE, MAX_SIZE);
        let _buffer: Vec<u8> = Vec::with_capacity(capacity);
        // ... read response body safely ...
    }
}

/// SAFE: Using assert! to validate before allocation
pub fn safe_with_assert(response: &reqwest::blocking::Response) {
    const MAX_ALLOWED: usize = 50 * 1024 * 1024; // 50 MB
    
    if let Some(len) = response.content_length() {
        let capacity = len as usize;
        // Safe: explicit validation with assert
        assert!(capacity <= MAX_ALLOWED, "Content-Length too large");
        let _buffer: Vec<u8> = Vec::with_capacity(capacity);
        // ... read response body safely ...
    }
}

/// SAFE: Using saturating_sub for bound calculation
pub fn safe_with_saturating_sub(response: &reqwest::blocking::Response) {
    const MAX_SIZE: usize = 10 * 1024 * 1024;
    
    if let Some(len) = response.content_length() {
        // Safe: saturating_sub ensures we don't exceed MAX_SIZE
        let capacity = MAX_SIZE.saturating_sub(0).min(len as usize);
        let _buffer: Vec<u8> = Vec::with_capacity(capacity);
        // ... read response body safely ...
    }
}

/// SAFE: Using checked_sub for safe calculation
pub fn safe_with_checked_operations(response: &reqwest::blocking::Response) {
    const MAX_SIZE: usize = 10 * 1024 * 1024;
    
    if let Some(len) = response.content_length() {
        let len_usize = len as usize;
        // Safe: checked operation provides bound validation
        if let Some(_remaining) = MAX_SIZE.checked_sub(len_usize) {
            let capacity = len_usize;
            let _buffer: Vec<u8> = Vec::with_capacity(capacity);
            // ... read response body safely ...
        }
    }
}

/// SAFE: Streaming approach without pre-allocation
pub fn safe_streaming_no_prealloc(_response: &reqwest::blocking::Response) {
    // Safe: no pre-allocation based on Content-Length
    // Let Vec grow dynamically as chunks are read
    let _buffer: Vec<u8> = Vec::new();
    // ... read response body in chunks ...
}

/// SAFE: Small fixed-size buffer
pub fn safe_fixed_size_buffer(_response: &reqwest::blocking::Response) {
    // Safe: fixed size not derived from header
    const CHUNK_SIZE: usize = 8192;
    let _buffer: Vec<u8> = Vec::with_capacity(CHUNK_SIZE);
    // ... read response body in chunks ...
}

// ============================================================================
// EDGE CASES
// ============================================================================

/// EDGE: Allocation size from unrelated calculation
pub fn edge_case_unrelated_calculation(response: &reqwest::blocking::Response) {
    // This should NOT trigger - size is not derived from Content-Length
    let size_from_config = 4096;
    let _buffer: Vec<u8> = Vec::with_capacity(size_from_config);
    
    // We still check Content-Length but don't use it for allocation
    if let Some(_len) = response.content_length() {
        // ... just logging or validation ...
    }
}

/// EDGE: Option/tuple flow patterns
pub fn edge_case_option_tuple(response: &reqwest::blocking::Response) {
    if let Some(len) = response.content_length() {
        let metadata = (len, "application/octet-stream");
        let (size, _mime) = metadata;
        // RUSTCOLA021 should track taint through tuple destructuring
        let _buffer: Vec<u8> = Vec::with_capacity(size as usize);
    }
}
