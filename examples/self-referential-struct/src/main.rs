//! Test cases for RUSTCOLA120: Self-Referential Struct Creation
//!
//! This rule detects unsafe patterns that create self-referential structs
//! without proper Pin usage, leading to UAF when the struct moves.

use std::marker::PhantomPinned;
use std::ptr::NonNull;

// ============================================================================
// BAD PATTERNS - Unsafe self-referential struct creation
// ============================================================================

/// BAD: Self-referential struct without Pin
pub struct BadSelfRef {
    data: String,
    ptr: *const String, // Points to self.data - DANGEROUS
}

impl BadSelfRef {
    /// BAD: Creates dangling pointer when struct moves
    pub fn new(data: String) -> Self {
        let mut s = Self {
            data,
            ptr: std::ptr::null(),
        };
        // Point ptr to our own data field
        s.ptr = &s.data; // Self-reference created!
        s // If this moves, ptr becomes dangling
    }

    /// BAD: Dereference potentially dangling pointer
    pub unsafe fn get_ref(&self) -> &String {
        &*self.ptr // UAF if struct was moved!
    }
}

/// BAD: Self-referential with NonNull (still moves)
pub struct BadNonNullSelfRef {
    value: i64,
    self_ptr: Option<NonNull<i64>>,
}

impl BadNonNullSelfRef {
    pub fn new(value: i64) -> Self {
        let mut s = Self {
            value,
            self_ptr: None,
        };
        s.self_ptr = NonNull::new(&mut s.value); // Self-reference!
        s
    }
}

/// BAD: Linked list node with raw pointer to self
pub struct BadNode {
    data: i32,
    next: *mut BadNode,
    prev: *mut BadNode, // Raw pointer - can dangle
}

impl BadNode {
    pub fn new_with_self_link(data: i32) -> Box<Self> {
        let mut node = Box::new(Self {
            data,
            next: std::ptr::null_mut(),
            prev: std::ptr::null_mut(),
        });
        // Point to self - creates self-reference
        node.prev = &mut *node as *mut BadNode;
        node
    }
}

/// BAD: Generator-like struct storing reference to owned data  
pub struct BadGenerator {
    buffer: Vec<u8>,
    current: *const u8, // Points into buffer
}

impl BadGenerator {
    pub fn new() -> Self {
        let buffer = vec![1, 2, 3, 4, 5];
        let current = buffer.as_ptr(); // Self-reference before struct exists!
        Self { buffer, current }
    }
}

/// BAD: Callback struct with pointer to captured context
pub struct BadCallback<'a> {
    data: Vec<u8>,
    callback: Option<Box<dyn Fn(&'a [u8]) + 'a>>,
}

// ============================================================================
// GOOD PATTERNS - Safe alternatives
// ============================================================================

/// GOOD: Using Pin to prevent moves
pub struct GoodPinnedSelfRef {
    data: String,
    ptr: *const String,
    _pin: PhantomPinned, // Opt out of Unpin
}

impl GoodPinnedSelfRef {
    /// Must be pinned before creating self-reference
    pub fn new(data: String) -> std::pin::Pin<Box<Self>> {
        let mut boxed = Box::pin(Self {
            data,
            ptr: std::ptr::null(),
            _pin: PhantomPinned,
        });
        // SAFETY: We don't move the struct after pinning
        unsafe {
            let mut_ref = std::pin::Pin::as_mut(&mut boxed);
            let this = std::pin::Pin::get_unchecked_mut(mut_ref);
            this.ptr = &this.data;
        }
        boxed
    }
}

/// GOOD: Use indices instead of pointers
pub struct GoodIndexBased {
    items: Vec<String>,
    current_index: usize, // Index instead of pointer
}

impl GoodIndexBased {
    pub fn current(&self) -> Option<&String> {
        self.items.get(self.current_index)
    }
}

/// GOOD: Use Rc/Arc for shared ownership
pub struct GoodSharedOwnership {
    data: std::sync::Arc<String>,
    reference: std::sync::Arc<String>, // Same Arc, no self-ref
}

/// GOOD: ouroboros crate for safe self-ref (conceptual)
// pub struct GoodOuroboros {
//     #[borrows(data)]
//     reference: &'this str,
// }

fn main() {
    println!("RUSTCOLA120 test cases");

    // Demonstrate the problem:
    let bad = BadSelfRef::new("hello".to_string());
    // If we move `bad`, the ptr becomes dangling!
    let moved = bad; // Move happens here
                     // unsafe { moved.get_ref() } // This would be UAF!
}
