//! Demonstrates RUSTCOLA052: Local RefCell usage detection
//!
//! This example shows when RefCell is used for purely local mutable state
//! where a regular mutable variable would be simpler and safer.

use std::cell::RefCell;

// ============================================================================
// PROBLEMATIC PATTERN - RefCell for local state
// ============================================================================

/// ❌ PROBLEMATIC: RefCell used for purely local counter
pub fn count_with_refcell(items: &[i32]) -> i32 {
    let counter = RefCell::new(0);

    for item in items {
        if *item > 0 {
            *counter.borrow_mut() += 1;
        }
    }

    counter.into_inner()
}

/// ❌ PROBLEMATIC: RefCell for accumulation - a plain mut var is clearer
pub fn accumulate_with_refcell(values: &[f64]) -> f64 {
    let sum = RefCell::new(0.0);

    for &val in values {
        *sum.borrow_mut() += val;
    }

    sum.into_inner()
}

/// ❌ PROBLEMATIC: RefCell in a closure, but no shared ownership
pub fn process_with_local_refcell(data: &[String]) -> Vec<String> {
    let buffer = RefCell::new(Vec::new());

    for item in data {
        buffer.borrow_mut().push(item.to_uppercase());
    }

    buffer.into_inner()
}

/// ❌ PROBLEMATIC: Multiple RefCells for local state
pub fn complex_local_refcell(numbers: &[i32]) -> (i32, i32) {
    let positive = RefCell::new(0);
    let negative = RefCell::new(0);

    for &num in numbers {
        if num > 0 {
            *positive.borrow_mut() += num;
        } else {
            *negative.borrow_mut() += num;
        }
    }

    (positive.into_inner(), negative.into_inner())
}

// ============================================================================
// BETTER PATTERN - Use regular mutable variables
// ============================================================================

/// ✅ BETTER: Plain mutable variable for local counter
pub fn count_with_mut(items: &[i32]) -> i32 {
    let mut counter = 0;

    for item in items {
        if *item > 0 {
            counter += 1;
        }
    }

    counter
}

/// ✅ BETTER: Plain mut variable for accumulation
pub fn accumulate_with_mut(values: &[f64]) -> f64 {
    let mut sum = 0.0;

    for &val in values {
        sum += val;
    }

    sum
}

/// ✅ BETTER: Regular mutable Vec
pub fn process_with_mut(data: &[String]) -> Vec<String> {
    let mut buffer = Vec::new();

    for item in data {
        buffer.push(item.to_uppercase());
    }

    buffer
}

// ============================================================================
// LEGITIMATE USES - RefCell is appropriate here
// ============================================================================

/// ✅ LEGITIMATE: RefCell needed for shared ownership in Rc
use std::rc::Rc;

pub struct SharedCounter {
    value: Rc<RefCell<i32>>,
}

impl SharedCounter {
    pub fn new() -> Self {
        Self {
            value: Rc::new(RefCell::new(0)),
        }
    }

    pub fn increment(&self) {
        *self.value.borrow_mut() += 1;
    }

    pub fn get(&self) -> i32 {
        *self.value.borrow()
    }

    pub fn clone_counter(&self) -> Self {
        Self {
            value: Rc::clone(&self.value),
        }
    }
}

/// ✅ LEGITIMATE: RefCell for interior mutability in trait implementation
pub trait Cache {
    fn get(&self, key: &str) -> Option<String>;
}

pub struct SimpleCache {
    data: RefCell<Vec<(String, String)>>,
}

impl SimpleCache {
    pub fn new() -> Self {
        Self {
            data: RefCell::new(Vec::new()),
        }
    }
}

impl Cache for SimpleCache {
    // Need &self but must mutate - RefCell is appropriate here
    fn get(&self, key: &str) -> Option<String> {
        let mut data = self.data.borrow_mut();

        if let Some(pos) = data.iter().position(|(k, _)| k == key) {
            Some(data[pos].1.clone())
        } else {
            data.push((key.to_string(), format!("cached_{}", key)));
            Some(data.last().unwrap().1.clone())
        }
    }
}
