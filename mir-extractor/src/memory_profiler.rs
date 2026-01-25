//! Memory profiling utilities for debugging memory usage during analysis
//!
//! Enable with RUSTCOLA_MEMORY_PROFILE=1 environment variable

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use sysinfo::{Pid, System};

static PROFILING_ENABLED: AtomicBool = AtomicBool::new(false);
static PEAK_MEMORY_MB: AtomicU64 = AtomicU64::new(0);

/// Initialize memory profiling based on environment variable
pub fn init() {
    if std::env::var("RUSTCOLA_MEMORY_PROFILE").is_ok() {
        PROFILING_ENABLED.store(true, Ordering::SeqCst);
        eprintln!("[MEMORY] Profiling enabled");
    }
}

/// Check if profiling is enabled
pub fn is_enabled() -> bool {
    PROFILING_ENABLED.load(Ordering::SeqCst)
}

/// Get current process memory usage in MB
pub fn current_memory_mb() -> f64 {
    let mut sys = System::new();
    let pid = Pid::from(std::process::id() as usize);
    sys.refresh_process(pid);

    if let Some(process) = sys.process(pid) {
        // process.memory() returns bytes
        let bytes = process.memory();
        bytes as f64 / (1024.0 * 1024.0)
    } else {
        0.0
    }
}

fn update_peak(current_mb: f64) -> f64 {
    let current_mb_int = current_mb as u64;
    let old_peak = PEAK_MEMORY_MB.fetch_max(current_mb_int, Ordering::SeqCst);
    old_peak.max(current_mb_int) as f64
}

/// Log memory usage at a checkpoint with context
pub fn checkpoint(label: &str) {
    if !is_enabled() {
        return;
    }

    let mb = current_memory_mb();
    let peak = update_peak(mb);

    eprintln!("[MEMORY] {}: {:.1} MB (peak: {:.1} MB)", label, mb, peak);
}

/// Log memory usage with additional context about what's being processed
pub fn checkpoint_with_context(label: &str, context: &str) {
    if !is_enabled() {
        return;
    }

    let mb = current_memory_mb();
    let peak = update_peak(mb);

    eprintln!(
        "[MEMORY] {} [{}]: {:.1} MB (peak: {:.1} MB)",
        label, context, mb, peak
    );
}

/// Track memory delta for a scope
pub struct MemoryScope {
    label: String,
    start_mb: f64,
}

impl MemoryScope {
    pub fn new(label: &str) -> Self {
        let start_mb = if is_enabled() {
            current_memory_mb()
        } else {
            0.0
        };

        Self {
            label: label.to_string(),
            start_mb,
        }
    }
}

impl Drop for MemoryScope {
    fn drop(&mut self) {
        if is_enabled() {
            let end_mb = current_memory_mb();
            let delta = end_mb - self.start_mb;
            let sign = if delta >= 0.0 { "+" } else { "" };
            eprintln!(
                "[MEMORY] {} completed: {:.1} MB ({}{:.1} MB)",
                self.label, end_mb, sign, delta
            );
        }
    }
}

/// Print final memory report
pub fn final_report() {
    if !is_enabled() {
        return;
    }

    let current = current_memory_mb();
    let peak = PEAK_MEMORY_MB.load(Ordering::SeqCst) as f64;

    eprintln!("\n[MEMORY] === Final Report ===");
    eprintln!("[MEMORY] Current: {:.1} MB", current);
    eprintln!("[MEMORY] Peak:    {:.1} MB", peak);
    eprintln!("[MEMORY] ====================\n");
}
