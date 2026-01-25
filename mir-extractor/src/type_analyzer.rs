//! Type Query Interface for Semantic Analysis
//!
//! Provides high-level queries about types for security rule implementation.
//! Backed by rustc's type system via TyCtxt and cached HIR information.

use anyhow::{Context, Result};
use rustc_middle::ty::TyCtxt;
use rustc_span::def_id::DefId;
use std::collections::HashMap;

/// Type analyzer providing semantic queries for security rules
pub struct TypeAnalyzer<'tcx> {
    tcx: TyCtxt<'tcx>,
    /// Cache of type -> trait implementations
    trait_cache: HashMap<String, Vec<String>>,
    /// Cache of type sizes (in bytes)
    size_cache: HashMap<String, Option<usize>>,
}

impl<'tcx> TypeAnalyzer<'tcx> {
    /// Create a new TypeAnalyzer from a TyCtxt
    pub fn new(tcx: TyCtxt<'tcx>) -> Self {
        Self {
            tcx,
            trait_cache: HashMap::new(),
            size_cache: HashMap::new(),
        }
    }

    /// Check if a type implements a specific trait
    ///
    /// # Arguments
    /// * `ty_name` - Type name (e.g., "MyStruct", "std::sync::Arc<T>")
    /// * `trait_name` - Trait name (e.g., "Send", "std::marker::Sync")
    ///
    /// # Returns
    /// * `Ok(true)` - Type definitely implements the trait
    /// * `Ok(false)` - Type definitely does NOT implement the trait
    /// * `Err(_)` - Unable to determine (e.g., generic parameters)
    ///
    /// # Example
    /// ```ignore
    /// let analyzer = TypeAnalyzer::new(tcx);
    /// if analyzer.implements_trait("MyStruct", "Send")? {
    ///     // MyStruct is Send...
    /// }
    /// ```
    pub fn implements_trait(&mut self, _ty_name: &str, _trait_name: &str) -> Result<bool> {
        // Trait checking requires the rustc trait solver, which has unstable APIs.
        // Current approach: extract trait bounds during HIR analysis and store in metadata.
        // This method is reserved for future direct trait queries.
        anyhow::bail!("implements_trait not yet implemented - use HIR metadata for Send/Sync info")
    }

    /// Check if a type is Send
    ///
    /// Convenience method for checking Send trait implementation.
    ///
    /// # Returns
    /// * `Ok(true)` - Type is Send
    /// * `Ok(false)` - Type is NOT Send
    /// * `Err(_)` - Unable to determine
    pub fn is_send(&mut self, ty_name: &str) -> Result<bool> {
        self.implements_trait(ty_name, "std::marker::Send")
    }

    /// Check if a type is Sync
    ///
    /// Convenience method for checking Sync trait implementation.
    ///
    /// # Returns
    /// * `Ok(true)` - Type is Sync
    /// * `Ok(false)` - Type is NOT Sync
    /// * `Err(_)` - Unable to determine
    pub fn is_sync(&mut self, ty_name: &str) -> Result<bool> {
        self.implements_trait(ty_name, "std::marker::Sync")
    }

    /// Get the size of a type in bytes
    ///
    /// Returns the size of the type as it would be reported by std::mem::size_of.
    /// Zero-sized types return `Some(0)`.
    ///
    /// # Arguments
    /// * `ty_name` - Type name (e.g., "MyStruct", "u32", "()")
    ///
    /// # Returns
    /// * `Ok(Some(size))` - Type has a known size
    /// * `Ok(None)` - Type is unsized (e.g., `[T]`, `dyn Trait`)
    /// * `Err(_)` - Unable to determine size
    ///
    /// # Example
    /// ```ignore
    /// match analyzer.size_of("MyStruct")? {
    ///     Some(0) => println!("Zero-sized type!"),
    ///     Some(n) => println!("Size: {} bytes", n),
    ///     None => println!("Unsized type"),
    /// }
    /// ```
    pub fn size_of(&mut self, ty_name: &str) -> Result<Option<usize>> {
        // Check cache first
        if let Some(size) = self.size_cache.get(ty_name) {
            return Ok(*size);
        }

        // Resolve type name to DefId
        let def_id = self.resolve_type(ty_name)?;

        // Use the same logic as extract_type_size from hir.rs
        use rustc_middle::ty::layout::LayoutOf;

        let ty = self.tcx.type_of(def_id).instantiate_identity();
        let typing_env = rustc_middle::ty::TypingEnv::non_body_analysis(self.tcx, def_id);
        let query_input = rustc_middle::ty::PseudoCanonicalInput {
            typing_env,
            value: ty,
        };

        let result = match self.tcx.layout_of(query_input) {
            Ok(layout) => Some(layout.size.bytes() as usize),
            Err(_) => None,
        };

        // Cache the result
        self.size_cache.insert(ty_name.to_string(), result);

        Ok(result)
    }

    /// Check if a type is zero-sized (ZST)
    ///
    /// Convenience method for detecting zero-sized types.
    /// Returns false for unsized types.
    ///
    /// # Returns
    /// * `Ok(true)` - Type is zero-sized
    /// * `Ok(false)` - Type has non-zero size or is unsized
    /// * `Err(_)` - Unable to determine
    ///
    /// # Example
    /// ```ignore
    /// if analyzer.is_zst("()")? {
    ///     // Unit type is ZST...
    /// }
    /// ```
    pub fn is_zst(&mut self, ty_name: &str) -> Result<bool> {
        match self.size_of(ty_name)? {
            Some(0) => Ok(true),
            Some(_) | None => Ok(false),
        }
    }

    /// Resolve a type string to a DefId
    ///
    /// Internal helper to convert type names to DefIds for rustc queries.
    fn resolve_type(&self, ty_name: &str) -> Result<DefId> {
        // Type name to DefId resolution requires symbol table integration.
        // Currently unused - callers use DefId directly from MIR extraction.
        anyhow::bail!("Type resolution not yet implemented: {}", ty_name)
    }

    /// Clear all caches
    ///
    /// Useful when analyzing a new crate or after significant changes.
    pub fn clear_cache(&mut self) {
        self.trait_cache.clear();
        self.size_cache.clear();
    }

    /// Get cache statistics for debugging
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            trait_entries: self.trait_cache.len(),
            size_entries: self.size_cache.len(),
        }
    }
}

/// Statistics about TypeAnalyzer cache usage
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    pub trait_entries: usize,
    pub size_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a TyCtxt which needs rustc test infrastructure
    // For now, these are placeholders documenting expected behavior

    #[test]
    #[ignore = "Requires rustc test infrastructure"]
    fn test_primitive_sizes() {
        // Expected behavior:
        // analyzer.size_of("u8").unwrap() == Some(1)
        // analyzer.size_of("u32").unwrap() == Some(4)
        // analyzer.size_of("usize").unwrap() == Some(8) // on 64-bit
    }

    #[test]
    #[ignore = "Requires rustc test infrastructure"]
    fn test_zst_detection() {
        // Expected behavior:
        // analyzer.is_zst("()").unwrap() == true
        // analyzer.is_zst("u32").unwrap() == false
        // analyzer.is_zst("PhantomData<T>").unwrap() == true
    }

    #[test]
    #[ignore = "Requires rustc test infrastructure"]
    fn test_send_sync() {
        // Expected behavior:
        // analyzer.is_send("u32").unwrap() == true
        // analyzer.is_sync("u32").unwrap() == true
        // analyzer.is_send("Rc<T>").unwrap() == false
    }
}
