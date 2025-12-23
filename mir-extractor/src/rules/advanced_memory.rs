//! Advanced memory safety rules.
//!
//! These rules perform deep dataflow analysis on MIR to detect:
//! - Use-after-free (dangling pointer dereference)
//! - Null pointer dereference
//! - Misaligned pointer access
//! - Pointer escapes from stack allocation
//! - Overlapping ptr::copy_nonoverlapping calls
//!
//! Migrated from mir-advanced-rules crate to use the standard Rule trait.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::{
    AttackComplexity, AttackVector, Confidence, Exploitability, Finding, MirFunction, MirPackage,
    PrivilegesRequired, Rule, RuleMetadata, RuleOrigin, Severity, UserInteraction,
    interprocedural::InterProceduralAnalysis,
};

// ============================================================================
// ADV001: Dangling Pointer / Use-After-Free Detection
// ============================================================================

/// Advanced memory safety rule: Detects use of pointers after their memory has been freed.
///
/// Approach:
/// - Track pointer allocations (Box, Vec, raw pointer creation)
/// - Track explicit deallocation (drop, free, Box::from_raw, etc.)
/// - Flag any dereference or use of a pointer after its memory has been freed
/// - Focus on unsafe blocks and FFI boundaries
pub struct DanglingPointerUseAfterFreeRule {
    metadata: RuleMetadata,
}

impl Default for DanglingPointerUseAfterFreeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl DanglingPointerUseAfterFreeRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA200".to_string(),
                name: "dangling-pointer-use-after-free".to_string(),
                short_description: "Detects use of pointers after their memory has been freed"
                    .to_string(),
                full_description: "This rule performs dataflow analysis to track pointer \
                    allocations and deallocations. It flags dereferences of pointers after \
                    their backing memory has been freed (use-after-free), null pointer \
                    dereferences, misaligned pointer access, and pointers that escape their \
                    stack allocation scope."
                    .to_string(),
                help_uri: None,
                default_severity: Severity::Critical,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: vec!["CWE-416".to_string(), "CWE-476".to_string(), "CWE-825".to_string()], // Use After Free, NULL Pointer Deref, Expired Pointer Deref
                fix_suggestion: Some(
                    "Ensure pointers are not used after their backing memory is freed. \
                    Consider using safe Rust abstractions like references with proper lifetimes, \
                    Rc/Arc for shared ownership, or ensure raw pointers are only dereferenced \
                    while the owner is still alive."
                        .to_string(),
                ),
                exploitability: Exploitability {
                    attack_vector: AttackVector::Network, // Can often be triggered remotely
                    attack_complexity: AttackComplexity::High, // Requires specific memory state
                    privileges_required: PrivilegesRequired::None,
                    user_interaction: UserInteraction::None,
                },
            },
        }
    }

    /// Check if function should be skipped (derive macro or safe trait method)
    fn should_skip_function(func: &MirFunction) -> bool {
        is_derive_macro_function(&func.name) || is_safe_trait_method(&func.name, &func.signature)
    }
}

impl Rule for DanglingPointerUseAfterFreeRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &package.functions {
            // Skip derive macro functions and safe trait methods to reduce false positives
            if Self::should_skip_function(func) {
                continue;
            }

            // Reconstruct MIR text from the function body
            let mir_text = format!("fn {}() {{\n{}\n}}", func.name, func.body.join("\n"));

            let analyzer = PointerAnalyzer::default();
            let raw_findings = analyzer.analyze(&mir_text);

            for msg in raw_findings {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    confidence: Confidence::High,
                    message: msg,
                    function: func.name.clone(),
                    function_signature: func.signature.clone(),
                    evidence: func.body.clone(),
                    span: func.span.clone(),
                    exploitability: self.metadata.exploitability.clone(),
                    exploitability_score: self.metadata.exploitability.score(),
                    ..Default::default()
                });
            }
        }

        findings
    }
}

// ============================================================================
// Helper Functions for Filtering
// ============================================================================

/// Detect derive macro generated functions by name pattern
fn is_derive_macro_function(func_name: &str) -> bool {
    // Derive macro functions have names like "<impl at src/lib.rs:10:5: 12:6>::eq"
    static RE_DERIVE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"<impl at [^>]+:\d+:\d+:\s*\d+:\d+>::").expect("derive macro regex")
    });
    RE_DERIVE.is_match(func_name)
}

/// Detect safe trait methods that commonly take references
fn is_safe_trait_method(func_name: &str, _func_signature: &str) -> bool {
    // These trait methods commonly take &self and are safe patterns
    let safe_methods = [
        "::eq",
        "::ne",
        "::partial_cmp",
        "::cmp",
        "::hash",
        "::fmt",
        "::clone",
        "::default",
        "::drop",
    ];
    safe_methods.iter().any(|m| func_name.ends_with(m))
}

// ============================================================================
// Pointer Analyzer (migrated from mir-advanced-rules)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerKind {
    Stack,
    Heap,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvalidationKind {
    Drop,
    Reallocate,
}

impl std::fmt::Display for InvalidationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Drop => write!(f, "drop"),
            Self::Reallocate => write!(f, "reallocation"),
        }
    }
}

#[derive(Debug, Clone)]
struct Invalidation {
    line_index: usize,
    line: String,
    kind: InvalidationKind,
}

#[derive(Debug, Clone)]
struct OwnerState {
    kind: OwnerKind,
    leaked: bool,
    invalidation: Option<Invalidation>,
}

impl OwnerState {
    fn new(kind: OwnerKind) -> Self {
        Self {
            kind,
            leaked: false,
            invalidation: None,
        }
    }

    fn note_invalidation(&mut self, inv: Invalidation) {
        if self.leaked {
            return;
        }

        match &self.invalidation {
            Some(current) if current.line_index >= inv.line_index => {}
            _ => self.invalidation = Some(inv),
        }
    }
}

#[derive(Debug, Clone)]
struct PointerInfo {
    owner: String,
    owner_kind: OwnerKind,
    creation_line: String,
    creation_index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PointerValidityKind {
    Null,
    Misaligned { alignment: usize, address: u128 },
}

#[derive(Debug, Clone)]
struct PointerValidityInfo {
    kind: PointerValidityKind,
    line: String,
}

/// Captures the MIR locals used as the source and destination operands of a
/// `ptr::copy_nonoverlapping` call so we can reason about aliasing.
#[derive(Debug, Clone)]
struct CopyNonOverlappingCall {
    src: String,
    dst: String,
}

#[derive(Debug, Default)]
struct PointerAnalyzer {
    pointers: HashMap<String, PointerInfo>,
    aliases: HashMap<String, String>,
    owners: HashMap<String, OwnerState>,
    findings: Vec<String>,
    reported: HashSet<(String, usize)>,
    pointer_validities: HashMap<String, PointerValidityInfo>,
}

impl PointerAnalyzer {
    fn analyze(mut self, mir: &str) -> Vec<String> {
        let lines: Vec<&str> = mir.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some((alias, base)) = Self::detect_alias_assignment(trimmed) {
                let base_resolved = self.resolve_alias(&base);
                self.aliases.insert(alias, base_resolved);
            }

            if let Some(pointer) = Self::detect_null_pointer_assignment(trimmed) {
                self.record_null_pointer(pointer, idx, trimmed);
            }

            if let Some(event) = Self::detect_const_pointer_assignment(trimmed) {
                self.record_const_pointer(event, idx, trimmed);
            }

            if let Some(event) = Self::detect_pointer_creation(trimmed) {
                self.record_pointer_creation(idx, event);
            }

            if let Some(call) = Self::detect_copy_nonoverlapping(trimmed) {
                self.evaluate_copy_nonoverlapping(idx, trimmed, call);
            }

            if let Some((owner_raw, kind)) = Self::detect_owner_invalidation(trimmed) {
                let mut owner = normalize_owner(&owner_raw);
                owner = self.resolve_alias(&owner);

                let mut inferred_kind = OwnerKind::Unknown;
                if let Some(info) = self.pointers.get(&owner) {
                    inferred_kind = info.owner_kind;
                    owner = info.owner.clone();
                }

                if owner.is_empty() {
                    continue;
                }

                let entry = self
                    .owners
                    .entry(owner.clone())
                    .or_insert_with(|| OwnerState::new(inferred_kind));

                if entry.kind == OwnerKind::Unknown {
                    entry.kind = inferred_kind;
                }

                entry.note_invalidation(Invalidation {
                    line_index: idx,
                    line: trimmed.to_string(),
                    kind,
                });
            }

            for ptr_var in Self::detect_pointer_dereference(trimmed) {
                self.evaluate_pointer_use(idx, trimmed, &ptr_var, "dereference after owner drop");
                self.evaluate_invalid_pointer_use(idx, trimmed, &ptr_var);
            }

            for ptr_var in Self::detect_return_aggregate_pointers(trimmed) {
                self.evaluate_pointer_escape(idx, trimmed, &ptr_var, "returned inside aggregate");
            }

            for ptr_var in Self::detect_pointer_store(trimmed) {
                self.evaluate_pointer_escape(idx, trimmed, &ptr_var, "stored through pointer");
            }

            if let Some(ptr_var) = Self::detect_return_pointer(trimmed) {
                self.evaluate_pointer_escape(idx, trimmed, &ptr_var, "returned to caller");
            }
        }

        self.findings
    }

    fn record_pointer_creation(&mut self, line_index: usize, event: PointerCreationEvent) {
        let mut owner = normalize_owner(&event.owner);
        owner = self.resolve_alias(&owner);

        let mut owner_kind = event.owner_kind;

        if let Some(existing) = self.pointers.get(&owner) {
            owner = existing.owner.clone();
            owner_kind = existing.owner_kind;
        }

        if owner.is_empty() {
            return;
        }

        let entry = self
            .owners
            .entry(owner.clone())
            .or_insert_with(|| OwnerState::new(owner_kind));

        if entry.kind == OwnerKind::Unknown {
            entry.kind = owner_kind;
        }

        if event.leaked {
            entry.leaked = true;
            entry.invalidation = None;
        }

        let info = PointerInfo {
            owner: owner.clone(),
            owner_kind: entry.kind,
            creation_line: event.line.to_string(),
            creation_index: line_index,
        };

        self.pointers.insert(event.pointer.clone(), info);
        self.aliases.remove(&event.pointer);
        self.pointer_validities.remove(&event.pointer);
    }

    fn reset_pointer_state(&mut self, pointer: &str) {
        self.aliases.remove(pointer);
        self.pointers.remove(pointer);
    }

    fn record_null_pointer(&mut self, pointer: String, _line_index: usize, line: &str) {
        self.reset_pointer_state(&pointer);
        let info = PointerValidityInfo {
            kind: PointerValidityKind::Null,
            line: line.to_string(),
        };
        self.pointer_validities.insert(pointer, info);
    }

    fn record_const_pointer(&mut self, event: ConstPointerEvent, _line_index: usize, line: &str) {
        self.reset_pointer_state(&event.pointer);

        if event.value == 0 {
            let info = PointerValidityInfo {
                kind: PointerValidityKind::Null,
                line: line.to_string(),
            };
            self.pointer_validities.insert(event.pointer, info);
            return;
        }

        if let Some(align) = alignment_for_type(&event.pointee) {
            if align > 1 && (event.value % align as u128 != 0) {
                let info = PointerValidityInfo {
                    kind: PointerValidityKind::Misaligned {
                        alignment: align,
                        address: event.value,
                    },
                    line: line.to_string(),
                };
                self.pointer_validities.insert(event.pointer, info);
                return;
            }
        }

        self.pointer_validities.remove(&event.pointer);
    }

    fn evaluate_pointer_use(&mut self, line_index: usize, line: &str, ptr_var: &str, reason: &str) {
        if let Some((pointer_key, info)) = self.lookup_pointer(ptr_var) {
            let (owner_leaked, owner_invalidation) = match self.owners.get(&info.owner) {
                Some(state) => (state.leaked, state.invalidation.clone()),
                None => return,
            };

            if owner_leaked {
                return;
            }

            if let Some(invalidation) = owner_invalidation {
                if invalidation.line_index < line_index
                    && invalidation.line_index >= info.creation_index
                    && self.reported.insert((pointer_key.clone(), line_index))
                {
                    let message = format!(
                        "Potential dangling pointer: `{}` {} after {} of `{}`.\n  \
                        creation: `{}`\n  invalidation: `{}`\n  use: `{}`",
                        pointer_key,
                        reason,
                        invalidation.kind,
                        info.owner,
                        info.creation_line.trim(),
                        invalidation.line.trim(),
                        line.trim()
                    );
                    self.findings.push(message);
                }
            }
        }
    }

    fn evaluate_invalid_pointer_use(&mut self, line_index: usize, line: &str, ptr_var: &str) {
        let pointer_key = self.resolve_alias(ptr_var);
        if pointer_key.is_empty() {
            return;
        }

        let info = match self.pointer_validities.get(&pointer_key) {
            Some(info) => info.clone(),
            None => return,
        };

        let display = if pointer_key == ptr_var {
            pointer_key.clone()
        } else {
            format!("{} (alias of {})", ptr_var, pointer_key)
        };

        let reported_key = format!("invalid:{}", pointer_key);
        if !self.reported.insert((reported_key, line_index)) {
            return;
        }

        let message = match info.kind {
            PointerValidityKind::Null => format!(
                "Invalid pointer dereference: `{}` is null.\n  \
                assignment: `{}`\n  use: `{}`",
                display,
                info.line.trim(),
                line.trim()
            ),
            PointerValidityKind::Misaligned { alignment, address } => format!(
                "Invalid pointer dereference: `{}` has address 0x{:x} which is not aligned \
                to {} bytes.\n  assignment: `{}`\n  use: `{}`",
                display,
                address,
                alignment,
                info.line.trim(),
                line.trim()
            ),
        };

        self.findings.push(message);
    }

    fn evaluate_pointer_escape(
        &mut self,
        line_index: usize,
        line: &str,
        ptr_var: &str,
        reason: &str,
    ) {
        if let Some((pointer_key, info)) = self.lookup_pointer(ptr_var) {
            if info.owner_kind == OwnerKind::Stack
                && self.reported.insert((pointer_key.clone(), line_index))
            {
                let message = format!(
                    "Pointer `{}` escapes stack allocation: {}.\n  \
                    creation: `{}`\n  escape: `{}`",
                    pointer_key,
                    reason,
                    info.creation_line.trim(),
                    line.trim()
                );
                self.findings.push(message);
            }
        }
    }

    fn evaluate_copy_nonoverlapping(
        &mut self,
        line_index: usize,
        line: &str,
        call: CopyNonOverlappingCall,
    ) {
        let src_candidates = self.pointer_equivalence_set(&call.src);
        let dst_candidates = self.pointer_equivalence_set(&call.dst);

        if src_candidates.is_empty() || dst_candidates.is_empty() {
            return;
        }

        let overlap = src_candidates
            .intersection(&dst_candidates)
            .any(|candidate| !candidate.is_empty());

        if !overlap {
            return;
        }

        let src_key = self.resolve_alias(&call.src);
        let dst_key = self.resolve_alias(&call.dst);

        let reported_key = format!("copy:{}->{}", src_key, dst_key);
        if !self.reported.insert((reported_key, line_index)) {
            return;
        }

        let src_origin = self
            .pointers
            .get(&src_key)
            .map(|info| info.creation_line.trim().to_string());
        let dst_origin = self
            .pointers
            .get(&dst_key)
            .map(|info| info.creation_line.trim().to_string());

        let src_display = if call.src == src_key {
            call.src.clone()
        } else {
            format!("{} (resolves to {})", call.src, src_key)
        };

        let dst_display = if call.dst == dst_key {
            call.dst.clone()
        } else {
            format!("{} (resolves to {})", call.dst, dst_key)
        };

        let mut message = format!(
            "Unsafe ptr::copy_nonoverlapping: src `{}` and dst `{}` may overlap.\n  \
            call: `{}`",
            src_display,
            dst_display,
            line.trim()
        );

        if let Some(origin) = src_origin {
            message.push_str(&format!("\n  src origin: `{}`", origin));
        }

        if let Some(origin) = dst_origin {
            message.push_str(&format!("\n  dst origin: `{}`", origin));
        }

        self.findings.push(message);
    }

    fn lookup_pointer(&self, var: &str) -> Option<(String, PointerInfo)> {
        let pointer_key = self.resolve_alias(var);
        self.pointers
            .get(&pointer_key)
            .cloned()
            .map(|info| (pointer_key, info))
    }

    fn resolve_alias(&self, var: &str) -> String {
        let mut current = var.trim().to_string();
        let mut visited = HashSet::new();

        while let Some(next) = self.aliases.get(&current) {
            if !visited.insert(current.clone()) {
                break;
            }
            current = next.clone();
        }

        current
    }

    fn pointer_equivalence_set(&self, var: &str) -> HashSet<String> {
        let mut set = HashSet::new();

        let trimmed = var.trim();
        if trimmed.is_empty() {
            return set;
        }

        set.insert(trimmed.to_string());

        let resolved = self.resolve_alias(trimmed);
        if !resolved.is_empty() {
            set.insert(resolved.clone());

            if let Some(info) = self.pointers.get(&resolved) {
                if !info.owner.is_empty() {
                    set.insert(info.owner.clone());
                }
            }
        }

        set
    }

    fn detect_alias_assignment(line: &str) -> Option<(String, String)> {
        static RE_ALIAS_SIMPLE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"^(_\d+)\s*=\s*(?:copy|move)\s+(_\d+)\s*;").expect("alias regex"));
        static RE_ALIAS_INDEX: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"^(_\d+)\s*=.*::index\(\s*(?:move|copy)\s+(_\d+),").expect("index alias regex"));

        if let Some(caps) = RE_ALIAS_SIMPLE.captures(line) {
            return Some((caps[1].to_string(), caps[2].to_string()));
        }

        if let Some(caps) = RE_ALIAS_INDEX.captures(line) {
            return Some((caps[1].to_string(), caps[2].to_string()));
        }

        None
    }

    fn detect_null_pointer_assignment(line: &str) -> Option<String> {
        static RE_NULL: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"^(_\d+)\s*=\s*null(?:_mut)?::<[^>]+>\(\)\s*->").expect("null pointer regex"));

        RE_NULL.captures(line).map(|caps| caps[1].to_string())
    }

    fn detect_const_pointer_assignment(line: &str) -> Option<ConstPointerEvent> {
        static RE_CONST_PTR: Lazy<Regex> = Lazy::new(|| {
            Regex::new(
                r"^(_\d+)\s*=\s*const\s+([0-9_]+)_(?:[iu](?:size|8|16|32|64|128))\s+as\s+\*(?:const|mut)\s+([A-Za-z0-9_]+)",
            )
            .expect("const pointer regex")
        });

        let caps = RE_CONST_PTR.captures(line)?;
        let pointer = caps[1].to_string();
        let value_raw = caps[2].replace('_', "");
        let value = u128::from_str(&value_raw).ok()?;
        let pointee = caps[3].to_ascii_lowercase();

        Some(ConstPointerEvent {
            pointer,
            value,
            pointee,
        })
    }

    fn detect_copy_nonoverlapping(line: &str) -> Option<CopyNonOverlappingCall> {
        static RE_COPY: Lazy<Regex> = Lazy::new(|| {
            Regex::new(
                r"copy_nonoverlapping::<[^>]+>\((?:move|copy)\s+(_\d+)[^,]*,\s*(?:move|copy)\s+(_\d+)",
            )
            .expect("copy_nonoverlapping regex")
        });

        let caps = RE_COPY.captures(line)?;
        Some(CopyNonOverlappingCall {
            src: caps[1].to_string(),
            dst: caps[2].to_string(),
        })
    }

    fn detect_pointer_creation(line: &str) -> Option<PointerCreationEvent<'_>> {
        static RE_ADDR_OF: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"^(_\d+)\s*=\s*&raw\s+(?:const|mut)\s+\(\*([^\)]+)\);").expect("addr-of regex"));
        static RE_REF: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"^(_\d+)\s*=\s*&(?:mut\s+)?(_\d+)\s*;").expect("ref regex"));
        static RE_INTO_RAW: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"^(_\d+)\s*=.*::into_raw\(\s*move\s+(_\d+)\s*\).*").expect("into_raw regex"));
        static RE_BOX_LEAK: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"^(_\d+)\s*=.*Box::leak\(\s*move\s+(_\d+)\s*\).*").expect("box leak regex"));
        static RE_AS_PTR: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"^(_\d+)\s*=\s*copy\s+(_\d+)\s+as\s+\*const").expect("as_ptr regex"));

        if let Some(caps) = RE_ADDR_OF.captures(line) {
            return Some(PointerCreationEvent::stack(
                caps[1].to_string(),
                caps[2].to_string(),
                line,
            ));
        }

        if let Some(caps) = RE_REF.captures(line) {
            return Some(PointerCreationEvent::stack(
                caps[1].to_string(),
                caps[2].to_string(),
                line,
            ));
        }

        if let Some(caps) = RE_BOX_LEAK.captures(line) {
            return Some(PointerCreationEvent::leaked_heap(
                caps[1].to_string(),
                caps[2].to_string(),
                line,
            ));
        }

        if let Some(caps) = RE_INTO_RAW.captures(line) {
            return Some(PointerCreationEvent::heap(
                caps[1].to_string(),
                caps[2].to_string(),
                line,
            ));
        }

        if let Some(caps) = RE_AS_PTR.captures(line) {
            return Some(PointerCreationEvent::heap(
                caps[1].to_string(),
                caps[2].to_string(),
                line,
            ));
        }

        None
    }

    fn detect_owner_invalidation(line: &str) -> Option<(String, InvalidationKind)> {
        static RE_DROP: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"drop\(\s*([^\)]+)\)").expect("drop regex"));
        static RE_STORAGE_DEAD: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"StorageDead\(\s*([^\)]+)\)").expect("storage dead regex"));
        static RE_DROP_IN_PLACE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"drop_in_place::<[^>]+>\(\s*(?:move\s+)?([^\)]+)\)").expect("drop_in_place regex"));
        static RE_DEALLOC: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"dealloc\(\s*(?:move\s+)?([^,\s\)]+)").expect("dealloc regex"));
        static RE_VEC_REALLOC: Lazy<Regex> = Lazy::new(|| {
            Regex::new(
                r"Vec::<[^>]+>::(?:push|append|extend|insert|reserve|reserve_exact|resize|resize_with|shrink_to_fit|shrink_to|truncate|clear)\(\s*(?:move|copy)?\s*(_\d+)",
            )
            .expect("vec realloc regex")
        });

        if let Some(caps) = RE_DROP.captures(line) {
            return Some((caps[1].to_string(), InvalidationKind::Drop));
        }

        if let Some(caps) = RE_STORAGE_DEAD.captures(line) {
            return Some((caps[1].to_string(), InvalidationKind::Drop));
        }

        if let Some(caps) = RE_DROP_IN_PLACE.captures(line) {
            return Some((caps[1].to_string(), InvalidationKind::Drop));
        }

        if let Some(caps) = RE_DEALLOC.captures(line) {
            return Some((caps[1].to_string(), InvalidationKind::Drop));
        }

        if let Some(caps) = RE_VEC_REALLOC.captures(line) {
            return Some((caps[1].to_string(), InvalidationKind::Reallocate));
        }

        None
    }

    fn detect_pointer_dereference(line: &str) -> Vec<String> {
        static RE_DEREF: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"\*\s*\(?\s*(_\d+)").expect("deref regex"));
        static RE_PTR_READ: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"ptr::(?:read|write)(?:_unchecked)?::<[^>]+>\(\s*(?:move\s+)?(_\d+)\)")
                .expect("ptr::read regex")
        });

        let mut vars: Vec<String> = RE_DEREF
            .captures_iter(line)
            .map(|caps| caps[1].to_string())
            .collect();

        for caps in RE_PTR_READ.captures_iter(line) {
            vars.push(caps[1].to_string());
        }

        vars
    }

    fn detect_return_aggregate_pointers(line: &str) -> Vec<String> {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("_0") {
            return Vec::new();
        }

        if !(trimmed.contains('{') || trimmed.contains('(')) {
            return Vec::new();
        }

        static RE_MOVE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?:move|copy)\s+(_\d+)").expect("aggregate move regex"));

        let mut vars = HashSet::new();

        for caps in RE_MOVE.captures_iter(line) {
            vars.insert(caps[1].to_string());
        }

        vars.into_iter().collect()
    }

    fn detect_pointer_store(line: &str) -> Vec<String> {
        static RE_STORE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\(\*[^\)]+\)\s*=\s*(?:move|copy)\s+(_\d+)").expect("pointer store regex")
        });

        RE_STORE
            .captures_iter(line)
            .map(|caps| caps[1].to_string())
            .collect()
    }

    fn detect_return_pointer(line: &str) -> Option<String> {
        static RE_RETURN: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"^_0\s*=\s*(?:copy|move)\s+(_\d+)\s*;").expect("return regex"));

        RE_RETURN.captures(line).map(|caps| caps[1].to_string())
    }
}

// ============================================================================
// Supporting Types
// ============================================================================

struct PointerCreationEvent<'a> {
    pointer: String,
    owner: String,
    owner_kind: OwnerKind,
    leaked: bool,
    line: &'a str,
}

struct ConstPointerEvent {
    pointer: String,
    value: u128,
    pointee: String,
}

impl<'a> PointerCreationEvent<'a> {
    fn stack(pointer: String, owner: String, line: &'a str) -> Self {
        Self {
            pointer,
            owner,
            owner_kind: OwnerKind::Stack,
            leaked: false,
            line,
        }
    }

    fn heap(pointer: String, owner: String, line: &'a str) -> Self {
        Self {
            pointer,
            owner,
            owner_kind: OwnerKind::Heap,
            leaked: false,
            line,
        }
    }

    fn leaked_heap(pointer: String, owner: String, line: &'a str) -> Self {
        Self {
            pointer,
            owner,
            owner_kind: OwnerKind::Heap,
            leaked: true,
            line,
        }
    }
}

fn normalize_owner(raw: &str) -> String {
    let mut text = raw.trim().trim_end_matches(';').trim();

    while text.starts_with('(') && text.ends_with(')') && text.len() > 2 {
        text = &text[1..text.len() - 1];
        text = text.trim();
    }

    if let Some(stripped) = text.strip_prefix('*') {
        text = stripped.trim();
    }

    if let Some(stripped) = text.strip_prefix("move ") {
        text = stripped.trim();
    }

    if let Some(stripped) = text.strip_prefix("copy ") {
        text = stripped.trim();
    }

    text.to_string()
}

fn alignment_for_type(pointee: &str) -> Option<usize> {
    match pointee {
        "u8" | "i8" => Some(1),
        "u16" | "i16" => Some(2),
        "u32" | "i32" | "f32" => Some(4),
        "u64" | "i64" | "f64" => Some(8),
        "u128" | "i128" => Some(16),
        "usize" | "isize" => Some(8), // Assume 64-bit
        _ => None,
    }
}

/// Register all advanced memory rules with the rule engine.
pub fn register_advanced_memory_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(DanglingPointerUseAfterFreeRule::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangling_pointer_rule_metadata() {
        let rule = DanglingPointerUseAfterFreeRule::new();
        assert_eq!(rule.metadata().id, "RUSTCOLA200");
        assert_eq!(rule.metadata().default_severity, Severity::Critical);
        assert!(rule.metadata().cwe_ids.contains(&"CWE-416".to_string())); // Use After Free
    }

    #[test]
    fn test_derive_macro_detection() {
        assert!(is_derive_macro_function(
            "<impl at src/lib.rs:10:5: 12:6>::eq"
        ));
        assert!(!is_derive_macro_function("my_module::my_function"));
    }

    #[test]
    fn test_safe_trait_method_detection() {
        assert!(is_safe_trait_method("MyType::eq", "fn eq(&self, other: &Self) -> bool"));
        assert!(is_safe_trait_method("MyType::clone", "fn clone(&self) -> Self"));
        assert!(!is_safe_trait_method("MyType::process", "fn process(&self)"));
    }
}
