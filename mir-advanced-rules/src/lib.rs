//! Advanced MIR-based security rules for Rust-cola

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use once_cell::sync::Lazy;
use regex::Regex;

// Example trait for rule integration
pub trait AdvancedRule {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn evaluate(&self, mir: &str) -> Vec<String>; // Replace with real MIR type
}

/// Advanced memory safety rule: Detects use of pointers after their memory has been freed.
/// Approach:
/// - Track pointer allocations (Box, Vec, raw pointer creation)
/// - Track explicit deallocation (drop, free, Box::from_raw, etc.)
/// - Flag any dereference or use of a pointer after its memory has been freed
/// - Focus on unsafe blocks and FFI boundaries
pub struct DanglingPointerUseAfterFreeRule;

impl AdvancedRule for DanglingPointerUseAfterFreeRule {
    fn id(&self) -> &'static str {
        "ADV001"
    }

    fn description(&self) -> &'static str {
        "Detects use of pointers after their memory has been freed (use-after-free)."
    }

    fn evaluate(&self, mir: &str) -> Vec<String> {
        PointerAnalyzer::default().analyze(mir)
    }
}

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
        // Reset any previous alias chain to ensure the pointer resolves to itself.
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
                    && self
                        .reported
                        .insert((pointer_key.clone(), line_index))
                {
                    let message = format!(
                        "Potential dangling pointer: `{}` {} after {} of `{}`.\n  creation: `{}`\n  invalidation: `{}`\n  use: `{}`",
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
                "Invalid pointer dereference: `{}` is null.\n  assignment: `{}`\n  use: `{}`",
                display,
                info.line.trim(),
                line.trim()
            ),
            PointerValidityKind::Misaligned { alignment, address } => format!(
                "Invalid pointer dereference: `{}` has address 0x{:x} which is not aligned to {} bytes.\n  assignment: `{}`\n  use: `{}`",
                display,
                address,
                alignment,
                info.line.trim(),
                line.trim()
            ),
        };

        self.findings.push(message);
    }

    fn evaluate_pointer_escape(&mut self, line_index: usize, line: &str, ptr_var: &str, reason: &str) {
        if let Some((pointer_key, info)) = self.lookup_pointer(ptr_var) {
            if info.owner_kind == OwnerKind::Stack
                && self.reported.insert((pointer_key.clone(), line_index))
            {
                let message = format!(
                    "Pointer `{}` escapes stack allocation: {}.\n  creation: `{}`\n  escape: `{}`",
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
            "Unsafe ptr::copy_nonoverlapping: src `{}` and dst `{}` may overlap.\n  call: `{}`",
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
        static RE_ALIAS_SIMPLE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^(_\d+)\s*=\s*(?:copy|move)\s+(_\d+)\s*;")
                .expect("alias regex")
        });
        static RE_ALIAS_INDEX: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^(_\d+)\s*=.*::index\(\s*(?:move|copy)\s+(_\d+),")
                .expect("index alias regex")
        });

        if let Some(caps) = RE_ALIAS_SIMPLE.captures(line) {
            return Some((caps[1].to_string(), caps[2].to_string()));
        }

        if let Some(caps) = RE_ALIAS_INDEX.captures(line) {
            return Some((caps[1].to_string(), caps[2].to_string()));
        }

        None
    }

    fn detect_null_pointer_assignment(line: &str) -> Option<String> {
        static RE_NULL: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^(_\d+)\s*=\s*null(?:_mut)?::<[^>]+>\(\)\s*->")
                .expect("null pointer regex")
        });

        RE_NULL
            .captures(line)
            .map(|caps| caps[1].to_string())
    }

    fn detect_const_pointer_assignment(line: &str) -> Option<ConstPointerEvent> {
        static RE_CONST_PTR: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^(_\d+)\s*=\s*const\s+([0-9_]+)_(?:[iu](?:size|8|16|32|64|128))\s+as\s+\*(?:const|mut)\s+([A-Za-z0-9_]+)")
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
            Regex::new(r"copy_nonoverlapping::<[^>]+>\((?:move|copy)\s+(_\d+)[^,]*,\s*(?:move|copy)\s+(_\d+)")
                .expect("copy_nonoverlapping regex")
        });

        let caps = RE_COPY.captures(line)?;
        Some(CopyNonOverlappingCall {
            src: caps[1].to_string(),
            dst: caps[2].to_string(),
        })
    }

    fn detect_pointer_creation(line: &str) -> Option<PointerCreationEvent<'_>> {
        static RE_ADDR_OF: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^(_\d+)\s*=\s*&raw\s+(?:const|mut)\s+\(\*([^\)]+)\);")
                .expect("addr-of regex")
        });
        static RE_REF: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^(_\d+)\s*=\s*&(?:mut\s+)?(_\d+)\s*;")
                .expect("ref regex")
        });
        static RE_INTO_RAW: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^(_\d+)\s*=.*::into_raw\(\s*move\s+(_\d+)\s*\).*")
                .expect("into_raw regex")
        });
        static RE_BOX_LEAK: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^(_\d+)\s*=.*Box::leak\(\s*move\s+(_\d+)\s*\).*")
                .expect("box leak regex")
        });
        static RE_AS_PTR: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^(_\d+)\s*=\s*copy\s+(_\d+)\s+as\s+\*const")
                .expect("as_ptr regex")
        });

        if let Some(caps) = RE_ADDR_OF.captures(line) {
            return Some(PointerCreationEvent::stack(caps[1].to_string(), caps[2].to_string(), line));
        }

        if let Some(caps) = RE_REF.captures(line) {
            return Some(PointerCreationEvent::stack(caps[1].to_string(), caps[2].to_string(), line));
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
        static RE_DROP: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"drop\(\s*([^\)]+)\)").expect("drop regex")
        });
        static RE_STORAGE_DEAD: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"StorageDead\(\s*([^\)]+)\)").expect("storage dead regex")
        });
        static RE_DROP_IN_PLACE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"drop_in_place::<[^>]+>\(\s*(?:move\s+)?([^\)]+)\)").expect("drop_in_place regex")
        });
        static RE_DEALLOC: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"dealloc\(\s*(?:move\s+)?([^,\s\)]+)").expect("dealloc regex")
        });
        static RE_VEC_REALLOC: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"Vec::<[^>]+>::(?:push|append|extend|insert|reserve|reserve_exact|resize|resize_with|shrink_to_fit|shrink_to|truncate|clear)\(\s*(?:move|copy)?\s*(_\d+)")
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
        static RE_DEREF: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\*\s*\(?\s*(_\d+)").expect("deref regex")
        });
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

        static RE_MOVE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:move|copy)\s+(_\d+)").expect("aggregate move regex")
        });

        let mut vars = HashSet::new();

        for caps in RE_MOVE.captures_iter(line) {
            vars.insert(caps[1].to_string());
        }

        vars.into_iter().collect()
    }

    fn detect_pointer_store(line: &str) -> Vec<String> {
        static RE_STORE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\(\*[^\)]+\)\s*=\s*(?:move|copy)\s+(_\d+)")
                .expect("pointer store regex")
        });

        RE_STORE
            .captures_iter(line)
            .map(|caps| caps[1].to_string())
            .collect()
    }

    fn detect_return_pointer(line: &str) -> Option<String> {
        static RE_RETURN: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^_0\s*=\s*(?:copy|move)\s+(_\d+)\s*;").expect("return regex")
        });

        RE_RETURN
            .captures(line)
            .map(|caps| caps[1].to_string())
    }
}

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
        text = text[1..text.len() - 1].trim();
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

    if let Some(idx) = text.find(&[' ', '.', ':', ','][..]) {
        text = text[..idx].trim();
    }

    text.to_string()
}

fn alignment_for_type(type_name: &str) -> Option<usize> {
    match type_name {
        "u8" | "i8" | "bool" | "()" | "str" => Some(1),
        "u16" | "i16" => Some(2),
        "u32" | "i32" | "f32" | "char" => Some(4),
        "u64" | "i64" | "f64" => Some(8),
        "u128" | "i128" => Some(16),
        "usize" | "isize" => Some(8),
        _ => None,
    }
}

// Add more advanced rules here...

/// Advanced rule that flags JSON/TOML deserialization on untrusted data without
/// prior validation. This mirrors RUSTCOLA091 in a lightweight form for the
/// standalone analyzer.
pub struct InsecureJsonTomlDeserializationRule;

impl AdvancedRule for InsecureJsonTomlDeserializationRule {
    fn id(&self) -> &'static str {
        "ADV002"
    }

    fn description(&self) -> &'static str {
        "Detects JSON/TOML deserialization on untrusted input without size checks."
    }

    fn evaluate(&self, mir: &str) -> Vec<String> {
        JsonTomlAnalyzer::default().analyze(mir)
    }
}

#[derive(Default)]
struct JsonTomlAnalyzer {
    tainted: HashSet<String>,
    taint_roots: HashMap<String, String>,
    sanitized_roots: HashSet<String>,
    pending_len_checks: HashMap<String, String>,
    sources: HashMap<String, String>,
    findings: Vec<String>,
}

impl JsonTomlAnalyzer {
    const SINK_PATTERNS: &'static [&'static str] = &[
        "serde_json::from_str",
        "serde_json::from_slice",
        "serde_json::from_reader",
        "serde_json::Deserializer::from_str",
        "serde_json::Deserializer::from_slice",
        "toml::from_str",
        "toml::de::from_str",
    ];

    const UNTRUSTED_PATTERNS: &'static [&'static str] = &[
        "env::var",
        "env::var_os",
        "env::args",
        "std::env::var",
        "std::env::args",
        "stdin",
        "TcpStream",
        "read_to_string",
        "read_to_end",
        "fs::read",
        "File::open",
    ];

    fn analyze(mut self, mir: &str) -> Vec<String> {
        for line in mir.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(dest) = detect_assignment(trimmed) {
                if Self::is_untrusted_source(trimmed) {
                    self.mark_source(&dest, trimmed);
                } else if let Some(source) = self.find_tainted_in_line(trimmed) {
                    self.mark_alias(&dest, &source);
                }
            }

            self.track_len_checks(trimmed);

            if let Some(sink_name) = Self::detect_sink(trimmed) {
                let args = extract_call_args(trimmed);
                for arg in args {
                    if let Some(root) = self.taint_roots.get(&arg).cloned() {
                        if self.sanitized_roots.contains(&root) {
                            continue;
                        }

                        let mut message = format!(
                            "Insecure JSON/TOML deserialization: untrusted data flows into `{}`.\n  call: `{}`",
                            sink_name,
                            trimmed
                        );

                        if let Some(origin) = self.sources.get(&root) {
                            message.push_str(&format!("\n  source: `{}`", origin));
                        }

                        self.findings.push(message);
                        break;
                    }
                }
            }
        }

        self.findings
    }

    fn mark_source(&mut self, var: &str, origin: &str) {
        let var = var.to_string();
        self.tainted.insert(var.clone());
        self.taint_roots.insert(var.clone(), var.clone());
        self.sources.entry(var).or_insert_with(|| origin.trim().to_string());
    }

    fn mark_alias(&mut self, dest: &str, source: &str) {
        if !self.tainted.contains(source) {
            return;
        }

        if let Some(root) = self.taint_roots.get(source).cloned() {
            self.tainted.insert(dest.to_string());
            self.taint_roots.insert(dest.to_string(), root.clone());
        }
    }

    fn track_len_checks(&mut self, line: &str) {
        if let Some((len_var, src_var)) = detect_len_call(line) {
            if let Some(root) = self.taint_roots.get(&src_var).cloned() {
                self.pending_len_checks.insert(len_var, root);
            }
        }

        if let Some(len_var) = detect_len_comparison(line) {
            if let Some(root) = self.pending_len_checks.remove(&len_var) {
                self.sanitized_roots.insert(root);
            }
        }
    }

    fn is_untrusted_source(line: &str) -> bool {
        Self::UNTRUSTED_PATTERNS.iter().any(|pattern| line.contains(pattern))
    }

    fn detect_sink(line: &str) -> Option<&'static str> {
        Self::SINK_PATTERNS
            .iter()
            .copied()
            .find(|pattern| line.contains(pattern))
    }

    fn find_tainted_in_line(&self, line: &str) -> Option<String> {
        self.tainted
            .iter()
            .find(|var| contains_var(line, var))
            .cloned()
    }
}

fn detect_assignment(line: &str) -> Option<String> {
    static RE_ASSIGN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(_\d+)\s*=").expect("assign regex"));

    if let Some(caps) = RE_ASSIGN.captures(line) {
        return Some(caps[1].to_string());
    }

    if line.starts_with("(*_") {
        if let Some(end) = line.find(')') {
            return Some(line[2..end].to_string());
        }
    }

    None
}

fn extract_call_args(line: &str) -> Vec<String> {
    static RE_ARG: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?:copy|move)\s+(_\d+)").expect("arg regex"));

    RE_ARG
        .captures_iter(line)
        .map(|caps| caps[1].to_string())
        .collect()
}

fn detect_len_call(line: &str) -> Option<(String, String)> {
    static RE_LEN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^(_\d+)\s*=.*::len\((?:move|copy)\s+(_\d+)")
            .expect("len regex")
    });

    RE_LEN
        .captures(line)
        .map(|caps| (caps[1].to_string(), caps[2].to_string()))
}

fn detect_len_comparison(line: &str) -> Option<String> {
    static RE_LEN_CMP: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?:Gt|Lt|Ge|Le)\((?:move|copy)\s+(_\d+),\s*const")
            .expect("len cmp regex")
    });

    RE_LEN_CMP
        .captures(line)
        .map(|caps| caps[1].to_string())
}

fn contains_var(text: &str, var: &str) -> bool {
    if text.contains(var) {
        return true;
    }

    let var_num = var.trim_start_matches('_');
    text.contains(&format!("move _{}", var_num))
        || text.contains(&format!("copy _{}", var_num))
        || text.contains(&format!("_{}.0", var_num))
        || text.contains(&format!("_{}.1", var_num))
        || text.contains(&format!("&_{}", var_num))
        || text.contains(&format!("(*_{})", var_num))
}

fn detect_const_string_assignment(line: &str) -> Option<(String, String)> {
    static RE_CONST_STR: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"^(_\d+)\s*=\s*const\s*\"((?:\\.|[^\"])*)\""#)
            .expect("const string regex")
    });

    RE_CONST_STR.captures(line).map(|caps| {
        let var = caps[1].to_string();
        let literal = caps[2].to_string();
        (var, literal)
    })
}

fn detect_var_alias(line: &str) -> Option<(String, String)> {
    static RE_ALIAS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^(_\d+)\s*=\s*(?:copy|move)\s+(_\d+)")
            .expect("alias regex")
    });

    RE_ALIAS
        .captures(line)
        .map(|caps| (caps[1].to_string(), caps[2].to_string()))
}

fn detect_drop_calls(line: &str) -> Vec<String> {
    static RE_DROP: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"drop\(\s*(?:move\s+)?(_\d+)\s*\)").expect("drop call regex")
    });

    RE_DROP
        .captures_iter(line)
        .map(|caps| caps[1].to_string())
        .collect()
}

fn detect_storage_dead_vars(line: &str) -> Vec<String> {
    static RE_DEAD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"StorageDead\(\s*(_\d+)\s*\)").expect("storage dead regex")
    });

    RE_DEAD
        .captures_iter(line)
        .map(|caps| caps[1].to_string())
        .collect()
}

fn extract_const_literals(line: &str) -> Vec<String> {
    static RE_LITERAL: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"const\s*\"((?:\\.|[^\"])*)\""#).expect("literal regex")
    });

    RE_LITERAL
        .captures_iter(line)
        .map(|caps| caps[1].to_string())
        .collect()
}

fn unescape_rust_literal(raw: &str) -> String {
    let mut result = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                match next {
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    '\\' => result.push('\\'),
                    '"' => result.push('"'),
                    other => {
                        result.push(other);
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }
    result
}

fn pattern_is_high_risk(pattern: &str) -> bool {
    static RE_NESTED_QUANTIFIERS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\((?:[^()]|\\.)*[+*](?:[^()]|\\.)*\)[+*{]")
            .expect("nested quantifier regex")
    });

    static RE_DOT_STAR_LOOP: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\(\?:?\.\*(?:[^()]|\\.)*\)[+*{]")
            .expect("dot-star loop regex")
    });

    let simplified = pattern.replace(' ', "");
    RE_NESTED_QUANTIFIERS.is_match(&simplified) || RE_DOT_STAR_LOOP.is_match(&simplified)
}

/// Advanced rule highlighting catastrophic backtracking patterns in regex
/// compilation.
pub struct RegexBacktrackingDosRule;

impl AdvancedRule for RegexBacktrackingDosRule {
    fn id(&self) -> &'static str {
        "ADV004"
    }

    fn description(&self) -> &'static str {
        "Detects regex patterns with nested quantifiers that trigger catastrophic backtracking."
    }

    fn evaluate(&self, mir: &str) -> Vec<String> {
        RegexDosAnalyzer::default().analyze(mir)
    }
}

#[derive(Default)]
struct RegexDosAnalyzer {
    const_strings: HashMap<String, String>,
    findings: Vec<String>,
    reported_lines: HashSet<String>,
}

impl RegexDosAnalyzer {
    const SINK_PATTERNS: &'static [&'static str] = &[
        "regex::Regex::new",
        "regex::RegexSet::new",
        "regex::builders::RegexBuilder::new",
        "regex::RegexBuilder::new",
    ];

    fn analyze(mut self, mir: &str) -> Vec<String> {
        for line in mir.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some((var, literal)) = detect_const_string_assignment(trimmed) {
                self.const_strings.insert(var, unescape_rust_literal(&literal));
                continue;
            }

            if let Some((dest, src)) = detect_var_alias(trimmed) {
                if let Some(value) = self.const_strings.get(&src).cloned() {
                    self.const_strings.insert(dest, value);
                }
            }

            if let Some(sink) = Self::detect_sink(trimmed) {
                if self.check_const_literals(sink, trimmed) {
                    continue;
                }

                let args = extract_call_args(trimmed);
                for arg in args {
                    if let Some(pattern) = self.const_strings.get(&arg).cloned() {
                        if pattern_is_high_risk(&pattern) {
                            self.report_finding(sink, trimmed, &pattern);
                            break;
                        }
                    }
                }
            }
        }

        self.findings
    }

    fn detect_sink(line: &str) -> Option<&'static str> {
        Self::SINK_PATTERNS
            .iter()
            .copied()
            .find(|pattern| line.contains(pattern))
    }

    fn check_const_literals(&mut self, sink: &str, line: &str) -> bool {
        for literal in extract_const_literals(line) {
            let unescaped = unescape_rust_literal(&literal);
            if pattern_is_high_risk(&unescaped) {
                self.report_finding(sink, line, &unescaped);
                return true;
            }
        }
        false
    }

    fn report_finding(&mut self, sink: &str, line: &str, pattern: &str) {
        let key = format!("{}::{}", sink, line.trim());
        if !self.reported_lines.insert(key) {
            return;
        }

        let display = if pattern.len() > 60 {
            format!("{}...", &pattern[..57])
        } else {
            pattern.to_string()
        };

        let message = format!(
            "Potential regex denial-of-service: pattern `{}` compiled via `{}` may trigger catastrophic backtracking.\n  call: `{}`",
            display,
            sink,
            line.trim()
        );

        self.findings.push(message);
    }
}

/// Advanced rule detecting template/HTML responses built from unescaped user
/// input in web handlers.
pub struct TemplateInjectionRule;

impl AdvancedRule for TemplateInjectionRule {
    fn id(&self) -> &'static str {
        "ADV005"
    }

    fn description(&self) -> &'static str {
        "Detects template/HTML responses built from untrusted input without HTML escaping."
    }

    fn evaluate(&self, mir: &str) -> Vec<String> {
        TemplateInjectionAnalyzer::default().analyze(mir)
    }
}

#[derive(Default)]
struct TemplateInjectionAnalyzer {
    tainted: HashSet<String>,
    taint_roots: HashMap<String, String>,
    sanitized_roots: HashSet<String>,
    sources: HashMap<String, String>,
    findings: Vec<String>,
}

/// Advanced rule detecting non-Send types moved into multi-threaded async
/// executors, which requires captured values to be `Send`.
pub struct UnsafeSendAcrossAsyncBoundaryRule;

impl AdvancedRule for UnsafeSendAcrossAsyncBoundaryRule {
    fn id(&self) -> &'static str {
        "ADV006"
    }

    fn description(&self) -> &'static str {
        "Detects non-Send types captured by multi-threaded async executors like `tokio::spawn`."
    }

    fn evaluate(&self, mir: &str) -> Vec<String> {
        AsyncSendAnalyzer::default().analyze(mir)
    }
}

#[derive(Default)]
struct AsyncSendAnalyzer {
    roots: HashMap<String, String>,
    unsafe_roots: HashSet<String>,
    safe_roots: HashSet<String>,
    sources: HashMap<String, String>,
    findings: Vec<String>,
}

impl AsyncSendAnalyzer {
    const NON_SEND_PATTERNS: &'static [&'static str] = &[
        "alloc::rc::Rc",
        "std::rc::Rc",
        "core::cell::RefCell",
        "std::cell::RefCell",
        "alloc::rc::Weak",
        "std::rc::Weak",
    ];

    const SAFE_PATTERNS: &'static [&'static str] = &[
        "std::sync::Arc",
        "alloc::sync::Arc",
        "std::sync::Mutex",
        "tokio::sync::Mutex",
    ];

    const SPAWN_PATTERNS: &'static [&'static str] = &[
        "tokio::spawn",
        "tokio::task::spawn",
        "tokio::task::spawn_blocking",
        "async_std::task::spawn",
        "async_std::task::spawn_blocking",
        "smol::spawn",
        "futures::executor::ThreadPool::spawn",
        "std::thread::spawn",
    ];

    const SPAWN_LOCAL_PATTERNS: &'static [&'static str] = &[
        "tokio::task::spawn_local",
        "async_std::task::spawn_local",
        "smol::spawn_local",
        "futures::task::SpawnExt::spawn_local",
    ];

    fn analyze(mut self, mir: &str) -> Vec<String> {
        for line in mir.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(dest) = detect_assignment(trimmed) {
                self.clear_var(&dest);

                if Self::is_non_send_origin(trimmed) {
                    self.mark_non_send(&dest, trimmed);
                } else if Self::is_safe_origin(trimmed) {
                    self.mark_safe(&dest);
                } else if let Some(source) = self.find_tracked_in_line(trimmed) {
                    self.mark_alias(&dest, &source);
                }
            }

            if let Some(spawn) = Self::detect_spawn(trimmed) {
                if Self::is_spawn_local(trimmed) {
                    continue;
                }

                let args = extract_call_args(trimmed);
                for arg in args {
                    if let Some(root) = self.roots.get(&arg).cloned() {
                        if self.safe_roots.contains(&root) {
                            continue;
                        }

                        if !self.unsafe_roots.contains(&root) {
                            continue;
                        }

                        let mut message = format!(
                            "Non-Send type captured in `{}` may cross thread boundary.
  call: `{}`",
                            spawn,
                            trimmed
                        );

                        if let Some(origin) = self.sources.get(&root) {
                            message.push_str(&format!("\n  source: `{}`", origin));
                        }

                        self.findings.push(message);
                        break;
                    }
                }
            }
        }

        self.findings
    }

    fn mark_non_send(&mut self, var: &str, origin: &str) {
        let var = var.to_string();
        self.roots.insert(var.clone(), var.clone());
        self.unsafe_roots.insert(var.clone());
        self.safe_roots.remove(&var);
        self.sources
            .entry(var)
            .or_insert_with(|| origin.trim().to_string());
    }

    fn mark_safe(&mut self, var: &str) {
        let var = var.to_string();
        self.roots.insert(var.clone(), var.clone());
        self.safe_roots.insert(var.clone());
        self.unsafe_roots.remove(&var);
    }

    fn mark_alias(&mut self, dest: &str, source: &str) {
        if let Some(root) = self.roots.get(source).cloned() {
            self.roots.insert(dest.to_string(), root);
        }
    }

    fn clear_var(&mut self, var: &str) {
        self.roots.remove(var);
    }

    fn find_tracked_in_line(&self, line: &str) -> Option<String> {
        self.roots
            .keys()
            .find(|var| contains_var(line, var))
            .cloned()
    }

    fn is_non_send_origin(line: &str) -> bool {
        Self::NON_SEND_PATTERNS
            .iter()
            .any(|pattern| line.contains(pattern))
    }

    fn is_safe_origin(line: &str) -> bool {
        Self::SAFE_PATTERNS
            .iter()
            .any(|pattern| line.contains(pattern))
    }

    fn detect_spawn(line: &str) -> Option<&'static str> {
        Self::SPAWN_PATTERNS
            .iter()
            .copied()
            .find(|pattern| line.contains(pattern))
    }

    fn is_spawn_local(line: &str) -> bool {
        Self::SPAWN_LOCAL_PATTERNS
            .iter()
            .any(|pattern| line.contains(pattern))
    }
}

/// Advanced rule detecting span guards that remain live across `.await`, which can
/// lead to incorrect tracing due to spans outliving their intended scope.
pub struct AwaitSpanGuardRule;

impl AdvancedRule for AwaitSpanGuardRule {
    fn id(&self) -> &'static str {
        "ADV007"
    }

    fn description(&self) -> &'static str {
        "Detects tracing span guards held across await points." 
    }

    fn evaluate(&self, mir: &str) -> Vec<String> {
        AwaitSpanGuardAnalyzer::default().analyze(mir)
    }
}

#[derive(Default)]
struct AwaitSpanGuardAnalyzer {
    var_to_root: HashMap<String, String>,
    guard_states: HashMap<String, GuardState>,
    findings: Vec<String>,
    reported: HashSet<String>,
}

#[derive(Clone)]
struct GuardState {
    origin: String,
    count: usize,
}

impl AwaitSpanGuardAnalyzer {
    const GUARD_PATTERNS: &'static [&'static str] = &[
        "tracing::Span::enter",
        "tracing::span::Span::enter",
        "tracing::dispatcher::DefaultGuard::new",
    ];

    fn analyze(mut self, mir: &str) -> Vec<String> {
        for line in mir.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some((dest, source)) = detect_var_alias(trimmed) {
                self.clear_var(&dest);
                self.mark_alias(&dest, &source);
                continue;
            }

            if let Some(dest) = detect_assignment(trimmed) {
                self.clear_var(&dest);
                if Self::is_guard_creation(trimmed) {
                    self.mark_guard(&dest, trimmed);
                }
            }

            for var in detect_drop_calls(trimmed) {
                self.release_guard(&var);
            }

            for var in detect_storage_dead_vars(trimmed) {
                self.release_guard(&var);
            }

            if Self::contains_await(trimmed) {
                self.check_await(trimmed);
            }
        }

        self.findings
    }

    fn mark_guard(&mut self, var: &str, origin: &str) {
        let var = var.to_string();
        self.var_to_root.insert(var.clone(), var.clone());
        self.guard_states.insert(
            var,
            GuardState {
                origin: origin.trim().to_string(),
                count: 1,
            },
        );
    }

    fn mark_alias(&mut self, dest: &str, source: &str) {
        if let Some(root) = self.var_to_root.get(source).cloned() {
            self.var_to_root.insert(dest.to_string(), root.clone());
            if let Some(state) = self.guard_states.get_mut(&root) {
                state.count += 1;
            }
        }
    }

    fn clear_var(&mut self, var: &str) {
        if let Some(root) = self.var_to_root.remove(var) {
            self.decrement_root(&root);
        }
    }

    fn release_guard(&mut self, var: &str) {
        self.clear_var(var);
    }

    fn decrement_root(&mut self, root: &str) {
        if let Some(state) = self.guard_states.get_mut(root) {
            if state.count > 1 {
                state.count -= 1;
            } else {
                self.guard_states.remove(root);
            }
        }
    }

    fn check_await(&mut self, await_line: &str) {
        if self.guard_states.is_empty() {
            return;
        }

        for (root, state) in self.guard_states.iter() {
            let key = format!("{}::{}", root, await_line.trim());
            if !self.reported.insert(key) {
                continue;
            }

            let message = format!(
                "Span guard held across await: guard `{}` created at `{}` remains active.
  await: `{}`",
                root,
                state.origin,
                await_line.trim()
            );
            self.findings.push(message);
        }
    }

    fn is_guard_creation(line: &str) -> bool {
        Self::GUARD_PATTERNS
            .iter()
            .any(|pattern| line.contains(pattern))
    }

    fn contains_await(line: &str) -> bool {
        line.contains(".await") || line.contains("Await") || line.contains("await ")
    }
}

impl TemplateInjectionAnalyzer {
    const UNTRUSTED_PATTERNS: &'static [&'static str] = &[
        "env::var",
        "env::var_os",
        "env::args",
        "std::env::var",
        "std::env::args",
        "stdin",
        "TcpStream",
        "read_to_string",
        "read_to_end",
        "axum::extract",
        "warp::filters::path::param",
        "warp::filters::query::query",
        "Request::uri",
        "Request::body",
        "hyper::body::to_bytes",
    ];

    const SANITIZER_PATTERNS: &'static [&'static str] = &[
        "html_escape::encode_safe",
        "html_escape::encode_double_quoted_attribute",
        "html_escape::encode_single_quoted_attribute",
        "ammonia::clean",
        "maud::Escaped",
    ];

    const SINK_PATTERNS: &'static [&'static str] = &[
        "warp::reply::html",
        "axum::response::Html::from",
        "axum::response::Html::new",
        "rocket::response::content::Html::new",
        "rocket::response::content::Html::from",
        "HttpResponse::body",
        "HttpResponse::Ok",
    ];

    fn analyze(mut self, mir: &str) -> Vec<String> {
        for line in mir.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(dest) = detect_assignment(trimmed) {
                if Self::is_untrusted_source(trimmed) {
                    self.mark_source(&dest, trimmed);
                    continue;
                }

                if Self::is_sanitizer_call(trimmed) {
                    if let Some(source) = self.find_tainted_in_line(trimmed) {
                        self.mark_sanitized(&dest, &source);
                        continue;
                    }
                }

                if let Some(source) = self.find_tainted_in_line(trimmed) {
                    self.mark_alias(&dest, &source);
                }
            }

            if let Some(sink) = Self::detect_sink(trimmed) {
                let args = extract_call_args(trimmed);
                for arg in args {
                    if let Some(root) = self.taint_roots.get(&arg).cloned() {
                        if self.sanitized_roots.contains(&root) {
                            continue;
                        }

                        let mut message = format!(
                            "Possible template injection: unescaped input flows into `{}`.\n  call: `{}`",
                            sink,
                            trimmed
                        );

                        if let Some(origin) = self.sources.get(&root) {
                            message.push_str(&format!("\n  source: `{}`", origin));
                        }

                        self.findings.push(message);
                        break;
                    }
                }
            }
        }

        self.findings
    }

    fn mark_source(&mut self, var: &str, origin: &str) {
        let var = var.to_string();
        self.tainted.insert(var.clone());
        self.taint_roots.insert(var.clone(), var.clone());
        self.sources.entry(var).or_insert_with(|| origin.trim().to_string());
    }

    fn mark_alias(&mut self, dest: &str, source: &str) {
        if !self.tainted.contains(source) {
            return;
        }

        if let Some(root) = self.taint_roots.get(source).cloned() {
            self.tainted.insert(dest.to_string());
            self.taint_roots.insert(dest.to_string(), root);
        }
    }

    fn mark_sanitized(&mut self, dest: &str, source: &str) {
        if let Some(root) = self.taint_roots.get(source).cloned() {
            self.sanitized_roots.insert(root.clone());
            self.tainted.insert(dest.to_string());
            self.taint_roots.insert(dest.to_string(), root);
        }
    }

    fn is_untrusted_source(line: &str) -> bool {
        Self::UNTRUSTED_PATTERNS
            .iter()
            .any(|pattern| line.contains(pattern))
    }

    fn is_sanitizer_call(line: &str) -> bool {
        Self::SANITIZER_PATTERNS
            .iter()
            .any(|pattern| line.contains(pattern))
    }

    fn detect_sink(line: &str) -> Option<&'static str> {
        Self::SINK_PATTERNS
            .iter()
            .copied()
            .find(|pattern| line.contains(pattern))
    }

    fn find_tainted_in_line(&self, line: &str) -> Option<String> {
        self.tainted
            .iter()
            .find(|var| contains_var(line, var))
            .cloned()
    }
}

/// Advanced rule that flags binary (bincode/postcard) deserialization on
/// untrusted data without prior validation.
pub struct InsecureBinaryDeserializationRule;

impl AdvancedRule for InsecureBinaryDeserializationRule {
    fn id(&self) -> &'static str {
        "ADV003"
    }

    fn description(&self) -> &'static str {
        "Detects binary deserialization on untrusted input without size checks."
    }

    fn evaluate(&self, mir: &str) -> Vec<String> {
        BinaryDeserializationAnalyzer::default().analyze(mir)
    }
}

#[derive(Default)]
struct BinaryDeserializationAnalyzer {
    tainted: HashSet<String>,
    taint_roots: HashMap<String, String>,
    sanitized_roots: HashSet<String>,
    pending_len_checks: HashMap<String, String>,
    sources: HashMap<String, String>,
    findings: Vec<String>,
}

impl BinaryDeserializationAnalyzer {
    const SINK_PATTERNS: &'static [&'static str] = &[
        "bincode::deserialize",
        "bincode::deserialize_from",
        "bincode::config::deserialize",
        "bincode::config::deserialize_from",
        "postcard::from_bytes",
        "postcard::from_bytes_cobs",
        "postcard::take_from_bytes",
        "postcard::take_from_bytes_cobs",
    ];

    const UNTRUSTED_PATTERNS: &'static [&'static str] = &[
        "env::var",
        "env::var_os",
        "env::args",
        "std::env::var",
        "std::env::args",
        "stdin",
        "TcpStream",
        "read_to_string",
        "read_to_end",
        "fs::read",
        "File::open",
    ];

    fn analyze(mut self, mir: &str) -> Vec<String> {
        for line in mir.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(dest) = detect_assignment(trimmed) {
                if Self::is_untrusted_source(trimmed) {
                    self.mark_source(&dest, trimmed);
                } else if let Some(source) = self.find_tainted_in_line(trimmed) {
                    self.mark_alias(&dest, &source);
                }
            }

            self.track_len_checks(trimmed);

            if let Some(sink_name) = Self::detect_sink(trimmed) {
                let args = extract_call_args(trimmed);
                for arg in args {
                    if let Some(root) = self.taint_roots.get(&arg).cloned() {
                        if self.sanitized_roots.contains(&root) {
                            continue;
                        }

                        let mut message = format!(
                            "Insecure binary deserialization: untrusted data flows into `{}`.\n  call: `{}`",
                            sink_name,
                            trimmed
                        );

                        if let Some(origin) = self.sources.get(&root) {
                            message.push_str(&format!("\n  source: `{}`", origin));
                        }

                        self.findings.push(message);
                        break;
                    }
                }
            }
        }

        self.findings
    }

    fn mark_source(&mut self, var: &str, origin: &str) {
        let var = var.to_string();
        self.tainted.insert(var.clone());
        self.taint_roots.insert(var.clone(), var.clone());
        self.sources.entry(var).or_insert_with(|| origin.trim().to_string());
    }

    fn mark_alias(&mut self, dest: &str, source: &str) {
        if !self.tainted.contains(source) {
            return;
        }

        if let Some(root) = self.taint_roots.get(source).cloned() {
            self.tainted.insert(dest.to_string());
            self.taint_roots.insert(dest.to_string(), root.clone());
        }
    }

    fn track_len_checks(&mut self, line: &str) {
        if let Some((len_var, src_var)) = detect_len_call(line) {
            if let Some(root) = self.taint_roots.get(&src_var).cloned() {
                self.pending_len_checks.insert(len_var, root);
            }
        }

        if let Some(len_var) = detect_len_comparison(line) {
            if let Some(root) = self.pending_len_checks.remove(&len_var) {
                self.sanitized_roots.insert(root);
            }
        }
    }

    fn is_untrusted_source(line: &str) -> bool {
        Self::UNTRUSTED_PATTERNS
            .iter()
            .any(|pattern| line.contains(pattern))
    }

    fn detect_sink(line: &str) -> Option<&'static str> {
        Self::SINK_PATTERNS
            .iter()
            .copied()
            .find(|pattern| line.contains(pattern))
    }

    fn find_tainted_in_line(&self, line: &str) -> Option<String> {
        self.tainted
            .iter()
            .find(|var| contains_var(line, var))
            .cloned()
    }
}

/// Advanced rule that detects uncontrolled allocation sizes from untrusted sources.
/// Flags allocations (Vec::with_capacity, reserve, HashMap::with_capacity, etc.)
/// that use sizes derived from untrusted external sources (env vars, CLI args,
/// stdin, network) without upper bound validation.
pub struct UncontrolledAllocationSizeRule;

impl AdvancedRule for UncontrolledAllocationSizeRule {
    fn id(&self) -> &'static str {
        "ADV008"
    }

    fn description(&self) -> &'static str {
        "Detects allocations sized from untrusted sources without upper bound validation."
    }

    fn evaluate(&self, mir: &str) -> Vec<String> {
        AllocationSizeAnalyzer::default().analyze(mir)
    }
}

#[derive(Default)]
struct AllocationSizeAnalyzer {
    tainted: HashSet<String>,
    taint_roots: HashMap<String, String>,
    sanitized_roots: HashSet<String>,
    sources: HashMap<String, String>,
    findings: Vec<String>,
}

impl AllocationSizeAnalyzer {
    /// Allocation API sinks that take a capacity/size argument
    const ALLOCATION_SINKS: &'static [&'static str] = &[
        "Vec::<",
        ">::with_capacity",
        "::with_capacity(",
        "with_capacity(",
        ">::reserve(",
        "::reserve(",
        ">::reserve_exact(",
        "::reserve_exact(",
        "HashMap::<",
        "HashSet::<",
        "BTreeMap::<",
        "BTreeSet::<",
        "VecDeque::<",
        "String::with_capacity",
        "BytesMut::with_capacity",
        "Bytes::with_capacity",
        "Box::new_uninit_slice",
        "Vec::from_raw_parts",
        "slice::from_raw_parts",
    ];

    /// Untrusted external input sources
    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        "env::var",
        "env::var_os",
        "env::args",
        "std::env::var",
        "std::env::args",
        "stdin",
        "Stdin",
        "TcpStream",
        "UdpSocket",
        "UnixStream",
        "read_to_string",
        "read_to_end",
        "read_line",
        "BufRead",
        "content_length",
        "Content-Length",
        "CONTENT_LENGTH",
    ];

    /// Safe bound-limiting patterns (sanitizers)
    const SANITIZER_PATTERNS: &'static [&'static str] = &[
        ".min(",
        "::min(",
        "cmp::min",
        ".clamp(",
        "::clamp(",
        ".saturating_",
        "::saturating_",
        ".checked_",
        "::checked_",
        "MAX_",
        "_MAX",
        "_LIMIT",
        "LIMIT_",
        "max_size",
        "max_capacity",
        "max_len",
    ];

    fn analyze(mut self, mir: &str) -> Vec<String> {
        let lines: Vec<&str> = mir.lines().collect();

        // First pass: identify untrusted sources and track taint propagation
        for line in &lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(dest) = detect_assignment(trimmed) {
                if Self::is_untrusted_source(trimmed) {
                    self.mark_source(&dest, trimmed);
                } else if let Some(source) = self.find_tainted_in_line(trimmed) {
                    self.mark_alias(&dest, &source);
                }
            }

            // Track sanitization patterns that bound the value
            self.track_sanitization(trimmed);
        }

        // Second pass: detect allocation sinks with tainted capacity
        for line in &lines {
            let trimmed = line.trim();
            if !Self::is_allocation_sink(trimmed) {
                continue;
            }

            // Extract capacity argument from allocation call
            if let Some(capacity_var) = Self::extract_capacity_arg(trimmed) {
                if let Some(root) = self.taint_roots.get(&capacity_var).cloned() {
                    // Skip if sanitized
                    if self.sanitized_roots.contains(&root) {
                        continue;
                    }

                    let mut message = format!(
                        "Uncontrolled allocation size: untrusted input flows to allocation capacity.\n  allocation: `{}`",
                        trimmed
                    );

                    if let Some(origin) = self.sources.get(&root) {
                        message.push_str(&format!("\n  source: `{}`", origin));
                    }

                    self.findings.push(message);
                }
            }
        }

        self.findings
    }

    fn mark_source(&mut self, var: &str, origin: &str) {
        let var = var.to_string();
        self.tainted.insert(var.clone());
        self.taint_roots.insert(var.clone(), var.clone());
        self.sources
            .entry(var)
            .or_insert_with(|| origin.trim().to_string());
    }

    fn mark_alias(&mut self, dest: &str, source: &str) {
        if !self.tainted.contains(source) {
            return;
        }

        if let Some(root) = self.taint_roots.get(source).cloned() {
            self.tainted.insert(dest.to_string());
            self.taint_roots.insert(dest.to_string(), root.clone());
        }
    }

    fn track_sanitization(&mut self, line: &str) {
        // Check for comparison guards (Lt, Le, Gt, Ge) - these act as implicit bounds
        if line.contains("= Lt(") || line.contains("= Le(")
            || line.contains("= Gt(") || line.contains("= Ge(")
        {
            // Find tainted variables in the comparison
            for var in self.tainted.clone() {
                if contains_var(line, &var) {
                    if let Some(root) = self.taint_roots.get(&var).cloned() {
                        self.sanitized_roots.insert(root);
                    }
                }
            }
        }

        // Check if line contains an explicit sanitization pattern
        if !Self::SANITIZER_PATTERNS.iter().any(|p| line.contains(p)) {
            return;
        }

        // Find which tainted variable is being sanitized
        if let Some(dest) = detect_assignment(line) {
            // If this assignment uses a tainted source and applies a bound, mark as sanitized
            if let Some(source) = self.find_tainted_in_line(line) {
                if let Some(root) = self.taint_roots.get(&source).cloned() {
                    self.sanitized_roots.insert(root.clone());
                    // Also mark the destination as having a sanitized root
                    self.tainted.insert(dest.clone());
                    self.taint_roots.insert(dest, root);
                }
            }
        }
    }

    fn is_untrusted_source(line: &str) -> bool {
        Self::UNTRUSTED_SOURCES
            .iter()
            .any(|pattern| line.contains(pattern))
    }

    fn is_allocation_sink(line: &str) -> bool {
        Self::ALLOCATION_SINKS
            .iter()
            .any(|pattern| line.contains(pattern))
    }

    fn extract_capacity_arg(line: &str) -> Option<String> {
        // Look for with_capacity, reserve, etc. and extract the capacity argument
        let capacity_keywords = ["with_capacity(", "reserve(", "reserve_exact("];
        
        for keyword in capacity_keywords {
            if let Some(start) = line.find(keyword) {
                let after_keyword = &line[start + keyword.len()..];
                // Find the closing paren
                if let Some(close) = after_keyword.find(')') {
                    let inside = &after_keyword[..close];
                    // Extract variable references (copy _N, move _N, or just _N)
                    let args = extract_call_args(&format!("({}", inside));
                    // For reserve/reserve_exact, capacity is second arg; for with_capacity, it's first
                    if keyword.contains("reserve") {
                        return args.into_iter().nth(1).or_else(|| {
                            // Fallback: try first arg
                            extract_call_args(&format!("({}", inside)).into_iter().next()
                        });
                    } else {
                        return args.into_iter().next();
                    }
                }
            }
        }

        None
    }

    fn find_tainted_in_line(&self, line: &str) -> Option<String> {
        self.tainted
            .iter()
            .find(|var| contains_var(line, var))
            .cloned()
    }
}

/// Advanced rule that detects integer overflow from untrusted sources.
/// Flags arithmetic operations (Add, Sub, Mul, etc.) where operands come from
/// untrusted external sources (env vars, CLI args, stdin, network) without
/// overflow protection (checked_*, saturating_*, etc.).
pub struct IntegerOverflowRule;

impl AdvancedRule for IntegerOverflowRule {
    fn id(&self) -> &'static str {
        "ADV009"
    }

    fn description(&self) -> &'static str {
        "Detects arithmetic operations on untrusted input without overflow protection."
    }

    fn evaluate(&self, mir: &str) -> Vec<String> {
        IntegerOverflowAnalyzer::default().analyze(mir)
    }
}

#[derive(Default)]
struct IntegerOverflowAnalyzer {
    tainted: HashSet<String>,
    taint_roots: HashMap<String, String>,
    sanitized_roots: HashSet<String>,
    sources: HashMap<String, String>,
    findings: Vec<String>,
}

impl IntegerOverflowAnalyzer {
    /// Unsafe arithmetic operations in MIR (can overflow/panic)
    /// Includes both release-mode (Add, Sub, etc.) and debug-mode (AddWithOverflow, etc.) patterns
    const UNSAFE_ARITHMETIC_OPS: &'static [&'static str] = &[
        "= Add(",
        "= Sub(",
        "= Mul(",
        "= Div(",
        "= Rem(",
        "= Shl(",
        "= Shr(",
        "= Neg(",
        // Debug mode overflow-checked operations (panic on overflow in debug builds)
        "AddWithOverflow(",
        "SubWithOverflow(",
        "MulWithOverflow(",
    ];

    /// Safe arithmetic patterns (already have overflow protection)
    const SAFE_ARITHMETIC_PATTERNS: &'static [&'static str] = &[
        "CheckedAdd",
        "CheckedSub",
        "CheckedMul",
        "CheckedDiv",
        "CheckedRem",
        "CheckedShl",
        "CheckedShr",
        "checked_add",
        "checked_sub",
        "checked_mul",
        "checked_div",
        "checked_rem",
        "saturating_add",
        "saturating_sub",
        "saturating_mul",
        "saturating_div",
        "saturating_pow",
        "overflowing_add",
        "overflowing_sub",
        "overflowing_mul",
        "overflowing_div",
        "wrapping_add",
        "wrapping_sub",
        "wrapping_mul",
        "wrapping_div",
        "wrapping_shl",
        "wrapping_shr",
        // Bounds-checking sanitizers
        "::min(",
        "::max(",
        "::clamp(",
        "Ord>::min(",
        "Ord>::max(",
        "Ord>::clamp(",
    ];

    /// Untrusted external input sources
    const UNTRUSTED_SOURCES: &'static [&'static str] = &[
        "env::var",
        "env::var_os",
        "env::args",
        "std::env::var",
        "std::env::args",
        // MIR-specific patterns for env::var
        "var::<&str>",
        "var::<String>",
        "stdin",
        "Stdin",
        "StdinLock",
        "TcpStream",
        "UdpSocket",
        "UnixStream",
        "read_to_string",
        "read_to_end",
        "read_line",
        "BufRead",
        "content_length",
        "Content-Length",
        "CONTENT_LENGTH",
    ];

    fn analyze(mut self, mir: &str) -> Vec<String> {
        let lines: Vec<&str> = mir.lines().collect();

        // First pass: identify untrusted sources and track taint propagation
        for line in &lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(dest) = detect_assignment(trimmed) {
                if Self::is_untrusted_source(trimmed) {
                    self.mark_source(&dest, trimmed);
                } else if let Some(source) = self.find_tainted_in_line(trimmed) {
                    self.mark_alias(&dest, &source);
                }
            }

            // Track safe arithmetic patterns that protect against overflow
            self.track_safe_arithmetic(trimmed);
        }

        // Second pass: detect unsafe arithmetic with tainted operands
        for line in &lines {
            let trimmed = line.trim();
            
            // Skip if line uses safe arithmetic patterns
            if Self::is_safe_arithmetic(trimmed) {
                continue;
            }

            // Check for unsafe arithmetic operations
            if !Self::is_unsafe_arithmetic(trimmed) {
                continue;
            }

            // Extract operands from arithmetic operation
            if let Some((op, operands)) = Self::extract_arithmetic_operands(trimmed) {
                for operand in operands {
                    if let Some(root) = self.taint_roots.get(&operand).cloned() {
                        // Skip if this root has been sanitized
                        if self.sanitized_roots.contains(&root) {
                            continue;
                        }

                        let mut message = format!(
                            "Integer overflow risk: untrusted input used in {} operation without overflow protection.\n  operation: `{}`",
                            op, trimmed
                        );

                        if let Some(origin) = self.sources.get(&root) {
                            message.push_str(&format!("\n  source: `{}`", origin));
                        }

                        message.push_str("\n  suggestion: Use checked_*, saturating_*, or wrapping_* arithmetic");

                        self.findings.push(message);
                        break; // Only report once per operation
                    }
                }
            }
        }

        self.findings
    }

    fn mark_source(&mut self, var: &str, origin: &str) {
        let var = var.to_string();
        self.tainted.insert(var.clone());
        self.taint_roots.insert(var.clone(), var.clone());
        self.sources
            .entry(var)
            .or_insert_with(|| origin.trim().to_string());
    }

    fn mark_alias(&mut self, dest: &str, source: &str) {
        if !self.tainted.contains(source) {
            return;
        }

        if let Some(root) = self.taint_roots.get(source).cloned() {
            self.tainted.insert(dest.to_string());
            self.taint_roots.insert(dest.to_string(), root.clone());
        }
    }

    fn track_safe_arithmetic(&mut self, line: &str) {
        // If line contains safe arithmetic patterns, mark the tainted source as sanitized
        if !Self::is_safe_arithmetic(line) {
            return;
        }

        // Find which tainted variable is being protected
        if let Some(dest) = detect_assignment(line) {
            if let Some(source) = self.find_tainted_in_line(line) {
                if let Some(root) = self.taint_roots.get(&source).cloned() {
                    self.sanitized_roots.insert(root.clone());
                    // Also propagate taint to dest (but it's now safe)
                    self.tainted.insert(dest.clone());
                    self.taint_roots.insert(dest, root);
                }
            }
        }
    }

    fn is_untrusted_source(line: &str) -> bool {
        Self::UNTRUSTED_SOURCES
            .iter()
            .any(|pattern| line.contains(pattern))
    }

    fn is_unsafe_arithmetic(line: &str) -> bool {
        Self::UNSAFE_ARITHMETIC_OPS
            .iter()
            .any(|pattern| line.contains(pattern))
    }

    fn is_safe_arithmetic(line: &str) -> bool {
        Self::SAFE_ARITHMETIC_PATTERNS
            .iter()
            .any(|pattern| line.contains(pattern))
    }

    fn extract_arithmetic_operands(line: &str) -> Option<(&'static str, Vec<String>)> {
        // Map MIR ops to human-readable names
        // Includes both release-mode and debug-mode (WithOverflow) patterns
        let ops = [
            ("= Add(", "addition"),
            ("= Sub(", "subtraction"),
            ("= Mul(", "multiplication"),
            ("= Div(", "division"),
            ("= Rem(", "remainder"),
            ("= Shl(", "left shift"),
            ("= Shr(", "right shift"),
            ("= Neg(", "negation"),
            // Debug mode patterns (panic on overflow)
            ("AddWithOverflow(", "addition"),
            ("SubWithOverflow(", "subtraction"),
            ("MulWithOverflow(", "multiplication"),
        ];

        for (pattern, name) in ops {
            if let Some(start) = line.find(pattern) {
                let after_op = &line[start + pattern.len()..];
                if let Some(close) = after_op.find(')') {
                    let inside = &after_op[..close];
                    // Parse operands: "copy _1, copy _2" or "move _1, const 5_i32"
                    let mut operands = Vec::new();
                    for part in inside.split(',') {
                        let part = part.trim();
                        // Extract variable references
                        if let Some(var) = extract_var_from_operand(part) {
                            operands.push(var);
                        }
                    }
                    return Some((name, operands));
                }
            }
        }
        None
    }

    fn find_tainted_in_line(&self, line: &str) -> Option<String> {
        self.tainted
            .iter()
            .find(|var| contains_var(line, var))
            .cloned()
    }
}

/// Extract variable name from MIR operand like "copy _1" or "move _2"
fn extract_var_from_operand(operand: &str) -> Option<String> {
    let operand = operand.trim();
    
    // Handle "copy _N" or "move _N"
    if operand.starts_with("copy ") {
        return Some(operand[5..].trim().to_string());
    }
    if operand.starts_with("move ") {
        return Some(operand[5..].trim().to_string());
    }
    
    // Handle bare "_N"
    if operand.starts_with('_') && operand.chars().skip(1).all(|c| c.is_ascii_digit()) {
        return Some(operand.to_string());
    }
    
    // Skip constants
    if operand.starts_with("const ") {
        return None;
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_rule(mir: &str) -> Vec<String> {
        let rule = DanglingPointerUseAfterFreeRule;
        rule.evaluate(mir)
    }

    fn run_json_rule(mir: &str) -> Vec<String> {
        let rule = InsecureJsonTomlDeserializationRule;
        rule.evaluate(mir)
    }

    fn run_binary_rule(mir: &str) -> Vec<String> {
        let rule = InsecureBinaryDeserializationRule;
        rule.evaluate(mir)
    }

    fn run_regex_rule(mir: &str) -> Vec<String> {
        let rule = RegexBacktrackingDosRule;
        rule.evaluate(mir)
    }

    fn run_template_rule(mir: &str) -> Vec<String> {
        let rule = TemplateInjectionRule;
        rule.evaluate(mir)
    }

    fn run_async_send_rule(mir: &str) -> Vec<String> {
        let rule = UnsafeSendAcrossAsyncBoundaryRule;
        rule.evaluate(mir)
    }

    fn run_span_guard_rule(mir: &str) -> Vec<String> {
        let rule = AwaitSpanGuardRule;
        rule.evaluate(mir)
    }

    #[test]
    fn detects_dereference_after_drop() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = const 42_i32;
    StorageLive(_2);
    _2 = &raw const (*_1);
    StorageDead(_1);
    _3 = * _2;
    return;
}
"#;

        let findings = run_rule(mir);
        assert!(!findings.is_empty(), "expected dangling pointer finding");
        assert!(findings[0].contains("dereference"));
    }

    #[test]
    fn detects_null_pointer_dereference() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = null::<i32>() -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = &raw const (*_1);
    _0 = copy (*_1);
    return;
}
"#;

        let findings = run_rule(mir);
        assert!(!findings.is_empty(), "expected null pointer finding");
        assert!(findings[0].contains("null"));
    }

    #[test]
    fn detects_misaligned_pointer_dereference() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = const 4097_usize as *const u16 (PointerWithExposedProvenance);
    _0 = copy (*_1);
    return;
}
"#;

        let findings = run_rule(mir);
        assert!(!findings.is_empty(), "expected misaligned pointer finding");
        assert!(findings[0].contains("not aligned"));
    }

    #[test]
    fn allows_aligned_constant_pointer() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = const 4096_usize as *const u16 (PointerWithExposedProvenance);
    _0 = copy (*_1);
    return;
}
"#;

        let findings = run_rule(mir);
        assert!(findings.is_empty(), "aligned constant pointer should not be flagged");
    }

    #[test]
    fn does_not_flag_use_before_drop() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = const 42_i32;
    StorageLive(_2);
    _2 = &raw const (*_1);
    _3 = * _2;
    StorageDead(_1);
    return;
}
"#;

        let findings = run_rule(mir);
        assert!(findings.is_empty(), "no findings expected before drop");
    }

    #[test]
    fn detects_return_of_stack_pointer() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = const 7_i32;
    StorageLive(_2);
    _2 = &raw const (*_1);
    _0 = copy _2;
    StorageDead(_1);
    return;
}
"#;

        let findings = run_rule(mir);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("escapes"));
    }

    #[test]
    fn ignores_leaked_box_pointer() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = alloc::boxed::Box::<i32>::new(const 5_i32);
    StorageLive(_2);
    _2 = alloc::boxed::Box::<i32>::leak(move _1);
    _0 = copy _2;
    return;
}
"#;

        let findings = run_rule(mir);
        assert!(findings.is_empty(), "leaked pointers should not be flagged");
    }

    #[test]
    fn detects_vec_reallocation_dereference() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = Vec::<i32>::new() -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = &mut _1;
    _3 = Vec::<i32>::push(move _2, const 1_i32) -> [return: bb2, unwind continue];
}

bb2: {
    StorageLive(_4);
    _4 = &_1;
    StorageLive(_5);
    _5 = <Vec<i32> as Index<usize>>::index(move _4, const 0_usize) -> [return: bb3, unwind continue];
}

bb3: {
    StorageLive(_6);
    _6 = &raw const (*_5);
    StorageLive(_7);
    _7 = &mut _1;
    _8 = Vec::<i32>::push(move _7, const 2_i32) -> [return: bb4, unwind continue];
}

bb4: {
    _9 = * _6;
    drop(_1) -> [return: bb5, unwind continue];
}

bb5: {
    return;
}
"#;

        let findings = run_rule(mir);
        assert!(!findings.is_empty(), "expected reallocation finding");
        assert!(findings[0].contains("reallocation"));
    }

    #[test]
    fn detects_returned_aggregate_with_stack_pointer() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = const 123_i32;
    StorageLive(_2);
    _2 = &raw const (*_1);
    _0 = PointerHolder { ptr: move _2 };
    StorageDead(_1);
    return;
}
"#;

        let findings = run_rule(mir);
        assert!(!findings.is_empty(), "expected aggregate escape finding");
        assert!(findings[0].contains("aggregate"));
    }

    #[test]
    fn detects_pointer_store_escape() {
        let mir = r#"
bb0: {
    StorageLive(_2);
    _2 = const 456_i32;
    StorageLive(_3);
    _3 = &raw const (*_2);
    (*_1) = move _3;
    StorageDead(_2);
    return;
}
"#;

        let findings = run_rule(mir);
        assert!(!findings.is_empty(), "expected pointer store escape finding");
        assert!(findings[0].contains("stored through pointer"));
    }

    #[test]
    fn detects_json_deserialization_from_env() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = std::env::var::<String>(const "CONFIG_JSON") -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = serde_json::from_str::<Config>(move _1) -> [return: bb2, unwind continue];
}

bb2: {
    return;
}
"#;

        let findings = run_json_rule(mir);
        assert!(!findings.is_empty(), "expected insecure deserialization finding");
        assert!(findings[0].contains("serde_json::from_str"));
    }

    #[test]
    fn allows_const_json_deserialization() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = const "{\\"name\\":\\"ok\\"}";
    StorageLive(_2);
    _2 = serde_json::from_str::<Config>(copy _1) -> [return: bb1, unwind continue];
}

bb1: {
    return;
}
"#;

        let findings = run_json_rule(mir);
        assert!(findings.is_empty(), "hardcoded JSON should not be flagged");
    }

    #[test]
    fn allows_json_with_size_check() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = std::env::var::<String>(const "CONFIG_JSON") -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = String::len(move _1);
    StorageLive(_3);
    _3 = Gt(move _2, const 1024_usize);
}

bb2: {
    StorageLive(_4);
    _4 = serde_json::from_str::<Config>(move _1) -> [return: bb3, unwind continue];
}

bb3: {
    return;
}
"#;

        let findings = run_json_rule(mir);
        assert!(findings.is_empty(), "size-checked JSON should not be flagged");
    }

    #[test]
    fn detects_bincode_deserialization_from_env() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = std::env::var::<String>(const "BIN_PAYLOAD") -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = copy _1;
    StorageLive(_3);
    _3 = bincode::deserialize::<Payload>(move _2) -> [return: bb2, unwind continue];
}

bb2: {
    return;
}
"#;

        let findings = run_binary_rule(mir);
        assert!(!findings.is_empty(), "expected binary deserialization finding");
        assert!(findings[0].contains("bincode::deserialize"));
    }

    #[test]
    fn allows_const_bincode_deserialization() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = const b"\x01\x02\x03\x04";
    StorageLive(_2);
    _2 = bincode::deserialize::<Payload>(move _1) -> [return: bb1, unwind continue];
}

bb1: {
    return;
}
"#;

        let findings = run_binary_rule(mir);
        assert!(findings.is_empty(), "expected constant binary input to be allowed");
    }

    #[test]
    fn allows_bincode_with_size_check() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = fs::read(const "payload.bin") -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = copy _1;
    StorageLive(_3);
    _3 = Vec::<u8>::len(move _2);
    StorageLive(_4);
    _4 = Lt(move _3, const 1024_usize);
}

bb2: {
    StorageLive(_5);
    _5 = bincode::deserialize::<Payload>(move _1) -> [return: bb3, unwind continue];
}

bb3: {
    return;
}
"#;

        let findings = run_binary_rule(mir);
        assert!(findings.is_empty(), "expected len-checked binary flow to be allowed");
    }

    #[test]
    fn detects_postcard_deserialization_from_socket() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = TcpStream::read_to_end(move _0) -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = postcard::from_bytes::<Payload>(move _1) -> [return: bb2, unwind continue];
}

bb2: {
    return;
}
"#;

        let findings = run_binary_rule(mir);
        assert!(!findings.is_empty(), "expected postcard binary finding");
        assert!(findings[0].contains("postcard::from_bytes"));
    }

    #[test]
    fn detects_copy_nonoverlapping_overlap() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    std::ptr::copy_nonoverlapping::<u8>(copy _1, copy _1, const 4_usize);
    return;
}
"#;

        let findings = run_rule(mir);
        assert!(!findings.is_empty(), "expected copy_nonoverlapping overlap finding");
        assert!(findings[0].contains("copy_nonoverlapping"));
    }

    #[test]
    fn detects_nested_quantifier_regex() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = const "(a+)+";
    StorageLive(_2);
    _2 = regex::Regex::new(move _1) -> [return: bb1, unwind continue];
}

bb1: {
    return;
}
"#;

        let findings = run_regex_rule(mir);
        assert!(!findings.is_empty(), "expected regex DoS finding");
        assert!(findings[0].contains("regex::Regex::new"));
    }

    #[test]
    fn detects_dot_star_loop_regex() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = const "(.*)+";
    _0 = regex::Regex::new(const "(.*)+") -> [return: bb1, unwind continue];
}

bb1: {
    return;
}
"#;

        let findings = run_regex_rule(mir);
        assert!(!findings.is_empty(), "expected dot-star regex finding");
        assert!(findings[0].contains("catastrophic backtracking"));
    }

    #[test]
    fn allows_simple_regex_pattern() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = const "^[a-z0-9_-]{3,16}$";
    StorageLive(_2);
    _2 = regex::Regex::new(copy _1) -> [return: bb1, unwind continue];
}

bb1: {
    return;
}
"#;

        let findings = run_regex_rule(mir);
        assert!(findings.is_empty(), "expected safe regex to be allowed");
    }

    #[test]
    fn detects_template_injection_env() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = std::env::var::<String>(const "USERNAME") -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = warp::reply::html(move _1) -> [return: bb2, unwind continue];
}

bb2: {
    return;
}
"#;

        let findings = run_template_rule(mir);
        assert!(!findings.is_empty(), "expected template injection finding");
        assert!(findings[0].contains("warp::reply::html"));
    }

    #[test]
    fn allows_template_with_escape() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = std::env::var::<String>(const "USERNAME") -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = html_escape::encode_safe(move _1);
    StorageLive(_3);
    _3 = warp::reply::html(move _2) -> [return: bb2, unwind continue];
}

bb2: {
    return;
}
"#;

        let findings = run_template_rule(mir);
        assert!(findings.is_empty(), "expected escaped template to be allowed");
    }

    #[test]
    fn allows_const_template() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = const "<p>Hello world</p>";
    StorageLive(_2);
    _2 = warp::reply::html(copy _1) -> [return: bb1, unwind continue];
}

bb1: {
    return;
}
"#;

        let findings = run_template_rule(mir);
        assert!(findings.is_empty(), "expected constant template to be allowed");
    }

    #[test]
    fn detects_rc_in_tokio_spawn() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = alloc::rc::Rc::<Data>::clone(move _0) -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = tokio::spawn(move _1) -> [return: bb2, unwind continue];
}

bb2: {
    return;
}
"#;

        let findings = run_async_send_rule(mir);
        assert!(!findings.is_empty(), "expected tokio::spawn to flag non-Send Rc");
        assert!(findings[0].contains("tokio::spawn"));
    }

    #[test]
    fn allows_arc_in_tokio_spawn() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = std::sync::Arc::<Data>::clone(move _0) -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = tokio::spawn(move _1) -> [return: bb2, unwind continue];
}

bb2: {
    return;
}
"#;

        let findings = run_async_send_rule(mir);
        assert!(findings.is_empty(), "Arc should satisfy Send in tokio::spawn");
    }

    #[test]
    fn allows_rc_with_spawn_local() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = std::rc::Rc::<Data>::clone(move _0) -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = tokio::task::spawn_local(move _1) -> [return: bb2, unwind continue];
}

bb2: {
    return;
}
"#;

        let findings = run_async_send_rule(mir);
        assert!(findings.is_empty(), "spawn_local should allow Rc");
    }

    #[test]
    fn detects_span_guard_across_await() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = tracing::Span::current() -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = tracing::Span::enter(move _1) -> [return: bb2, unwind continue];
}

bb2: {
    StorageLive(_3);
    _3 = external_future() -> [return: bb3, unwind continue];
}

bb3: {
    _4 = external_future::poll.await(move _3) -> [return: bb4, unwind continue];
}

bb4: {
    StorageDead(_2);
    return;
}
"#;

        let findings = run_span_guard_rule(mir);
        assert!(!findings.is_empty(), "span guard across await should be flagged");
        assert!(findings[0].contains("await"));
    }

    #[test]
    fn allows_span_guard_dropped_before_await() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    _1 = tracing::Span::current() -> [return: bb1, unwind continue];
}

bb1: {
    StorageLive(_2);
    _2 = tracing::Span::enter(move _1) -> [return: bb2, unwind continue];
}

bb2: {
    drop(_2);
    StorageLive(_3);
    _3 = external_future() -> [return: bb3, unwind continue];
}

bb3: {
    _4 = external_future::poll.await(move _3) -> [return: bb4, unwind continue];
}

bb4: {
    return;
}
"#;

        let findings = run_span_guard_rule(mir);
        assert!(findings.is_empty(), "guard dropped before await should be allowed");
    }

    #[test]
    fn allows_disjoint_copy_nonoverlapping() {
        let mir = r#"
bb0: {
    StorageLive(_1);
    StorageLive(_2);
    std::ptr::copy_nonoverlapping::<u8>(copy _1, copy _2, const 4_usize);
    return;
}
"#;

        let findings = run_rule(mir);
        assert!(findings.is_empty(), "disjoint copy_nonoverlapping should not be flagged");
    }

    // ==================== ADV008: Uncontrolled Allocation Size Tests ====================

    fn run_allocation_rule(mir: &str) -> Vec<String> {
        let rule = UncontrolledAllocationSizeRule;
        rule.evaluate(mir)
    }

    #[test]
    fn detects_env_var_to_with_capacity() {
        let mir = r#"
fn example() -> () {
    let mut _0: ();
    let _1: Result<String, VarError>;
    let _2: String;
    let _3: usize;
    let _4: Vec<u8>;

    bb0: {
        StorageLive(_1);
        _1 = std::env::var(const "SIZE") -> [return: bb1, unwind continue];
    }

    bb1: {
        StorageLive(_2);
        _2 = Result::unwrap(move _1) -> [return: bb2, unwind continue];
    }

    bb2: {
        StorageLive(_3);
        _3 = str::parse::<usize>(move _2) -> [return: bb3, unwind continue];
    }

    bb3: {
        StorageLive(_4);
        _4 = Vec::with_capacity(move _3) -> [return: bb4, unwind continue];
    }

    bb4: {
        return;
    }
}
"#;

        let findings = run_allocation_rule(mir);
        assert!(!findings.is_empty(), "env var to with_capacity should be flagged");
        assert!(findings[0].contains("with_capacity") || findings[0].contains("allocation"));
    }

    #[test]
    fn detects_stdin_to_reserve() {
        let mir = r#"
fn example() -> () {
    let mut _0: ();
    let _1: Stdin;
    let _2: String;
    let _3: usize;
    let mut _4: Vec<u8>;

    bb0: {
        StorageLive(_1);
        _1 = std::io::stdin() -> [return: bb1, unwind continue];
    }

    bb1: {
        StorageLive(_2);
        _2 = BufRead::read_line(move _1) -> [return: bb2, unwind continue];
    }

    bb2: {
        StorageLive(_3);
        _3 = str::parse::<usize>(move _2) -> [return: bb3, unwind continue];
    }

    bb3: {
        StorageLive(_4);
        _4 = Vec::new() -> [return: bb4, unwind continue];
    }

    bb4: {
        Vec::reserve(&mut _4, move _3) -> [return: bb5, unwind continue];
    }

    bb5: {
        return;
    }
}
"#;

        let findings = run_allocation_rule(mir);
        assert!(!findings.is_empty(), "stdin to reserve should be flagged");
    }

    #[test]
    fn allows_constant_allocation_size() {
        let mir = r#"
fn example() -> () {
    let mut _0: ();
    let _1: Vec<u8>;

    bb0: {
        StorageLive(_1);
        _1 = Vec::with_capacity(const 1024_usize) -> [return: bb1, unwind continue];
    }

    bb1: {
        return;
    }
}
"#;

        let findings = run_allocation_rule(mir);
        assert!(findings.is_empty(), "constant allocation size should not be flagged");
    }

    #[test]
    fn allows_min_bounded_allocation() {
        let mir = r#"
fn example() -> () {
    let mut _0: ();
    let _1: Result<String, VarError>;
    let _2: String;
    let _3: usize;
    let _4: usize;
    let _5: Vec<u8>;

    bb0: {
        StorageLive(_1);
        _1 = std::env::var(const "SIZE") -> [return: bb1, unwind continue];
    }

    bb1: {
        StorageLive(_2);
        _2 = Result::unwrap(move _1) -> [return: bb2, unwind continue];
    }

    bb2: {
        StorageLive(_3);
        _3 = str::parse::<usize>(move _2) -> [return: bb3, unwind continue];
    }

    bb3: {
        StorageLive(_4);
        _4 = usize::min(move _3, const 1024_usize) -> [return: bb4, unwind continue];
    }

    bb4: {
        StorageLive(_5);
        _5 = Vec::with_capacity(move _4) -> [return: bb5, unwind continue];
    }

    bb5: {
        return;
    }
}
"#;

        let findings = run_allocation_rule(mir);
        assert!(findings.is_empty(), "min-bounded allocation should not be flagged");
    }

    #[test]
    fn allows_comparison_guarded_allocation() {
        let mir = r#"
fn example() -> () {
    let mut _0: ();
    let _1: Result<String, VarError>;
    let _2: String;
    let _3: usize;
    let _4: bool;
    let _5: Vec<u8>;

    bb0: {
        StorageLive(_1);
        _1 = std::env::var(const "SIZE") -> [return: bb1, unwind continue];
    }

    bb1: {
        StorageLive(_2);
        _2 = Result::unwrap(move _1) -> [return: bb2, unwind continue];
    }

    bb2: {
        StorageLive(_3);
        _3 = str::parse::<usize>(move _2) -> [return: bb3, unwind continue];
    }

    bb3: {
        StorageLive(_4);
        _4 = Lt(copy _3, const 1024_usize);
        switchInt(move _4) -> [0: bb5, otherwise: bb4];
    }

    bb4: {
        StorageLive(_5);
        _5 = Vec::with_capacity(move _3) -> [return: bb6, unwind continue];
    }

    bb5: {
        return;
    }

    bb6: {
        return;
    }
}
"#;

        let findings = run_allocation_rule(mir);
        assert!(findings.is_empty(), "comparison-guarded allocation should not be flagged");
    }

    #[test]
    fn detects_file_read_to_hashmap_capacity() {
        let mir = r#"
fn example() -> () {
    let mut _0: ();
    let _1: File;
    let _2: String;
    let _3: usize;
    let _4: HashMap<String, String>;

    bb0: {
        StorageLive(_1);
        _1 = File::open(const "config.txt") -> [return: bb1, unwind continue];
    }

    bb1: {
        StorageLive(_2);
        _2 = std::io::read_to_string(move _1) -> [return: bb2, unwind continue];
    }

    bb2: {
        StorageLive(_3);
        _3 = str::parse::<usize>(move _2) -> [return: bb3, unwind continue];
    }

    bb3: {
        StorageLive(_4);
        _4 = HashMap::with_capacity(move _3) -> [return: bb4, unwind continue];
    }

    bb4: {
        return;
    }
}
"#;

        let findings = run_allocation_rule(mir);
        assert!(!findings.is_empty(), "file read to HashMap::with_capacity should be flagged");
    }

    // ==================== ADV009: Integer Overflow Tests ====================

    fn run_overflow_rule(mir: &str) -> Vec<String> {
        let rule = IntegerOverflowRule;
        rule.evaluate(mir)
    }

    #[test]
    fn detects_env_var_to_addition() {
        let mir = r#"
fn example() -> () {
    let mut _0: ();
    let _1: Result<String, VarError>;
    let _2: String;
    let _3: i32;
    let _4: i32;

    bb0: {
        StorageLive(_1);
        _1 = std::env::var(const "VALUE") -> [return: bb1, unwind continue];
    }

    bb1: {
        StorageLive(_2);
        _2 = Result::unwrap(move _1) -> [return: bb2, unwind continue];
    }

    bb2: {
        StorageLive(_3);
        _3 = str::parse::<i32>(move _2) -> [return: bb3, unwind continue];
    }

    bb3: {
        StorageLive(_4);
        _4 = Add(copy _3, const 100_i32);
        return;
    }
}
"#;

        let findings = run_overflow_rule(mir);
        assert!(!findings.is_empty(), "env var to addition should be flagged");
        assert!(findings[0].contains("addition") || findings[0].contains("overflow"));
    }

    #[test]
    fn detects_stdin_to_multiplication() {
        let mir = r#"
fn example() -> () {
    let mut _0: ();
    let _1: Stdin;
    let _2: String;
    let _3: i64;
    let _4: i64;

    bb0: {
        StorageLive(_1);
        _1 = std::io::stdin() -> [return: bb1, unwind continue];
    }

    bb1: {
        StorageLive(_2);
        _2 = BufRead::read_line(move _1) -> [return: bb2, unwind continue];
    }

    bb2: {
        StorageLive(_3);
        _3 = str::parse::<i64>(move _2) -> [return: bb3, unwind continue];
    }

    bb3: {
        StorageLive(_4);
        _4 = Mul(copy _3, const 1000_i64);
        return;
    }
}
"#;

        let findings = run_overflow_rule(mir);
        assert!(!findings.is_empty(), "stdin to multiplication should be flagged");
        assert!(findings[0].contains("multiplication") || findings[0].contains("overflow"));
    }

    #[test]
    fn allows_constant_arithmetic() {
        let mir = r#"
fn example() -> () {
    let mut _0: ();
    let _1: i32;

    bb0: {
        StorageLive(_1);
        _1 = Add(const 10_i32, const 20_i32);
        return;
    }
}
"#;

        let findings = run_overflow_rule(mir);
        assert!(findings.is_empty(), "constant arithmetic should not be flagged");
    }

    #[test]
    fn allows_checked_add() {
        let mir = r#"
fn example() -> () {
    let mut _0: ();
    let _1: Result<String, VarError>;
    let _2: String;
    let _3: i32;
    let _4: Option<i32>;

    bb0: {
        StorageLive(_1);
        _1 = std::env::var(const "VALUE") -> [return: bb1, unwind continue];
    }

    bb1: {
        StorageLive(_2);
        _2 = Result::unwrap(move _1) -> [return: bb2, unwind continue];
    }

    bb2: {
        StorageLive(_3);
        _3 = str::parse::<i32>(move _2) -> [return: bb3, unwind continue];
    }

    bb3: {
        StorageLive(_4);
        _4 = i32::checked_add(move _3, const 100_i32) -> [return: bb4, unwind continue];
    }

    bb4: {
        return;
    }
}
"#;

        let findings = run_overflow_rule(mir);
        assert!(findings.is_empty(), "checked_add should not be flagged");
    }

    #[test]
    fn allows_saturating_mul() {
        let mir = r#"
fn example() -> () {
    let mut _0: ();
    let _1: Result<String, VarError>;
    let _2: String;
    let _3: u64;
    let _4: u64;

    bb0: {
        StorageLive(_1);
        _1 = std::env::var(const "COUNT") -> [return: bb1, unwind continue];
    }

    bb1: {
        StorageLive(_2);
        _2 = Result::unwrap(move _1) -> [return: bb2, unwind continue];
    }

    bb2: {
        StorageLive(_3);
        _3 = str::parse::<u64>(move _2) -> [return: bb3, unwind continue];
    }

    bb3: {
        StorageLive(_4);
        _4 = u64::saturating_mul(move _3, const 1024_u64) -> [return: bb4, unwind continue];
    }

    bb4: {
        return;
    }
}
"#;

        let findings = run_overflow_rule(mir);
        assert!(findings.is_empty(), "saturating_mul should not be flagged");
    }

    #[test]
    fn detects_network_input_to_subtraction() {
        let mir = r#"
fn example() -> () {
    let mut _0: ();
    let _1: TcpStream;
    let _2: String;
    let _3: usize;
    let _4: usize;

    bb0: {
        StorageLive(_1);
        _1 = TcpStream::connect(const "127.0.0.1:8080") -> [return: bb1, unwind continue];
    }

    bb1: {
        StorageLive(_2);
        _2 = read_to_string(move _1) -> [return: bb2, unwind continue];
    }

    bb2: {
        StorageLive(_3);
        _3 = str::parse::<usize>(move _2) -> [return: bb3, unwind continue];
    }

    bb3: {
        StorageLive(_4);
        _4 = Sub(copy _3, const 1_usize);
        return;
    }
}
"#;

        let findings = run_overflow_rule(mir);
        assert!(!findings.is_empty(), "network input to subtraction should be flagged");
        assert!(findings[0].contains("subtraction") || findings[0].contains("overflow"));
    }

    #[test]
    fn allows_wrapping_operations() {
        let mir = r#"
fn example() -> () {
    let mut _0: ();
    let _1: Result<String, VarError>;
    let _2: String;
    let _3: u32;
    let _4: u32;

    bb0: {
        StorageLive(_1);
        _1 = std::env::var(const "OFFSET") -> [return: bb1, unwind continue];
    }

    bb1: {
        StorageLive(_2);
        _2 = Result::unwrap(move _1) -> [return: bb2, unwind continue];
    }

    bb2: {
        StorageLive(_3);
        _3 = str::parse::<u32>(move _2) -> [return: bb3, unwind continue];
    }

    bb3: {
        StorageLive(_4);
        _4 = u32::wrapping_add(move _3, const 1_u32) -> [return: bb4, unwind continue];
    }

    bb4: {
        return;
    }
}
"#;

        let findings = run_overflow_rule(mir);
        assert!(findings.is_empty(), "wrapping_add should not be flagged (intentional)");
    }

}
