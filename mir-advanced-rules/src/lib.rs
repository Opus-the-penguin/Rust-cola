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

}
