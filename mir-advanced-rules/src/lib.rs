//! Advanced MIR-based security rules for Rust-cola

use std::collections::{HashMap, HashSet};

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

#[derive(Debug, Default)]
struct PointerAnalyzer {
    pointers: HashMap<String, PointerInfo>,
    aliases: HashMap<String, String>,
    owners: HashMap<String, OwnerState>,
    findings: Vec<String>,
    reported: HashSet<(String, usize)>,
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

            if let Some(event) = Self::detect_pointer_creation(trimmed) {
                self.record_pointer_creation(idx, event);
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
            Regex::new(r"\*\s+(_\d+)").expect("deref regex")
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

// Add more advanced rules here...

#[cfg(test)]
mod tests {
    use super::*;

    fn run_rule(mir: &str) -> Vec<String> {
        let rule = DanglingPointerUseAfterFreeRule;
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
}
