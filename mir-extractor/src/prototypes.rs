use std::collections::HashSet;

use crate::{dataflow::extract_variables, MirDataflow, MirFunction};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentLengthAllocation {
    pub allocation_line: String,
    pub capacity_var: String,
    pub tainted_vars: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthTruncationCast {
    pub cast_line: String,
    pub target_var: String,
    pub source_vars: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastUnsyncUsage {
    pub line: String,
}

pub fn detect_content_length_allocations(function: &MirFunction) -> Vec<ContentLengthAllocation> {
    let dataflow = MirDataflow::new(function);
    let tainted = dataflow.taint_from(|assignment| {
        let rhs_lower = assignment.rhs.to_lowercase();
        rhs_lower.contains("content_length")
            || rhs_lower.contains("\"content-length\"")
            || rhs_lower.contains("header::content_length")
    });

    if tainted.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for line in &function.body {
        if let Some(capacity_var) = extract_capacity_variable(line) {
            if tainted.contains(&capacity_var)
                && !is_guarded_capacity(function, &dataflow, &capacity_var)
            {
                findings.push(ContentLengthAllocation {
                    allocation_line: line.trim().to_string(),
                    capacity_var,
                    tainted_vars: tainted.clone(),
                });
            }
        }
    }

    findings
}

fn extract_capacity_variable(line: &str) -> Option<String> {
    let lowered = line.to_lowercase();
    let keyword = if lowered.contains("with_capacity") {
        "with_capacity"
    } else if lowered.contains("reserve_exact") {
        "reserve_exact"
    } else if lowered.contains("reserve") {
        "reserve"
    } else {
        return None;
    };

    let start = line.find(keyword)? + keyword.len();
    let remainder = line[start..].trim_start();
    if !remainder.starts_with('(') {
        return None;
    }

    let closing = remainder.find(')')?;
    let inside = &remainder[1..closing];
    let vars = extract_variables(inside);
    vars.into_iter().next()
}

fn is_guarded_capacity(
    function: &MirFunction,
    dataflow: &MirDataflow,
    capacity_var: &str,
) -> bool {
    let mut queue = vec![capacity_var.to_string()];
    let mut visited = HashSet::new();

    while let Some(var) = queue.pop() {
        if !visited.insert(var.clone()) {
            continue;
        }

        if assert_mentions_var(function, &var) {
            return true;
        }

        for assignment in dataflow.assignments() {
            if assignment.target != var {
                continue;
            }

            if rhs_contains_upper_bound_guard(&assignment.rhs) {
                return true;
            }

            for source in &assignment.sources {
                queue.push(source.clone());
            }
        }
    }

    false
}

fn rhs_contains_upper_bound_guard(rhs: &str) -> bool {
    let lowered = rhs.to_lowercase();
    let guard_patterns = [
        "::min",
        ".min(",
        "cmp::min",
        "::clamp",
        ".clamp(",
        "::saturating_sub",
        "::checked_sub",
        "::min_by",
        "::min_by_key",
    ];

    guard_patterns.iter().any(|pattern| lowered.contains(pattern))
}

fn assert_mentions_var(function: &MirFunction, var: &str) -> bool {
    function.body.iter().any(|line| {
        if !line.contains("assert") || !line.contains(var) {
            return false;
        }
        let lowered = line.to_lowercase();
        lowered.contains(" <= ")
            || lowered.contains(" < ")
            || lowered.contains(" >= ")
            || lowered.contains(" > ")
    })
}

pub fn detect_truncating_len_casts(function: &MirFunction) -> Vec<LengthTruncationCast> {
    let dataflow = MirDataflow::new(function);
    let seeds = collect_length_seed_vars(function, &dataflow);
    let tainted = propagate_length_seeds(&dataflow, seeds);

    if tainted.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for assignment in dataflow.assignments() {
        if !is_narrow_cast(&assignment.rhs) {
            continue;
        }

        if assignment
            .sources
            .iter()
            .any(|source| tainted.contains(source))
        {
            findings.push(LengthTruncationCast {
                cast_line: assignment.line.clone(),
                target_var: assignment.target.clone(),
                source_vars: assignment.sources.clone(),
            });
        }
    }

    findings
}

pub fn detect_broadcast_unsync_payloads(
    function: &MirFunction,
) -> Vec<BroadcastUnsyncUsage> {
    let mut findings = Vec::new();

    for line in &function.body {
        if !(line.contains("tokio::sync::broadcast::channel")
            || line.contains("tokio::sync::broadcast::Sender::"))
        {
            continue;
        }

        if payload_looks_unsync(line) {
            findings.push(BroadcastUnsyncUsage {
                line: line.trim().to_string(),
            });
        }
    }

    findings
}

fn collect_length_seed_vars(
    function: &MirFunction,
    dataflow: &MirDataflow,
) -> HashSet<String> {
    let mut seeds = HashSet::new();

    for line in &function.body {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("debug ") {
            if let Some((name_part, var_part)) = rest.split_once("=>") {
                let name = name_part.trim();
                let var = var_part.trim().trim_end_matches(';');
                if is_length_identifier(name) && var.starts_with('_') {
                    seeds.insert(var.to_string());
                }
            }
        }
    }

    for assignment in dataflow.assignments() {
        let lowered = assignment.rhs.to_lowercase();
        if lowered.contains(".len(")
            || lowered.contains("::len(")
            || lowered.contains("len()")
            || lowered.contains("length")
            || lowered.contains("payload_len")
            || lowered.contains("payload_length")
        {
            seeds.insert(assignment.target.clone());
        }
    }

    seeds
}

fn propagate_length_seeds(
    dataflow: &MirDataflow,
    seeds: HashSet<String>,
) -> HashSet<String> {
    let mut tainted = seeds;
    if tainted.is_empty() {
        return tainted;
    }

    let mut changed = true;
    while changed {
        changed = false;
        for assignment in dataflow.assignments() {
            if tainted.contains(&assignment.target) {
                continue;
            }

            if assignment
                .sources
                .iter()
                .any(|source| tainted.contains(source))
            {
                tainted.insert(assignment.target.clone());
                changed = true;
            }
        }
    }

    tainted
}

fn is_length_identifier(name: &str) -> bool {
    let lowered = name.to_lowercase();
    lowered.contains("len")
        || lowered.contains("length")
        || lowered.contains("payload")
        || lowered.contains("size")
}

fn is_narrow_cast(rhs: &str) -> bool {
    let lowered = rhs.to_lowercase();
    let targets = [" as i32", " as u32", " as i16", " as u16", " as i8", " as u8"];

    lowered.contains("inttoint")
        && targets.iter().any(|target| lowered.contains(target))
}

fn payload_looks_unsync(line: &str) -> bool {
    let lowered = line.to_lowercase();
    let unsync_markers = [
        "::rc<",
        "::refcell<",
        "std::rc::rc<",
        "alloc::rc::rc<",
        "std::cell::refcell<",
        "core::cell::refcell<",
        "std::cell::cell<",
        "core::cell::cell<",
    ];

    unsync_markers.iter().any(|marker| lowered.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function_from_lines(lines: &[&str]) -> MirFunction {
        MirFunction {
            name: "demo".to_string(),
            signature: "fn demo()".to_string(),
            body: lines.iter().map(|l| l.to_string()).collect(),
        }
    }

    #[test]
    fn detects_simple_content_length_allocation() {
        let function = function_from_lines(&[
            "    _5 = reqwest::Response::content_length(move _1);",
            "    _6 = copy _5;",
            "    _7 = Vec::<u8>::with_capacity(move _6);",
        ]);

        let findings = detect_content_length_allocations(&function);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.capacity_var, "_6");
        assert!(finding.tainted_vars.contains("_5"));
    }

    #[test]
    fn ignores_min_guard() {
        let function = function_from_lines(&[
            "    _2 = reqwest::Response::content_length(move _1);",
            "    _3 = copy _2;",
            "    _4 = core::cmp::min(move _3, const 1048576_usize);",
            "    _5 = Vec::<u8>::with_capacity(move _4);",
        ]);

        let findings = detect_content_length_allocations(&function);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_clamp_guard() {
        let function = function_from_lines(&[
            "    _2 = reqwest::Response::content_length(move _1);",
            "    _3 = copy _2;",
            "    _4 = core::cmp::Ord::clamp(copy _3, const 0_usize, const 65536_usize);",
            "    _5 = Vec::<u8>::with_capacity(move _4);",
        ]);

        let findings = detect_content_length_allocations(&function);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_assert_guard() {
        let function = function_from_lines(&[
            "    _2 = reqwest::Response::content_length(move _1);",
            "    assert(move _2 <= const 1048576_usize, ...);",
            "    _3 = copy _2;",
            "    _4 = Vec::<u8>::with_capacity(move _3);",
        ]);

        let findings = detect_content_length_allocations(&function);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_truncating_len_cast() {
        let function = function_from_lines(&[
            "    debug payload_len => _1;",
            "    _2 = copy _1;",
            "    _3 = move _2 as i32 (IntToInt);",
            "    _4 = Vec::<u8>::with_capacity(move _3);",
        ]);

        let casts = detect_truncating_len_casts(&function);
        assert_eq!(casts.len(), 1);
        assert_eq!(casts[0].target_var, "_3");
        assert_eq!(casts[0].source_vars, vec!["_2".to_string()]);
    }

    #[test]
    fn ignores_wide_len_cast() {
        let function = function_from_lines(&[
            "    debug payload_len => _1;",
            "    _2 = copy _1;",
            "    _3 = move _2 as i64 (IntToInt);",
            "    _4 = Vec::<u8>::with_capacity(move _3);",
        ]);

        let casts = detect_truncating_len_casts(&function);
        assert!(casts.is_empty());
    }

    #[test]
    fn detects_broadcast_rc_payload() {
        let function = function_from_lines(&[
            "    _5 = tokio::sync::broadcast::channel::<std::rc::Rc<String>>(const 16_usize);",
        ]);

        let findings = detect_broadcast_unsync_payloads(&function);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].line.contains("std::rc::Rc"));
    }

    #[test]
    fn ignores_broadcast_arc_payload() {
        let function = function_from_lines(&[
            "    _5 = tokio::sync::broadcast::channel::<std::sync::Arc<String>>(const 16_usize);",
        ]);

        let findings = detect_broadcast_unsync_payloads(&function);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_findings_without_taint() {
        let function = function_from_lines(&[
            "    _3 = Vec::<u8>::with_capacity(const 4096_usize);",
        ]);

        let findings = detect_content_length_allocations(&function);
        assert!(findings.is_empty());
    }
}
