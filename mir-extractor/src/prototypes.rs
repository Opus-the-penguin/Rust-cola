use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use crate::{dataflow::extract_variables, MirDataflow, MirFunction};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrototypeOptions {
    pub guard_markers: Vec<String>,
    pub unsync_markers: Vec<String>,
    pub narrow_cast_targets: Vec<String>,
    pub try_into_targets: Vec<String>,
    pub serialization_sinks: Vec<String>,
    pub length_identifiers: Vec<String>,
}

impl Default for PrototypeOptions {
    fn default() -> Self {
        Self {
            guard_markers: vec![
                "::min".to_string(),
                ".min(".to_string(),
                "cmp::min".to_string(),
                "::clamp".to_string(),
                ".clamp(".to_string(),
                "::saturating_sub".to_string(),
                "::checked_sub".to_string(),
                "::min_by".to_string(),
                "::min_by_key".to_string(),
            ],
            unsync_markers: vec![
                "::rc<".to_string(),
                "::refcell<".to_string(),
                "std::rc::rc<".to_string(),
                "alloc::rc::rc<".to_string(),
                "std::cell::refcell<".to_string(),
                "core::cell::refcell<".to_string(),
                "std::cell::cell<".to_string(),
                "core::cell::cell<".to_string(),
            ],
            narrow_cast_targets: vec![
                " as i32".to_string(),
                " as u32".to_string(),
                " as i16".to_string(),
                " as u16".to_string(),
                " as i8".to_string(),
                " as u8".to_string(),
            ],
            try_into_targets: vec![
                "<i32>".to_string(),
                "<u32>".to_string(),
                "<i16>".to_string(),
                "<u16>".to_string(),
                "<i8>".to_string(),
                "<u8>".to_string(),
            ],
            serialization_sinks: vec![
                "put_i32".to_string(),
                "put_u32".to_string(),
                "put_u64".to_string(),
                "put_i16".to_string(),
                "put_u16".to_string(),
                "put_u8".to_string(),
                "write_i32".to_string(),
                "write_u32".to_string(),
                "write_u64".to_string(),
                "write_i16".to_string(),
                "write_u16".to_string(),
                "write_u8".to_string(),
                "unwrap(".to_string(),
                "::unwrap(".to_string(),
                "expect(".to_string(),
                "::expect(".to_string(),
            ],
            length_identifiers: vec![
                "len".to_string(),
                "length".to_string(),
                "payload".to_string(),
                "size".to_string(),
            ],
        }
    }
}

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
    pub sink_lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastUnsyncUsage {
    pub line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandInvocation {
    pub command_line: String,
    pub tainted_args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpensslVerifyNoneInvocation {
    pub call_line: String,
    pub supporting_lines: Vec<String>,
}

pub fn detect_content_length_allocations(function: &MirFunction) -> Vec<ContentLengthAllocation> {
    detect_content_length_allocations_with_options(function, &PrototypeOptions::default())
}

pub fn detect_content_length_allocations_with_options(
    function: &MirFunction,
    options: &PrototypeOptions,
) -> Vec<ContentLengthAllocation> {
    let dataflow = MirDataflow::new(function);
    let tainted = dataflow.taint_from(|assignment| rhs_mentions_content_length(&assignment.rhs));

    if tainted.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for line in &function.body {
        if let Some(capacity_var) = extract_capacity_variable(line) {
            if tainted.contains(&capacity_var)
                && !is_guarded_capacity(function, &dataflow, &capacity_var, options)
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

pub fn detect_unbounded_allocations(function: &MirFunction) -> Vec<ContentLengthAllocation> {
    detect_unbounded_allocations_with_options(function, &PrototypeOptions::default())
}

pub fn detect_unbounded_allocations_with_options(
    function: &MirFunction,
    options: &PrototypeOptions,
) -> Vec<ContentLengthAllocation> {
    let dataflow = MirDataflow::new(function);
    let seeds = collect_length_seed_vars(function, &dataflow, options);
    if seeds.is_empty() {
        return Vec::new();
    }

    let tainted = propagate_length_seeds(&dataflow, seeds);
    if tainted.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for line in &function.body {
        if let Some(capacity_var) = extract_capacity_variable(line) {
            if tainted.contains(&capacity_var)
                && !is_guarded_capacity(function, &dataflow, &capacity_var, options)
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

fn rhs_mentions_content_length(rhs: &str) -> bool {
    let lower = rhs.to_lowercase();
    if lower.contains("content_length")
        || lower.contains("\"content-length\"")
        || lower.contains("header::content-length")
        || lower.contains("headername::from_static(\"content-length\"")
        || lower.contains("headervalue::from_static(\"content-length\"")
        || lower.contains("from_bytes(b\"content-length\")")
    {
        return true;
    }

    rhs.contains("CONTENT_LENGTH")
}

fn is_guarded_capacity(
    function: &MirFunction,
    dataflow: &MirDataflow,
    capacity_var: &str,
    options: &PrototypeOptions,
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

            if rhs_contains_upper_bound_guard(&assignment.rhs, options) {
                return true;
            }

            for source in &assignment.sources {
                queue.push(source.clone());
            }
        }
    }

    false
}

fn rhs_contains_upper_bound_guard(rhs: &str, options: &PrototypeOptions) -> bool {
    let lowered = rhs.to_lowercase();
    options
        .guard_markers
        .iter()
        .any(|pattern| lowered.contains(pattern))
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
    detect_truncating_len_casts_with_options(function, &PrototypeOptions::default())
}

pub fn detect_truncating_len_casts_with_options(
    function: &MirFunction,
    options: &PrototypeOptions,
) -> Vec<LengthTruncationCast> {
    let dataflow = MirDataflow::new(function);
    let seeds = collect_length_seed_vars(function, &dataflow, options);
    let tainted = propagate_length_seeds(&dataflow, seeds);

    if tainted.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for assignment in dataflow.assignments() {
        let rhs_lower = assignment.rhs.to_lowercase();
        if !is_narrow_cast(&rhs_lower, options) && !is_try_into_narrow(&rhs_lower, options) {
            continue;
        }

        if assignment
            .sources
            .iter()
            .any(|source| tainted.contains(source))
        {
            let sink_lines = collect_sink_lines(function, &dataflow, &assignment.target, options);
            findings.push(LengthTruncationCast {
                cast_line: assignment.line.clone(),
                target_var: assignment.target.clone(),
                source_vars: assignment.sources.clone(),
                sink_lines,
            });
        }
    }

    findings
}

pub fn detect_broadcast_unsync_payloads(function: &MirFunction) -> Vec<BroadcastUnsyncUsage> {
    detect_broadcast_unsync_payloads_with_options(function, &PrototypeOptions::default())
}

pub fn detect_broadcast_unsync_payloads_with_options(
    function: &MirFunction,
    options: &PrototypeOptions,
) -> Vec<BroadcastUnsyncUsage> {
    let dataflow = MirDataflow::new(function);
    let mut seed_lines = Vec::new();

    let unsync_vars = dataflow.taint_from(|assignment| {
        if is_broadcast_constructor(&assignment.rhs)
            && payload_looks_unsync(&assignment.rhs, options)
        {
            seed_lines.push(assignment.line.trim().to_string());
            return true;
        }

        false
    });

    if unsync_vars.is_empty() {
        return seed_lines
            .into_iter()
            .map(|line| BroadcastUnsyncUsage { line })
            .collect();
    }

    let mut lines: BTreeSet<String> = seed_lines.into_iter().collect();

    for raw_line in &function.body {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let lower = trimmed.to_lowercase();
        let references_unsync_var = unsync_vars.iter().any(|var| trimmed.contains(var));

        if payload_looks_unsync(trimmed, options) && lower.contains("tokio::sync::broadcast") {
            lines.insert(trimmed.to_string());
            continue;
        }

        if references_unsync_var && line_mentions_broadcast_usage(&lower) {
            lines.insert(trimmed.to_string());
        }
    }

    lines
        .into_iter()
        .map(|line| BroadcastUnsyncUsage { line })
        .collect()
}

pub fn detect_command_invocations(function: &MirFunction) -> Vec<CommandInvocation> {
    let dataflow = MirDataflow::new(function);
    let taint_sources = dataflow.taint_from(|assignment| {
        let lowered = assignment.rhs.to_lowercase();
        lowered.contains("env::var")
            || lowered.contains("env::args")
            || lowered.contains("env::var_os")
            || lowered.contains("env::args_os")
            || lowered.contains("std::env::args")
            || lowered.contains("std::env::vars")
    });

    let mut findings = Vec::new();

    fn pattern_outside_quotes(text: &str, idx: usize) -> bool {
        let bytes = text.as_bytes();
        let mut in_quotes = false;
        let mut escaped = false;

        for (pos, byte) in bytes.iter().enumerate() {
            if pos >= idx {
                break;
            }

            if escaped {
                escaped = false;
                continue;
            }

            match byte {
                b'\\' => escaped = true,
                b'"' => in_quotes = !in_quotes,
                _ => {}
            }
        }

        !in_quotes
    }

    for assignment in dataflow.assignments() {
        let lowered = assignment.rhs.to_lowercase();
        let first_paren = lowered.find('(').unwrap_or(lowered.len());

        let is_process_command = [
            "::std::process::command::new",
            "std::process::command::new",
            "::tokio::process::command::new",
            "tokio::process::command::new",
            "::async_process::command::new",
            "async_process::command::new",
        ]
        .into_iter()
        .any(|pattern| {
            lowered.find(pattern).map_or(false, |idx| {
                idx < first_paren && pattern_outside_quotes(&assignment.rhs, idx)
            })
        });

        if !is_process_command {
            continue;
        }

        let mut tainted_args = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(assignment.target.clone());

        while let Some(current) = queue.pop_front() {
            if !visited.insert(current.clone()) {
                continue;
            }

            let mut arg_sites = Vec::new();

            for other in dataflow.assignments() {
                if other.target == current {
                    for src in &other.sources {
                        queue.push_back(src.clone());
                    }
                }

                let rhs_lower = other.rhs.to_lowercase();
                if other.sources.iter().any(|src| src == &current)
                    && (rhs_lower.contains("command::arg(")
                        || rhs_lower.contains("command::args(")
                        || rhs_lower.contains("command::env(")
                        || rhs_lower.contains("command::arg_os(")
                        || rhs_lower.contains("command::args_os("))
                {
                    arg_sites.push(other.clone());
                }
            }

            for site in arg_sites {
                let mut queue_inputs = Vec::new();
                for src in &site.sources {
                    queue_inputs.push(src.clone());
                    if taint_sources.contains(src) {
                        tainted_args.push(src.clone());
                    }
                }
                for src in queue_inputs {
                    queue.push_back(src);
                }
            }
        }

        tainted_args.sort();
        tainted_args.dedup();

        findings.push(CommandInvocation {
            command_line: assignment.line.trim().to_string(),
            tainted_args,
        });
    }

    findings
}

pub fn detect_openssl_verify_none(function: &MirFunction) -> Vec<OpensslVerifyNoneInvocation> {
    let dataflow = MirDataflow::new(function);
    let mut var_to_lines: HashMap<String, Vec<String>> = HashMap::new();

    for assignment in dataflow.assignments() {
        var_to_lines
            .entry(assignment.target.clone())
            .or_default()
            .push(assignment.line.trim().to_string());
    }

    let tainted_modes =
        dataflow.taint_from(|assignment| rhs_disables_verification(&assignment.rhs));
    let mut findings: HashMap<String, Vec<String>> = HashMap::new();

    for assignment in dataflow.assignments() {
        if !is_verify_configuration_call(&assignment.rhs) {
            continue;
        }

        let mut supporting = Vec::new();
        let mut disables = rhs_disables_verification(&assignment.rhs);

        for source in &assignment.sources {
            if tainted_modes.contains(source) {
                disables = true;
                if let Some(lines) = var_to_lines.get(source) {
                    for line in lines {
                        if !supporting.contains(line) {
                            supporting.push(line.clone());
                        }
                    }
                }
            }
        }

        if !disables {
            continue;
        }

        let entry = findings
            .entry(assignment.line.trim().to_string())
            .or_insert_with(Vec::new);
        for line in supporting {
            if !entry.contains(&line) {
                entry.push(line);
            }
        }
    }

    for raw_line in &function.body {
        let trimmed = raw_line.trim().to_string();
        if !is_verify_configuration_call(&trimmed) {
            continue;
        }
        if !rhs_disables_verification(&trimmed) {
            continue;
        }
        findings.entry(trimmed).or_insert_with(Vec::new);
    }

    let mut result: Vec<_> = findings
        .into_iter()
        .map(
            |(call_line, supporting_lines)| OpensslVerifyNoneInvocation {
                call_line,
                supporting_lines,
            },
        )
        .collect();

    result.sort_by(|a, b| a.call_line.cmp(&b.call_line));
    result
}

fn is_verify_configuration_call(text: &str) -> bool {
    let lowered = text.to_lowercase();
    lowered.contains("set_verify(") || lowered.contains("set_verify_callback(")
}

fn rhs_disables_verification(rhs: &str) -> bool {
    let rhs_lower = rhs.to_lowercase();

    rhs_lower.contains("sslverifymode::none")
        || rhs_lower.contains("ssl_verify_none")
        || rhs_lower.contains("verify_none")
        || rhs_lower.contains("sslverifymode::empty(")
        || rhs_lower.contains("verify_mode::empty(")
        || rhs_lower.contains("sslverifymode::from_bits_truncate(0")
        || rhs_lower.contains("sslverifymode::from_bits(0")
        || rhs_lower.contains("sslverifymode::from_bits_truncate(const 0")
        || rhs_lower.contains("sslverifymode::from_bits(const 0")
        || rhs_lower.contains("sslverifymode::bits(0")
}

fn collect_length_seed_vars(
    function: &MirFunction,
    dataflow: &MirDataflow,
    options: &PrototypeOptions,
) -> HashSet<String> {
    let mut seeds = HashSet::new();

    for line in &function.body {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("debug ") {
            if let Some((name_part, var_part)) = rest.split_once("=>") {
                let name = name_part.trim();
                let var = var_part.trim().trim_end_matches(';');
                if is_length_identifier(name, options) && var.starts_with('_') {
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
            || options
                .length_identifiers
                .iter()
                .any(|marker| lowered.contains(marker))
        {
            seeds.insert(assignment.target.clone());
        }
    }

    seeds
}

fn propagate_length_seeds(dataflow: &MirDataflow, seeds: HashSet<String>) -> HashSet<String> {
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

fn collect_sink_lines(
    function: &MirFunction,
    dataflow: &MirDataflow,
    root_var: &str,
    options: &PrototypeOptions,
) -> Vec<String> {
    let related_vars = collect_related_vars(dataflow, root_var);
    let mut sinks = Vec::new();

    for line in &function.body {
        let lowered = line.to_lowercase();
        if !options
            .serialization_sinks
            .iter()
            .any(|marker| lowered.contains(marker))
        {
            continue;
        }

        if related_vars.iter().any(|var| line.contains(var)) {
            let trimmed = line.trim().to_string();
            if !sinks.contains(&trimmed) {
                sinks.push(trimmed);
            }
        }
    }

    sinks
}

fn collect_related_vars(dataflow: &MirDataflow, root_var: &str) -> HashSet<String> {
    let mut related = HashSet::new();
    related.insert(root_var.to_string());
    let mut changed = true;

    while changed {
        changed = false;
        for assignment in dataflow.assignments() {
            if related.contains(&assignment.target) {
                continue;
            }

            if assignment
                .sources
                .iter()
                .any(|source| related.contains(source))
            {
                related.insert(assignment.target.clone());
                changed = true;
            }
        }
    }

    related
}

fn is_length_identifier(name: &str, options: &PrototypeOptions) -> bool {
    let lowered = name.to_lowercase();
    options
        .length_identifiers
        .iter()
        .any(|marker| lowered.contains(marker))
}

fn is_narrow_cast(rhs_lower: &str, options: &PrototypeOptions) -> bool {
    rhs_lower.contains("inttoint")
        && options
            .narrow_cast_targets
            .iter()
            .any(|target| rhs_lower.contains(target))
}

fn is_try_into_narrow(rhs_lower: &str, options: &PrototypeOptions) -> bool {
    if !rhs_lower.contains("try_into") {
        return false;
    }

    options
        .try_into_targets
        .iter()
        .any(|target| rhs_lower.contains(target))
}

fn is_broadcast_constructor(rhs: &str) -> bool {
    let lower = rhs.to_lowercase();
    lower.contains("tokio::sync::broadcast::channel")
        || lower.contains("tokio::sync::broadcast::sender::")
        || lower.contains("tokio::sync::broadcast::receiver::")
}

fn line_mentions_broadcast_usage(lower: &str) -> bool {
    [
        "tokio::sync::broadcast::",
        ".send(",
        "::send(",
        "::send_ref(",
        ".subscribe(",
        "::subscribe(",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn payload_looks_unsync(line: &str, options: &PrototypeOptions) -> bool {
    let lowered = line.to_lowercase();
    options
        .unsync_markers
        .iter()
        .any(|marker| lowered.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function_from_lines(lines: &[&str]) -> MirFunction {
        MirFunction {
            name: "demo".to_string(),
            signature: "fn demo()".to_string(),
            body: lines.iter().map(|l| l.to_string()).collect(),
            span: None,
            ..Default::default()
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
    fn detects_unbounded_allocation_from_len() {
        let function = function_from_lines(&[
            "    debug body_len => _1;",
            "    _2 = copy _1;",
            "    _3 = Vec::<u8>::with_capacity(move _2);",
        ]);

        let findings = detect_unbounded_allocations(&function);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].capacity_var, "_2");
    }

    #[test]
    fn unbounded_allocation_respects_guard() {
        let function = function_from_lines(&[
            "    debug payload_size => _1;",
            "    _2 = core::cmp::min(move _1, const 65536_usize);",
            "    _3 = Vec::<u8>::with_capacity(move _2);",
        ]);

        let findings = detect_unbounded_allocations(&function);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_tainted_command_arg() {
        let function = function_from_lines(&[
            "    _1 = std::env::var(const \"USER\");",
            "    _2 = std::process::Command::new(const \"/bin/echo\");",
            "    _3 = std::process::Command::arg(move _2, move _1);",
        ]);

        let invocations = detect_command_invocations(&function);
        assert_eq!(invocations.len(), 1);
        assert!(invocations[0].tainted_args.contains(&"_1".to_string()));
    }

    #[test]
    fn ignores_constant_command_args() {
        let function = function_from_lines(&[
            "    _1 = std::process::Command::new(const \"git\");",
            "    _2 = std::process::Command::arg(move _1, const \"status\");",
        ]);

        let invocations = detect_command_invocations(&function);
        assert_eq!(invocations.len(), 1);
        assert!(invocations[0].tainted_args.is_empty());
    }

    #[test]
    fn ignores_clap_command_builder() {
        let function = function_from_lines(&[
            "    _1 = clap::Command::new(const \"cargo-cola\");",
            "    _2 = clap::Command::arg(move _1, const \"--help\");",
        ]);

        let invocations = detect_command_invocations(&function);
        assert!(invocations.is_empty());
    }

    #[test]
    fn ignores_command_string_literal_checks() {
        let function = function_from_lines(&[
            "    _1 = core::str::<impl str>::contains::<&str>(copy _0, const \"std::process::Command::new\");",
        ]);

        let invocations = detect_command_invocations(&function);
        assert!(invocations.is_empty());
    }

    #[test]
    fn detects_openssl_verify_none_inline() {
        let function = function_from_lines(&[
            "    _1 = openssl::ssl::SslContextBuilder::set_verify(move _0, openssl::ssl::SslVerifyMode::NONE);",
        ]);

        let findings = detect_openssl_verify_none(&function);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].call_line.contains("set_verify"));
        assert!(findings[0].supporting_lines.is_empty());
    }

    #[test]
    fn detects_openssl_verify_none_via_empty_mode() {
        let function = function_from_lines(&[
            "    _1 = openssl::ssl::SslVerifyMode::empty();",
            "    _2 = openssl::ssl::SslContextBuilder::set_verify(move _0, move _1);",
        ]);

        let findings = detect_openssl_verify_none(&function);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].supporting_lines.len(), 1);
        assert!(findings[0].supporting_lines[0].contains("SslVerifyMode::empty"));
    }

    #[test]
    fn detects_openssl_verify_none_callback() {
        let function = function_from_lines(&[
            "    _2 = openssl::ssl::SslContextBuilder::set_verify_callback(move _0, openssl::ssl::SslVerifyMode::NONE, move _1);",
        ]);

        let findings = detect_openssl_verify_none(&function);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].call_line.contains("set_verify_callback"));
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
        assert!(casts[0].sink_lines.is_empty());
    }

    #[test]
    fn detects_try_into_len_cast() {
        let function = function_from_lines(&[
            "    debug payload_len => _1;",
            "    _2 = copy _1;",
            "    _3 = core::convert::TryInto::try_into::<i16>(move _2);",
        ]);

        let casts = detect_truncating_len_casts(&function);
        assert_eq!(casts.len(), 1);
        assert_eq!(casts[0].target_var, "_3");
    }

    #[test]
    fn captures_serialization_sinks() {
        let function = function_from_lines(&[
            "    debug payload_len => _1;",
            "    _2 = copy _1;",
            "    _3 = move _2 as u16 (IntToInt);",
            "    _4 = copy _3;",
            "    _5 = byteorder::WriteBytesExt::write_u16::<byteorder::BigEndian>(move _0, move _4);",
        ]);

        let casts = detect_truncating_len_casts(&function);
        assert_eq!(casts.len(), 1);
        assert_eq!(casts[0].sink_lines.len(), 1);
        assert!(casts[0].sink_lines[0].contains("WriteBytesExt::write_u16"));
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
    fn respects_custom_guard_markers() {
        let function = function_from_lines(&[
            "    _2 = reqwest::Response::content_length(move _1);",
            "    _3 = copy _2;",
            "    _4 = my_crate::ensure_capacity(move _3);",
            "    _5 = Vec::<u8>::with_capacity(move _4);",
        ]);

        let mut options = PrototypeOptions::default();
        options.guard_markers.push("ensure_capacity".to_string());

        let findings = detect_content_length_allocations_with_options(&function, &options);
        assert!(findings.is_empty());
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
        let function =
            function_from_lines(&["    _3 = Vec::<u8>::with_capacity(const 4096_usize);"]);

        let findings = detect_content_length_allocations(&function);
        assert!(findings.is_empty());
    }
}
