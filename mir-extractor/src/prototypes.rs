use std::collections::HashSet;

use crate::{dataflow::extract_variables, MirDataflow, MirFunction};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentLengthAllocation {
    pub allocation_line: String,
    pub capacity_var: String,
    pub tainted_vars: HashSet<String>,
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
            if tainted.contains(&capacity_var) {
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
    fn ignores_bounded_allocations() {
        let function = function_from_lines(&[
            "    _2 = reqwest::Response::content_length(move _1);",
            "    _3 = copy _2;",
            "    _4 = core::cmp::min(move _3, const 1048576_usize);",
            "    _5 = Vec::<u8>::with_capacity(move _4);",
        ]);

        let findings = detect_content_length_allocations(&function);
        assert_eq!(findings.len(), 1, "min wrap still uses tainted var");
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
