use std::collections::HashSet;

use crate::MirFunction;

#[derive(Debug, Clone)]
pub struct Assignment {
    pub target: String,
    pub sources: Vec<String>,
    pub rhs: String,
    pub line: String,
}

pub struct MirDataflow {
    assignments: Vec<Assignment>,
}

impl MirDataflow {
    pub fn new(function: &MirFunction) -> Self {
        let assignments = function
            .body
            .iter()
            .flat_map(|line| parse_assignment_line(line))
            .collect();
        Self { assignments }
    }

    pub fn assignments(&self) -> &[Assignment] {
        &self.assignments
    }

    pub fn taint_from<F>(&self, mut predicate: F) -> HashSet<String>
    where
        F: FnMut(&Assignment) -> bool,
    {
        let mut tainted: HashSet<String> = HashSet::new();

        for assignment in &self.assignments {
            if predicate(assignment) {
                tainted.insert(assignment.target.clone());
            }
        }

        let mut changed = true;
        while changed {
            changed = false;
            for assignment in &self.assignments {
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
}

fn parse_assignment_line(line: &str) -> Vec<Assignment> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut parts = trimmed.splitn(2, '=');
    let lhs = match parts.next() {
        Some(value) => value.trim(),
        None => return Vec::new(),
    };
    let rhs = match parts.next() {
        Some(value) => value.trim(),
        None => return Vec::new(),
    };

    let rhs = rhs.trim_end_matches(';').trim();
    if rhs.is_empty() {
        return Vec::new();
    }

    let mut targets = extract_variables(lhs);
    if targets.is_empty() {
        return Vec::new();
    }

    targets.sort();
    targets.dedup();

    let sources = extract_variables(rhs);

    targets
        .into_iter()
        .map(|target| Assignment {
            target,
            sources: sources.clone(),
            rhs: rhs.to_string(),
            line: trimmed.to_string(),
        })
        .collect()
}

pub(crate) fn extract_variables(input: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let mut chars = input.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        if ch == '_' {
            let mut end = idx + ch.len_utf8();
            while let Some((next_idx, next_ch)) = chars.peek().copied() {
                if next_ch.is_ascii_digit() {
                    chars.next();
                    end = next_idx + next_ch.len_utf8();
                } else {
                    break;
                }
            }
            if end > idx + ch.len_utf8() {
                vars.push(input[idx..end].to_string());
            }
        }
    }

    vars
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_function(lines: &[&str]) -> MirFunction {
        MirFunction {
            name: "demo".to_string(),
            signature: "fn demo()".to_string(),
            body: lines.iter().map(|line| line.to_string()).collect(),
            span: None,
        }
    }

    #[test]
    fn parses_simple_assignment() {
        let function = make_function(&["    _1 = copy _2;"]);
        let dataflow = MirDataflow::new(&function);
        assert_eq!(dataflow.assignments().len(), 1);
        let assignment = &dataflow.assignments()[0];
        assert_eq!(assignment.target, "_1");
        assert_eq!(assignment.sources, vec!["_2".to_string()]);
    }

    #[test]
    fn taint_propagates_transitively() {
        let function = make_function(&[
            "    _1 = std::http::HeaderMap::get(move _0);",
            "    _2 = copy _1;",
            "    _3 = Vec::<u8>::with_capacity(move _2);",
        ]);

        let dataflow = MirDataflow::new(&function);
        let tainted = dataflow.taint_from(|assignment| assignment.rhs.contains("HeaderMap::get"));
    assert!(tainted.contains("_1"));
    assert!(tainted.contains("_2"));
    assert!(tainted.contains("_3"));
    }

    #[test]
    fn skip_non_assignments() {
        let function = make_function(&[
            "    assert(!const false) -> [success: bb1, unwind: bb2];",
            "    _1 = Vec::<u8>::with_capacity(const 1024_usize);",
        ]);

        let dataflow = MirDataflow::new(&function);
        assert_eq!(dataflow.assignments().len(), 1);
    }

    #[test]
    fn tuple_destructuring_creates_assignments_for_each_slot() {
        let function = make_function(&[
            "    (_1, _2) = move _3;",
            "    _4 = copy _2;",
        ]);

        let dataflow = MirDataflow::new(&function);
        assert_eq!(dataflow.assignments().len(), 3);

    let tainted = dataflow.taint_from(|assignment| assignment.rhs.contains("_3"));
        assert!(tainted.contains("_1"));
        assert!(tainted.contains("_2"));
        assert!(tainted.contains("_4"));
    }

    #[test]
    fn option_projections_propagate_through_fields() {
        let function = make_function(&[
            "    _4 = reqwest::Response::content_length(move _1);",
            "    (_5.0: core::option::Option<usize>) = move _4;",
            "    _6 = move (_5.0: core::option::Option<usize>);",
            "    _7 = Vec::<u8>::with_capacity(move _6);",
        ]);

        let dataflow = MirDataflow::new(&function);
        let tainted = dataflow.taint_from(|assignment| assignment.rhs.contains("content_length"));

        assert!(tainted.contains("_4"));
        assert!(tainted.contains("_5"));
        assert!(tainted.contains("_6"));
        assert!(tainted.contains("_7"));
    }
}
