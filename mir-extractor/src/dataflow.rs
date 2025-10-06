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
            .filter_map(|line| parse_assignment_line(line))
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

fn parse_assignment_line(line: &str) -> Option<Assignment> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.splitn(2, '=');
    let lhs = parts.next()?.trim();
    let rhs = parts.next()?.trim();

    if !lhs.starts_with('_') {
        return None;
    }

    if lhs.contains(',') || lhs.contains('(') || lhs.contains('[') {
        return None;
    }

    if !lhs
        .chars()
        .all(|ch| ch == '_' || ch.is_ascii_digit() || ch.is_alphabetic())
    {
        return None;
    }

    let rhs = rhs.trim_end_matches(';').trim();
    if rhs.is_empty() {
        return None;
    }

    let sources = extract_variables(rhs);

    Some(Assignment {
        target: lhs.to_string(),
        sources,
        rhs: rhs.to_string(),
        line: trimmed.to_string(),
    })
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
}
