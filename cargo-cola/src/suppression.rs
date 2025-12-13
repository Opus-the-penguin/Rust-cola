use mir_extractor::{Finding, SuppressionRule};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub fn filter_suppressed_findings(findings: &mut Vec<Finding>, crate_root: &Path, suppressions: &[SuppressionRule]) {
    let mut file_cache: HashMap<String, Vec<String>> = HashMap::new();
    
    findings.retain(|finding| {
        // Check YAML suppressions first
        for suppression in suppressions {
            if suppression.rule_id == finding.rule_id {
                let mut matches = true;

                // Check file match
                if let Some(file_pattern) = &suppression.file {
                    if let Some(span) = &finding.span {
                        if !span.file.contains(file_pattern) {
                            matches = false;
                        }
                    } else {
                        matches = false;
                    }
                }

                // Check function match
                if let Some(function_pattern) = &suppression.function {
                    if finding.function.contains(function_pattern) {
                        // Match found
                    } else {
                        matches = false;
                    }
                }

                if matches {
                    return false; // Suppressed
                }
            }
        }

        if let Some(span) = &finding.span {
            let file_path_str = &span.file;
            let file_path = if Path::new(file_path_str).is_absolute() {
                Path::new(file_path_str).to_path_buf()
            } else {
                crate_root.join(file_path_str)
            };
            let cache_key = file_path.to_string_lossy().to_string();
            
            // Ensure file is in cache
            if !file_cache.contains_key(&cache_key) {
                if let Ok(content) = fs::read_to_string(&file_path) {
                    let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
                    file_cache.insert(cache_key.clone(), lines);
                } else {
                    // If we can't read the file, we can't check for suppression, so keep the finding
                    return true;
                }
            }
            
            if let Some(lines) = file_cache.get(&cache_key) {
                let line_idx = (span.start_line as usize).saturating_sub(1);
                
                // Check current line (inline comment)
                if line_idx < lines.len() {
                    if check_suppression(&lines[line_idx], &finding.rule_id) {
                        return false;
                    }
                }
                
                // Check previous line
                if line_idx > 0 && line_idx - 1 < lines.len() {
                    if check_suppression(&lines[line_idx - 1], &finding.rule_id) {
                        return false;
                    }
                }
            }
        }
        true
    });
}

fn check_suppression(line: &str, rule_id: &str) -> bool {
    let trimmed = line.trim();
    if let Some(idx) = trimmed.find("//") {
        let comment = &trimmed[idx..];
        if comment.contains("rust-cola:ignore") {
            // Check if it ignores this specific rule or all rules
            // Format: // rust-cola:ignore RUSTCOLA123, RUSTCOLA456
            // Or: // rust-cola:ignore (ignores all)
            
            let parts: Vec<&str> = comment.split("rust-cola:ignore").collect();
            if parts.len() > 1 {
                let args = parts[1].trim();
                if args.is_empty() {
                    return true; // Ignore all
                }
                
                // Check if rule_id is present in the args
                // We split by comma and whitespace
                let ignored_rules: Vec<&str> = args
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|s| !s.is_empty())
                    .collect();
                    
                if ignored_rules.contains(&rule_id) {
                    return true;
                }
            }
        }
    }
    false
}
