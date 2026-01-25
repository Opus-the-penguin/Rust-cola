/// Test false positive reduction strategies
use std::process::Command;

#[test]
fn test_false_positive_reduction() {
    // Build the interprocedural examples from workspace root
    let workspace_root = std::env::current_dir()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    let examples_path = workspace_root.join("examples/interprocedural");

    // Extract MIR from interprocedural examples
    let output = Command::new("cargo")
        .current_dir(&workspace_root)
        .args(&["run", "--bin", "mir-extractor", "--", "--crate-path"])
        .arg(&examples_path)
        .args(&["--mir-json", "target/interprocedural_fp.json"])
        .output()
        .expect("Failed to extract MIR");

    if !output.status.success() {
        panic!(
            "MIR extraction failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Load the extracted MIR
    let mir_path = workspace_root.join("target/interprocedural_fp.json");
    let mir_content = std::fs::read_to_string(&mir_path).expect("Failed to read MIR JSON");
    let package: mir_extractor::MirPackage =
        serde_json::from_str(&mir_content).expect("Failed to parse MIR JSON");

    // Run inter-procedural analysis
    let mut analysis = mir_extractor::interprocedural::InterProceduralAnalysis::new(&package)
        .expect("Failed to create analysis");
    analysis.analyze(&package).expect("Analysis failed");

    // Detect flows
    let flows = analysis.detect_inter_procedural_flows(&package);

    // Check specific cases

    // Case 1: test_validation_check
    // This uses is_safe_input() guard. It should be filtered out.
    let validation_check_flows: Vec<_> = flows
        .iter()
        .filter(|f| f.source_function == "test_validation_check")
        .collect();

    // Currently (before fix), this might be 1. After fix, should be 0.
    println!(
        "test_validation_check flows: {}",
        validation_check_flows.len()
    );

    // Case 2: test_helper_sanitization
    // This uses validate_input() which returns sanitized data.
    // This should be detected as a flow, but marked as sanitized.
    let helper_sanitization_flows: Vec<_> = flows
        .iter()
        .filter(|f| f.source_function == "test_helper_sanitization")
        .collect();

    println!(
        "test_helper_sanitization flows: {}",
        helper_sanitization_flows.len()
    );
    if !helper_sanitization_flows.is_empty() {
        println!("  Sanitized: {}", helper_sanitization_flows[0].sanitized);
    }
}
