/// Test advanced rules (Phase 3.5)
use std::process::Command;

#[test]
fn test_advanced_rules() {
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
        .args(&[
            "run",
            "--bin",
            "mir-extractor",
            "--",
            "--crate-path",
        ])
        .arg(&examples_path)
        .args(&["--mir-json", "target/interprocedural_adv.json"])
        .output()
        .expect("Failed to extract MIR");
    
    if !output.status.success() {
        panic!(
            "MIR extraction failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    
    // Load the extracted MIR
    let mir_path = workspace_root.join("target/interprocedural_adv.json");
    let mir_content = std::fs::read_to_string(&mir_path).expect("Failed to read MIR JSON");
    let package: mir_extractor::MirPackage = serde_json::from_str(&mir_content).expect("Failed to parse MIR JSON");
    
    // Run inter-procedural analysis
    let mut analysis = mir_extractor::interprocedural::InterProceduralAnalysis::new(&package).expect("Failed to create analysis");
    
    // Debug: Print all functions in the package
    for func in &package.functions {
        println!("[DEBUG] Package contains function: {}", func.name);
    }

    analysis.analyze(&package).expect("Analysis failed");
    
    // Detect flows
    let flows = analysis.detect_inter_procedural_flows(&package);
    
    // Check for trait method flow
    let trait_flows: Vec<_> = flows.iter()
        .filter(|f| f.source_function == "test_trait_method")
        .collect();
        
    println!("test_trait_method flows: {}", trait_flows.len());
    
    // We expect 1 flow if trait resolution is working
    // assert_eq!(trait_flows.len(), 1, "Should detect flow through trait method");

    // Check for async flow
    let async_flows: Vec<_> = flows.iter()
        .filter(|f| f.source_function == "test_async_flow")
        .collect();
        
    println!("test_async_flow flows: {}", async_flows.len());
    
    // We expect 1 flow if async analysis is working
    assert_eq!(async_flows.len(), 1, "Should detect flow through async function");
}
