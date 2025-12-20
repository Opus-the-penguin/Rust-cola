/// Test path-sensitive taint analysis on test_partial_sanitization
use std::process::Command;

#[test]
fn test_partial_sanitization_path_analysis() {
    let workspace_root = std::env::current_dir()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    
    let examples_path = workspace_root.join("examples/interprocedural");
    let mir_json_path = workspace_root.join("target/interprocedural.json");
    
    // Build and extract MIR if needed
    if !mir_json_path.exists() {
        let manifest_path = examples_path.join("Cargo.toml");
        
        println!("Building interprocedural examples...");
        let output = Command::new("cargo")
            .args(&["build", "--manifest-path"])
            .arg(&manifest_path)
            .output()
            .expect("Failed to build");
        
        if !output.status.success() {
            panic!("Build failed: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        println!("Extracting MIR...");
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
            .args(&["--mir-json"])
            .arg(&mir_json_path)
            .output()
            .expect("Failed to extract MIR");
        
        if !output.status.success() {
            panic!("MIR extraction failed: {}", String::from_utf8_lossy(&output.stderr));
        }
    }
    
    // Load MIR package
    let mir_json = std::fs::read_to_string(&mir_json_path)
        .expect("Failed to read MIR JSON");
    
    let package: mir_extractor::MirPackage = serde_json::from_str(&mir_json)
        .expect("Failed to parse MIR JSON");
    
    // Find test_partial_sanitization function
    let function = package
        .functions
        .iter()
        .find(|f| f.name == "test_partial_sanitization")
        .expect("test_partial_sanitization not found");
    
    println!("\n=== Analyzing test_partial_sanitization ===");
    println!("Function: {}", function.name);
    println!("Body lines: {}", function.body.len());
    
    // Build CFG
    use mir_extractor::dataflow::cfg::ControlFlowGraph;
    let cfg = ControlFlowGraph::from_mir_function(function);
    
    println!("\n=== Control Flow Graph ===");
    println!("Blocks: {}", cfg.blocks.len());
    println!("Entry: {}", cfg.entry_block);
    println!("Exit blocks: {:?}", cfg.exit_blocks);
    println!("Has branching: {}", cfg.has_branching());
    
    // Print all blocks and their successors
    for (block_id, block) in &cfg.blocks {
        println!("\n{} ({} statements):", block_id, block.statements.len());
        if !block.statements.is_empty() {
            for stmt in &block.statements {
                if stmt.contains("execute_command") || stmt.contains("validate_input") || stmt.contains("args") {
                    println!("  * {}", stmt);
                }
            }
        }
        println!("  Terminator: {:?}", block.terminator);
        if let Some(successors) = cfg.edges.get(block_id) {
            println!("  → {:?}", successors);
        }
    }
    
    // Enumerate all paths
    let (paths, _skipped) = cfg.get_all_paths();
    println!("\n=== Paths ===");
    println!("Total paths: {}", paths.len());
    
    for (i, path) in paths.iter().enumerate() {
        println!("\nPath {}: {}", i + 1, path.join(" → "));
        
        // Check if this path contains validate_input or execute_command
        let mut has_validate = false;
        let mut has_execute = false;
        
        for block_id in path {
            if let Some(block) = cfg.get_block(block_id) {
                for stmt in &block.statements {
                    if stmt.contains("validate_input") {
                        has_validate = true;
                        println!("  [SANITIZE] {}", stmt);
                    }
                    if stmt.contains("execute_command") {
                        has_execute = true;
                        println!("  [SINK] {}", stmt);
                    }
                }
            }
        }
        
        let status = match (has_validate, has_execute) {
            (true, true) => "✓ SAFE (sanitized before sink)",
            (false, true) => "✗ VULNERABLE (sink without sanitization)",
            (_, false) => "○ No sink",
        };
        println!("  Status: {}", status);
    }
    
    // Run path-sensitive taint analysis
    use mir_extractor::dataflow::path_sensitive::PathSensitiveTaintAnalysis;
    let mut analysis = PathSensitiveTaintAnalysis::new(cfg);
    let result = analysis.analyze(function, None);
    
    println!("\n=== Path-Sensitive Analysis Results ===");
    println!("Total paths analyzed: {}", result.total_paths);
    println!("Vulnerable paths: {}", result.vulnerable_paths().len());
    println!("Safe paths: {}", result.safe_paths().len());
    println!("Has any vulnerable path: {}", result.has_any_vulnerable_path);
    
    for (i, path_result) in result.path_results.iter().enumerate() {
        println!("\nPath {} Analysis:", i + 1);
        println!("  Blocks: {}", path_result.path.join(" → "));
        println!("  Vulnerable: {}", path_result.has_vulnerable_sink);
        println!("  Sources: {}", path_result.source_calls.len());
        println!("  Sanitizers: {}", path_result.sanitizer_calls.len());
        println!("  Sinks: {}", path_result.sink_calls.len());
        
        if !path_result.source_calls.is_empty() {
            println!("  Source calls:");
            for source in &path_result.source_calls {
                println!("    - {}: {}", source.block_id, source.source_function);
            }
        }
        
        if !path_result.sanitizer_calls.is_empty() {
            println!("  Sanitizer calls:");
            for sanitizer in &path_result.sanitizer_calls {
                println!("    - {}: {}", sanitizer.block_id, sanitizer.sanitizer_function);
            }
        }
        
        if !path_result.sink_calls.is_empty() {
            println!("  Sink calls:");
            for sink in &path_result.sink_calls {
                println!("    - {}: {} (tainted args: {:?})", sink.block_id, sink.sink_function, sink.tainted_args);
            }
        }
    }
    
    // ASSERTION: We should detect at least one vulnerable path
    assert!(
        result.has_any_vulnerable_path,
        "test_partial_sanitization should have at least one vulnerable path (bb6→bb12→bb13)"
    );
    
    println!("\n✓ Test passed! Path-sensitive analysis correctly detected vulnerable path.");
}
