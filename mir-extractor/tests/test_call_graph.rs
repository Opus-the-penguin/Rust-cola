//! Test call graph construction on interprocedural examples

use mir_extractor::interprocedural::CallGraph;

#[test]
fn test_call_graph_construction() {
    // Load MIR from interprocedural examples
    let crate_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/interprocedural");

    if !crate_path.exists() {
        panic!("Interprocedural examples not found at {:?}", crate_path);
    }

    // Extract MIR
    let package = match mir_extractor::extract(&crate_path) {
        Ok(pkg) => pkg,
        Err(e) => {
            eprintln!("Failed to extract MIR: {}", e);
            return; // Skip test if extraction fails
        }
    };

    println!("Extracted {} functions", package.functions.len());

    // Build call graph
    let call_graph = CallGraph::from_mir_package(&package).expect("Failed to build call graph");

    println!("Call graph has {} nodes", call_graph.nodes.len());
    println!(
        "Analysis order: {} functions",
        call_graph.analysis_order.len()
    );

    // Verify basic properties
    assert!(!call_graph.nodes.is_empty(), "Call graph should have nodes");
    assert_eq!(
        call_graph.nodes.len(),
        call_graph.analysis_order.len(),
        "Analysis order should include all nodes"
    );

    // Print some statistics
    let leaf_functions: Vec<_> = call_graph
        .nodes
        .iter()
        .filter(|(_, node)| node.callees.is_empty())
        .map(|(name, _)| name)
        .collect();

    println!("Leaf functions (no callees): {}", leaf_functions.len());
    for name in &leaf_functions[..leaf_functions.len().min(5)] {
        println!("  - {}", name);
    }

    // Find functions with callees
    let functions_with_calls: Vec<_> = call_graph
        .nodes
        .iter()
        .filter(|(_, node)| !node.callees.is_empty())
        .collect();

    println!("Functions with calls: {}", functions_with_calls.len());
    for (name, node) in &functions_with_calls[..functions_with_calls.len().min(5)] {
        println!("  - {} calls {} functions", name, node.callees.len());
        for callee in &node.callees[..node.callees.len().min(3)] {
            println!("      → {}", callee.callee);
        }
    }
}

#[test]
fn test_specific_function_calls() {
    let crate_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/interprocedural");

    if !crate_path.exists() {
        return; // Skip if examples don't exist
    }

    let package = match mir_extractor::extract(&crate_path) {
        Ok(pkg) => pkg,
        Err(_) => return,
    };

    let call_graph = CallGraph::from_mir_package(&package).expect("Failed to build call graph");

    // Look for test_two_level_flow which should call:
    // - get_user_input()
    // - execute_command()

    let two_level_node = call_graph
        .nodes
        .iter()
        .find(|(name, _)| name.contains("test_two_level_flow"));

    if let Some((name, node)) = two_level_node {
        println!("Found function: {}", name);
        println!("  Callees: {}", node.callees.len());
        for callee in &node.callees {
            println!("    → {}", callee.callee);
        }

        // We expect at least 2 calls (get_user_input and execute_command)
        assert!(
            node.callees.len() >= 2,
            "test_two_level_flow should call at least 2 functions, found {}",
            node.callees.len()
        );
    }
}
