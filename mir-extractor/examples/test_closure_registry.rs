/// Example demonstrating closure registry building
/// 
/// This example:
/// 1. Loads MIR JSON for interprocedural examples
/// 2. Builds a closure registry
/// 3. Displays all detected closures and their captures

use std::fs;
use mir_extractor::{MirPackage, dataflow::closure::ClosureRegistryBuilder};

fn main() {
    println!("=== Closure Registry Example ===\n");
    
    // Load MIR JSON
    let mir_json_path = "target/closure_mir.json";
    println!("Loading MIR from: {}", mir_json_path);
    
    let mir_json = fs::read_to_string(mir_json_path)
        .expect("Failed to read MIR JSON. Run: cargo run --bin mir-extractor -- --crate-path examples/interprocedural --mir-json target/closure_mir.json");
    
    let package: MirPackage = serde_json::from_str(&mir_json)
        .expect("Failed to parse MIR JSON");
    
    println!("Loaded {} functions\n", package.functions.len());
    
    // Build closure registry
    println!("Building closure registry...");
    let registry = ClosureRegistryBuilder::build_from_package(&package);
    
    // Display results
    println!("\n=== Closure Registry ===\n");
    
    let mut closure_count = 0;
    
    // Group closures by parent function
    let mut parents: Vec<_> = registry.get_all_parents();
    parents.sort();
    
    for parent in &parents {
        let closures = registry.get_closures_for_parent(parent);
        
        if closures.is_empty() {
            continue;
        }
        
        println!("Parent Function: {}", parent);
        println!("  Closures: {}", closures.len());
        
        for closure_info in closures {
            closure_count += 1;
            
            println!("\n  Closure: {}", closure_info.name);
            
            if let Some(ref location) = closure_info.source_location {
                println!("    Location: {}", location);
            }
            
            if closure_info.captured_vars.is_empty() {
                println!("    Captures: (none)");
            } else {
                println!("    Captures: {} variables", closure_info.captured_vars.len());
                
                for (i, capture) in closure_info.captured_vars.iter().enumerate() {
                    println!(
                        "      [{}.{}] {} (from parent: {}, mode: {:?}, taint: {:?})",
                        i,
                        capture.field_index,
                        if capture.parent_var.is_empty() { "<unnamed>" } else { &capture.parent_var },
                        capture.parent_var,
                        capture.capture_mode,
                        capture.taint_state
                    );
                }
            }
            
            if closure_info.has_tainted_captures() {
                println!("    ⚠️  HAS TAINTED CAPTURES");
            }
        }
        
        println!();
    }
    
    println!("=== Summary ===");
    println!("Total closures found: {}", closure_count);
    println!("Functions with closures: {}", parents.len());
    
    // Highlight test_closure_capture specifically
    println!("\n=== Focus: test_closure_capture ===");
    if let Some(closure) = registry.get_closures_for_parent("test_closure_capture").first() {
        println!("Found closure: {}", closure.name);
        println!("Captured variables: {}", closure.captured_vars.len());
        
        for capture in &closure.captured_vars {
            println!(
                "  - Field .{}: {} (mode: {:?}, taint: {:?})",
                capture.field_index,
                capture.parent_var,
                capture.capture_mode,
                capture.taint_state
            );
        }
        
        if closure.has_tainted_captures() {
            println!("\n⚠️  VULNERABLE: Closure captures tainted data!");
        } else {
            println!("\n✓ Safe: No tainted captures detected");
        }
    } else {
        println!("No closures found for test_closure_capture");
    }
}
