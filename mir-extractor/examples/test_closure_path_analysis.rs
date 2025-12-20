/// Example: Test path-sensitive analysis for closures
///
/// This example demonstrates how to analyze closures using the integrated
/// closure registry and path-sensitive taint analysis.

use mir_extractor::dataflow::closure::ClosureRegistryBuilder;
use mir_extractor::dataflow::cfg::ControlFlowGraph;
use mir_extractor::dataflow::path_sensitive::PathSensitiveTaintAnalysis;
use mir_extractor::MirFunction;
use serde_json;
use std::fs;

fn main() {
    println!("=== Closure Path-Sensitive Analysis Demo ===\n");
    
    // Load MIR JSON
    let mir_json = fs::read_to_string("target/closure_mir.json")
        .expect("Failed to read closure_mir.json");
    
    let mir_data: serde_json::Value = serde_json::from_str(&mir_json)
        .expect("Failed to parse JSON");
    
    // Extract functions
    let functions: Vec<MirFunction> = mir_data["functions"]
        .as_array()
        .expect("No functions array")
        .iter()
        .filter_map(|f| serde_json::from_value(f.clone()).ok())
        .collect();
    
    println!("📊 Loaded {} functions from MIR\n", functions.len());
    
    // Build closure registry
    println!("🔍 Building closure registry with taint tracking...");
    let registry = ClosureRegistryBuilder::build(&functions);
    
    let all_closures = registry.get_all_closures();
    println!("   Found {} closures\n", all_closures.len());
    
    // Analyze test_closure_capture
    if let Some(closure_info) = all_closures.iter()
        .find(|c| c.name.contains("test_closure_capture") && c.name.contains("{closure#0}"))
    {
        println!("=== Analyzing: {} ===", closure_info.name);
        println!("Parent: {}", closure_info.parent_function);
        println!("Captured variables: {}\n", closure_info.captured_vars.len());
        
        // Show captured variable taint state
        for capture in &closure_info.captured_vars {
            println!("  Field .{}: {} (mode: {:?})", 
                capture.field_index,
                capture.parent_var,
                capture.capture_mode
            );
            println!("    Taint state: {:?}", capture.taint_state);
        }
        println!();
        
        // Find the closure function in MIR
        if let Some(closure_fn) = functions.iter()
            .find(|f| f.name == closure_info.name)
        {
            println!("🔬 Running path-sensitive analysis on closure body...\n");
            
            // Build CFG for the closure
            let cfg = ControlFlowGraph::from_mir_function(closure_fn);
            let (paths, _) = cfg.get_all_paths();
            println!("   CFG: {} basic blocks, {} paths",
                cfg.blocks.len(),
                paths.len()
            );
            
            // Run path-sensitive analysis with closure context
            let mut analysis = PathSensitiveTaintAnalysis::new(cfg);
            let result = analysis.analyze_closure(closure_fn, closure_info, None);
            
            println!("\n📋 Analysis Results:");
            println!("   Total paths analyzed: {}", result.total_paths);
            println!("   Vulnerable paths: {}", result.vulnerable_paths().len());
            println!("   Safe paths: {}", result.safe_paths().len());
            
            if result.has_any_vulnerable_path {
                println!("\n⚠️  VULNERABILITY DETECTED!");
                println!("\n   Tainted data from captured variables flows to sink functions.");
                
                for (i, path_result) in result.vulnerable_paths().iter().enumerate() {
                    println!("\n   Vulnerable Path #{}:", i + 1);
                    println!("     Blocks: {:?}", path_result.path);
                    println!("     Sink calls: {}", path_result.sink_calls.len());
                    
                    for sink in &path_result.sink_calls {
                        println!("\n       🚨 Sink found:");
                        println!("         Block: {}", sink.block_id);
                        println!("         Function: {}", sink.sink_function);
                        println!("         Statement: {}", sink.statement);
                        println!("         Tainted args: {:?}", sink.tainted_args);
                    }
                    
                    if !path_result.source_calls.is_empty() {
                        println!("\n       Sources in this path:");
                        for source in &path_result.source_calls {
                            println!("         - {} in {}", source.source_function, source.block_id);
                        }
                    }
                }
            } else {
                println!("\n✅ No vulnerabilities detected.");
                println!("   All paths are safe or sanitized.");
            }
            
        } else {
            println!("❌ Could not find closure function in MIR");
        }
        
    } else {
        println!("❌ Could not find test_closure_capture closure in registry");
    }
    
    println!("\n=== Analysis Complete ===");
}
