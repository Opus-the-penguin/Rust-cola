/// Quick test to verify CFG extraction and path-sensitive analysis works
use mir_extractor::dataflow::cfg::ControlFlowGraph;
use mir_extractor::dataflow::path_sensitive::PathSensitiveTaintAnalysis;
use mir_extractor::MirPackage;

fn main() {
    // Load the MIR JSON
    let mir_json = std::fs::read_to_string("target/partial_mir.json")
        .expect("Failed to read MIR JSON");
    
    let package: MirPackage = serde_json::from_str(&mir_json)
        .expect("Failed to parse MIR JSON");
    
    // Find test_partial_sanitization
    let function = package.functions.iter()
        .find(|f| f.name.contains("partial_sanitization"))
        .expect("Could not find test_partial_sanitization");
    
    println!("Function: {}", function.name);
    println!("Body lines: {}", function.body.len());
    
    // Extract CFG
    let cfg = ControlFlowGraph::from_mir_function(function);
    
    println!("\n=== CFG Statistics ===");
    println!("Blocks: {}", cfg.blocks.len());
    println!("Entry: {}", cfg.entry_block);
    println!("Exits: {:?}", cfg.exit_blocks);
    println!("Has branching: {}", cfg.has_branching());
    
    println!("\n=== Basic Blocks ===");
    let mut block_ids: Vec<_> = cfg.blocks.keys().collect();
    block_ids.sort();
    
    for block_id in block_ids {
        let block = &cfg.blocks[block_id];
        println!("\n{}:", block.id);
        println!("  Statements: {}", block.statements.len());
        for stmt in &block.statements {
            println!("    {}", stmt);
        }
        println!("  Terminator: {:?}", block.terminator);
        
        if let Some(successors) = cfg.edges.get(block_id) {
            println!("  Successors: {:?}", successors);
        }
    }
    
    println!("\n=== Execution Paths ===");
    let paths = cfg.get_all_paths();
    println!("Total paths: {}", paths.len());
    
    for (i, path) in paths.iter().enumerate() {
        println!("\nPath {}:", i + 1);
        println!("  {}", path.join(" -> "));
        println!("  Length: {} blocks", path.len());
    }
    
    println!("\n=== Path-Sensitive Taint Analysis ===");
    let mut analysis = PathSensitiveTaintAnalysis::new(cfg);
    let result = analysis.analyze(function);
    
    println!("Total paths analyzed: {}", result.total_paths);
    println!("Vulnerable paths: {}", result.vulnerable_paths().len());
    println!("Safe paths: {}", result.safe_paths().len());
    println!("Has any vulnerable path: {}", result.has_any_vulnerable_path);
    
    for (i, path_result) in result.path_results.iter().enumerate() {
        println!("\nPath {} Analysis:", i + 1);
        println!("  Vulnerable: {}", path_result.has_vulnerable_sink);
        println!("  Source calls: {}", path_result.source_calls.len());
        println!("  Sink calls: {}", path_result.sink_calls.len());
        println!("  Sanitizer calls: {}", path_result.sanitizer_calls.len());
    }
}
