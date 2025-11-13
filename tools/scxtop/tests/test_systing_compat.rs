// Test systing trace compatibility
use scxtop::mcp::PerfettoTrace;
use std::path::Path;
use std::sync::Arc;

#[test]
fn test_load_systing_trace() {
    let trace_path = "/home/hodgesd/systing/trace.pb";

    // Skip test if trace file doesn't exist
    if !Path::new(trace_path).exists() {
        eprintln!("Skipping test - systing trace not found at: {}", trace_path);
        return;
    }

    println!("Loading systing trace from: {}", trace_path);

    let trace =
        PerfettoTrace::from_file(Path::new(trace_path)).expect("Failed to load systing trace");

    println!("✓ Successfully loaded systing trace!");
    let (start_ns, end_ns) = trace.time_range();
    println!("  Time range: {} - {} ns", start_ns, end_ns);
    println!(
        "  Duration: {:.2} seconds",
        (end_ns - start_ns) as f64 / 1e9
    );
    println!("  Number of CPUs: {}", trace.num_cpus());
    println!("  Total events: {}", trace.total_events());
    println!("  Processes: {}", trace.get_processes().len());

    // Check event types
    let event_types = trace.list_event_types();
    println!("  Event types: {:?}", event_types);

    // Verify we actually got some data
    assert!(end_ns > start_ns, "Trace should have non-zero duration");
    assert!(trace.total_events() > 0, "Trace should contain events");

    // Verify scheduler events are present
    assert!(
        event_types.contains(&"sched_switch".to_string()),
        "Should have sched_switch events"
    );
    assert!(
        event_types.contains(&"sched_waking".to_string()),
        "Should have sched_waking events"
    );

    println!("\n✓ Systing trace successfully loaded and parsed!");
}

#[test]
fn test_systing_analyzers() {
    use scxtop::mcp::perfetto_analyzer_registry::AnalyzerRegistry;

    let trace_path = "/home/hodgesd/systing/trace.pb";

    // Skip test if trace file doesn't exist
    if !Path::new(trace_path).exists() {
        eprintln!("Skipping test - systing trace not found at: {}", trace_path);
        return;
    }

    println!("Loading systing trace for analyzer testing...");
    let trace = Arc::new(
        PerfettoTrace::from_file(Path::new(trace_path)).expect("Failed to load systing trace"),
    );

    // Create analyzer registry with builtins
    let registry = AnalyzerRegistry::with_builtins();

    // Discover which analyzers can run on this trace
    let applicable_analyzers = registry.discover_analyzers(&trace);

    println!(
        "\nFound {} applicable analyzers for systing trace",
        applicable_analyzers.len()
    );

    // Run each applicable analyzer
    let mut ran_count = 0;
    for analyzer_info in &applicable_analyzers {
        println!("\nRunning analyzer: {}", analyzer_info.name);
        let result = registry.analyze_by_id(&analyzer_info.id, trace.clone());

        match result {
            Some(_) => {
                println!("  ✓ {} completed successfully", analyzer_info.name);
                ran_count += 1;
            }
            None => {
                println!("  ✗ {} not found in registry", analyzer_info.name);
            }
        }
    }

    println!(
        "\n✓ Ran {} analyzers successfully on systing trace!",
        ran_count
    );
    assert!(ran_count >= 5, "Should be able to run at least 5 analyzers on systing trace (CPU, process, latency, migration, etc.)");
}
