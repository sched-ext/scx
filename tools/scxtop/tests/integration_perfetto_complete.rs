// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Complete end-to-end integration test for perfetto trace analysis

use scxtop::mcp::{McpServer, McpServerConfig};
use serde_json::json;
use std::path::Path;

#[test]
#[ignore] // Long-running integration test
fn test_complete_perfetto_analysis_workflow() {
    let trace_path = "/home/hodgesd/scx/scxtop_trace_0.proto";

    if !Path::new(trace_path).exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  COMPREHENSIVE PERFETTO TRACE ANALYSIS INTEGRATION TEST  ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    // Setup
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    let trace_cache = Arc::new(Mutex::new(HashMap::new()));
    let mut server = McpServer::new(McpServerConfig::default()).with_trace_cache(trace_cache);

    let mut total_time = std::time::Duration::ZERO;

    // Test 1: Load trace
    println!("📂 Test 1: Loading trace file...");
    let start = std::time::Instant::now();
    let result = server.tools_mut().call(&json!({
        "name": "load_perfetto_trace",
        "arguments": {
            "file_path": trace_path,
            "trace_id": "integration_test"
        }
    }));
    assert!(result.is_ok(), "Failed to load trace: {:?}", result.err());
    let elapsed = start.elapsed();
    total_time += elapsed;
    println!("   ✓ Loaded in {:?}", elapsed);
    println!("   Response: {}\n", result.unwrap()["content"][0]["text"]);

    // Test 2: Query events by type
    println!("🔍 Test 2: Querying sched_switch events...");
    let start = std::time::Instant::now();
    let result = server.tools_mut().call(&json!({
        "name": "query_trace_events",
        "arguments": {
            "trace_id": "integration_test",
            "event_type": "sched_switch",
            "limit": 10
        }
    }));
    assert!(result.is_ok(), "Failed to query events: {:?}", result.err());
    let elapsed = start.elapsed();
    total_time += elapsed;
    println!("   ✓ Queried in {:?}\n", elapsed);

    // Test 3: CPU utilization (parallel)
    println!("💻 Test 3: Analyzing CPU utilization (multi-threaded)...");
    let start = std::time::Instant::now();
    let result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "integration_test",
            "analysis_type": "cpu_utilization",
            "use_parallel": true
        }
    }));
    assert!(result.is_ok(), "Failed CPU analysis: {:?}", result.err());
    let elapsed = start.elapsed();
    total_time += elapsed;
    println!("   ✓ Analyzed in {:?}", elapsed);
    let response = result.unwrap();
    let text = response["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("p99_timeslice_ns"));
    println!("   ✓ Verified percentile stats present\n");

    // Test 4: Process runtime (parallel)
    println!("📊 Test 4: Analyzing process runtime (multi-threaded)...");
    let start = std::time::Instant::now();
    let result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "integration_test",
            "analysis_type": "process_runtime",
            "use_parallel": true,
            "limit": 20
        }
    }));
    assert!(
        result.is_ok(),
        "Failed process analysis: {:?}",
        result.err()
    );
    let elapsed = start.elapsed();
    total_time += elapsed;
    println!("   ✓ Analyzed in {:?}\n", elapsed);

    // Test 5: Wakeup latency
    println!("⏰ Test 5: Analyzing wakeup latency...");
    let start = std::time::Instant::now();
    let result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "integration_test",
            "analysis_type": "wakeup_latency"
        }
    }));
    assert!(result.is_ok(), "Failed wakeup analysis: {:?}", result.err());
    let elapsed = start.elapsed();
    total_time += elapsed;
    println!("   ✓ Analyzed in {:?}", elapsed);
    let response = result.unwrap();
    let text = response["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("p999_latency_ns"));
    println!("   ✓ Verified p999 percentile present\n");

    // Test 6: Migration patterns
    println!("🔄 Test 6: Analyzing migration patterns...");
    let start = std::time::Instant::now();
    let result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "integration_test",
            "analysis_type": "migration_patterns"
        }
    }));
    assert!(
        result.is_ok(),
        "Failed migration analysis: {:?}",
        result.err()
    );
    let elapsed = start.elapsed();
    total_time += elapsed;
    println!("   ✓ Analyzed in {:?}\n", elapsed);

    // Test 7: DSQ summary (sched_ext)
    println!("🎯 Test 7: Getting DSQ summary...");
    let start = std::time::Instant::now();
    let result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "integration_test",
            "analysis_type": "dsq_summary"
        }
    }));
    assert!(result.is_ok(), "Failed DSQ analysis: {:?}", result.err());
    let elapsed = start.elapsed();
    total_time += elapsed;
    println!("   ✓ Analyzed in {:?}", elapsed);
    let response = result.unwrap();
    let text = response["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("dsq_summary") || text.contains("sched_ext"));
    println!("   ✓ DSQ data extracted\n");

    // Test 8: Process timeline
    println!("📅 Test 8: Getting process timeline...");
    let start = std::time::Instant::now();
    let result = server.tools_mut().call(&json!({
        "name": "get_process_timeline",
        "arguments": {
            "trace_id": "integration_test",
            "pid": 2952187
        }
    }));
    assert!(result.is_ok(), "Failed timeline query: {:?}", result.err());
    let elapsed = start.elapsed();
    total_time += elapsed;
    println!("   ✓ Retrieved in {:?}\n", elapsed);

    // Test 9: CPU timeline
    println!("🖥️  Test 9: Getting CPU timeline...");
    let start = std::time::Instant::now();
    let result = server.tools_mut().call(&json!({
        "name": "get_cpu_timeline",
        "arguments": {
            "trace_id": "integration_test",
            "cpu": 0
        }
    }));
    assert!(result.is_ok(), "Failed CPU timeline: {:?}", result.err());
    let elapsed = start.elapsed();
    total_time += elapsed;
    println!("   ✓ Retrieved in {:?}\n", elapsed);

    // Test 10: Bottleneck detection
    println!("🔍 Test 10: Detecting scheduling bottlenecks...");
    let start = std::time::Instant::now();
    let result = server.tools_mut().call(&json!({
        "name": "find_scheduling_bottlenecks",
        "arguments": {
            "trace_id": "integration_test",
            "limit": 5
        }
    }));
    assert!(
        result.is_ok(),
        "Failed bottleneck detection: {:?}",
        result.err()
    );
    let elapsed = start.elapsed();
    total_time += elapsed;
    println!("   ✓ Detected in {:?}", elapsed);
    let response = result.unwrap();
    let text = response["content"][0]["text"].as_str().unwrap();
    println!(
        "   Bottlenecks: {}",
        text.lines().take(5).collect::<Vec<_>>().join("\n   ")
    );
    println!();

    // Test 11: Wakeup→Schedule correlation
    println!("🔗 Test 11: Correlating wakeup→schedule events...");
    let start = std::time::Instant::now();
    let result = server.tools_mut().call(&json!({
        "name": "correlate_wakeup_to_schedule",
        "arguments": {
            "trace_id": "integration_test",
            "limit": 20
        }
    }));
    assert!(result.is_ok(), "Failed correlation: {:?}", result.err());
    let elapsed = start.elapsed();
    total_time += elapsed;
    println!("   ✓ Correlated in {:?}\n", elapsed);

    // Test 12: Export comprehensive analysis
    println!("💾 Test 12: Exporting comprehensive analysis...");
    let output_path = "/tmp/scxtop_integration_test_export.json";
    let start = std::time::Instant::now();
    let result = server.tools_mut().call(&json!({
        "name": "export_trace_analysis",
        "arguments": {
            "trace_id": "integration_test",
            "output_path": output_path
        }
    }));
    assert!(result.is_ok(), "Failed export: {:?}", result.err());
    let elapsed = start.elapsed();
    total_time += elapsed;
    println!("   ✓ Exported in {:?}", elapsed);

    // Verify export file exists and is valid JSON
    assert!(Path::new(output_path).exists(), "Export file not created");
    let export_content = std::fs::read_to_string(output_path).unwrap();
    let export_json: serde_json::Value = serde_json::from_str(&export_content).unwrap();
    println!("   ✓ Export file valid: {} bytes", export_content.len());
    println!(
        "   ✓ Contains {} analysis sections",
        export_json.as_object().unwrap().len() - 6
    );
    println!();

    // Final Summary
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║                    TEST SUMMARY                          ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("  Total tests: 12");
    println!("  All tests: ✓ PASSED");
    println!("  Total time (excluding trace load): {:?}", total_time);
    println!("  Export file: {}", output_path);
    println!("\n✨ All perfetto trace analysis features working correctly! ✨\n");
}
