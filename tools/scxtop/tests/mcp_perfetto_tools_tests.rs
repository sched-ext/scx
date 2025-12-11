// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scxtop::mcp::{McpServer, McpServerConfig};
use serde_json::json;
use std::path::Path;

#[test]
#[ignore] // Requires real trace file
fn test_load_perfetto_trace_tool() {
    let trace_path = "/home/hodgesd/scx/scxtop_trace_0.proto";

    if !Path::new(trace_path).exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    // Create MCP server with trace cache
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    let trace_cache = Arc::new(Mutex::new(HashMap::new()));

    let mut server = McpServer::new(McpServerConfig::default()).with_trace_cache(trace_cache);

    // Simulate tool call
    let params = json!({
        "name": "load_perfetto_trace",
        "arguments": {
            "file_path": trace_path,
            "trace_id": "test_trace"
        }
    });

    let result = server.tools_mut().call(&params);

    assert!(result.is_ok(), "Tool call failed: {:?}", result.err());

    let response = result.unwrap();
    println!("\n=== Load Perfetto Trace Tool ===");
    println!("{}", response["content"][0]["text"]);

    // Verify response contains expected fields
    let text = response["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("Loaded perfetto trace"));
    assert!(text.contains("Trace ID: test_trace"));
    assert!(text.contains("sched_ext trace: yes"));
}

#[test]
#[ignore]
fn test_query_trace_events_tool() {
    let trace_path = "/home/hodgesd/scx/scxtop_trace_0.proto";

    if !Path::new(trace_path).exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    let trace_cache = Arc::new(Mutex::new(HashMap::new()));

    let mut server = McpServer::new(McpServerConfig::default()).with_trace_cache(trace_cache);

    // First load the trace
    let load_params = json!({
        "name": "load_perfetto_trace",
        "arguments": {
            "file_path": trace_path,
            "trace_id": "test_trace"
        }
    });
    server.tools_mut().call(&load_params).unwrap();

    // Now query events
    let query_params = json!({
        "name": "query_trace_events",
        "arguments": {
            "trace_id": "test_trace",
            "event_type": "sched_switch",
            "limit": 10
        }
    });

    let result = server.tools_mut().call(&query_params);

    assert!(result.is_ok(), "Tool call failed: {:?}", result.err());

    let response = result.unwrap();
    println!("\n=== Query Trace Events Tool ===");
    println!("{}", response["content"][0]["text"]);

    let text = response["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("Trace Query Results"));
    assert!(text.contains("Event type filter: sched_switch"));
}

#[test]
#[ignore]
fn test_analyze_cpu_utilization_tool() {
    let trace_path = "/home/hodgesd/scx/scxtop_trace_0.proto";

    if !Path::new(trace_path).exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    let trace_cache = Arc::new(Mutex::new(HashMap::new()));

    let mut server = McpServer::new(McpServerConfig::default()).with_trace_cache(trace_cache);

    // Load trace
    let load_params = json!({
        "name": "load_perfetto_trace",
        "arguments": {
            "file_path": trace_path,
            "trace_id": "test_trace"
        }
    });
    server.tools_mut().call(&load_params).unwrap();

    // Analyze CPU utilization (with multi-threading)
    let analysis_params = json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "test_trace",
            "analysis_type": "cpu_utilization",
            "use_parallel": true
        }
    });

    let result = server.tools_mut().call(&analysis_params);

    assert!(result.is_ok(), "Tool call failed: {:?}", result.err());

    let response = result.unwrap();
    println!("\n=== Analyze CPU Utilization Tool ===");
    let text = response["content"][0]["text"].as_str().unwrap();

    // Show first 1000 characters
    println!("{}", &text[..text.len().min(1000)]);

    assert!(text.contains("Analysis completed"));
    assert!(text.contains("cpu_utilization"));
    assert!(text.contains("p99_timeslice_ns"));
}

#[test]
#[ignore]
fn test_analyze_process_runtime_tool() {
    let trace_path = "/home/hodgesd/scx/scxtop_trace_0.proto";

    if !Path::new(trace_path).exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    let trace_cache = Arc::new(Mutex::new(HashMap::new()));

    let mut server = McpServer::new(McpServerConfig::default()).with_trace_cache(trace_cache);

    // Load trace
    let load_params = json!({
        "name": "load_perfetto_trace",
        "arguments": {
            "file_path": trace_path,
            "trace_id": "test_trace"
        }
    });
    server.tools_mut().call(&load_params).unwrap();

    // Analyze process runtime with limit
    let analysis_params = json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "test_trace",
            "analysis_type": "process_runtime",
            "use_parallel": true,
            "limit": 10
        }
    });

    let result = server.tools_mut().call(&analysis_params);

    assert!(result.is_ok(), "Tool call failed: {:?}", result.err());

    let response = result.unwrap();
    println!("\n=== Analyze Process Runtime Tool ===");
    println!("{}", response["content"][0]["text"]);

    let text = response["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("process_runtime"));
    assert!(text.contains("p95_timeslice_ns"));
}

#[test]
#[ignore]
fn test_analyze_wakeup_latency_tool() {
    let trace_path = "/home/hodgesd/scx/scxtop_trace_0.proto";

    if !Path::new(trace_path).exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    let trace_cache = Arc::new(Mutex::new(HashMap::new()));

    let mut server = McpServer::new(McpServerConfig::default()).with_trace_cache(trace_cache);

    // Load trace
    let load_params = json!({
        "name": "load_perfetto_trace",
        "arguments": {
            "file_path": trace_path,
            "trace_id": "test_trace"
        }
    });
    server.tools_mut().call(&load_params).unwrap();

    // Analyze wakeup latency
    let analysis_params = json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "test_trace",
            "analysis_type": "wakeup_latency"
        }
    });

    let result = server.tools_mut().call(&analysis_params);

    assert!(result.is_ok(), "Tool call failed: {:?}", result.err());

    let response = result.unwrap();
    println!("\n=== Analyze Wakeup Latency Tool ===");
    let text = response["content"][0]["text"].as_str().unwrap();
    println!("{}", &text[..text.len().min(1000)]);

    assert!(text.contains("wakeup_latency"));
    assert!(text.contains("p999_latency_ns"));
    assert!(text.contains("per_cpu_stats"));
}

#[test]
#[ignore]
fn test_full_mcp_workflow() {
    let trace_path = "/home/hodgesd/scx/scxtop_trace_0.proto";

    if !Path::new(trace_path).exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    let trace_cache = Arc::new(Mutex::new(HashMap::new()));

    let mut server = McpServer::new(McpServerConfig::default()).with_trace_cache(trace_cache);

    println!("\n=== Full MCP Perfetto Analysis Workflow ===\n");

    // Step 1: Load trace
    println!("Step 1: Loading trace...");
    let load_start = std::time::Instant::now();
    let load_result = server.tools_mut().call(&json!({
        "name": "load_perfetto_trace",
        "arguments": {
            "file_path": trace_path,
            "trace_id": "workflow_test"
        }
    }));
    assert!(load_result.is_ok());
    println!("  ✓ Loaded in {:?}", load_start.elapsed());

    // Step 2: Query events
    println!("\nStep 2: Querying sched_switch events...");
    let query_result = server.tools_mut().call(&json!({
        "name": "query_trace_events",
        "arguments": {
            "trace_id": "workflow_test",
            "event_type": "sched_switch",
            "limit": 100
        }
    }));
    assert!(query_result.is_ok());
    println!("  ✓ Query completed");

    // Step 3: CPU utilization analysis
    println!("\nStep 3: Analyzing CPU utilization (parallel)...");
    let cpu_start = std::time::Instant::now();
    let cpu_result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "workflow_test",
            "analysis_type": "cpu_utilization",
            "use_parallel": true
        }
    }));
    assert!(cpu_result.is_ok());
    println!("  ✓ Analyzed in {:?}", cpu_start.elapsed());

    // Step 4: Process runtime analysis
    println!("\nStep 4: Analyzing process runtime (parallel)...");
    let proc_start = std::time::Instant::now();
    let proc_result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "workflow_test",
            "analysis_type": "process_runtime",
            "use_parallel": true,
            "limit": 20
        }
    }));
    assert!(proc_result.is_ok());
    println!("  ✓ Analyzed in {:?}", proc_start.elapsed());

    // Step 5: Wakeup latency analysis
    println!("\nStep 5: Analyzing wakeup latency...");
    let wakeup_start = std::time::Instant::now();
    let wakeup_result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "workflow_test",
            "analysis_type": "wakeup_latency"
        }
    }));
    assert!(wakeup_result.is_ok());
    println!("  ✓ Analyzed in {:?}", wakeup_start.elapsed());

    // Step 6: Migration analysis
    println!("\nStep 6: Analyzing migration patterns...");
    let migration_start = std::time::Instant::now();
    let migration_result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "workflow_test",
            "analysis_type": "migration_patterns"
        }
    }));
    assert!(migration_result.is_ok());
    println!("  ✓ Analyzed in {:?}", migration_start.elapsed());

    // Step 7: DSQ summary
    println!("\nStep 7: Getting DSQ summary...");
    let dsq_result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "workflow_test",
            "analysis_type": "dsq_summary"
        }
    }));
    assert!(dsq_result.is_ok());
    println!("  ✓ Completed");

    println!("\n=== All MCP tools working successfully! ===");
}
