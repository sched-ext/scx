// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! MCP tool tests for extended scheduler analyses

use scxtop::mcp::{McpServer, McpServerConfig};
use serde_json::json;
use std::path::Path;

#[test]
#[ignore]
fn test_task_states_via_mcp() {
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
    server
        .tools_mut()
        .call(&json!({
            "name": "load_perfetto_trace",
            "arguments": {
                "file_path": trace_path,
                "trace_id": "test"
            }
        }))
        .unwrap();

    // Analyze task states
    let result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "test",
            "analysis_type": "task_states",
            "limit": 10
        }
    }));

    assert!(result.is_ok(), "Failed: {:?}", result.err());

    let response = result.unwrap();
    let text = response["content"][0]["text"].as_str().unwrap();

    println!("\n=== Task States via MCP ===");
    println!("{}", &text[..text.len().min(1500)]);

    assert!(text.contains("task_states"));
    assert!(text.contains("scheduler_latency"));
    assert!(text.contains("voluntary_switches"));
}

#[test]
#[ignore]
fn test_preemptions_via_mcp() {
    let trace_path = "/home/hodgesd/scx/scxtop_trace_0.proto";

    if !Path::new(trace_path).exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    let trace_cache = Arc::new(Mutex::new(HashMap::new()));
    let mut server = McpServer::new(McpServerConfig::default()).with_trace_cache(trace_cache);

    server
        .tools_mut()
        .call(&json!({
            "name": "load_perfetto_trace",
            "arguments": {
                "file_path": trace_path,
                "trace_id": "test"
            }
        }))
        .unwrap();

    let result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "test",
            "analysis_type": "preemptions",
            "limit": 10
        }
    }));

    assert!(result.is_ok(), "Failed: {:?}", result.err());

    let response = result.unwrap();
    let text = response["content"][0]["text"].as_str().unwrap();

    println!("\n=== Preemptions via MCP ===");
    println!("{}", &text[..text.len().min(1000)]);

    assert!(text.contains("preemptions"));
    assert!(text.contains("preempted_by"));
}

#[test]
#[ignore]
fn test_wakeup_chains_via_mcp() {
    let trace_path = "/home/hodgesd/scx/scxtop_trace_0.proto";

    if !Path::new(trace_path).exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    let trace_cache = Arc::new(Mutex::new(HashMap::new()));
    let mut server = McpServer::new(McpServerConfig::default()).with_trace_cache(trace_cache);

    server
        .tools_mut()
        .call(&json!({
            "name": "load_perfetto_trace",
            "arguments": {
                "file_path": trace_path,
                "trace_id": "test"
            }
        }))
        .unwrap();

    let result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "test",
            "analysis_type": "wakeup_chains",
            "limit": 5
        }
    }));

    assert!(result.is_ok(), "Failed: {:?}", result.err());

    let response = result.unwrap();
    let text = response["content"][0]["text"].as_str().unwrap();

    println!("\n=== Wakeup Chains via MCP ===");
    println!("{}", &text[..text.len().min(1000)]);

    assert!(text.contains("wakeup_chains"));
    assert!(text.contains("criticality_score"));
}

#[test]
#[ignore]
fn test_latency_breakdown_via_mcp() {
    let trace_path = "/home/hodgesd/scx/scxtop_trace_0.proto";

    if !Path::new(trace_path).exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    let trace_cache = Arc::new(Mutex::new(HashMap::new()));
    let mut server = McpServer::new(McpServerConfig::default()).with_trace_cache(trace_cache);

    server
        .tools_mut()
        .call(&json!({
            "name": "load_perfetto_trace",
            "arguments": {
                "file_path": trace_path,
                "trace_id": "test"
            }
        }))
        .unwrap();

    let result = server.tools_mut().call(&json!({
        "name": "analyze_trace_scheduling",
        "arguments": {
            "trace_id": "test",
            "analysis_type": "latency_breakdown"
        }
    }));

    assert!(result.is_ok(), "Failed: {:?}", result.err());

    let response = result.unwrap();
    let text = response["content"][0]["text"].as_str().unwrap();

    println!("\n=== Latency Breakdown via MCP ===");
    println!("{}", text);

    assert!(text.contains("latency_breakdown"));
    assert!(text.contains("waking_to_wakeup"));
    assert!(text.contains("wakeup_to_schedule"));
    assert!(text.contains("percent_of_total"));
}

#[test]
#[ignore]
fn test_export_with_extended_analyses() {
    let trace_path = "/home/hodgesd/scx/scxtop_trace_0.proto";

    if !Path::new(trace_path).exists() {
        eprintln!("Trace file not found, skipping test");
        return;
    }

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    let trace_cache = Arc::new(Mutex::new(HashMap::new()));
    let mut server = McpServer::new(McpServerConfig::default()).with_trace_cache(trace_cache);

    server
        .tools_mut()
        .call(&json!({
            "name": "load_perfetto_trace",
            "arguments": {
                "file_path": trace_path,
                "trace_id": "test"
            }
        }))
        .unwrap();

    let output_path = "/tmp/extended_analysis_export.json";

    let result = server.tools_mut().call(&json!({
        "name": "export_trace_analysis",
        "arguments": {
            "trace_id": "test",
            "output_path": output_path,
            "analysis_types": [
                "task_states",
                "preemptions",
                "wakeup_chains",
                "latency_breakdown"
            ]
        }
    }));

    assert!(result.is_ok(), "Failed: {:?}", result.err());

    // Verify file exists
    assert!(Path::new(output_path).exists());

    // Verify valid JSON with expected fields
    let content = std::fs::read_to_string(output_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();

    println!("\n=== Export Extended Analyses ===");
    println!("File size: {} bytes", content.len());
    println!("Analyses included:");
    println!("  - task_states: {}", json["task_states"].is_array());
    println!("  - preemptions: {}", json["preemptions"].is_array());
    println!("  - wakeup_chains: {}", json["wakeup_chains"].is_array());
    println!(
        "  - latency_breakdown: {}",
        json["latency_breakdown"].is_object()
    );

    assert!(json["task_states"].is_array());
    assert!(json["preemptions"].is_array());
    assert!(json["wakeup_chains"].is_array());
    assert!(json["latency_breakdown"].is_object());
}
