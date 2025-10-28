// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scx_utils::Topology;
use scxtop::mcp::{McpTools, SharedPerfProfiler};
use serde_json::json;

/// Helper function to get system topology for testing
/// Returns None if topology cannot be loaded (e.g., in restricted environments)
fn try_create_test_topology() -> Option<Topology> {
    Topology::new().ok()
}

#[test]
fn test_mcp_tools_new() {
    let tools = McpTools::new();
    // Should create successfully
    drop(tools);
}

#[test]
fn test_mcp_tools_default() {
    let tools = McpTools::default();
    drop(tools);
}

#[test]
fn test_mcp_tools_list() {
    let tools = McpTools::new();
    let result = tools.list();

    assert!(result["tools"].is_array());
    let tools_array = result["tools"].as_array().unwrap();

    // Should have the expected tools
    let tool_names: Vec<String> = tools_array
        .iter()
        .filter_map(|t| t["name"].as_str().map(|s| s.to_string()))
        .collect();

    assert!(tool_names.contains(&"query_stats".to_string()));
    assert!(tool_names.contains(&"get_topology".to_string()));
    assert!(tool_names.contains(&"list_events".to_string()));
    assert!(tool_names.contains(&"start_perf_profiling".to_string()));
    assert!(tool_names.contains(&"stop_perf_profiling".to_string()));
    assert!(tool_names.contains(&"get_perf_results".to_string()));
}

#[test]
fn test_mcp_tools_list_has_proper_schema() {
    let tools = McpTools::new();
    let result = tools.list();

    let tools_array = result["tools"].as_array().unwrap();

    for tool in tools_array {
        assert!(tool["name"].is_string());
        assert!(tool["description"].is_string());
        // inputSchema should exist (can be object or other valid JSON Schema type)
        assert!(!tool["inputSchema"].is_null());
        // Most schemas should be objects with type and properties
        if tool["inputSchema"].is_object() {
            assert!(
                tool["inputSchema"]["type"].is_string() || tool["inputSchema"]["type"].is_null()
            );
        }
    }
}

#[test]
fn test_tool_query_stats_no_args() {
    let mut tools = McpTools::new();
    let params = json!({
        "name": "query_stats",
        "arguments": {}
    });

    let result = tools.call(&params);
    assert!(result.is_ok());

    let value = result.unwrap();
    assert!(value["content"].is_array());

    let content = &value["content"][0];
    assert_eq!(content["type"], "text");

    let text = content["text"].as_str().unwrap();
    assert!(text.contains("Available statistics resources"));
    assert!(text.contains("stats://aggregated/cpu"));
    assert!(text.contains("stats://aggregated/llc"));
}

#[test]
fn test_tool_query_stats_cpu() {
    let mut tools = McpTools::new();
    let params = json!({
        "name": "query_stats",
        "arguments": {
            "stat_type": "cpu"
        }
    });

    let result = tools.call(&params);
    assert!(result.is_ok());

    let value = result.unwrap();
    let text = value["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("Statistics resources for cpu"));
    assert!(text.contains("stats://aggregated/cpu"));
    assert!(text.contains("stats://system/cpu"));
}

#[test]
fn test_tool_query_stats_llc() {
    let mut tools = McpTools::new();
    let params = json!({
        "name": "query_stats",
        "arguments": {
            "stat_type": "llc"
        }
    });

    let result = tools.call(&params);
    assert!(result.is_ok());

    let value = result.unwrap();
    let text = value["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("Statistics resources for llc"));
    assert!(text.contains("stats://aggregated/llc"));
}

#[test]
fn test_tool_query_stats_invalid_type() {
    let mut tools = McpTools::new();
    let params = json!({
        "name": "query_stats",
        "arguments": {
            "stat_type": "invalid_type"
        }
    });

    let result = tools.call(&params);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Unknown stat_type"));
}

#[test]
fn test_tool_get_topology_without_topology_set() {
    let mut tools = McpTools::new();
    let params = json!({
        "name": "get_topology",
        "arguments": {}
    });

    let result = tools.call(&params);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "Topology not available");
}

#[test]
fn test_tool_get_topology_summary() {
    let Some(topology) = try_create_test_topology() else {
        // Skip test if topology is unavailable
        return;
    };

    let mut tools = McpTools::new();
    tools.set_topology(std::sync::Arc::new(topology));

    let params = json!({
        "name": "get_topology",
        "arguments": {
            "detail_level": "summary"
        }
    });

    let result = tools.call(&params);
    assert!(result.is_ok());

    let value = result.unwrap();
    let text = value["content"][0]["text"].as_str().unwrap();

    // Should be JSON containing summary
    let summary: serde_json::Value = serde_json::from_str(text).unwrap();
    assert!(summary["summary"].is_object());
    assert!(summary["summary"]["total_cpus"].is_number());
}

#[test]
fn test_tool_get_topology_full() {
    let Some(topology) = try_create_test_topology() else {
        // Skip test if topology is unavailable
        return;
    };

    let mut tools = McpTools::new();
    tools.set_topology(std::sync::Arc::new(topology));

    let params = json!({
        "name": "get_topology",
        "arguments": {
            "detail_level": "full"
        }
    });

    let result = tools.call(&params);
    assert!(result.is_ok());

    let value = result.unwrap();
    let text = value["content"][0]["text"].as_str().unwrap();

    // Should contain detailed topology
    let topo: serde_json::Value = serde_json::from_str(text).unwrap();
    assert!(topo["cpus"].is_array());
    assert!(!topo["cpus"].as_array().unwrap().is_empty());
}

#[test]
fn test_tool_list_events_without_subsystem() {
    let mut tools = McpTools::new();
    let params = json!({
        "name": "list_events",
        "arguments": {
            "event_type": "perf"
        }
    });

    // Should fail without subsystem
    let result = tools.call(&params);
    assert!(result.is_err());
}

#[test]
fn test_tool_start_perf_profiling_without_profiler() {
    let mut tools = McpTools::new();
    let params = json!({
        "name": "start_perf_profiling",
        "arguments": {}
    });

    let result = tools.call(&params);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Perf profiler not available"
    );
}

#[test]
fn test_tool_start_perf_profiling_with_default_args() {
    let mut tools = McpTools::new();

    let profiler = SharedPerfProfiler::new();
    tools.set_perf_profiler(profiler.clone());

    let params = json!({
        "name": "start_perf_profiling",
        "arguments": {}
    });

    let result = tools.call(&params);
    assert!(result.is_ok());
}

#[test]
fn test_tool_stop_perf_profiling_without_profiler() {
    let mut tools = McpTools::new();
    let params = json!({
        "name": "stop_perf_profiling",
        "arguments": {}
    });

    let result = tools.call(&params);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Perf profiler not available"
    );
}

#[test]
fn test_tool_get_perf_results_without_profiler() {
    let mut tools = McpTools::new();
    let params = json!({
        "name": "get_perf_results",
        "arguments": {}
    });

    let result = tools.call(&params);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Perf profiler not available"
    );
}

#[test]
fn test_tool_get_perf_results() {
    let mut tools = McpTools::new();

    let profiler = SharedPerfProfiler::new();
    tools.set_perf_profiler(profiler.clone());

    let params = json!({
        "name": "get_perf_results",
        "arguments": {
            "limit": 10,
            "include_stacks": false
        }
    });

    let result = tools.call(&params);
    assert!(result.is_ok());

    let value = result.unwrap();
    assert!(value["content"].is_array());
}

#[test]
fn test_tool_call_unknown_tool() {
    let mut tools = McpTools::new();
    let params = json!({
        "name": "unknown_tool",
        "arguments": {}
    });

    let result = tools.call(&params);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Unknown tool"));
}

#[test]
fn test_tool_call_missing_name() {
    let mut tools = McpTools::new();
    let params = json!({
        "arguments": {}
    });

    let result = tools.call(&params);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "Missing tool name");
}

#[test]
fn test_set_topology() {
    let Some(topology) = try_create_test_topology() else {
        // Skip test if topology is unavailable
        return;
    };

    let mut tools = McpTools::new();
    tools.set_topology(std::sync::Arc::new(topology));

    // Should be able to call topology tool now
    let params = json!({
        "name": "get_topology",
        "arguments": {}
    });

    let result = tools.call(&params);
    assert!(result.is_ok());
}
