use serde_json::Value;

use scx_simulator::*;

#[macro_use]
mod common;

#[test]
fn test_perfetto_json_structure() {
    let _lock = common::setup_test();
    let scenario = Scenario::builder()
        .cpus(2)
        .instant_timing()
        .add_task(
            "worker-0",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(5_000_000), Phase::Sleep(5_000_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .add_task(
            "worker-1",
            0,
            TaskBehavior {
                phases: vec![Phase::Run(10_000_000)],
                repeat: RepeatMode::Forever,
            },
        )
        .duration_ms(50)
        .build();

    let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);

    let mut buf = Vec::new();
    trace
        .write_perfetto_json(&mut buf)
        .expect("write_perfetto_json failed");

    // Must be valid JSON
    let parsed: Value = serde_json::from_slice(&buf).expect("invalid JSON output");

    // Must have traceEvents array
    let events = parsed["traceEvents"]
        .as_array()
        .expect("traceEvents is not an array");
    assert!(!events.is_empty(), "traceEvents should not be empty");

    // Check metadata events exist (process_name + thread_name for each CPU)
    let meta_events: Vec<&Value> = events.iter().filter(|e| e["ph"] == "M").collect();
    // 2 CPUs × 2 metadata events (process_name + thread_name) = 4
    assert!(
        meta_events.len() >= 4,
        "expected at least 4 metadata events, got {}",
        meta_events.len()
    );

    // Check that process names are "CPU 0" and "CPU 1"
    let process_names: Vec<&str> = meta_events
        .iter()
        .filter(|e| e["name"] == "process_name")
        .filter_map(|e| e["args"]["name"].as_str())
        .collect();
    assert!(
        process_names.contains(&"CPU 0"),
        "missing CPU 0 process name"
    );
    assert!(
        process_names.contains(&"CPU 1"),
        "missing CPU 1 process name"
    );

    // Check B/E pairs exist
    let begin_count = events.iter().filter(|e| e["ph"] == "B").count();
    let end_count = events.iter().filter(|e| e["ph"] == "E").count();
    assert!(begin_count > 0, "no begin (B) events found");
    assert!(end_count > 0, "no end (E) events found");
    assert_eq!(
        begin_count, end_count,
        "B/E event count mismatch: {begin_count} begins vs {end_count} ends"
    );

    // All timestamps must be non-negative integers
    for event in events {
        if let Some(ts) = event.get("ts") {
            assert!(
                ts.is_u64() || ts.is_i64(),
                "timestamp is not an integer: {ts}"
            );
            let ts_val = ts.as_i64().unwrap_or(-1);
            assert!(ts_val >= 0, "negative timestamp: {ts_val}");
        }
    }

    // B events should have task names (not empty)
    for event in events.iter().filter(|e| e["ph"] == "B") {
        let name = event["name"].as_str().unwrap_or("");
        assert!(!name.is_empty(), "B event has empty name");
        assert_ne!(name, "???", "B event has unresolved task name");
    }

    // Check instant events exist (ops/kfunc categories)
    let instant_count = events.iter().filter(|e| e["ph"] == "i").count();
    assert!(instant_count > 0, "no instant (i) events found");
}
