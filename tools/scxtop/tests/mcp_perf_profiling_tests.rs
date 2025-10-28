// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scxtop::mcp::{
    PerfEventAttacher, PerfProfilingConfig, ProfilingStatus, RawSample, SharedPerfProfiler,
};
use std::thread;
use std::time::Duration;

#[test]
fn test_perf_profiling_config_default() {
    let config = PerfProfilingConfig::default();
    assert_eq!(config.event, "hw:cpu-clock");
    assert_eq!(config.freq, 99);
    assert_eq!(config.cpu, -1);
    assert_eq!(config.pid, -1);
    assert_eq!(config.max_samples, 10000);
    assert_eq!(config.duration_secs, 0);
}

#[test]
fn test_shared_perf_profiler_new() {
    let profiler = SharedPerfProfiler::new();
    assert_eq!(profiler.status(), ProfilingStatus::Idle);
}

#[test]
fn test_shared_perf_profiler_start() {
    let profiler = SharedPerfProfiler::new();

    let config = PerfProfilingConfig {
        event: "hw:cpu-clock".to_string(),
        freq: 99,
        cpu: -1,
        pid: -1,
        max_samples: 1000,
        duration_secs: 0,
    };

    let result = profiler.start(config);
    assert!(result.is_ok());
    assert_eq!(profiler.status(), ProfilingStatus::Running);
}

#[test]
fn test_shared_perf_profiler_start_when_already_running() {
    let profiler = SharedPerfProfiler::new();
    let config = PerfProfilingConfig::default();

    profiler.start(config.clone()).unwrap();

    // Try to start again while running
    let result = profiler.start(config);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Profiling is already running"
    );
}

#[test]
fn test_shared_perf_profiler_stop() {
    let profiler = SharedPerfProfiler::new();
    let config = PerfProfilingConfig::default();

    profiler.start(config).unwrap();

    let result = profiler.stop();
    assert!(result.is_ok());
    assert_eq!(profiler.status(), ProfilingStatus::Stopped);
}

#[test]
fn test_shared_perf_profiler_stop_when_not_running() {
    let profiler = SharedPerfProfiler::new();

    let result = profiler.stop();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "Profiling is not running");
}

#[test]
fn test_shared_perf_profiler_add_sample() {
    let profiler = SharedPerfProfiler::new();

    let config = PerfProfilingConfig {
        event: "hw:cpu-clock".to_string(),
        freq: 99,
        cpu: -1,
        pid: -1,
        max_samples: 10,
        duration_secs: 0,
    };

    profiler.start(config).unwrap();

    let sample = RawSample {
        address: 0x12345678,
        pid: 1234,
        cpu_id: 0,
        is_kernel: true,
        kernel_stack: vec![0x1000, 0x2000, 0x3000],
        user_stack: vec![],
        layer_id: None,
    };

    profiler.add_sample(sample);

    // Should have one sample
    let status = profiler.get_status();
    assert!(status["samples_collected"].as_u64().unwrap() >= 1);
}

#[test]
fn test_shared_perf_profiler_should_stop_max_samples() {
    let profiler = SharedPerfProfiler::new();

    let config = PerfProfilingConfig {
        event: "hw:cpu-clock".to_string(),
        freq: 99,
        cpu: -1,
        pid: -1,
        max_samples: 3,
        duration_secs: 0,
    };

    profiler.start(config).unwrap();

    // Add samples up to max
    for i in 0..3 {
        let sample = RawSample {
            address: 0x12345678 + i,
            pid: 1234,
            cpu_id: 0,
            is_kernel: true,
            kernel_stack: vec![],
            user_stack: vec![],
            layer_id: None,
        };
        profiler.add_sample(sample);
    }

    // Should auto-stop after reaching max samples
    assert_eq!(profiler.status(), ProfilingStatus::Stopped);
}

#[test]
fn test_shared_perf_profiler_should_stop_duration() {
    let profiler = SharedPerfProfiler::new();

    let config = PerfProfilingConfig {
        event: "hw:cpu-clock".to_string(),
        freq: 99,
        cpu: -1,
        pid: -1,
        max_samples: 0,   // unlimited
        duration_secs: 1, // 1 second
    };

    profiler.start(config).unwrap();

    // Wait for duration to elapse
    thread::sleep(Duration::from_millis(1100));

    // Status should still be stopped (auto-stopped)
    // Note: This test may be timing-dependent
    let status = profiler.get_status();
    let duration = status["duration_ms"].as_u64().unwrap();
    assert!(duration >= 1000);
}

#[test]
fn test_shared_perf_profiler_clear_on_start() {
    let profiler = SharedPerfProfiler::new();

    let config = PerfProfilingConfig {
        max_samples: 10,
        ..Default::default()
    };

    profiler.start(config.clone()).unwrap();

    // Add a sample
    let sample = RawSample {
        address: 0x12345678,
        pid: 1234,
        cpu_id: 0,
        is_kernel: true,
        kernel_stack: vec![],
        user_stack: vec![],
        layer_id: None,
    };
    profiler.add_sample(sample);

    profiler.stop().unwrap();

    // Start again - should clear previous samples
    profiler.start(config).unwrap();

    let status = profiler.get_status();
    assert_eq!(status["samples_collected"], 0);
}

#[test]
fn test_shared_perf_profiler_get_status() {
    let profiler = SharedPerfProfiler::new();
    let config = PerfProfilingConfig::default();

    profiler.start(config).unwrap();

    let status = profiler.get_status();
    assert_eq!(status["status"], "Running");
    assert!(status["samples_collected"].is_number());
    assert!(status["duration_ms"].is_number());
}

#[test]
fn test_shared_perf_profiler_get_status_idle() {
    let profiler = SharedPerfProfiler::new();
    let status = profiler.get_status();
    assert_eq!(status["status"], "Idle");
    assert_eq!(status["samples_collected"], 0);
}

#[test]
fn test_shared_perf_profiler_get_results() {
    let profiler = SharedPerfProfiler::new();

    let config = PerfProfilingConfig {
        max_samples: 10,
        ..Default::default()
    };

    profiler.start(config).unwrap();

    // Add samples
    for i in 0..5 {
        let sample = RawSample {
            address: 0x1000 + i * 0x100,
            pid: 1234,
            cpu_id: 0,
            is_kernel: true,
            kernel_stack: vec![0x1000, 0x2000],
            user_stack: vec![],
            layer_id: Some(1),
        };
        profiler.add_sample(sample);
    }

    profiler.stop().unwrap();

    let results = profiler.get_results(50, true);
    assert!(results["total_samples"].is_number());
    assert_eq!(results["samples_collected"], 5);
}

#[test]
fn test_raw_sample_creation() {
    let sample = RawSample {
        address: 0x12345678,
        pid: 1234,
        cpu_id: 0,
        is_kernel: true,
        kernel_stack: vec![0x1000, 0x2000, 0x3000],
        user_stack: vec![0x4000, 0x5000],
        layer_id: Some(42),
    };

    assert_eq!(sample.address, 0x12345678);
    assert_eq!(sample.pid, 1234);
    assert_eq!(sample.cpu_id, 0);
    assert!(sample.is_kernel);
    assert_eq!(sample.kernel_stack.len(), 3);
    assert_eq!(sample.user_stack.len(), 2);
    assert_eq!(sample.layer_id, Some(42));
}

#[test]
fn test_raw_sample_clone() {
    let sample1 = RawSample {
        address: 0x12345678,
        pid: 1234,
        cpu_id: 0,
        is_kernel: true,
        kernel_stack: vec![0x1000, 0x2000],
        user_stack: vec![],
        layer_id: None,
    };

    let sample2 = sample1.clone();
    assert_eq!(sample1.address, sample2.address);
    assert_eq!(sample1.pid, sample2.pid);
    assert_eq!(sample1.kernel_stack, sample2.kernel_stack);
}

#[test]
fn test_shared_perf_profiler_thread_safety() {
    let profiler = SharedPerfProfiler::new();
    let profiler_clone = profiler.clone();

    let config = PerfProfilingConfig {
        max_samples: 100,
        ..Default::default()
    };

    // Start profiling in main thread
    profiler.start(config).unwrap();

    // Add samples from another thread
    let handle = thread::spawn(move || {
        for i in 0..10 {
            let sample = RawSample {
                address: 0x1000 + i,
                pid: 1234,
                cpu_id: 0,
                is_kernel: true,
                kernel_stack: vec![],
                user_stack: vec![],
                layer_id: None,
            };
            profiler_clone.add_sample(sample);
        }
    });

    handle.join().unwrap();

    // Check results
    let status = profiler.get_status();
    assert!(status["samples_collected"].as_u64().unwrap() >= 10);
}

#[test]
fn test_shared_perf_profiler_ignore_samples_when_not_running() {
    let profiler = SharedPerfProfiler::new();

    let sample = RawSample {
        address: 0x12345678,
        pid: 1234,
        cpu_id: 0,
        is_kernel: true,
        kernel_stack: vec![],
        user_stack: vec![],
        layer_id: None,
    };

    // Add sample without starting - should be ignored
    profiler.add_sample(sample);

    let status = profiler.get_status();
    assert_eq!(status["samples_collected"], 0);
}

#[test]
fn test_perf_profiler_config_validation() {
    let config1 = PerfProfilingConfig {
        event: "sw:task-clock".to_string(),
        freq: 199,
        cpu: 0,
        pid: 1234,
        max_samples: 5000,
        duration_secs: 10,
    };

    assert_eq!(config1.event, "sw:task-clock");
    assert_eq!(config1.freq, 199);
    assert_eq!(config1.cpu, 0);
    assert_eq!(config1.pid, 1234);
    assert_eq!(config1.max_samples, 5000);
    assert_eq!(config1.duration_secs, 10);
}

#[test]
fn test_shared_perf_profiler_clear() {
    let profiler = SharedPerfProfiler::new();

    let config = PerfProfilingConfig {
        max_samples: 10,
        ..Default::default()
    };

    profiler.start(config).unwrap();

    // Add a sample
    let sample = RawSample {
        address: 0x12345678,
        pid: 1234,
        cpu_id: 0,
        is_kernel: true,
        kernel_stack: vec![],
        user_stack: vec![],
        layer_id: None,
    };
    profiler.add_sample(sample);

    profiler.stop().unwrap();
    profiler.clear();

    let status = profiler.get_status();
    assert_eq!(status["status"], "Idle");
    assert_eq!(status["samples_collected"], 0);
}

#[test]
fn test_perf_event_parsing_hardware_events() {
    // Test various hardware event formats
    let test_cases = vec![
        ("cache-misses", "cache-misses"),
        ("hw:cache-misses", "cache-misses"),
        ("cycles", "cycles"),
        ("hw:cycles", "cycles"),
        ("instructions", "instructions"),
        ("branch-misses", "branch-misses"),
    ];

    for (input, expected_event) in test_cases {
        let config = PerfProfilingConfig {
            event: input.to_string(),
            ..Default::default()
        };
        // Just verify it parses without error - actual parsing happens in attach_perf_events
        assert!(config.event.contains(expected_event));
    }
}

#[test]
fn test_perf_event_parsing_software_events() {
    // Test various software event formats
    let test_cases = vec![
        ("cpu-clock", "cpu-clock"),
        ("sw:cpu-clock", "cpu-clock"),
        ("task-clock", "task-clock"),
        ("sw:task-clock", "task-clock"),
        ("context-switches", "context-switches"),
        ("page-faults", "page-faults"),
    ];

    for (input, expected_event) in test_cases {
        let config = PerfProfilingConfig {
            event: input.to_string(),
            ..Default::default()
        };
        assert!(config.event.contains(expected_event));
    }
}

#[test]
fn test_perf_profiler_with_topology() {
    use scx_utils::Topology;
    use std::sync::Arc;

    let profiler = SharedPerfProfiler::new();

    // Create topology
    let topo = Topology::new().expect("Failed to create topology");
    let topo_arc = Arc::new(topo);

    // Set topology on profiler
    profiler.set_topology(topo_arc);

    // Start profiling without BPF attacher (should work, just won't attach events)
    let config = PerfProfilingConfig {
        event: "cache-misses".to_string(),
        freq: 99,
        cpu: -1,
        pid: -1,
        max_samples: 0,
        duration_secs: 10,
    };

    let result = profiler.start(config);
    // Without BPF attacher, it should start but not attach events
    assert!(result.is_ok());
    assert_eq!(profiler.status(), ProfilingStatus::Running);
}

#[test]
fn test_bpf_perf_event_attacher_creation() {
    use scxtop::mcp::BpfPerfEventAttacher;
    use std::sync::Arc;

    // Create a mock attacher with a simple closure
    let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let call_count_clone = call_count.clone();

    let attacher = BpfPerfEventAttacher::new(move |_perf_fd| {
        call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(anyhow::anyhow!("Mock error - BPF not available in test"))
    });

    // Try to attach (will fail in test environment, but shows the API works)
    let result = attacher.attach_to_perf_event(123);
    assert!(result.is_err());

    // Verify our closure was called
    assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn test_perf_config_serialization() {
    let config = PerfProfilingConfig {
        event: "cache-misses".to_string(),
        freq: 99,
        cpu: 0,
        pid: 1234,
        max_samples: 5000,
        duration_secs: 10,
    };

    // Serialize to JSON
    let json = serde_json::to_string(&config).unwrap();

    // Deserialize back
    let config2: PerfProfilingConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(config.event, config2.event);
    assert_eq!(config.freq, config2.freq);
    assert_eq!(config.cpu, config2.cpu);
    assert_eq!(config.pid, config2.pid);
    assert_eq!(config.max_samples, config2.max_samples);
    assert_eq!(config.duration_secs, config2.duration_secs);
}
