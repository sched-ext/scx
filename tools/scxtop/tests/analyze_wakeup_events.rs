use scxtop::mcp::perfetto_track_event_types::{
    Annotation, AnnotationValue, ParsedTrackEvent, TrackEventMetadata, TrackEventType,
};
use std::collections::HashMap;

// Helper function to create synthetic track events for testing
fn create_test_track_events() -> Vec<ParsedTrackEvent> {
    let mut events = Vec::new();
    let mut ts = 1_000_000_000u64; // Start at 1 second

    // Create instant events (wakeups) followed by slice begin events
    for i in 0..100 {
        let track_uuid = i % 10; // Simulate 10 different tracks

        // Create an Instant event (wakeup)
        events.push(ParsedTrackEvent {
            timestamp_ns: ts,
            event_type: TrackEventType::Instant,
            category: Some("WAKER".to_string()),
            name: Some(format!("wakeup_{}", i)),
            track_uuid: Some(track_uuid),
            annotations: vec![
                Annotation {
                    name: "pid".to_string(),
                    value: AnnotationValue::Int((1000 + i) as i64),
                },
                Annotation {
                    name: "tid".to_string(),
                    value: AnnotationValue::Int((2000 + i) as i64),
                },
                Annotation {
                    name: "comm".to_string(),
                    value: AnnotationValue::String(format!("task_{}", i % 5)),
                },
            ],
            metadata: TrackEventMetadata {
                cpu: Some((i % 4) as u32),
                pid: Some((1000 + i) as i32),
                tid: Some((2000 + i) as i32),
                comm: Some(format!("task_{}", i % 5)),
                numa_node: Some((i % 2) as u32),
                ..Default::default()
            },
        });

        // Create a corresponding SliceBegin event shortly after
        let latency_ns = (i % 50) * 1000 + 500; // Varying latency: 0.5-50 µs
        events.push(ParsedTrackEvent {
            timestamp_ns: ts + latency_ns,
            event_type: TrackEventType::SliceBegin,
            category: Some("ONCPU".to_string()),
            name: Some(format!("oncpu_{}", i)),
            track_uuid: Some(track_uuid + 100), // Different track for oncpu
            annotations: vec![],
            metadata: TrackEventMetadata {
                cpu: Some((i % 4) as u32),
                pid: Some((1000 + i) as i32),
                tid: Some((2000 + i) as i32),
                ..Default::default()
            },
        });

        ts += 10000; // Advance time by 10 µs
    }

    events
}

// Helper struct to mock PerfettoTrace
struct MockTrace {
    track_events: Vec<ParsedTrackEvent>,
}

impl MockTrace {
    fn new() -> Self {
        Self {
            track_events: create_test_track_events(),
        }
    }

    fn get_track_events(&self) -> &[ParsedTrackEvent] {
        &self.track_events
    }
}

#[test]
fn analyze_wakeup_events() {
    let trace = MockTrace::new();

    let track_events = trace.get_track_events();
    eprintln!("\n========== WAKEUP EVENT ANALYSIS ==========\n");

    // Analyze instant events (potential wakeups)
    let mut instant_count = 0;
    let mut instant_by_track = HashMap::new();
    let mut instant_timestamps = Vec::new();

    for event in track_events.iter() {
        if matches!(event.event_type, TrackEventType::Instant) {
            instant_count += 1;
            if let Some(uuid) = event.track_uuid {
                *instant_by_track.entry(uuid).or_insert(0) += 1;
            }
            instant_timestamps.push(event.timestamp_ns);
        }
    }

    eprintln!("Total Instant Events: {}", instant_count);
    eprintln!("Instant events with track UUID: {}", instant_by_track.len());
    eprintln!("");

    // Look for wakeup patterns: instant followed by slice begin
    let mut wakeup_patterns = Vec::new();

    for i in 0..track_events.len().saturating_sub(10) {
        let event = &track_events[i];
        if matches!(event.event_type, TrackEventType::Instant) {
            // Look for SliceBegin events shortly after this instant
            for j in (i + 1)..std::cmp::min(i + 10, track_events.len()) {
                let next = &track_events[j];
                if matches!(next.event_type, TrackEventType::SliceBegin) {
                    let latency_ns = next.timestamp_ns.saturating_sub(event.timestamp_ns);
                    if latency_ns < 100_000 {
                        // Within 100 microseconds
                        wakeup_patterns.push((
                            event.timestamp_ns,
                            next.timestamp_ns,
                            latency_ns,
                            event.track_uuid,
                            next.track_uuid,
                        ));
                        if wakeup_patterns.len() >= 100 {
                            break;
                        }
                    }
                }
            }
            if wakeup_patterns.len() >= 100 {
                break;
            }
        }
    }

    eprintln!("=== Potential Wakeup Patterns (Instant → SliceBegin) ===");
    eprintln!("Found {} potential wakeup patterns", wakeup_patterns.len());
    eprintln!("");

    if !wakeup_patterns.is_empty() {
        // Calculate latency statistics
        let mut latencies: Vec<u64> = wakeup_patterns
            .iter()
            .map(|(_, _, lat, _, _)| *lat)
            .collect();
        latencies.sort();

        let min = latencies.first().unwrap();
        let max = latencies.last().unwrap();
        let median = latencies[latencies.len() / 2];
        let p95 = latencies[latencies.len() * 95 / 100];
        let p99 = latencies[latencies.len() * 99 / 100];
        let avg: u64 = latencies.iter().sum::<u64>() / latencies.len() as u64;

        eprintln!("Wakeup-to-Schedule Latency Statistics:");
        eprintln!("  Minimum: {} ns ({:.2} µs)", min, *min as f64 / 1000.0);
        eprintln!("  Average: {} ns ({:.2} µs)", avg, avg as f64 / 1000.0);
        eprintln!(
            "  Median:  {} ns ({:.2} µs)",
            median,
            median as f64 / 1000.0
        );
        eprintln!("  P95:     {} ns ({:.2} µs)", p95, p95 as f64 / 1000.0);
        eprintln!("  P99:     {} ns ({:.2} µs)", p99, p99 as f64 / 1000.0);
        eprintln!("  Maximum: {} ns ({:.2} µs)", max, *max as f64 / 1000.0);
        eprintln!("");

        eprintln!("Sample wakeup patterns (first 10):");
        for (i, (instant_ts, slice_ts, latency, instant_track, slice_track)) in
            wakeup_patterns.iter().take(10).enumerate()
        {
            eprintln!(
                "  {}: Instant@{} ns (track {:?}) → SliceBegin@{} ns (track {:?}) = {} ns ({:.2} µs)",
                i+1, instant_ts, instant_track, slice_ts, slice_track, latency, *latency as f64 / 1000.0
            );
        }
    }

    eprintln!("");
    eprintln!("=== Detailed Instant Event Analysis ===");

    // Sample first 20 instant events with full details
    let mut instant_samples = 0;
    for event in track_events.iter() {
        if matches!(event.event_type, TrackEventType::Instant) {
            eprintln!("Instant event {}:", instant_samples + 1);
            eprintln!("  Timestamp: {} ns", event.timestamp_ns);
            eprintln!("  Track UUID: {:?}", event.track_uuid);
            eprintln!("  Category: {:?}", event.category);
            eprintln!("  Name: {:?}", event.name);
            eprintln!("  Annotations: {}", event.annotations.len());
            if !event.annotations.is_empty() {
                for ann in &event.annotations {
                    eprintln!("    {}: {:?}", ann.name, ann.value);
                }
            }
            eprintln!("  Metadata:");
            eprintln!("    cpu: {:?}", event.metadata.cpu);
            eprintln!("    pid: {:?}", event.metadata.pid);
            eprintln!("    tid: {:?}", event.metadata.tid);
            eprintln!("");

            instant_samples += 1;
            if instant_samples >= 20 {
                break;
            }
        }
    }

    eprintln!("========== END WAKEUP ANALYSIS ==========\n");
}
