use scxtop::mcp::perfetto_track_event_types::{
    ParsedTrackEvent, TrackEventMetadata, TrackEventType,
};
use std::collections::HashMap;

// Mock trace structure for testing
struct MockTrace {
    track_events: Vec<ParsedTrackEvent>,
}

impl MockTrace {
    fn new() -> Self {
        let mut track_events = Vec::new();
        let mut ts = 1_000_000_000u64;

        // Create diverse track events with different types
        let categories = vec!["ONCPU", "WAKER", "WAKEE"];
        let event_types = vec![
            TrackEventType::SliceBegin,
            TrackEventType::SliceEnd,
            TrackEventType::Instant,
            TrackEventType::Counter,
        ];

        for i in 0..100 {
            let category = categories[i % categories.len()];
            let event_type = event_types[i % event_types.len()];

            track_events.push(ParsedTrackEvent {
                timestamp_ns: ts,
                event_type,
                category: Some(category.to_string()),
                name: Some(format!("event_{}", i)),
                track_uuid: Some((i % 10) as u64),
                annotations: vec![],
                metadata: TrackEventMetadata {
                    cpu: Some((i % 4) as u32),
                    pid: Some((1000 + i) as i32),
                    ..Default::default()
                },
            });

            ts += 10000;
        }

        Self { track_events }
    }

    fn get_track_events(&self) -> &[ParsedTrackEvent] {
        &self.track_events
    }
}

#[test]
fn test_wprof_event_types() {
    let trace = MockTrace::new();

    let mut event_type_counts = HashMap::new();
    for event in trace.get_track_events() {
        let event_type_name = format!("{:?}", event.event_type);
        *event_type_counts.entry(event_type_name).or_insert(0) += 1;
    }

    eprintln!("\nEvent type distribution:");
    for (type_name, count) in event_type_counts.iter() {
        eprintln!("  {}: {}", type_name, count);
    }

    eprintln!("\nSample events (first 10):");
    for (i, event) in trace.get_track_events().iter().take(10).enumerate() {
        eprintln!(
            "  Event {}: type={:?}, category={:?}, name={:?}",
            i, event.event_type, event.category, event.name
        );
    }
}
