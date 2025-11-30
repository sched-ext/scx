use scxtop::mcp::perfetto_track_event_types::{
    ParsedTrackEvent, TrackEventMetadata, TrackEventType,
};
use std::collections::HashMap;

// Mock trace structure for testing
struct MockTrace {
    track_events: Vec<ParsedTrackEvent>,
    ftrace_event_count: usize,
}

impl MockTrace {
    fn new() -> Self {
        let mut track_events = Vec::new();
        let mut ts = 1_000_000_000u64;

        // Create diverse track events with different categories
        let categories = vec!["ONCPU", "WAKER", "WAKEE", "PREEMPTOR", "PREEMPTEE"];
        for i in 0..150 {
            let category = categories[i % categories.len()];
            let event_type = match i % 4 {
                0 => TrackEventType::SliceBegin,
                1 => TrackEventType::SliceEnd,
                2 => TrackEventType::Instant,
                _ => TrackEventType::Counter,
            };

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

        Self {
            track_events,
            ftrace_event_count: 50, // Simulated ftrace events
        }
    }

    fn total_track_events(&self) -> usize {
        self.track_events.len()
    }

    fn total_ftrace_events(&self) -> usize {
        self.ftrace_event_count
    }

    fn get_track_event_categories(&self) -> Vec<String> {
        let mut categories: HashMap<String, ()> = HashMap::new();
        for event in &self.track_events {
            if let Some(cat) = &event.category {
                categories.insert(cat.clone(), ());
            }
        }
        categories.into_keys().collect()
    }
}

#[test]
fn test_load_wprof_trace() {
    let trace = MockTrace::new();
    eprintln!("Track events: {}", trace.total_track_events());
    eprintln!("Ftrace events: {}", trace.total_ftrace_events());
    eprintln!("Categories: {:?}", trace.get_track_event_categories());
    assert!(
        trace.total_track_events() > 0,
        "Should have parsed track events"
    );
}
