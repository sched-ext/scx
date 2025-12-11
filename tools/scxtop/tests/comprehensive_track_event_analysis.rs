use scxtop::mcp::perfetto_track_event_types::{
    Annotation, AnnotationValue, ParsedTrackEvent, TrackEventMetadata, TrackEventType,
};
use std::collections::HashMap;

// Helper function to create synthetic track events for testing
fn create_test_track_events() -> Vec<ParsedTrackEvent> {
    let mut events = Vec::new();
    let mut ts = 1_000_000_000u64; // Start at 1 second

    // Create a variety of event types with different categories
    let categories = vec!["ONCPU", "WAKER", "WAKEE", "PREEMPTOR", "PREEMPTEE"];
    let event_types = vec![
        TrackEventType::SliceBegin,
        TrackEventType::SliceEnd,
        TrackEventType::Instant,
        TrackEventType::Counter,
    ];

    for i in 0..200 {
        let category = categories[i % categories.len()];
        let event_type = event_types[i % event_types.len()];

        events.push(ParsedTrackEvent {
            timestamp_ns: ts,
            event_type,
            category: Some(category.to_string()),
            name: Some(format!("event_{}", i)),
            track_uuid: Some((i % 20) as u64),
            annotations: vec![
                Annotation {
                    name: "pid".to_string(),
                    value: AnnotationValue::Int((1000 + i) as i64),
                },
                Annotation {
                    name: "cpu".to_string(),
                    value: AnnotationValue::Uint((i % 8) as u64),
                },
            ],
            metadata: TrackEventMetadata {
                cpu: Some((i % 8) as u32),
                pid: Some((1000 + i) as i32),
                tid: Some((2000 + i) as i32),
                comm: Some(format!("process_{}", i % 5)),
                ..Default::default()
            },
        });

        ts += 5000; // Advance time by 5 µs
    }

    events
}

// Helper struct to mock time_range functionality
struct MockTrace {
    track_events: Vec<ParsedTrackEvent>,
}

impl MockTrace {
    fn new() -> Self {
        Self {
            track_events: create_test_track_events(),
        }
    }

    fn time_range(&self) -> (u64, u64) {
        let min = self
            .track_events
            .iter()
            .map(|e| e.timestamp_ns)
            .min()
            .unwrap_or(0);
        let max = self
            .track_events
            .iter()
            .map(|e| e.timestamp_ns)
            .max()
            .unwrap_or(0);
        (min, max)
    }

    fn get_track_events(&self) -> &[ParsedTrackEvent] {
        &self.track_events
    }
}

#[test]
fn comprehensive_track_event_analysis() {
    let trace = MockTrace::new();

    let track_events = trace.get_track_events();
    eprintln!("\n========== COMPREHENSIVE TRACKEVENT ANALYSIS ==========\n");

    // Basic counts
    eprintln!("Total TrackEvents: {}", track_events.len());
    eprintln!(
        "Trace duration: {} ms",
        (trace.time_range().1 - trace.time_range().0) / 1_000_000
    );

    // Event type distribution
    let mut type_counts = HashMap::new();
    for event in track_events.iter() {
        let type_name = match event.event_type {
            TrackEventType::SliceBegin => "SliceBegin",
            TrackEventType::SliceEnd => "SliceEnd",
            TrackEventType::Instant => "Instant",
            TrackEventType::Counter => "Counter",
            TrackEventType::Unspecified => "Unspecified",
        };
        *type_counts.entry(type_name).or_insert(0) += 1;
    }
    eprintln!("\n=== Event Type Distribution ===");
    for (type_name, count) in type_counts.iter() {
        eprintln!("  {}: {}", type_name, count);
    }

    // Category distribution
    let mut category_counts = HashMap::new();
    for event in track_events.iter() {
        let cat = event.category.as_deref().unwrap_or("None");
        *category_counts.entry(cat.to_string()).or_insert(0) += 1;
    }
    eprintln!("\n=== Category Distribution ===");
    let mut sorted_cats: Vec<_> = category_counts.iter().collect();
    sorted_cats.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    for (cat, count) in sorted_cats.iter().take(20) {
        eprintln!("  {}: {}", cat, count);
    }

    // Name distribution (for instants)
    let mut name_counts = HashMap::new();
    for event in track_events.iter() {
        if let Some(name) = &event.name {
            *name_counts.entry(name.clone()).or_insert(0) += 1;
        }
    }
    eprintln!("\n=== Event Name Distribution ===");
    let mut sorted_names: Vec<_> = name_counts.iter().collect();
    sorted_names.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    for (name, count) in sorted_names.iter().take(20) {
        eprintln!("  {}: {}", name, count);
    }

    // Annotation analysis
    let mut annotation_names = HashMap::new();
    for event in track_events.iter() {
        for ann in &event.annotations {
            *annotation_names.entry(ann.name.clone()).or_insert(0) += 1;
        }
    }
    eprintln!("\n=== Annotation Names (from all events) ===");
    if annotation_names.is_empty() {
        eprintln!("  No annotations found");
    } else {
        let mut sorted_anns: Vec<_> = annotation_names.iter().collect();
        sorted_anns.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        for (name, count) in sorted_anns.iter().take(30) {
            eprintln!("  {}: {}", name, count);
        }
    }

    // Sample events
    eprintln!("\n=== Sample Slice Begin Events (first 5) ===");
    let mut slice_count = 0;
    for event in track_events.iter() {
        if matches!(event.event_type, TrackEventType::SliceBegin) {
            eprintln!(
                "  Event: category={:?}, name={:?}, timestamp={} ns",
                event.category, event.name, event.timestamp_ns
            );
            eprintln!("    track_uuid={:?}", event.track_uuid);
            if !event.annotations.is_empty() {
                eprintln!("    Annotations:");
                for ann in &event.annotations {
                    eprintln!("      {}: {:?}", ann.name, ann.value);
                }
            }
            if event.metadata.cpu.is_some() {
                eprintln!(
                    "    Metadata: cpu={:?}, pid={:?}, tid={:?}",
                    event.metadata.cpu, event.metadata.pid, event.metadata.tid
                );
            }
            eprintln!("");
            slice_count += 1;
            if slice_count >= 5 {
                break;
            }
        }
    }

    eprintln!("\n=== Sample Instant Events (first 5) ===");
    let mut instant_count = 0;
    for event in track_events.iter() {
        if matches!(event.event_type, TrackEventType::Instant) {
            eprintln!(
                "  Event: category={:?}, name={:?}, timestamp={} ns",
                event.category, event.name, event.timestamp_ns
            );
            if !event.annotations.is_empty() {
                eprintln!("    Annotations:");
                for ann in &event.annotations {
                    eprintln!("      {}: {:?}", ann.name, ann.value);
                }
            }
            eprintln!("");
            instant_count += 1;
            if instant_count >= 5 {
                break;
            }
        }
    }

    // Track UUID analysis
    let mut track_uuids = HashMap::new();
    for event in track_events.iter() {
        if let Some(uuid) = event.track_uuid {
            *track_uuids.entry(uuid).or_insert(0) += 1;
        }
    }
    eprintln!("\n=== Track UUID Statistics ===");
    eprintln!("  Unique tracks: {}", track_uuids.len());
    eprintln!("  Top 10 most active tracks:");
    let mut sorted_tracks: Vec<_> = track_uuids.iter().collect();
    sorted_tracks.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    for (uuid, count) in sorted_tracks.iter().take(10) {
        eprintln!("    Track {}: {} events", uuid, count);
    }

    eprintln!("\n========== END ANALYSIS ==========\n");
}
