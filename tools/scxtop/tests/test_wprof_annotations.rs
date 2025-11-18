use scxtop::mcp::perfetto_track_event_types::{
    Annotation, AnnotationValue, ParsedTrackEvent, TrackEventMetadata, TrackEventType,
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

        // Create events with various annotations
        for i in 0..1000 {
            let mut annotations = vec![
                Annotation {
                    name: "pid".to_string(),
                    value: AnnotationValue::Int((1000 + i) as i64),
                },
                Annotation {
                    name: "cpu".to_string(),
                    value: AnnotationValue::Uint((i % 8) as u64),
                },
            ];

            // Add some conditional annotations
            if i % 3 == 0 {
                annotations.push(Annotation {
                    name: "waking_delay_us".to_string(),
                    value: AnnotationValue::Uint((i % 100) as u64),
                });
            }

            if i % 5 == 0 {
                annotations.push(Annotation {
                    name: "comm".to_string(),
                    value: AnnotationValue::String(format!("task_{}", i % 10)),
                });
            }

            if i % 7 == 0 {
                annotations.push(Annotation {
                    name: "numa_node".to_string(),
                    value: AnnotationValue::Uint((i % 2) as u64),
                });
            }

            track_events.push(ParsedTrackEvent {
                timestamp_ns: ts,
                event_type: TrackEventType::Instant,
                category: Some("WAKER".to_string()),
                name: Some(format!("event_{}", i)),
                track_uuid: Some((i % 10) as u64),
                annotations,
                metadata: TrackEventMetadata {
                    cpu: Some((i % 8) as u32),
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
fn test_wprof_annotations() {
    let trace = MockTrace::new();

    let mut annotation_names = HashMap::new();
    for event in trace.get_track_events().iter().take(1000) {
        for ann in &event.annotations {
            *annotation_names.entry(ann.name.clone()).or_insert(0) += 1;
        }
    }

    eprintln!("\nAnnotation names (from first 1000 events):");
    let mut sorted: Vec<_> = annotation_names.iter().collect();
    sorted.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    for (name, count) in sorted.iter().take(20) {
        eprintln!("  {}: {}", name, count);
    }

    eprintln!("\nSample event with annotations:");
    for event in trace.get_track_events().iter() {
        if !event.annotations.is_empty() {
            eprintln!("  Event type={:?}, annotations:", event.event_type);
            for ann in &event.annotations {
                eprintln!("    {}: {:?}", ann.name, ann.value);
            }
            break;
        }
    }
}
