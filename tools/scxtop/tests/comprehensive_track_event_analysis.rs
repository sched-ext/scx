use scxtop::mcp::PerfettoTrace;
use std::collections::HashMap;
use std::path::Path;

#[test]
fn comprehensive_track_event_analysis() {
    let trace =
        PerfettoTrace::from_file(Path::new("/home/hodgesd/scx/wprof_lavd_whatsapp.pb")).unwrap();

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
        *type_counts
            .entry(format!("{:?}", event.event_type))
            .or_insert(0) += 1;
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
        if format!("{:?}", event.event_type) == "SliceBegin" {
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
        if format!("{:?}", event.event_type) == "Instant" {
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
