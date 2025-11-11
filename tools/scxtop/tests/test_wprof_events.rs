use scxtop::mcp::PerfettoTrace;
use std::collections::HashMap;
use std::path::Path;

#[test]
fn test_wprof_event_types() {
    let trace =
        PerfettoTrace::from_file(Path::new("/home/hodgesd/scx/wprof_lavd_whatsapp.pb")).unwrap();

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
