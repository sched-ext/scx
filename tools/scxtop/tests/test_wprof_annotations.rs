use scxtop::mcp::PerfettoTrace;
use std::collections::HashMap;
use std::path::Path;

#[test]
fn test_wprof_annotations() {
    let trace =
        PerfettoTrace::from_file(Path::new("/home/hodgesd/scx/wprof_lavd_whatsapp.pb")).unwrap();

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
