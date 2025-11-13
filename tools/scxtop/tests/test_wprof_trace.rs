use scxtop::mcp::PerfettoTrace;
use std::path::Path;

#[test]
fn test_load_wprof_trace() {
    let trace =
        PerfettoTrace::from_file(Path::new("/home/hodgesd/scx/wprof_lavd_whatsapp.pb")).unwrap();
    eprintln!("Track events: {}", trace.total_track_events());
    eprintln!("Ftrace events: {}", trace.total_ftrace_events());
    eprintln!("Categories: {:?}", trace.get_track_event_categories());
    assert!(
        trace.total_track_events() > 0,
        "Should have parsed track events"
    );
}
