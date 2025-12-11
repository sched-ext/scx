use scxtop::mcp::perfetto_track_event_types::{
    ParsedTrackEvent, TrackEventMetadata, TrackEventType,
};
use std::collections::HashMap;

// Helper function to create synthetic track events for testing
fn create_test_track_events() -> Vec<ParsedTrackEvent> {
    let mut events = Vec::new();
    let mut ts = 1_000_000_000u64; // Start at 1 second

    // Create some instant events (simulating wakeups) followed by slice begin events
    for i in 0..100 {
        let track_uuid = i % 10; // Simulate 10 different tracks

        // Create an Instant event (wakeup)
        events.push(ParsedTrackEvent {
            timestamp_ns: ts,
            event_type: TrackEventType::Instant,
            category: Some("WAKER".to_string()),
            name: Some(format!("wakeup_{}", i)),
            track_uuid: Some(track_uuid),
            annotations: vec![],
            metadata: TrackEventMetadata {
                cpu: Some((i % 4) as u32),
                pid: Some((1000 + i) as i32),
                ..Default::default()
            },
        });

        // Create a corresponding SliceBegin event shortly after with varying latency
        let latency_ns = match i % 10 {
            0..=5 => 1000 + (i % 6) * 200,  // Normal latency: 1-2 µs
            6..=8 => 5000 + (i % 3) * 1000, // Higher latency: 5-8 µs
            _ => 50000 + (i % 2) * 100000,  // Outliers: 50-150 µs
        };

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
                ..Default::default()
            },
        });

        ts += 10000; // Advance time by 10 µs
    }

    events
}

#[test]
fn comprehensive_wakeup_outlier_analysis() {
    let track_events = create_test_track_events();
    eprintln!("\n========== COMPREHENSIVE WAKEUP & OUTLIER ANALYSIS ==========\n");

    // Collect all instant events and their indices
    let mut instant_events = Vec::new();
    for (i, event) in track_events.iter().enumerate() {
        if matches!(event.event_type, TrackEventType::Instant) {
            instant_events.push((i, event.timestamp_ns, event.track_uuid));
        }
    }

    eprintln!("Total Instant Events: {}", instant_events.len());
    eprintln!("");

    // Find wakeup-to-schedule patterns
    let mut all_wakeup_latencies = Vec::new();
    let mut wakeup_details = Vec::new();

    for (idx, instant_ts, instant_track) in &instant_events {
        // Look for the next SliceBegin event within reasonable time
        for j in (idx + 1)..std::cmp::min(idx + 20, track_events.len()) {
            let next = &track_events[j];
            if matches!(next.event_type, TrackEventType::SliceBegin) {
                let latency_ns = next.timestamp_ns.saturating_sub(*instant_ts);
                if latency_ns < 1_000_000 {
                    // Within 1 millisecond
                    all_wakeup_latencies.push(latency_ns);
                    wakeup_details.push((
                        *instant_ts,
                        next.timestamp_ns,
                        latency_ns,
                        *instant_track,
                        next.track_uuid,
                    ));
                    break;
                }
            }
        }
    }

    eprintln!("=== Wakeup-to-Schedule Analysis ===");
    eprintln!("Correlated wakeup patterns: {}", all_wakeup_latencies.len());
    eprintln!(
        "Correlation rate: {:.1}%",
        all_wakeup_latencies.len() as f64 / instant_events.len() as f64 * 100.0
    );
    eprintln!("");

    if all_wakeup_latencies.is_empty() {
        eprintln!("No wakeup patterns found");
        return;
    }

    // Calculate statistics
    all_wakeup_latencies.sort();
    let count = all_wakeup_latencies.len();

    let min = all_wakeup_latencies[0];
    let max = all_wakeup_latencies[count - 1];
    let median = all_wakeup_latencies[count / 2];
    let p25 = all_wakeup_latencies[count / 4];
    let p75 = all_wakeup_latencies[count * 3 / 4];
    let p90 = all_wakeup_latencies[count * 90 / 100];
    let p95 = all_wakeup_latencies[count * 95 / 100];
    let p99 = all_wakeup_latencies[count * 99 / 100];
    let p999 = all_wakeup_latencies[count * 999 / 1000];
    let avg: u64 = all_wakeup_latencies.iter().sum::<u64>() / count as u64;

    eprintln!("=== Wakeup Latency Statistics ===");
    eprintln!("  Samples: {}", count);
    eprintln!("  Minimum: {} ns ({:.2} µs)", min, min as f64 / 1000.0);
    eprintln!("  P25:     {} ns ({:.2} µs)", p25, p25 as f64 / 1000.0);
    eprintln!(
        "  Median:  {} ns ({:.2} µs)",
        median,
        median as f64 / 1000.0
    );
    eprintln!("  Average: {} ns ({:.2} µs)", avg, avg as f64 / 1000.0);
    eprintln!("  P75:     {} ns ({:.2} µs)", p75, p75 as f64 / 1000.0);
    eprintln!("  P90:     {} ns ({:.2} µs)", p90, p90 as f64 / 1000.0);
    eprintln!("  P95:     {} ns ({:.2} µs)", p95, p95 as f64 / 1000.0);
    eprintln!("  P99:     {} ns ({:.2} µs)", p99, p99 as f64 / 1000.0);
    eprintln!("  P99.9:   {} ns ({:.2} µs)", p999, p999 as f64 / 1000.0);
    eprintln!("  Maximum: {} ns ({:.2} µs)", max, max as f64 / 1000.0);
    eprintln!("");

    // Outlier detection using IQR method
    let iqr = p75 - p25;
    let outlier_threshold = p75 + (iqr as f64 * 1.5) as u64;
    let extreme_outlier_threshold = p75 + (iqr as f64 * 3.0) as u64;

    eprintln!("=== Outlier Detection (IQR Method) ===");
    eprintln!("  IQR: {} ns ({:.2} µs)", iqr, iqr as f64 / 1000.0);
    eprintln!(
        "  Outlier threshold (Q3 + 1.5*IQR): {} ns ({:.2} µs)",
        outlier_threshold,
        outlier_threshold as f64 / 1000.0
    );
    eprintln!(
        "  Extreme outlier threshold (Q3 + 3*IQR): {} ns ({:.2} µs)",
        extreme_outlier_threshold,
        extreme_outlier_threshold as f64 / 1000.0
    );
    eprintln!("");

    let outliers: Vec<_> = wakeup_details
        .iter()
        .filter(|(_, _, lat, _, _)| *lat >= outlier_threshold)
        .collect();

    let extreme_outliers: Vec<_> = outliers
        .iter()
        .filter(|(_, _, lat, _, _)| *lat >= extreme_outlier_threshold)
        .collect();

    eprintln!(
        "  Outliers found: {} ({:.2}% of samples)",
        outliers.len(),
        outliers.len() as f64 / count as f64 * 100.0
    );
    eprintln!(
        "  Extreme outliers: {} ({:.2}% of samples)",
        extreme_outliers.len(),
        extreme_outliers.len() as f64 / count as f64 * 100.0
    );
    eprintln!("");

    // Show worst outliers
    let mut sorted_outliers = outliers.clone();
    sorted_outliers.sort_by_key(|(_, _, lat, _, _)| std::cmp::Reverse(*lat));

    eprintln!("=== Top 20 Worst Latency Outliers ===");
    for (i, (instant_ts, slice_ts, latency, instant_track, slice_track)) in
        sorted_outliers.iter().take(20).enumerate()
    {
        let is_extreme = *latency >= extreme_outlier_threshold;
        let marker = if is_extreme { "🔴 EXTREME" } else { "⚠️" };
        eprintln!(
            "  {} {}: Instant@{} ns (track {:?}) → SliceBegin@{} ns (track {:?})",
            marker,
            i + 1,
            instant_ts,
            instant_track,
            slice_ts,
            slice_track
        );
        eprintln!(
            "       Latency: {} ns ({:.2} µs) - {:.1}× median",
            latency,
            *latency as f64 / 1000.0,
            *latency as f64 / median as f64
        );
    }
    eprintln!("");

    // Latency distribution
    eprintln!("=== Latency Distribution ===");
    let buckets = vec![
        (0, 1000, "0-1 µs"),
        (1000, 2000, "1-2 µs"),
        (2000, 5000, "2-5 µs"),
        (5000, 10000, "5-10 µs"),
        (10000, 20000, "10-20 µs"),
        (20000, 50000, "20-50 µs"),
        (50000, 100000, "50-100 µs"),
        (100000, 1000000, "100-1000 µs"),
    ];

    for (min_lat, max_lat, label) in buckets {
        let count_in_bucket = all_wakeup_latencies
            .iter()
            .filter(|&&lat| lat >= min_lat && lat < max_lat)
            .count();
        let pct = count_in_bucket as f64 / count as f64 * 100.0;
        let bar = "#".repeat((pct * 0.5) as usize);
        eprintln!(
            "  {:12}: {:6} ({:5.1}%) {}",
            label, count_in_bucket, pct, bar
        );
    }
    eprintln!("");

    // Zero latency analysis
    let zero_latency_count = all_wakeup_latencies.iter().filter(|&&lat| lat == 0).count();
    if zero_latency_count > 0 {
        eprintln!("=== Zero Latency Wakeups ===");
        eprintln!(
            "  Count: {} ({:.1}%)",
            zero_latency_count,
            zero_latency_count as f64 / count as f64 * 100.0
        );
        eprintln!(
            "  Interpretation: Task was already scheduled or instant/slice timestamps aligned"
        );
        eprintln!("");
    }

    // Track UUID analysis for outliers
    let mut outlier_tracks: HashMap<Option<u64>, usize> = HashMap::new();
    for (_, _, _, instant_track, slice_track) in &outliers {
        *outlier_tracks.entry(*instant_track).or_insert(0) += 1;
        *outlier_tracks.entry(*slice_track).or_insert(0) += 1;
    }

    let mut track_vec: Vec<_> = outlier_tracks.iter().collect();
    track_vec.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

    eprintln!("=== Tracks with Most Outlier Wakeups (Top 10) ===");
    for (track, count) in track_vec.iter().take(10) {
        eprintln!("  Track {:?}: {} outlier wakeups", track, count);
    }
    eprintln!("");

    eprintln!("========== END WAKEUP & OUTLIER ANALYSIS ==========\n");
}
