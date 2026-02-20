// PANDEMONIUM EVENT LOG TESTS
// UNIT TESTS FOR THE PRE-ALLOCATED RING BUFFER

use pandemonium::event::{EventLog, MAX_SNAPSHOTS};

#[test]
fn snapshot_records() {
    let mut log = EventLog::new();
    assert_eq!(log.len(), 0);

    log.snapshot(100, 90, 10, 5, 30, 65, 20, 10, 40, 50);
    assert_eq!(log.len(), 1);
    assert_eq!(log.get(0).dispatches, 100);
    assert_eq!(log.get(0).idle_hits, 90);
    assert_eq!(log.get(0).shared, 10);
    assert_eq!(log.get(0).preempt, 5);
    assert_eq!(log.get(0).keep_run, 30);
    assert_eq!(log.get(0).wake_avg_us, 65);
    assert_eq!(log.get(0).hard_kicks, 20);
    assert_eq!(log.get(0).soft_kicks, 10);
    assert_eq!(log.get(0).lat_idle_us, 40);
    assert_eq!(log.get(0).lat_kick_us, 50);
    assert!(log.get(0).ts_ns > 0);
}

#[test]
fn ring_buffer_wraps() {
    let mut log = EventLog::new();

    // FILL TO CAPACITY
    for i in 0..MAX_SNAPSHOTS {
        log.snapshot(i as u64, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
    assert_eq!(log.len(), MAX_SNAPSHOTS);
    assert_eq!(log.head(), 0); // WRAPPED BACK TO START

    // WRITE ONE MORE -- OVERWRITES OLDEST
    log.snapshot(9999, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert_eq!(log.len(), MAX_SNAPSHOTS);
    assert_eq!(log.head(), 1);
    assert_eq!(log.get(0).dispatches, 9999);

    // CHRONOLOGICAL ITERATION STARTS FROM OLDEST (INDEX 1)
    let ordered: Vec<u64> = log.iter_chronological().map(|s| s.dispatches).collect();
    assert_eq!(ordered[0], 1); // OLDEST SURVIVING ENTRY
    assert_eq!(*ordered.last().unwrap(), 9999); // NEWEST
    assert_eq!(ordered.len(), MAX_SNAPSHOTS);
}

#[test]
fn summary_no_panic_empty() {
    let log = EventLog::new();
    log.summary(); // SHOULD NOT PANIC WITH 0 SNAPSHOTS
}

#[test]
fn summary_no_panic_one() {
    let mut log = EventLog::new();
    log.snapshot(100, 50, 50, 10, 20, 70, 0, 0, 0, 0);
    log.summary(); // SHOULD NOT PANIC WITH 1 SNAPSHOT
}

#[test]
fn dump_no_panic() {
    let mut log = EventLog::new();
    log.snapshot(100, 50, 50, 5, 25, 70, 0, 0, 0, 0);
    log.snapshot(200, 150, 50, 10, 40, 150, 0, 0, 0, 0);
    log.dump(); // SHOULD NOT PANIC
}
