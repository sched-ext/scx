// PANDEMONIUM EVENT LOG
// RECORDS STATS SNAPSHOTS DURING SCHEDULER EXECUTION
// PRE-ALLOCATED RING BUFFER. NO HEAP ALLOCATION DURING MONITORING.
// WRAPS AROUND AT CAPACITY -- OLDEST ENTRIES OVERWRITTEN.

pub const MAX_SNAPSHOTS: usize = 8192;

#[derive(Clone, Copy)]
pub struct Snapshot {
    pub ts_ns: u64,
    pub dispatches: u64,
    pub idle_hits: u64,
    pub shared: u64,
    pub preempt: u64,
    pub keep_run: u64,
    pub wake_avg_us: u64,
    pub hard_kicks: u64,
    pub soft_kicks: u64,
    pub lat_idle_us: u64,
    pub lat_kick_us: u64,
}

pub struct EventLog {
    snapshots: Vec<Snapshot>,
    head: usize,
    len: usize,
}

impl EventLog {
    pub fn new() -> Self {
        Self {
            snapshots: vec![
                Snapshot {
                    ts_ns: 0,
                    dispatches: 0,
                    idle_hits: 0,
                    shared: 0,
                    preempt: 0,
                    keep_run: 0,
                    wake_avg_us: 0,
                    hard_kicks: 0,
                    soft_kicks: 0,
                    lat_idle_us: 0,
                    lat_kick_us: 0
                };
                MAX_SNAPSHOTS
            ],
            head: 0,
            len: 0,
        }
    }

    // RECORD ONE STATS SNAPSHOT. CALLED ONCE PER SECOND FROM THE MONITOR LOOP.
    // OVERWRITES OLDEST ENTRY WHEN FULL.
    pub fn snapshot(
        &mut self,
        dispatches: u64,
        idle_hits: u64,
        shared: u64,
        preempt: u64,
        keep_run: u64,
        wake_avg_us: u64,
        hard_kicks: u64,
        soft_kicks: u64,
        lat_idle_us: u64,
        lat_kick_us: u64,
    ) {
        self.snapshots[self.head] = Snapshot {
            ts_ns: now_ns(),
            dispatches,
            idle_hits,
            shared,
            preempt,
            keep_run,
            wake_avg_us,
            hard_kicks,
            soft_kicks,
            lat_idle_us,
            lat_kick_us,
        };
        self.head = (self.head + 1) % MAX_SNAPSHOTS;
        if self.len < MAX_SNAPSHOTS {
            self.len += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn head(&self) -> usize {
        self.head
    }

    pub fn get(&self, idx: usize) -> &Snapshot {
        &self.snapshots[idx]
    }

    // ITERATE SNAPSHOTS IN CHRONOLOGICAL ORDER
    pub fn iter_chronological(&self) -> impl Iterator<Item = &Snapshot> {
        let start = if self.len < MAX_SNAPSHOTS {
            0
        } else {
            self.head
        };
        (0..self.len).map(move |i| &self.snapshots[(start + i) % MAX_SNAPSHOTS])
    }

    // DUMP THE TIME SERIES AFTER EXECUTION
    pub fn dump(&self) {
        if self.len == 0 {
            return;
        }

        let mut iter = self.iter_chronological();
        let first = iter.next().unwrap();
        let base_ts = first.ts_ns;

        println!(
            "\n{:<10} {:<12} {:<10} {:<10} {:<10} {:<10} {:<10} {:<8} {:<8} {:<10} {:<10}",
            "TIME_S",
            "DISPATCH/S",
            "IDLE/S",
            "SHARED/S",
            "PREEMPT",
            "KEEP_RUN",
            "WAKE_US",
            "KICK_H",
            "KICK_S",
            "LAT_IDLE",
            "LAT_KICK"
        );
        println!(
            "{:<10.1} {:<12} {:<10} {:<10} {:<10} {:<10} {:<10} {:<8} {:<8} {:<10} {:<10}",
            0.0,
            first.dispatches,
            first.idle_hits,
            first.shared,
            first.preempt,
            first.keep_run,
            first.wake_avg_us,
            first.hard_kicks,
            first.soft_kicks,
            first.lat_idle_us,
            first.lat_kick_us
        );

        for s in iter {
            let elapsed_s = (s.ts_ns - base_ts) as f64 / 1_000_000_000.0;
            println!(
                "{:<10.1} {:<12} {:<10} {:<10} {:<10} {:<10} {:<10} {:<8} {:<8} {:<10} {:<10}",
                elapsed_s,
                s.dispatches,
                s.idle_hits,
                s.shared,
                s.preempt,
                s.keep_run,
                s.wake_avg_us,
                s.hard_kicks,
                s.soft_kicks,
                s.lat_idle_us,
                s.lat_kick_us
            );
        }

        if self.len == MAX_SNAPSHOTS {
            println!(
                "\n(RING BUFFER WRAPPED -- SHOWING MOST RECENT {} SNAPSHOTS)",
                MAX_SNAPSHOTS
            );
        }
        println!("TOTAL SNAPSHOTS: {}", self.len);
    }

    // SUMMARY STATISTICS
    pub fn summary(&self) {
        if self.len < 2 {
            return;
        }

        let snapshots: Vec<&Snapshot> = self.iter_chronological().collect();

        let total_d: u64 = snapshots.iter().map(|s| s.dispatches).sum();
        let total_idle: u64 = snapshots.iter().map(|s| s.idle_hits).sum();
        let total_shared: u64 = snapshots.iter().map(|s| s.shared).sum();
        let total_preempt: u64 = snapshots.iter().map(|s| s.preempt).sum();
        let total_keep: u64 = snapshots.iter().map(|s| s.keep_run).sum();

        let peak_d = snapshots.iter().map(|s| s.dispatches).max().unwrap_or(0);

        let elapsed_ns = snapshots.last().unwrap().ts_ns - snapshots.first().unwrap().ts_ns;
        let elapsed_s = elapsed_ns as f64 / 1_000_000_000.0;

        println!("\nPANDEMONIUM SUMMARY");
        println!("  TOTAL DISPATCHES:  {}", total_d);
        println!("  TOTAL IDLE HITS:   {}", total_idle);
        println!("  TOTAL SHARED:      {}", total_shared);
        println!("  TOTAL PREEMPT:     {}", total_preempt);
        println!("  TOTAL KEEP_RUN:    {}", total_keep);
        println!("  PEAK DISPATCH/S:   {}", peak_d);
        if elapsed_s > 0.0 {
            println!("  AVG DISPATCH/S:    {:.0}", total_d as f64 / elapsed_s);
            let idle_pct = if total_d > 0 {
                total_idle as f64 / total_d as f64 * 100.0
            } else {
                0.0
            };
            println!("  IDLE HIT RATE:     {:.1}%", idle_pct);
        }
        println!("  ELAPSED:           {:.1}s", elapsed_s);
        println!("  SAMPLES:           {}", self.len);
    }
}

fn now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}
