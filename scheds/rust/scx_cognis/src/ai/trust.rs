// Copyright (c) scx_cognis contributors
// SPDX-License-Identifier: GPL-2.0-only
//
// TrustTable — fixed-size trust/watchlist tracking for observability and exit
// cleanup. This is no longer the main basis for slice or placement decisions;
// it is retained to surface repeatedly bad actors in stats/TUI and to keep
// per-PID exit accounting bounded and allocation-free.
//
// ── Trust score design ────────────────────────────────────────────────────
//
// Each PID occupies one slot determined by Fibonacci hashing of its PID.
// Trust score ∈ [-1.0, +1.0], stored as f32.  Starts at 0.0 (neutral).
//
//   Cooperative events (yield within slice, clean exit, low fork rate)
//     → move score toward +1.0   (positive delta, EMA update)
//   Adversarial events (full-slice burn, adverse exit flag, excessive forking)
//     → move score toward -1.0   (negative delta, EMA update)
//
// EMA update:  score ← clamp(score × α + delta, -1.0, +1.0)
//
// Watchlist threshold: score < TRUST_THRESHOLD (-0.35)
//   → task is reported in observability surfaces as below-threshold.
//
// ── Anomaly flag design ──────────────────────────────────────────────────
//
// The anomaly flag is set behaviorally:
//
//   After 2 consecutive adversarial exits (`cheat_flagged == true`):
//     → `flagged[slot]` is set to true.
//   After one clean exit (`cheat_flagged == false`):
//     → `cheat_streak` resets to 0, flag is cleared.
//
// This keeps the watchlist logic simple and transparent.
//
// ── Memory layout ─────────────────────────────────────────────────────────
//
// All state lives in six fixed arrays of length TRUST_TABLE_SIZE = 4096.
// Total size: ~100 KB.  Allocated ONCE in `Scheduler::init()` via `Box::new`,
// then NEVER reallocated.  Zero heap allocations on any trust operation.
//
// Lookup + update cost: 1 multiply (Fibonacci hash) + 5 array reads/writes ≈ 2 ns.
//
// Reads happen when metrics/TUI want the current watchlist.
// Updates are applied from the exit/stale-PID cleanup paths in `main.rs`,
// which convert lifetime snapshots into `ExitObservation` records without
// adding any per-event heap allocation.

#![allow(dead_code)]

use std::io;

/// Number of slots in the trust table.  Power of 2 so the hash shift is exact.
/// 4096 slots can track up to 4096 simultaneous PIDs before collision eviction.
pub const TRUST_TABLE_SIZE: usize = 4096;
const PID_EMPTY: i32 = 0;
const PID_TOMBSTONE: i32 = -1;

/// Trust score below which a PID is reported as below-threshold in observability.
pub const TRUST_THRESHOLD: f32 = -0.35;

/// Maximum number of entries returned by `worst_actors()`.
/// Matches the TUI trust-watchlist display limit.
pub const SHAME_MAX: usize = 20;

/// Fibonacci multiplier for 32-bit integer hashing.
/// Maps pid (i32) → slot uniformly across the table with no modulo bias.
const FIB32: u32 = 2_654_435_769;

// ── Trust-watchlist entry ───────────────────────────────────────────────────

/// One entry in the trust-watchlist result returned by `worst_actors()`.
#[derive(Debug, Clone, Copy)]
pub struct ShameEntry {
    pub pid: i32,
    pub trust: f32,
    /// Process name, NUL-terminated (Linux TASK_COMM_LEN = 16 bytes including NUL).
    pub comm: [u8; 16],
    /// `true` if this PID has been anomaly-flagged (repeated adversarial exits).
    pub flagged: bool,
}

impl ShameEntry {
    pub const ZERO: Self = Self {
        pid: 0,
        trust: 0.0,
        comm: [0u8; 16],
        flagged: false,
    };

    /// Return the comm as a UTF-8 `&str`, up to the first NUL byte.
    pub fn comm_str(&self) -> &str {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        std::str::from_utf8(&self.comm[..end]).unwrap_or("?")
    }
}

// ── Exit observation ─────────────────────────────────────────────────────────

/// Events observed at task-exit time that drive the trust score update.
///
/// Identical to the old `reputation::ExitObservation` — the same call sites
/// in `main.rs` populate this struct from `TaskLifetime` data.
#[derive(Debug, Default, Clone)]
pub struct ExitObservation {
    /// Task used less than 50% of its last assigned slice → cooperative.
    pub slice_underrun: bool,
    /// Task was forcibly preempted (burned full slice) → adversarial.
    pub preempted: bool,
    /// Task exited cleanly with no adverse conditions.
    pub clean_exit: bool,
    /// Task lifetime ended with an adverse exit flag.
    pub cheat_flagged: bool,
    /// Number of child forks spawned during this lifetime window.
    pub fork_count: u64,
    /// Number of involuntary context switches during this window.
    pub involuntary_ctx_sw: u64,
}

// ── Comm conversion ──────────────────────────────────────────────────────────

/// Convert a `&str` comm name into a NUL-terminated `[u8; 16]` buffer
/// (Linux TASK_COMM_LEN = 16 including the NUL terminator).
///
/// If `s` is longer than 15 bytes, it is silently truncated.
pub fn str_to_comm(s: &str) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let bytes = s.as_bytes();
    let n = bytes.len().min(15); // leave room for NUL terminator
    buf[..n].copy_from_slice(&bytes[..n]);
    buf
}

// ── TrustTable ───────────────────────────────────────────────────────────────

/// O(1) combined trust-score and watchlist table.
///
/// Uses a flat, fixed-size open-addressing structure so trust/watchlist state
/// stays bounded and allocation-free after startup.
///
/// All state lives in six `[T; TRUST_TABLE_SIZE]` arrays.
/// Allocated once via `TrustTable::new()` (which uses `alloc_zeroed`).
/// Zero heap allocations on any subsequent operation.
pub struct TrustTable {
    /// EMA trust score ∈ [-1.0, +1.0].  0.0 = neutral.
    scores: [f32; TRUST_TABLE_SIZE],
    /// PID that owns this slot.  0 = empty.
    pids: [i32; TRUST_TABLE_SIZE],
    /// Process name (TASK_COMM_LEN = 16, NUL-terminated) for TUI display.
    comms: [[u8; 16]; TRUST_TABLE_SIZE],
    /// Whether this PID has been anomaly-flagged (repeated adversarial exits).
    flagged: [bool; TRUST_TABLE_SIZE],
    /// Consecutive adversarial-exit counter.  Resets on any cooperative exit.
    /// When ≥ 2 → `flagged` is set.  Saturates at 255 (u8 max).
    cheat_streak: [u8; TRUST_TABLE_SIZE],
    /// TGID-level trust aggregation (simple EWMA blend of thread scores).
    /// Indexed by TGID using the same Fibonacci hash.
    tgid_scores: [f32; TRUST_TABLE_SIZE],
}

impl TrustTable {
    /// Allocate a new TrustTable.  All slots start at 0.0 (neutral).
    ///
    /// Uses `alloc_zeroed` to ensure the full ~100 KB struct is placed on the
    /// heap in one operation at scheduler startup.  Zero bits are valid for all
    /// field types (f32 → 0.0, i32 → 0, bool → false, u8 → 0).
    pub fn new() -> io::Result<Box<Self>> {
        // SAFETY: all-zero bytes are valid for every field type in this struct.
        unsafe {
            let layout = std::alloc::Layout::new::<Self>();
            let ptr = std::alloc::alloc_zeroed(layout) as *mut Self;
            if ptr.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "TrustTable allocation failed",
                ));
            }
            Ok(Box::from_raw(ptr))
        }
    }

    /// Fibonacci hash: map any PID → slot index in O(1).
    ///
    /// Takes the top 12 bits of (pid × FIB32) as the slot index.
    /// Empirically distributes PIDs uniformly across [0, TRUST_TABLE_SIZE).
    #[inline(always)]
    fn slot(pid: i32) -> usize {
        // Right-shift by (32 - 12) = 20 to take the top 12 bits → range 0..4095.
        ((pid as u32).wrapping_mul(FIB32) >> 20) as usize
    }

    #[inline(always)]
    fn find_slot(&self, pid: i32) -> Option<usize> {
        let start = Self::slot(pid);

        for step in 0..TRUST_TABLE_SIZE {
            let s = (start + step) & (TRUST_TABLE_SIZE - 1);
            let cur = self.pids[s];

            if cur == pid {
                return Some(s);
            }
            if cur == PID_EMPTY {
                return None;
            }
        }

        None
    }

    /// Return the slot for `pid`, evicting a stale occupant if the slot is
    /// occupied by a different PID.
    ///
    /// Eviction resets the slot to neutral for the incoming PID.
    /// On a collision (slot taken by a different PID), the old trust data is
    /// lost only when the table is truly full and no empty/tombstone slot can
    /// be found.
    #[inline(always)]
    fn get_or_insert_slot(&mut self, pid: i32) -> usize {
        let start = Self::slot(pid);
        let mut first_tombstone = None;

        for step in 0..TRUST_TABLE_SIZE {
            let s = (start + step) & (TRUST_TABLE_SIZE - 1);
            let cur = self.pids[s];

            if cur == pid {
                return s;
            }
            if cur == PID_TOMBSTONE && first_tombstone.is_none() {
                first_tombstone = Some(s);
                continue;
            }
            if cur == PID_EMPTY {
                let dst = first_tombstone.unwrap_or(s);
                self.pids[dst] = pid;
                self.scores[dst] = 0.0;
                self.comms[dst] = [0u8; 16];
                self.flagged[dst] = false;
                self.cheat_streak[dst] = 0;
                self.tgid_scores[dst] = 0.0;
                return dst;
            }
        }

        let dst = first_tombstone.unwrap_or(start);
        self.pids[dst] = pid;
        self.scores[dst] = 0.0;
        self.comms[dst] = [0u8; 16];
        self.flagged[dst] = false;
        self.cheat_streak[dst] = 0;
        self.tgid_scores[dst] = 0.0;
        dst
    }

    // ── Trust score API (replacing ReputationEngine) ─────────────────────────

    /// Trust score for a PID ∈ [-1.0, +1.0].
    /// Returns 0.0 (neutral) for unknown PIDs (slot not owned by this PID).
    pub fn trust_score(&self, pid: i32) -> f32 {
        self.find_slot(pid).map(|s| self.scores[s]).unwrap_or(0.0)
    }

    /// Whether this PID is currently below the observability trust threshold.
    pub fn is_quarantined(&self, pid: i32) -> bool {
        self.trust_score(pid) < TRUST_THRESHOLD
    }

    /// Whether this PID has been watchlist-flagged after repeated adverse exits.
    pub fn is_flagged(&self, pid: i32) -> bool {
        self.find_slot(pid)
            .map(|s| self.flagged[s])
            .unwrap_or(false)
    }

    /// Update this PID's trust score based on its most recent exit observation.
    ///
    /// Called from `flush_trust_updates()` (once per second, staleness-based).
    pub fn update_on_exit(&mut self, pid: i32, tgid: i32, obs: &ExitObservation, comm: &str) {
        let s = self.get_or_insert_slot(pid);

        // Store the comm name for TUI display.
        if !comm.is_empty() {
            self.comms[s] = str_to_comm(comm);
        }

        // ── Cooperative signals → push score toward +1.0 ──────────────────
        // Slice underrun: task yielded before its slice expired.
        if obs.slice_underrun {
            self.scores[s] = (self.scores[s] * 0.95 + 0.10_f32).min(1.0);
        }
        // Clean exit with no adversarial flags.
        if obs.clean_exit && !obs.cheat_flagged {
            self.scores[s] = (self.scores[s] * 0.97 + 0.06_f32).min(1.0);
        }

        // ── Adversarial signals → push score toward -1.0 ──────────────────
        // Burned the full slice: high CPU pressure on others.
        if obs.preempted {
            self.scores[s] = (self.scores[s] * 0.93 - 0.07_f32).max(-1.0);
        }
        // Adverse exit flag: strongest adversarial signal.
        if obs.cheat_flagged {
            self.scores[s] = (self.scores[s] * 0.90 - 0.30_f32).max(-1.0);
            self.cheat_streak[s] = self.cheat_streak[s].saturating_add(1);
        } else {
            // Any clean exit resets the streak and clears the watchlist flag.
            self.cheat_streak[s] = 0;
            self.flagged[s] = false;
        }
        // Excessive forking: potential fork-bomb signal.
        if obs.fork_count > 50 {
            let penalty = ((obs.fork_count - 50) as f32 * 0.002).min(0.30);
            self.scores[s] = (self.scores[s] - penalty).max(-1.0);
        }
        // Lots of involuntary context switches: spinning / yield-looping.
        if obs.involuntary_ctx_sw > 1_000 {
            self.scores[s] = (self.scores[s] - 0.08_f32).max(-1.0);
        }

        // ── Watchlist flag: set after 2 consecutive adverse exits ──────────
        // Keep the criterion direct and predictable.
        if self.cheat_streak[s] >= 2 {
            self.flagged[s] = true;
        }

        // ── TGID-level trust aggregation (EWMA blend of thread scores) ─────
        let ts = Self::slot(tgid);
        if self.pids[ts] == tgid || self.pids[ts] == 0 {
            if self.pids[ts] == 0 {
                self.pids[ts] = tgid;
                self.tgid_scores[ts] = 0.0;
            }
            self.tgid_scores[ts] = self.tgid_scores[ts] * 0.8 + self.scores[s] * 0.2;
        }
    }

    /// Time-slice multiplier derived from trust score ∈ [0.25, 1.0].
    ///
    /// Neutral and positively-scored tasks keep a full slice. Only negative
    /// scores are penalized:
    ///   - Neutral (0.0) or trusted (+1.0) → 1.0×
    ///   - Adversarial (-1.0)              → 0.25×
    ///
    /// This avoids pre-penalizing long-lived desktop tasks that have not yet
    /// exited and therefore have not produced any trust observations.
    pub fn slice_factor(&self, pid: i32) -> f64 {
        let t = self.trust_score(pid);
        if t >= 0.0 {
            1.0
        } else {
            (1.0 + t as f64 * 0.75).clamp(0.25, 1.0)
        }
    }

    /// Evict a PID's slot when a process fully exits the system.
    pub fn evict(&mut self, pid: i32) {
        if let Some(s) = self.find_slot(pid) {
            self.pids[s] = PID_TOMBSTONE;
            self.scores[s] = 0.0;
            self.comms[s] = [0u8; 16];
            self.flagged[s] = false;
            self.cheat_streak[s] = 0;
            self.tgid_scores[s] = 0.0;
        }
    }

    // ── Trust watchlist (worst trust scores first) ───────────────────────────

    /// Return the up-to-`SHAME_MAX` most distrusted PIDs (worst trust scores).
    ///
    /// Returns a fixed-size array and a count `n` of valid entries in `[..n]`.
    ///
    /// Runs in O(TRUST_TABLE_SIZE = 4096) — called only from `update_tui()`
    /// every 50 ms, never from the hot scheduling dispatch path.
    ///
    pub fn worst_actors(&self) -> ([ShameEntry; SHAME_MAX], usize) {
        let mut out = [ShameEntry::ZERO; SHAME_MAX];
        let mut n = 0usize;

        for slot in 0..TRUST_TABLE_SIZE {
            let pid = self.pids[slot];
            if pid <= 0 {
                continue;
            }
            let score = self.scores[slot];
            if score < TRUST_THRESHOLD {
                let entry = ShameEntry {
                    pid,
                    trust: score,
                    comm: self.comms[slot],
                    flagged: self.flagged[slot],
                };
                if n < SHAME_MAX {
                    out[n] = entry;
                    n += 1;
                } else {
                    // Fixed-array replacement: swap with the least-bad current entry.
                    // O(SHAME_MAX) = O(20) — negligible.
                    if let Some(pos) = out[..n].iter().position(|e| e.trust > score) {
                        out[pos] = entry;
                    }
                }
            }
        }
        (out, n)
    }

    // ── Metric counters ───────────────────────────────────────────────────────

    /// Count of PIDs currently below the trust threshold.
    ///
    /// O(TRUST_TABLE_SIZE) — called only from `get_metrics()` (every 50 ms).
    pub fn quarantined_count(&self) -> u64 {
        self.pids
            .iter()
            .zip(self.scores.iter())
            .filter(|(&pid, &score)| pid != 0 && score < TRUST_THRESHOLD)
            .filter(|(&pid, _)| pid > 0)
            .count() as u64
    }

    /// Count of anomaly-flagged PIDs.
    ///
    /// O(TRUST_TABLE_SIZE) — called only from `get_metrics()`.
    pub fn flagged_count(&self) -> u64 {
        self.pids
            .iter()
            .zip(self.flagged.iter())
            .filter(|(&pid, &f)| pid != 0 && f)
            .filter(|(&pid, _)| pid > 0)
            .count() as u64
    }

    // ── Periodic tick ─────────────────────────────────────────────────────────

    /// Periodic maintenance tick — reserved for future time-decay of trust scores.
    ///
    /// Returns a fixed-size list of newly flagged PIDs. Currently always empty
    /// because watchlist flags are set eagerly in `update_on_exit`; the return
    /// type remains for call-site compatibility.
    pub fn tick(&self, _now_ns: u64) -> ([i32; 64], usize) {
        // Future extension: apply periodic trust decay for inactive PIDs.
        // e.g.: score[s] *= 0.999 for slots with last_seen_ns > 30s
        // For now: no-op.
        ([0i32; 64], 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutral_initial_score() {
        let t = TrustTable::new().expect("trust table");
        assert_eq!(t.trust_score(1234), 0.0);
        assert!(!t.is_quarantined(1234));
        assert!(!t.is_flagged(1234));
    }

    #[test]
    fn cooperative_exits_improve_trust() {
        let mut t = TrustTable::new().expect("trust table");
        let obs = ExitObservation {
            slice_underrun: true,
            clean_exit: true,
            ..ExitObservation::default()
        };
        for _ in 0..20 {
            t.update_on_exit(999, 999, &obs, "test");
        }
        assert!(
            t.trust_score(999) > 0.0,
            "repeated cooperative exits should raise trust above neutral"
        );
    }

    #[test]
    fn adversarial_exits_lower_trust_to_quarantine() {
        let mut t = TrustTable::new().expect("trust table");
        let obs = ExitObservation {
            cheat_flagged: true,
            preempted: true,
            ..ExitObservation::default()
        };
        for _ in 0..10 {
            t.update_on_exit(42, 42, &obs, "badproc");
        }
        assert!(
            t.is_quarantined(42),
            "repeatedly cheat-flagged process must be quarantined"
        );
        assert!(
            t.is_flagged(42),
            "repeatedly cheat-flagged process must be anomaly-flagged"
        );
    }

    #[test]
    fn clean_exit_clears_cheat_flag() {
        let mut t = TrustTable::new().expect("trust table");
        // First, trigger the flag.
        let bad = ExitObservation {
            cheat_flagged: true,
            ..Default::default()
        };
        for _ in 0..3 {
            t.update_on_exit(7, 7, &bad, "x");
        }
        assert!(t.is_flagged(7));
        // One clean exit resets the streak and clears the flag.
        let clean = ExitObservation {
            clean_exit: true,
            ..Default::default()
        };
        t.update_on_exit(7, 7, &clean, "x");
        assert!(!t.is_flagged(7), "clean exit must clear the anomaly flag");
    }

    #[test]
    fn evict_clears_slot() {
        let mut t = TrustTable::new().expect("trust table");
        let obs = ExitObservation {
            cheat_flagged: true,
            ..Default::default()
        };
        for _ in 0..10 {
            t.update_on_exit(7, 7, &obs, "x");
        }
        assert!(t.trust_score(7) < 0.0);
        t.evict(7);
        // Slot now empty → trust_score returns 0.0.
        assert_eq!(t.trust_score(7), 0.0);
    }

    #[test]
    fn slice_factor_ranges() {
        let mut t = TrustTable::new().expect("trust table");
        // Unknown PID → neutral score → no penalty.
        let f_neutral = t.slice_factor(9999);
        assert!(
            (f_neutral - 1.0).abs() < 0.01,
            "neutral trust → 1.0×, got {f_neutral}"
        );
        // Fully trusted → 1.0×
        let obs_good = ExitObservation {
            slice_underrun: true,
            clean_exit: true,
            ..Default::default()
        };
        for _ in 0..100 {
            t.update_on_exit(1, 1, &obs_good, "good");
        }
        let f_high = t.slice_factor(1);
        assert!(
            f_high > 0.9,
            "trusted task should have near-1.0× slice factor"
        );
        // Adversarial → 0.25× minimum.
        let obs_bad = ExitObservation {
            cheat_flagged: true,
            preempted: true,
            ..Default::default()
        };
        for _ in 0..50 {
            t.update_on_exit(2, 2, &obs_bad, "bad");
        }
        let f_low = t.slice_factor(2);
        assert!(
            f_low < 0.35,
            "adversarial task should have near-0.25× slice factor"
        );
    }

    #[test]
    fn worst_actors_finds_low_trust_entries() {
        let mut t = TrustTable::new().expect("trust table");
        let bad = ExitObservation {
            cheat_flagged: true,
            preempted: true,
            ..Default::default()
        };
        for _ in 0..15 {
            t.update_on_exit(1, 1, &bad, "malicious");
        }
        let good = ExitObservation {
            slice_underrun: true,
            clean_exit: true,
            ..Default::default()
        };
        for _ in 0..20 {
            t.update_on_exit(2, 2, &good, "normal");
        }
        let (entries, n) = t.worst_actors();
        assert!(n >= 1, "at least one bad actor expected");
        assert!(
            entries[..n].iter().any(|e| e.pid == 1),
            "PID 1 should appear in worst_actors"
        );
        assert!(
            !entries[..n].iter().any(|e| e.pid == 2),
            "PID 2 (good actor) should NOT appear in worst_actors"
        );
    }

    #[test]
    fn colliding_pids_keep_independent_trust() {
        let mut t = TrustTable::new().expect("trust table");
        let good = ExitObservation {
            slice_underrun: true,
            clean_exit: true,
            ..Default::default()
        };
        let bad = ExitObservation {
            cheat_flagged: true,
            preempted: true,
            ..Default::default()
        };

        t.update_on_exit(2, 2, &good, "good");
        t.update_on_exit(2586, 2586, &bad, "bad");

        assert!(t.trust_score(2) > 0.0);
        assert!(t.trust_score(2586) < 0.0);
    }

    #[test]
    fn str_to_comm_truncates_at_15() {
        let comm = str_to_comm("this_is_a_very_long_comm_name");
        assert_eq!(comm[15], 0, "last byte must be NUL");
        let s = std::str::from_utf8(&comm[..15]).unwrap();
        assert_eq!(s, "this_is_a_very_");
    }
}
