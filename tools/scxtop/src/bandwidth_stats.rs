// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Memory-bandwidth and L3 occupancy collection via Intel RDT / AMD PQoS
//! monitoring exported through the kernel's resctrl filesystem.
//!
//! Reads counters from `/sys/fs/resctrl/mon_data/mon_L3_<id>/` and derives
//! bytes-per-second rates from tick-to-tick deltas.

use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const RESCTRL_ROOT: &str = "/sys/fs/resctrl";

/// Event-name keys used to store bandwidth samples in the shared
/// per-topology EventData maps.
pub const EVENT_MBM_LOCAL_BPS: &str = "mbm_local_bps";
pub const EVENT_MBM_TOTAL_BPS: &str = "mbm_total_bps";
pub const EVENT_LLC_OCCUPANCY: &str = "llc_occupancy_bytes";

pub const ALL_EVENTS: &[&str] = &[
    EVENT_MBM_LOCAL_BPS,
    EVENT_MBM_TOTAL_BPS,
    EVENT_LLC_OCCUPANCY,
];

/// Per-L3-domain reading derived from a single sample.
#[derive(Copy, Clone, Debug, Default)]
pub struct LlcBandwidth {
    /// Local (same-NUMA) memory bandwidth in bytes/sec.
    pub mbm_local_bps: u64,
    /// Total memory bandwidth in bytes/sec.
    pub mbm_total_bps: u64,
    /// Instantaneous L3 occupancy in bytes.
    pub llc_occupancy_bytes: u64,
}

/// Result of a sample() call: one reading per L3 domain, keyed by
/// resctrl domain id (matches [`scx_utils::Topology`]'s LLC `kernel_id`).
#[derive(Clone, Debug, Default)]
pub struct BandwidthSnapshot {
    pub per_domain: BTreeMap<usize, LlcBandwidth>,
}

#[derive(Clone, Debug)]
enum State {
    /// Detection has not been attempted yet.
    Uninit,
    /// Ready to sample. Holds the last raw counter values and their timestamp.
    Ready {
        domains: Vec<Domain>,
        has_local: bool,
        has_total: bool,
        has_occupancy: bool,
    },
    /// Detection failed; reason is displayed in the view.
    Unavailable(String),
}

#[derive(Clone, Debug)]
struct Domain {
    id: usize,
    path: PathBuf,
    last_local: Option<u64>,
    last_total: Option<u64>,
    last_read: Option<Instant>,
}

pub struct BandwidthStats {
    state: State,
}

impl Default for BandwidthStats {
    fn default() -> Self {
        Self {
            state: State::Uninit,
        }
    }
}

impl BandwidthStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Human-readable description of the current source (or the reason
    /// no source is available). Suitable for a view header.
    pub fn source_label(&self) -> String {
        match &self.state {
            State::Uninit => "resctrl (not probed)".to_string(),
            State::Ready {
                has_local,
                has_total,
                has_occupancy,
                ..
            } => {
                let mut feats: Vec<&str> = Vec::new();
                if *has_local {
                    feats.push("local_bw");
                }
                if *has_total {
                    feats.push("total_bw");
                }
                if *has_occupancy {
                    feats.push("occupancy");
                }
                format!("resctrl [{}]", feats.join(","))
            }
            State::Unavailable(reason) => format!("unavailable: {reason}"),
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self.state, State::Ready { .. })
    }

    /// Returns which of the three metrics the current source actually
    /// exposes. Used by the renderer to hide/label empty panels.
    pub fn feature_flags(&self) -> (bool, bool, bool) {
        match &self.state {
            State::Ready {
                has_local,
                has_total,
                has_occupancy,
                ..
            } => (*has_local, *has_total, *has_occupancy),
            _ => (false, false, false),
        }
    }

    /// Reads all monitor domains and returns per-LLC bandwidth. Returns
    /// `Ok(None)` if the source is unavailable.
    ///
    /// The first successful call primes the deltas and returns `Ok(Some(..))`
    /// with zero-valued bandwidths (occupancy is a gauge, so it's populated
    /// immediately).
    pub fn sample(&mut self) -> Result<Option<BandwidthSnapshot>> {
        if matches!(self.state, State::Uninit) {
            self.state = detect();
        }
        let State::Ready {
            domains,
            has_local,
            has_total,
            has_occupancy,
            ..
        } = &mut self.state
        else {
            return Ok(None);
        };

        let now = Instant::now();
        let mut out = BandwidthSnapshot::default();

        for dom in domains.iter_mut() {
            let mut reading = LlcBandwidth::default();

            // Bandwidth (rate metrics: need a delta).
            let cur_local = if *has_local {
                read_counter(&dom.path.join("mbm_local_bytes"))
                    .ok()
                    .flatten()
            } else {
                None
            };
            let cur_total = if *has_total {
                read_counter(&dom.path.join("mbm_total_bytes"))
                    .ok()
                    .flatten()
            } else {
                None
            };

            if let (Some(prev), Some(cur), Some(prev_t)) =
                (dom.last_local, cur_local, dom.last_read)
            {
                reading.mbm_local_bps = to_bps(prev, cur, now.duration_since(prev_t).as_secs_f64());
            }
            if let (Some(prev), Some(cur), Some(prev_t)) =
                (dom.last_total, cur_total, dom.last_read)
            {
                reading.mbm_total_bps = to_bps(prev, cur, now.duration_since(prev_t).as_secs_f64());
            }

            if *has_occupancy {
                if let Ok(Some(occ)) = read_counter(&dom.path.join("llc_occupancy")) {
                    reading.llc_occupancy_bytes = occ;
                }
            }

            dom.last_local = cur_local.or(dom.last_local);
            dom.last_total = cur_total.or(dom.last_total);
            dom.last_read = Some(now);

            out.per_domain.insert(dom.id, reading);
        }

        Ok(Some(out))
    }
}

fn detect() -> State {
    let root = Path::new(RESCTRL_ROOT);
    if !root.is_dir() {
        return State::Unavailable(format!("{RESCTRL_ROOT} not present"));
    }
    let mon_data = root.join("mon_data");
    if !mon_data.is_dir() {
        return State::Unavailable(
            "resctrl not mounted (try: mount -t resctrl resctrl /sys/fs/resctrl)".to_string(),
        );
    }

    let features = fs::read_to_string(root.join("info/L3_MON/mon_features")).unwrap_or_default();
    let has_local = features
        .split_ascii_whitespace()
        .any(|f| f == "mbm_local_bytes");
    let has_total = features
        .split_ascii_whitespace()
        .any(|f| f == "mbm_total_bytes");
    let has_occupancy = features
        .split_ascii_whitespace()
        .any(|f| f == "llc_occupancy");
    if !has_local && !has_total && !has_occupancy {
        return State::Unavailable("L3_MON exposes no supported features".to_string());
    }

    let domains = match enumerate_domains(&mon_data) {
        Ok(d) if !d.is_empty() => d,
        Ok(_) => return State::Unavailable("no mon_L3_* domains found".to_string()),
        Err(e) => return State::Unavailable(format!("enumerate mon_data: {e}")),
    };

    State::Ready {
        domains,
        has_local,
        has_total,
        has_occupancy,
    }
}

fn enumerate_domains(mon_data: &Path) -> Result<Vec<Domain>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(mon_data)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(rest) = name.strip_prefix("mon_L3_") else {
            continue;
        };
        let id = match rest.parse::<usize>() {
            Ok(id) => id,
            Err(_) => continue,
        };
        out.push(Domain {
            id,
            path: entry.path(),
            last_local: None,
            last_total: None,
            last_read: None,
        });
    }
    out.sort_by_key(|d| d.id);
    Ok(out)
}

/// Reads a resctrl counter file. Returns `Ok(None)` when the counter
/// reports "Unavailable" (kernel signals that the RMID lost its slot).
fn read_counter(path: &Path) -> Result<Option<u64>> {
    let raw = fs::read_to_string(path)?;
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("Unavailable") {
        return Ok(None);
    }
    match trimmed.parse::<u64>() {
        Ok(v) => Ok(Some(v)),
        Err(e) => bail!("parse {}: {}", path.display(), e),
    }
}

fn to_bps(prev: u64, cur: u64, seconds: f64) -> u64 {
    if seconds <= 0.0 {
        return 0;
    }
    // The kernel unwraps hardware counters into a 64-bit software counter,
    // so a simple wrapping delta is enough for the pathological reset case.
    let delta = cur.wrapping_sub(prev);
    (delta as f64 / seconds) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bps_zero_when_no_elapsed() {
        assert_eq!(to_bps(100, 200, 0.0), 0);
    }

    #[test]
    fn bps_computes_rate() {
        assert_eq!(to_bps(1_000, 2_000, 1.0), 1_000);
        assert_eq!(to_bps(0, 1_000_000_000, 2.0), 500_000_000);
    }

    #[test]
    fn bps_handles_wrap() {
        assert_eq!(to_bps(u64::MAX - 99, u64::MAX, 1.0), 99);
        assert_eq!(to_bps(u64::MAX, 0, 1.0), 1);
    }

    #[test]
    fn detect_reports_unavailable_gracefully() {
        // We just want to prove the collector doesn't panic when nothing is
        // present. On CI the resctrl root may or may not exist.
        let mut s = BandwidthStats::new();
        let _ = s.sample();
        let label = s.source_label();
        assert!(!label.is_empty());
    }
}
