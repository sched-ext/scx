use std::time::{Duration, Instant};

use crate::bpf_skel::BpfSkel;

pub(crate) const CAKE_TRUST_FLAG_PREV_DIRECT: u32 = 1 << 0;
pub(crate) const CAKE_TRUST_DEMOTE_NONE: u32 = 0;
pub(crate) const CAKE_TRUST_DEMOTE_PREV_CLAIM_MISS: u32 = 1;

const CAKE_CONF_SELECT_EARLY_SHIFT: u32 = 0;
const CAKE_CONF_PULL_SHAPE_SHIFT: u32 = 24;
const CAKE_CONF_ROUTE_SHIFT: u32 = 28;
const CAKE_CONF_ROUTE_KIND_SHIFT: u32 = 32;
const CAKE_CONF_STATUS_TRUST_SHIFT: u32 = 52;
const CAKE_CONF_LOAD_SHOCK_SHIFT: u32 = 60;
const CAKE_CONF_NIBBLE_MASK: u64 = 0xf;
const CAKE_ROUTE_PREV: u64 = 1;

const TRUST_TICK_PERIOD: Duration = Duration::from_millis(250);
const TRUST_COOLDOWN: Duration = Duration::from_secs(2);
const TRUST_ROUTE_MIN: u64 = 15;
const TRUST_SELECT_MIN: u64 = 14;
const TRUST_STATUS_MIN: u64 = 15;
const TRUST_PULL_MIN: u64 = 12;
const TRUST_SHOCK_MAX: u64 = 7;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CpuTrustSnapshot {
    pub policy: u32,
    pub generation: u32,
    pub blocked: u32,
    pub blocked_generation: u32,
    pub reason: u32,
    pub demotion_count: u32,
}

impl CpuTrustSnapshot {
    pub(crate) fn prev_direct_enabled(self) -> bool {
        self.policy & CAKE_TRUST_FLAG_PREV_DIRECT != 0
    }

    pub(crate) fn prev_direct_blocked(self) -> bool {
        self.prev_direct_enabled()
            && self.blocked_generation == self.generation
            && self.blocked & CAKE_TRUST_FLAG_PREV_DIRECT != 0
    }

    pub(crate) fn prev_direct_active(self) -> bool {
        self.prev_direct_enabled() && !self.prev_direct_blocked()
    }
}

pub(crate) struct TrustGovernor {
    cooldown_until: Vec<Instant>,
    last_seen_demotions: Vec<u32>,
    last_tick: Option<Instant>,
}

impl TrustGovernor {
    pub(crate) fn new(nr_cpus: usize) -> Self {
        Self {
            cooldown_until: vec![Instant::now(); nr_cpus],
            last_seen_demotions: vec![0; nr_cpus],
            last_tick: None,
        }
    }

    pub(crate) fn tick(&mut self, skel: &mut BpfSkel, nr_cpus: usize) {
        let now = Instant::now();
        if self
            .last_tick
            .is_some_and(|last| now.duration_since(last) < TRUST_TICK_PERIOD)
        {
            return;
        }
        self.last_tick = Some(now);
        self.ensure_cpu_capacity(nr_cpus, now);

        let Some(bss) = &mut skel.maps.bss_data else {
            return;
        };

        let limit = nr_cpus
            .min(bss.cpu_bss.len())
            .min(bss.trust_user.len())
            .min(bss.trust_bpf.len());
        for idx in 0..limit {
            let confidence = bss.cpu_bss[idx].decision_confidence;
            let bpf_demotions = bss.trust_bpf[idx].demotion_count;
            if bpf_demotions != self.last_seen_demotions[idx] {
                self.cooldown_until[idx] = now + TRUST_COOLDOWN;
                self.last_seen_demotions[idx] = bpf_demotions;
            }

            let ready = confidence_trust_prev_ready(confidence);
            let generation = bss.trust_user[idx].generation;
            let cooling_down = now < self.cooldown_until[idx];
            let policy = bss.trust_user[idx].policy;

            if !ready || cooling_down {
                if policy & CAKE_TRUST_FLAG_PREV_DIRECT != 0 {
                    bss.trust_user[idx].policy = policy & !CAKE_TRUST_FLAG_PREV_DIRECT;
                }
                continue;
            }

            if policy & CAKE_TRUST_FLAG_PREV_DIRECT == 0 {
                bss.trust_user[idx].generation = generation.wrapping_add(1).max(1);
                bss.trust_user[idx].policy = policy | CAKE_TRUST_FLAG_PREV_DIRECT;
            }
        }
    }

    fn ensure_cpu_capacity(&mut self, nr_cpus: usize, now: Instant) {
        if self.cooldown_until.len() < nr_cpus {
            self.cooldown_until.resize(nr_cpus, now);
        }
        if self.last_seen_demotions.len() < nr_cpus {
            self.last_seen_demotions.resize(nr_cpus, 0);
        }
    }
}

pub(crate) fn extract_trust_snapshots(skel: &BpfSkel, nr_cpus: usize) -> Vec<CpuTrustSnapshot> {
    let mut rows = vec![CpuTrustSnapshot::default(); nr_cpus];
    let Some(bss) = &skel.maps.bss_data else {
        return rows;
    };

    let limit = nr_cpus.min(bss.trust_user.len()).min(bss.trust_bpf.len());
    for (idx, row) in rows.iter_mut().enumerate().take(limit) {
        row.policy = bss.trust_user[idx].policy;
        row.generation = bss.trust_user[idx].generation;
        row.blocked = bss.trust_bpf[idx].blocked;
        row.blocked_generation = bss.trust_bpf[idx].generation;
        row.reason = bss.trust_bpf[idx].reason;
        row.demotion_count = bss.trust_bpf[idx].demotion_count;
    }
    rows
}

pub(crate) fn trust_demotion_label(reason: u32) -> &'static str {
    match reason {
        CAKE_TRUST_DEMOTE_NONE => "none",
        CAKE_TRUST_DEMOTE_PREV_CLAIM_MISS => "prev_claim_miss",
        _ => "unknown",
    }
}

fn conf_value(confidence: u64, shift: u32) -> u64 {
    (confidence >> shift) & CAKE_CONF_NIBBLE_MASK
}

fn confidence_trust_prev_ready(confidence: u64) -> bool {
    confidence != 0
        && conf_value(confidence, CAKE_CONF_ROUTE_KIND_SHIFT) == CAKE_ROUTE_PREV
        && conf_value(confidence, CAKE_CONF_ROUTE_SHIFT) >= TRUST_ROUTE_MIN
        && conf_value(confidence, CAKE_CONF_SELECT_EARLY_SHIFT) >= TRUST_SELECT_MIN
        && conf_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT) >= TRUST_STATUS_MIN
        && conf_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT) >= TRUST_PULL_MIN
        && conf_value(confidence, CAKE_CONF_LOAD_SHOCK_SHIFT) <= TRUST_SHOCK_MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    fn confidence(
        route_kind: u64,
        route: u64,
        select: u64,
        status: u64,
        pull: u64,
        shock: u64,
    ) -> u64 {
        (route_kind << CAKE_CONF_ROUTE_KIND_SHIFT)
            | (route << CAKE_CONF_ROUTE_SHIFT)
            | (select << CAKE_CONF_SELECT_EARLY_SHIFT)
            | (status << CAKE_CONF_STATUS_TRUST_SHIFT)
            | (pull << CAKE_CONF_PULL_SHAPE_SHIFT)
            | (shock << CAKE_CONF_LOAD_SHOCK_SHIFT)
    }

    #[test]
    fn confidence_trust_prev_requires_prev_route_and_thresholds() {
        let ready = confidence(
            CAKE_ROUTE_PREV,
            TRUST_ROUTE_MIN,
            TRUST_SELECT_MIN,
            TRUST_STATUS_MIN,
            TRUST_PULL_MIN,
            TRUST_SHOCK_MAX,
        );

        assert!(confidence_trust_prev_ready(ready));
        assert!(!confidence_trust_prev_ready(0));
        assert!(!confidence_trust_prev_ready(confidence(
            2,
            TRUST_ROUTE_MIN,
            TRUST_SELECT_MIN,
            TRUST_STATUS_MIN,
            TRUST_PULL_MIN,
            TRUST_SHOCK_MAX,
        )));
        assert!(!confidence_trust_prev_ready(confidence(
            CAKE_ROUTE_PREV,
            TRUST_ROUTE_MIN - 1,
            TRUST_SELECT_MIN,
            TRUST_STATUS_MIN,
            TRUST_PULL_MIN,
            TRUST_SHOCK_MAX,
        )));
        assert!(!confidence_trust_prev_ready(confidence(
            CAKE_ROUTE_PREV,
            TRUST_ROUTE_MIN,
            TRUST_SELECT_MIN - 1,
            TRUST_STATUS_MIN,
            TRUST_PULL_MIN,
            TRUST_SHOCK_MAX,
        )));
        assert!(!confidence_trust_prev_ready(confidence(
            CAKE_ROUTE_PREV,
            TRUST_ROUTE_MIN,
            TRUST_SELECT_MIN,
            TRUST_STATUS_MIN - 1,
            TRUST_PULL_MIN,
            TRUST_SHOCK_MAX,
        )));
        assert!(!confidence_trust_prev_ready(confidence(
            CAKE_ROUTE_PREV,
            TRUST_ROUTE_MIN,
            TRUST_SELECT_MIN,
            TRUST_STATUS_MIN,
            TRUST_PULL_MIN - 1,
            TRUST_SHOCK_MAX,
        )));
        assert!(!confidence_trust_prev_ready(confidence(
            CAKE_ROUTE_PREV,
            TRUST_ROUTE_MIN,
            TRUST_SELECT_MIN,
            TRUST_STATUS_MIN,
            TRUST_PULL_MIN,
            TRUST_SHOCK_MAX + 1,
        )));
    }

    #[test]
    fn trust_snapshot_tracks_enabled_blocked_and_active_generation() {
        let disabled = CpuTrustSnapshot::default();
        assert!(!disabled.prev_direct_enabled());
        assert!(!disabled.prev_direct_blocked());
        assert!(!disabled.prev_direct_active());

        let active = CpuTrustSnapshot {
            policy: CAKE_TRUST_FLAG_PREV_DIRECT,
            generation: 7,
            blocked: 0,
            blocked_generation: 7,
            ..Default::default()
        };
        assert!(active.prev_direct_enabled());
        assert!(!active.prev_direct_blocked());
        assert!(active.prev_direct_active());

        let blocked = CpuTrustSnapshot {
            blocked: CAKE_TRUST_FLAG_PREV_DIRECT,
            ..active
        };
        assert!(blocked.prev_direct_enabled());
        assert!(blocked.prev_direct_blocked());
        assert!(!blocked.prev_direct_active());

        let old_block = CpuTrustSnapshot {
            blocked_generation: 6,
            ..blocked
        };
        assert!(old_block.prev_direct_enabled());
        assert!(!old_block.prev_direct_blocked());
        assert!(old_block.prev_direct_active());
    }

    #[test]
    fn trust_demotion_labels_are_stable_for_reports() {
        assert_eq!(trust_demotion_label(CAKE_TRUST_DEMOTE_NONE), "none");
        assert_eq!(
            trust_demotion_label(CAKE_TRUST_DEMOTE_PREV_CLAIM_MISS),
            "prev_claim_miss"
        );
        assert_eq!(trust_demotion_label(u32::MAX), "unknown");
    }
}
