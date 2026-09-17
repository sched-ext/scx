// SPDX-License-Identifier: GPL-2.0
/*
 * Snapshot reads
 *
 * Builds the metrics view and the dashboard view from the BPF maps and the
 * static cards. Gauges only with no deltas. Frequency, LLC, and CPU cards stay
 * display only and never shape placement.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

use crate::Scheduler;
use crate::stats;

use stats::EnergyMetrics;

/* Waiting entry bound in W. Idle near 7 W sits well under, light */
/* near 30 W sits well over, so 15.0 W marks the idle floor. */
pub(crate) const PROBE_WAIT_ENTER_W: f64 = 15.0;
/* Waiting exit bound in W. Hysteresis over entry keeps flap out, */
/* light near 30 W clears 20.0 W while idle near 7 W stays under. */
pub(crate) const PROBE_WAIT_EXIT_W: f64 = 20.0;
/* Waiting entry debounce ticks. Five low W ticks prove idle, missed ticks */
/* freeze the count with no reset and no advance. */
pub(crate) const PROBE_WAIT_ENTER_TICKS: u32 = 5;
/* Waiting exit debounce ticks. Five high W ticks prove load, missed ticks */
/* freeze the count with no reset and no advance. */
pub(crate) const PROBE_WAIT_EXIT_TICKS: u32 = 5;
/* Waiting timeout seconds. One hundred eighty seconds parks idle, */
/* then collecting resumes with re wait on still idle W. */
pub(crate) const PROBE_WAIT_TIMEOUT_SECS: u64 = 180;
/* Bad intervals before backoff. Five straight bad seconds park */
/* the probe for a minute, then collection starts over. */
pub(crate) const PROBE_MAX_CONSEC_INVALID: u32 = 5;
/* Backoff seconds after repeated bad intervals. */
pub(crate) const PROBE_BACKOFF_SECS: u64 = 60;
/* Gap seconds proving a missed window. Five seconds stands far */
/* past tick jitter, so a resume keeps the meter with no trip. */
pub(crate) const PROBE_MAX_GAP_S: f64 = 5.0;
/* Microjoules in one kWh. Maps package joules to kWh for the meter. */
pub(crate) const UJ_PER_KWH: f64 = 3_600_000_000_000.0;

/* Top state of the energy probe. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ProbeState {
    Unavailable,
    Baseline,
    Collecting,
    Waiting,
    Backoff,
}

/* One snapshot tick for the probe. */
pub(crate) struct ProbeSample {
    pub rapl_present: bool,
    pub delta_uj: Option<u64>,
    pub dt_s: f64,
    pub perf_governor: bool,
    pub online_changed: bool,
}

/*
 * Meter over package joules. Counts used joules since launch, so the hero
 * shows cumulative kWh with a live watts readout. Idle parks in waiting on
 * low W, load returns on high W, timeout resumes collecting with re wait.
 * Suspend, resume, hotplug, and gaps keep the meter with no trip.
 * Restart clears all history, since nothing is stored off process.
 * Placement follows the governor only.
 */
pub(crate) struct EnergyProbe {
    state: ProbeState,
    /* Used microjoules since launch for the meter. */
    total_uj: u64,
    /* Last good watts for the live readout. None before the first read. */
    last_watts: Option<f64>,
    consec_invalid: u32,
    backoff_left: u64,
    backoff_wall_s: f64,
    /* Low W ticks toward waiting entry while collecting. */
    wait_enter: u32,
    /* High W ticks toward collecting exit while waiting. */
    wait_exit: u32,
    /* Seconds parked in waiting toward timeout. */
    wait_wall_s: f64,
    trace: String,
}

impl EnergyProbe {
    /* Fresh probe opening in collecting with an empty meter. */
    pub(crate) fn new() -> Self {
        let mut p = Self {
            state: ProbeState::Collecting,
            total_uj: 0,
            last_watts: None,
            consec_invalid: 0,
            backoff_left: 0,
            backoff_wall_s: 0.0,
            wait_enter: 0,
            wait_exit: 0,
            wait_wall_s: 0.0,
            trace: String::new(),
        };
        p.render_trace();
        p
    }

    /* Watts of one tick from joules and time. Missed yields nothing. */
    fn tick_watts(delta_uj: Option<u64>, dt_s: f64) -> Option<f64> {
        let uj = delta_uj?;
        if dt_s <= 0.0 {
            return None;
        }
        Some(uj as f64 / dt_s / 1_000_000.0)
    }

    /* Enter waiting with a fresh wall and frozen entry count. */
    fn enter_waiting(&mut self) {
        self.state = ProbeState::Waiting;
        self.wait_enter = 0;
        self.wait_exit = 0;
        self.wait_wall_s = 0.0;
    }

    /* Leave waiting into collecting with a fresh wall. */
    fn exit_waiting(&mut self) {
        self.state = ProbeState::Collecting;
        self.wait_enter = 0;
        self.wait_exit = 0;
        self.wait_wall_s = 0.0;
    }

    /* One word state text for the schema. */
    fn state_text(&self) -> &'static str {
        match self.state {
            ProbeState::Unavailable => "unavailable",
            ProbeState::Baseline => "baseline",
            ProbeState::Collecting => "collecting",
            ProbeState::Waiting => "waiting",
            ProbeState::Backoff => "backoff",
        }
    }

    /* Seconds left in waiting or backoff from wall clock. */
    fn countdown(&self) -> u64 {
        match self.state {
            ProbeState::Backoff => self.backoff_left,
            ProbeState::Waiting => {
                let left = PROBE_WAIT_TIMEOUT_SECS as f64 - self.wait_wall_s;
                left.ceil().clamp(0.0, PROBE_WAIT_TIMEOUT_SECS as f64) as u64
            }
            _ => 0,
        }
    }

    /* Refresh the backoff countdown from true elapsed. */
    fn refresh_countdown(&mut self) {
        if self.state != ProbeState::Backoff {
            return;
        }
        let left = PROBE_BACKOFF_SECS as f64 - self.backoff_wall_s;
        self.backoff_left = left.ceil().clamp(0.0, PROBE_BACKOFF_SECS as f64) as u64;
    }

    /* Rebuild the monospace derivation for the page. */
    fn render_trace(&mut self) {
        let mut t = String::new();
        match self.state {
            ProbeState::Unavailable => {
                t.push_str("state unavailable\n");
                t.push_str("no package counter found, check permissions\n");
            }
            ProbeState::Baseline => {
                t.push_str("state baseline, paused while governor reads performance\n");
            }
            ProbeState::Waiting => {
                t.push_str(&format!(
                    "state waiting {:.0}s to timeout, idle under {:.1}W\n",
                    (PROBE_WAIT_TIMEOUT_SECS as f64 - self.wait_wall_s).max(0.0),
                    PROBE_WAIT_ENTER_W
                ));
            }
            ProbeState::Backoff => {
                t.push_str(&format!(
                    "state backoff {}s left after bad intervals\n",
                    self.backoff_left
                ));
            }
            ProbeState::Collecting => {
                t.push_str("state collecting\n");
            }
        }
        match self.last_watts {
            Some(w) => {
                t.push_str(&format!("live {w:.1}W\n"));
            }
            None => {
                t.push_str("live unknown\n");
            }
        }
        /* Meter shows used energy since launch. */
        t.push_str(&format!(
            "meter used {:.6} kWh since launch\n",
            self.total_uj as f64 / UJ_PER_KWH
        ));
        t.push_str("section shows energy consumed since launch, note numbers for manual compare\n");
        self.trace = t;
    }

    /*
     * Drive one snapshot tick. Missing RAPL parks the probe unavailable. Perf
     * governor suspends into baseline. Gaps and hotplug keep the meter with
     * no trip. Five straight bad intervals park the probe in backoff for a
     * minute. Idle parks in waiting on low W, load returns on high W,
     * timeout resumes collecting with re wait. Missed ticks freeze waiting
     * counts with no reset and no advance. Used joules add to the meter on
     * every good read. Live watts follow the last good read with no trip.
     * Countdown follows wall clock, not tick count.
     */
    pub(crate) fn tick(&mut self, s: &ProbeSample) {
        /* Count used joules for the meter on every good read. */
        if let Some(uj) = s.delta_uj {
            self.total_uj = self.total_uj.saturating_add(uj);
        }
        /* Track live watts on valid time with no hotplug move. */
        /* Missed reads keep the last good watts with no clear. */
        if s.rapl_present
            && !s.online_changed
            && s.dt_s > 0.0
            && s.dt_s <= PROBE_MAX_GAP_S
            && let Some(w) = Self::tick_watts(s.delta_uj, s.dt_s)
        {
            self.last_watts = Some(w);
        }
        if !s.rapl_present {
            if self.state != ProbeState::Unavailable {
                self.state = ProbeState::Unavailable;
                self.last_watts = None;
                self.wait_enter = 0;
                self.wait_exit = 0;
                self.wait_wall_s = 0.0;
                self.consec_invalid = 0;
                self.backoff_wall_s = 0.0;
                self.backoff_left = 0;
            }
            self.render_trace();
            return;
        }
        if s.perf_governor {
            if self.state != ProbeState::Baseline {
                self.state = ProbeState::Baseline;
                self.wait_enter = 0;
                self.wait_exit = 0;
                self.wait_wall_s = 0.0;
                self.consec_invalid = 0;
                self.backoff_wall_s = 0.0;
                self.backoff_left = 0;
            }
            self.render_trace();
            return;
        }
        match self.state {
            ProbeState::Unavailable | ProbeState::Baseline => {
                self.state = ProbeState::Collecting;
                self.wait_enter = 0;
                self.wait_exit = 0;
                self.wait_wall_s = 0.0;
                self.consec_invalid = 0;
                self.backoff_wall_s = 0.0;
                self.backoff_left = 0;
            }
            ProbeState::Waiting => {
                /* Hotplug, gaps, and bad time stay waiting. Missed ticks */
                /* freeze exit counts with wall kept. */
                if s.online_changed || s.dt_s > PROBE_MAX_GAP_S || s.dt_s <= 0.0 {
                    self.wait_exit = 0;
                    self.refresh_countdown();
                    self.render_trace();
                    return;
                }
                if s.dt_s > 0.0 {
                    self.wait_wall_s += s.dt_s;
                }
                self.refresh_countdown();
                if self.wait_wall_s >= PROBE_WAIT_TIMEOUT_SECS as f64 {
                    self.exit_waiting();
                    self.refresh_countdown();
                    self.render_trace();
                    return;
                }
                if let Some(w) = Self::tick_watts(s.delta_uj, s.dt_s) {
                    if w > PROBE_WAIT_EXIT_W {
                        self.wait_exit += 1;
                    } else {
                        self.wait_exit = 0;
                    }
                    if self.wait_exit >= PROBE_WAIT_EXIT_TICKS {
                        self.exit_waiting();
                        self.refresh_countdown();
                        self.render_trace();
                        return;
                    }
                }
                self.refresh_countdown();
                self.render_trace();
                return;
            }
            ProbeState::Backoff => {
                if s.dt_s > 0.0 {
                    self.backoff_wall_s += s.dt_s;
                }
                self.refresh_countdown();
                if self.backoff_wall_s >= PROBE_BACKOFF_SECS as f64 {
                    self.state = ProbeState::Collecting;
                    self.backoff_wall_s = 0.0;
                    self.backoff_left = 0;
                    self.consec_invalid = 0;
                    self.wait_enter = 0;
                    self.wait_exit = 0;
                    self.wait_wall_s = 0.0;
                    self.refresh_countdown();
                }
                self.render_trace();
                return;
            }
            ProbeState::Collecting => {}
        }
        if s.online_changed || s.dt_s > PROBE_MAX_GAP_S || s.dt_s <= 0.0 {
            self.refresh_countdown();
            self.render_trace();
            return;
        }
        /* Waiting entry on low W. Missed ticks freeze the count. */
        if let Some(w) = Self::tick_watts(s.delta_uj, s.dt_s) {
            if w < PROBE_WAIT_ENTER_W {
                self.wait_enter = self.wait_enter.saturating_add(1);
            } else {
                self.wait_enter = 0;
            }
        }
        if self.wait_enter >= PROBE_WAIT_ENTER_TICKS {
            self.enter_waiting();
            self.refresh_countdown();
            self.render_trace();
            return;
        }
        match s.delta_uj {
            Some(_) => {
                self.consec_invalid = 0;
            }
            None => {
                self.consec_invalid += 1;
                if self.consec_invalid >= PROBE_MAX_CONSEC_INVALID {
                    self.state = ProbeState::Backoff;
                    self.backoff_wall_s = 0.0;
                    self.backoff_left = PROBE_BACKOFF_SECS;
                    self.wait_enter = 0;
                    self.wait_exit = 0;
                    self.wait_wall_s = 0.0;
                    self.refresh_countdown();
                    self.render_trace();
                    return;
                }
            }
        }
        self.refresh_countdown();
        self.render_trace();
    }

    /* Snapshot view for the dashboard schema. Meter only. */
    pub(crate) fn output(&self, _uptime_s: f64) -> EnergyMetrics {
        let since_kwh = self.total_uj as f64 / UJ_PER_KWH;
        EnergyMetrics {
            state: self.state_text().to_string(),
            since_running_kwh: since_kwh,
            live_watts: self.last_watts.unwrap_or(0.0),
            countdown_s: self.countdown(),
            trace: self.trace.clone(),
        }
    }
}

impl<'a> Scheduler<'a> {
    pub(crate) fn get_metrics(&self) -> stats::Metrics {
        let bss = self.skel.maps.bss_data.as_ref().expect("bss missing");
        let s = &bss.flow_stats;
        stats::Metrics {
            on_cpu: s.on_cpu,
            total_runtime: s.total_runtime,
            uptime_ns: self.started_at.elapsed().as_nanos() as u64,
            inserts: s.inserts,
            requeues: s.requeues,
            completions: s.completions,
            park_moves: s.park_moves,
            steal_moves: s.steal_moves,
            kicks: s.kicks,
            enq_no_tctx: s.enq_no_tctx,
            edf_enqueued: s.edf_enqueued,
            edf_clamped: s.edf_clamped,
            edf_ordered: s.edf_ordered,
            group_demote: s.group_demote,
            group_promote: s.group_promote,
            pinned_hog_inflated: s.pinned_hog_inflated,
            group_steal_skipped: s.group_steal_skipped,
            group_wake_promote: s.group_wake_promote,
            preempt_kicks: s.preempt_kicks,
            preempt_skipped: s.preempt_skipped,
            kick_coalesced: s.kick_coalesced,
            preempt_skipped_armed: s.preempt_skipped_armed,
            preempt_skipped_deserved: s.preempt_skipped_deserved,
            preempt_skipped_group: s.preempt_skipped_group,
            preempt_skipped_mask: s.preempt_skipped_mask,
            preempt_skipped_rate: s.preempt_skipped_rate,
            wheel_overflow: s.wheel_overflow,
            token_boosts: s.token_boosts,
            slot_kicks: s.slot_kicks,
            token_cas_fails: s.token_cas_fails,
            slot_moves: s.slot_moves,
            slot_defer: s.slot_defer,
            steal_xmoves: s.steal_xmoves,
            lifo_heads: s.lifo_heads,
            lifo_bound_hits: s.lifo_bound_hits,
        }
    }

    /*
     * Read one CPU state without heap use. Failed lookups yield an idle view
     * with fixed slice and zero EMA. Slice stays fixed at 1ms. Zero EMA
     * matches BSS and init with no trap.
     */
    pub(crate) fn read_cpu(&self, cpu: usize) -> crate::flow_cpu_state {
        let idle = crate::flow_cpu_state {
            frontier: 0,
            running_est: 0,
            running_pid: 0,
            cursor: 0,
            running_nice: 0,
            running_weight: 1024,
            delay_win: 0,
            delay_cur: 0,
            delay_cnt: 0,
            cpuperf_ema: 0,
            cpuperf_ema_at: 0,
            active_ns: 0,
            occupant_group: 0,
        };
        if cpu >= crate::MAX_CPUS {
            return idle;
        }
        let fd = self.skel.maps.cpu_state_stor.as_fd().as_raw_fd();
        let key = cpu as u32;
        let mut out = MaybeUninit::<crate::flow_cpu_state>::zeroed();
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_lookup_elem(
                fd,
                &key as *const _ as *const std::ffi::c_void,
                out.as_mut_ptr() as *mut std::ffi::c_void,
            )
        };
        if ret == 0 {
            unsafe { out.assume_init() }
        } else {
            idle
        }
    }

    /*
     * Dashboard snapshot. Merges the static cards with live state by online
     * rank. Gauges only, no deltas. Frequency, LLC, and CPU cards stay display
     * only and never feed placement or division. Slice stays fixed at 1ms.
     * Group follows the live table when ready, else halves fallback with no
     * trap. Offline stays out, so per CPU count matches online count. Version,
     * timestamp, topology, depths, allowance, mode, and governor join the
     * counters. The set covers one screenshot and one JSON log. Governor
     * polls online only on the 1s tick with a transition only BSS write, so
     * strict stays quiet.
     */
    pub(crate) fn get_web_metrics(&mut self) -> stats::WebMetrics {
        let (nr_raw, light_depth, hog_depth, burst_allowance_ns) = {
            let bss = self.skel.maps.bss_data.as_ref().expect("bss missing");
            (
                bss.nr_cpu_ids as usize,
                bss.flow_light_depth,
                bss.flow_hog_depth,
                bss.flow_burst_allowance_ns,
            )
        };
        let nr = nr_raw.min(crate::MAX_CPUS);
        let online = if self.online_cpus.is_empty() {
            (0..nr as u32).collect::<Vec<u32>>()
        } else {
            self.online_cpus.clone()
        };
        let now = std::time::Instant::now();
        let old = self
            .freq_read_at
            .is_none_or(|t| now.duration_since(t).as_secs() >= 1);
        if old {
            self.cur_freq_khz.clear();
            for &id in &online {
                self.cur_freq_khz
                    .push(crate::topology::current_freq_khz(id));
            }
            self.freq_read_at = Some(now);
        }
        let gov_old = self
            .governor_read_at
            .is_none_or(|t| now.duration_since(t).as_secs() >= 1);
        if gov_old {
            let governors = crate::topology::collect_governors(&online);
            let mode: u8 = if crate::topology::perf_unanimous(&governors) {
                1
            } else {
                0
            };
            let gov = crate::topology::display_governor(&governors);
            self.governor = gov;
            if mode != self.perf_mode {
                self.perf_mode = mode;
                if let Some(bss) = self.skel.maps.bss_data.as_mut() {
                    bss.flow_perf_mode = mode;
                }
                log::info!(
                    "governor: {} with perf_mode {}",
                    self.governor,
                    self.perf_mode
                );
            }
            self.governor_read_at = Some(now);
        }
        let mut per_cpu = Vec::with_capacity(online.len());
        for (rank, &id) in online.iter().enumerate() {
            let cpu = id as usize;
            let mut e = self
                .cpu_static
                .iter()
                .find(|v| v.id == id)
                .cloned()
                .unwrap_or_default();
            e.id = id;
            e.cur_freq_khz = self.cur_freq_khz.get(rank).copied().unwrap_or(0);
            e.group = crate::flow::group_live(id, nr, &self.group_table, self.group_ready);
            let st = self.read_cpu(cpu);
            e.running_est_ns = st.running_est;
            e.running_pid = st.running_pid;
            e.running_nice = st.running_nice as i32;
            e.running_weight = st.running_weight as u32;
            e.delay_win = st.delay_win;
            e.delay_armed =
                crate::flow::delay_armed_latched(st.delay_win, crate::flow::stand_held(st.cursor));
            e.slice_ns = crate::flow::SLICE_NS;
            e.active_ns = st.active_ns;
            per_cpu.push(e);
        }
        let topology = if self.cpu_static.is_empty() {
            crate::topology::describe_topology(&per_cpu)
        } else {
            crate::topology::describe_topology(&self.cpu_static)
        };
        /*
         * Energy probe tick at 1s cadence. Samples package joules for the
         * cumulative meter with live watts. Placement follows the governor
         * only.
         */
        let now_tick = std::time::Instant::now();
        let rapl_due = self
            .rapl_read_at
            .is_none_or(|t| now_tick.duration_since(t).as_secs_f64() >= 1.0);
        if rapl_due {
            let dt_s = self
                .rapl_read_at
                .map(|t| now_tick.duration_since(t).as_secs_f64())
                .unwrap_or(1.0);
            let delta_uj = self.rapl.as_mut().and_then(|r| r.sample());
            let present = self.rapl.is_some();
            let perf_gov = self.perf_mode == 1;
            let mut known = self.online_cpus.clone();
            known.sort_unstable();
            let mut fresh = crate::topology::online_cpus();
            fresh.sort_unstable();
            let changed = known != fresh;
            self.probe.tick(&ProbeSample {
                rapl_present: present,
                delta_uj,
                dt_s,
                perf_governor: perf_gov,
                online_changed: changed,
            });
            let uptime_s = self.started_at.elapsed().as_secs_f64();
            self.energy = self.probe.output(uptime_s);
            self.rapl_read_at = Some(now_tick);
        }
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|v| v.as_nanos() as u64)
            .unwrap_or(0);
        let stats = self.get_metrics();
        stats::WebMetrics {
            stats,
            per_cpu,
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp_ns,
            topology,
            light_depth,
            hog_depth,
            burst_allowance_ns,
            perf_mode: self.perf_mode,
            governor: self.governor.clone(),
            energy: self.energy.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /* One quiet tick at fixed W. */
    fn quiet(watts: f64) -> ProbeSample {
        let uj = (watts * 1_000_000.0) as u64;
        ProbeSample {
            rapl_present: true,
            delta_uj: Some(uj),
            dt_s: 1.0,
            perf_governor: false,
            online_changed: false,
        }
    }

    /* Ticks since a fresh probe with meter live. */
    fn fresh_ticks(p: &mut EnergyProbe, n: u64) {
        for _ in 0..n {
            let q = quiet(50.0);
            p.tick(&q);
        }
    }

    /* Meter constants hold the live bounds. */
    #[test]
    fn probe_consts_hold_live_bounds() {
        assert_eq!(PROBE_WAIT_ENTER_W, 15.0);
        assert_eq!(PROBE_WAIT_EXIT_W, 20.0);
        assert_eq!(PROBE_WAIT_ENTER_TICKS, 5);
        assert_eq!(PROBE_WAIT_EXIT_TICKS, 5);
        assert_eq!(PROBE_WAIT_TIMEOUT_SECS, 180);
        assert_eq!(PROBE_BACKOFF_SECS, 60);
        assert_eq!(PROBE_MAX_CONSEC_INVALID, 5);
        assert_eq!(PROBE_MAX_GAP_S, 5.0);
        assert_eq!(UJ_PER_KWH, 3_600_000_000_000.0);
    }

    /* Watts helper maps joules over time with no trip. */
    #[test]
    fn tick_watts_maps_joules_over_time() {
        assert_eq!(EnergyProbe::tick_watts(Some(50_000_000), 1.0), Some(50.0));
        assert_eq!(EnergyProbe::tick_watts(None, 1.0), None);
        assert_eq!(EnergyProbe::tick_watts(Some(50_000_000), 0.0), None);
        assert_eq!(EnergyProbe::tick_watts(Some(50_000_000), -1.0), None);
    }

    /* Meter sums joules since launch with no reset. */
    #[test]
    fn meter_sums_joules_since_launch() {
        let mut p = EnergyProbe::new();
        for _ in 0..10 {
            let q = quiet(50.0);
            p.tick(&q);
        }
        let e = p.output(10.0);
        let want = 500_000_000_f64 / UJ_PER_KWH;
        assert!((e.since_running_kwh - want).abs() < 1e-12);
        assert_eq!(e.state, "collecting");
        assert!((e.live_watts - 50.0).abs() < 1e-9);
        for _ in 0..10 {
            let q = quiet(50.0);
            p.tick(&q);
        }
        let two = p.output(20.0);
        let want_two = 1_000_000_000_f64 / UJ_PER_KWH;
        assert!((two.since_running_kwh - want_two).abs() < 1e-12);
    }

    /* Live watts follow the last good read. */
    #[test]
    fn live_watts_follow_last_good_read() {
        let mut p = EnergyProbe::new();
        assert_eq!(p.output(0.0).live_watts, 0.0);
        assert!(p.trace.contains("live unknown"));
        let q = quiet(42.0);
        p.tick(&q);
        assert!((p.output(1.0).live_watts - 42.0).abs() < 1e-9);
        assert!(p.trace.contains("live 42.0W"));
        let miss = ProbeSample {
            delta_uj: None,
            ..quiet(42.0)
        };
        p.tick(&miss);
        assert!((p.output(2.0).live_watts - 42.0).abs() < 1e-9);
    }

    /* Idle parks in waiting with the meter live. */
    #[test]
    fn waiting_enters_on_idle_with_meter_live() {
        let mut p = EnergyProbe::new();
        for _ in 0..70 {
            let q = quiet(7.0);
            p.tick(&q);
        }
        assert_eq!(p.output(100.0).state, "waiting");
        assert!(p.trace.contains("waiting"));
        assert!(p.trace.contains("meter"));
        assert!(p.output(100.0).since_running_kwh > 0.0);
    }

    /* Load returns from waiting with a fresh collect. */
    #[test]
    fn waiting_exits_on_load() {
        let mut p = EnergyProbe::new();
        for _ in 0..70 {
            let q = quiet(7.0);
            p.tick(&q);
        }
        assert_eq!(p.output(100.0).state, "waiting");
        for _ in 0..PROBE_WAIT_EXIT_TICKS {
            let q = quiet(30.0);
            p.tick(&q);
        }
        assert_eq!(p.output(200.0).state, "collecting");
    }

    /* Flap holds with hysteresis and debounce on both sides. */
    #[test]
    fn waiting_flap_holds_with_hysteresis() {
        let mut p = EnergyProbe::new();
        for i in 0..20 {
            let w = if i % 2 == 0 { 7.0 } else { 30.0 };
            let q = quiet(w);
            p.tick(&q);
        }
        assert_eq!(p.output(100.0).state, "collecting");
        for _ in 0..70 {
            let q = quiet(7.0);
            p.tick(&q);
        }
        assert_eq!(p.output(200.0).state, "waiting");
        for i in 0..8 {
            let w = if i % 3 == 2 { 7.0 } else { 30.0 };
            let q = quiet(w);
            p.tick(&q);
        }
        assert_eq!(p.output(300.0).state, "waiting");
    }

    /* Timeout resumes collecting then re waits on still idle W. */
    #[test]
    fn waiting_timeout_resumes_then_rewaits() {
        let mut p = EnergyProbe::new();
        for _ in 0..70 {
            let q = quiet(7.0);
            p.tick(&q);
        }
        assert_eq!(p.output(100.0).state, "waiting");
        /* Run to the timeout with no trip past it. */
        let mut saw_collecting = false;
        for _ in 0..PROBE_WAIT_TIMEOUT_SECS {
            let q = quiet(7.0);
            p.tick(&q);
            if p.output(0.0).state == "collecting" {
                saw_collecting = true;
                break;
            }
        }
        assert!(saw_collecting);
        assert_eq!(p.output(300.0).state, "collecting");
        for _ in 0..10 {
            let q = quiet(7.0);
            p.tick(&q);
        }
        assert_eq!(p.output(500.0).state, "waiting");
    }

    /* Waiting holds idle with the meter live. */
    #[test]
    fn waiting_holds_idle_with_meter_live() {
        let mut p = EnergyProbe::new();
        for _ in 0..70 {
            let q = quiet(7.0);
            p.tick(&q);
        }
        assert_eq!(p.output(100.0).state, "waiting");
        for _ in 0..10 {
            let q = quiet(7.0);
            p.tick(&q);
        }
        assert_eq!(p.output(200.0).state, "waiting");
    }

    /* Perf governor suspends into baseline with the meter live. */
    #[test]
    fn perf_governor_suspends_to_baseline() {
        let mut p = EnergyProbe::new();
        fresh_ticks(&mut p, 10);
        let g = ProbeSample {
            perf_governor: true,
            ..quiet(50.0)
        };
        p.tick(&g);
        assert_eq!(p.output(10.0).state, "baseline");
        p.tick(&g);
        assert_eq!(p.output(10.0).state, "baseline");
        let q = quiet(50.0);
        p.tick(&q);
        assert_eq!(p.output(20.0).state, "collecting");
        assert!(p.trace.contains("collecting"));
    }

    /* Hotplug and gaps keep the meter with no trip. */
    #[test]
    fn hotplug_and_gap_keep_meter() {
        let mut p = EnergyProbe::new();
        fresh_ticks(&mut p, 10);
        let before = p.output(10.0).since_running_kwh;
        let h = ProbeSample {
            online_changed: true,
            ..quiet(50.0)
        };
        p.tick(&h);
        assert!(p.output(11.0).since_running_kwh > before);
        assert_eq!(p.output(11.0).state, "collecting");
        fresh_ticks(&mut p, 10);
        let mid = p.output(20.0).since_running_kwh;
        let gap = ProbeSample {
            rapl_present: true,
            delta_uj: Some(300_000_000),
            dt_s: 6.0,
            perf_governor: false,
            online_changed: false,
        };
        p.tick(&gap);
        assert!(p.output(21.0).since_running_kwh > mid);
        assert_eq!(p.output(21.0).state, "collecting");
    }

    /* Five bad intervals park the probe in backoff. */
    #[test]
    fn bad_intervals_park_in_backoff() {
        let mut p = EnergyProbe::new();
        fresh_ticks(&mut p, 5);
        for _ in 0..5 {
            let b = ProbeSample {
                delta_uj: None,
                ..quiet(50.0)
            };
            p.tick(&b);
        }
        let e = p.output(60.0);
        assert_eq!(e.state, "backoff");
        assert_eq!(e.countdown_s, 60);
        for _ in 0..PROBE_BACKOFF_SECS {
            let q = quiet(50.0);
            p.tick(&q);
        }
        assert_eq!(p.output(200.0).state, "collecting");
    }

    /* Missing RAPL parks the probe unavailable. */
    #[test]
    fn missing_rapl_is_unavailable() {
        let mut p = EnergyProbe::new();
        let m = ProbeSample {
            rapl_present: false,
            delta_uj: None,
            ..quiet(50.0)
        };
        p.tick(&m);
        let e = p.output(10.0);
        assert_eq!(e.state, "unavailable");
        assert!(e.trace.contains("unavailable"));
    }

    /* Trace carries state, live watts, meter, and manual note. */
    #[test]
    fn trace_carries_meter_derivation() {
        let mut p = EnergyProbe::new();
        for _ in 0..10 {
            let q = quiet(50.0);
            p.tick(&q);
        }
        assert!(p.trace.contains("collecting"));
        assert!(p.trace.contains("live 50.0W"));
        assert!(p.trace.contains("meter"));
        assert!(p.trace.contains("since launch"));
        assert!(p.trace.contains("note numbers"));
        assert!(p.trace.contains("manual compare"));
    }

    /* Countdown tracks waiting timeout and backoff wall. */
    #[test]
    fn countdown_tracks_waiting_and_backoff() {
        let mut p = EnergyProbe::new();
        for _ in 0..70 {
            let q = quiet(7.0);
            p.tick(&q);
        }
        assert_eq!(p.output(0.0).state, "waiting");
        let wait_left = p.output(0.0).countdown_s;
        assert!(wait_left <= PROBE_WAIT_TIMEOUT_SECS);
        assert!(wait_left > 0);
        let mut b = EnergyProbe::new();
        fresh_ticks(&mut b, 5);
        for _ in 0..5 {
            let miss = ProbeSample {
                delta_uj: None,
                ..quiet(50.0)
            };
            b.tick(&miss);
        }
        assert_eq!(b.output(0.0).state, "backoff");
        assert_eq!(b.output(0.0).countdown_s, 60);
    }

    /* Default energy view reads unavailable with an empty meter. */
    #[test]
    fn energy_default_is_unavailable() {
        let e = EnergyMetrics::default();
        assert_eq!(e.state, "unavailable");
        assert_eq!(e.since_running_kwh, 0.0);
        assert_eq!(e.live_watts, 0.0);
        assert_eq!(e.countdown_s, 0);
    }
}
