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

/* Seconds of one probe arm. Thirty second arms hold the */
/* ninety five percent half width near half a W in the */
/* light regime, see the SE table in the RAPL probe data. */
pub(crate) const PROBE_ARM_SECS: u64 = 30;
/* Lead seconds dropped per arm. Power and frequency settle inside three */
/* seconds after a step in the RAPL probe data. */
pub(crate) const PROBE_DISCARD_LEAD_S: f64 = 3.0;
/* Tail seconds dropped per arm. Teardown tails run two to */
/* four seconds in the RAPL probe data, two keeps twenty five. */
pub(crate) const PROBE_DISCARD_TAIL_S: f64 = 2.0;
/* Shortest honest arm in seconds. Twenty seconds still resolves */
/* near one W at ninety five percent in the light regime, */
/* see the detection table in the RAPL probe data. Never lower. */
pub(crate) const PROBE_MIN_ARM_SECS: u64 = 20;
/* Fewest kept samples to accept one arm. Twenty five survive */
/* the discard from a full arm, so twenty tolerates a few */
/* missed ticks with no weak arm entering the sums. */
pub(crate) const PROBE_MIN_KEPT: usize = 20;
/* Settle seconds between arms. Two thirty second arms with two three second settles make the */
/* sixty six second pair cycle. */
pub(crate) const PROBE_SETTLE_SECS: u64 = 3;
/* Relative noise bound. Idle CV 21.7 percent and soak light 11.2 percent */
/* need headroom, light 4.2 percent and load 2.0 percent stay well under, so */
/* 0.15 splits steady arms from churn. */
pub(crate) const PROBE_STD_REL: f64 = 0.15;
/* Noise floor in W. Idle median near 7 W times 0.15 is near 1.0, */
/* so 1.5 W rejects idle churn while light near 30 W uses 4.5 W, */
/* load near 100 W uses 15.0 W with no false trip. */
pub(crate) const PROBE_STD_FLOOR_W: f64 = 1.5;
/* Relative outlier bound. Idle spike 127 percent must reject, light hump */
/* 18.7 percent and load hump 5.2 percent must pass, so 0.35 splits the probe */
/* spikes with margin. */
pub(crate) const PROBE_OUTLIER_REL: f64 = 0.35;
/* Outlier floor in W. Idle median near 7 W times 0.35 is near 2.4, */
/* so 3.0 W rejects idle spikes while light near 30 W uses 10.5 W, */
/* load near 100 W uses 35.0 W with no false trip. */
pub(crate) const PROBE_OUTLIER_FLOOR_W: f64 = 3.0;
/* Trim retry bound. One retry drops at most two farthest from median samples */
/* on noise and outlier fails only, then all stats recompute from the trimmed */
/* set with no cherry pick. */
pub(crate) const PROBE_TRIM_MAX: usize = 2;
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
/* then one pair attempts with re wait on still idle W. */
pub(crate) const PROBE_WAIT_TIMEOUT_SECS: u64 = 180;
/* Accepted pairs before headlines. One pair never headlines, */
/* three to four pairs carry a low confidence hint. Three */
/* is policy, not measurement. */
pub(crate) const PROBE_MIN_PAIRS: u64 = 3;
/* Smallest honest perf joules for a headline. Below one */
/* millijoule the ratio turns noise into absurd percent. */
pub(crate) const PROBE_MIN_J: f64 = 1e-3;
/* Bad intervals before backoff. Five straight bad seconds park */
/* the probe for a minute, then collection starts over. */
pub(crate) const PROBE_MAX_CONSEC_INVALID: u32 = 5;
/* Backoff seconds after repeated bad intervals. */
pub(crate) const PROBE_BACKOFF_SECS: u64 = 60;
/* Gap seconds proving a missed window. Five seconds stands far */
/* past tick jitter, so a resume starts a fresh pair. */
pub(crate) const PROBE_MAX_GAP_S: f64 = 5.0;
/* Active plausibility slack in nanos. Ten milliseconds covers boundary */
/* segments and clock read skew over one arm. */
pub(crate) const PROBE_ACTIVE_SLACK_NS: u64 = 10_000_000;

/* Top state of the energy probe. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ProbeState {
    Unavailable,
    Baseline,
    Collecting,
    Waiting,
    Backoff,
}

/* Arm under collection. Settle separates both arms. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ProbePhase {
    Strict,
    Perf,
    Settle,
}

/* One tick inside an arm. */
#[derive(Clone, Copy, Debug)]
pub(crate) struct ArmSample {
    offset_s: f64,
    dt_s: f64,
    watts: f64,
    joules: f64,
}

/* Accepted arm summary. */
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ArmStats {
    joules: f64,
    secs: f64,
    kept: u64,
    mean_w: f64,
    median_w: f64,
    p99_w: f64,
    std_w: f64,
    min_w: f64,
    max_w: f64,
    /* Dropped farthest from median samples on one retry. */
    trimmed: u64,
}

/* Why one arm stayed out of the sums. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ArmReject {
    TooFew,
    TooNoisy,
    Outlier,
    Implausible,
}

/* Accepted pair summary. */
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PairRecord {
    strict_j: f64,
    perf_j: f64,
    delta_j: f64,
    secs: f64,
}

/* Mean of one slice. Empty yields zero. */
pub(crate) fn probe_mean(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.iter().sum::<f64>() / v.len() as f64
}

/* Population stdev of one slice. Empty yields zero. */
pub(crate) fn probe_std(v: &[f64], mean: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let var = v.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / v.len() as f64;
    var.sqrt()
}

/* Median of one slice. Empty yields zero. Sorts a copy. */
pub(crate) fn probe_median(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    }
}

/* Ninety ninth percentile by nearest rank. Empty yields zero. */
pub(crate) fn probe_p99(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let rank = (0.99 * s.len() as f64).ceil() as usize;
    s[rank.clamp(1, s.len()) - 1]
}

/*
 * Judge one arm as a unit. Drops the lead and tail window, then checks kept
 * count, noise, outlier, and per CPU plausibility in order. Noise rejects past
 * max floor and relative share of median, outlier rejects past max floor and
 * relative share of median. One retry drops at most two farthest from median
 * samples on noise and outlier fails only, then all stats recompute from the
 * trimmed set. Too few and implausible never trim, nor below kept minimum. Any
 * failure rejects the whole arm, so the pair falls with it and nothing is
 * cherry picked. Empty active snapshots pass vacuously, so an old BPF object
 * without the active tail still measures.
 */
pub(crate) fn evaluate_arm(
    samples: &[ArmSample],
    arm_wall_s: f64,
    active_start: &[stats::PerCpuMetrics],
    active_end: &[stats::PerCpuMetrics],
) -> Result<ArmStats, ArmReject> {
    let mut watts: Vec<f64> = Vec::new();
    let mut kept_joules: Vec<f64> = Vec::new();
    let mut kept_dt: Vec<f64> = Vec::new();
    let mut joules = 0.0;
    let mut secs = 0.0;
    let mut min_w = f64::INFINITY;
    let mut max_w = f64::NEG_INFINITY;
    for s in samples {
        if s.offset_s < PROBE_DISCARD_LEAD_S {
            continue;
        }
        if s.offset_s >= arm_wall_s - PROBE_DISCARD_TAIL_S {
            continue;
        }
        watts.push(s.watts);
        kept_joules.push(s.joules);
        kept_dt.push(s.dt_s);
        joules += s.joules;
        secs += s.dt_s;
        if s.watts < min_w {
            min_w = s.watts;
        }
        if s.watts > max_w {
            max_w = s.watts;
        }
    }
    if watts.len() < PROBE_MIN_KEPT {
        return Err(ArmReject::TooFew);
    }
    /* Noise and outlier bounds from median with floor. Idle CV 21.7 percent, */
    /* soak light 11.2 percent sit over light 4.2 percent, and load 2.0 */
    /* percent, so relative and floor splits steady arms from churn. Idle */
    /* spike 127 percent must reject, light hump 18.7 percent and load hump */
    /* 5.2 percent must pass, so relative and floor splits spikes from humps. */
    let median = probe_median(&watts);
    let mean = probe_mean(&watts);
    let std = probe_std(&watts, mean);
    let noise_bound = PROBE_STD_FLOOR_W.max(PROBE_STD_REL * median);
    let outlier_bound = PROBE_OUTLIER_FLOOR_W.max(PROBE_OUTLIER_REL * median);
    let noisy = std > noise_bound;
    let wild = max_w - median > outlier_bound;
    if !noisy && !wild {
        let wall_ns = (arm_wall_s * 1e9) as u64;
        for end in active_end {
            if let Some(start) = active_start.iter().find(|c| c.id == end.id)
                && end.active_delta(start) > wall_ns.saturating_add(PROBE_ACTIVE_SLACK_NS)
            {
                return Err(ArmReject::Implausible);
            }
        }
        return Ok(ArmStats {
            joules,
            secs,
            kept: watts.len() as u64,
            mean_w: mean,
            median_w: median,
            p99_w: probe_p99(&watts),
            std_w: std,
            min_w,
            max_w,
            trimmed: 0,
        });
    }
    /* Single retry on noise and outlier fails only. Drops at most two */
    /* farthest from median samples, never below kept minimum, then all stats */
    /* recompute from the trimmed set with no cherry pick beyond the retry. */
    let max_drop = PROBE_TRIM_MAX.min(watts.len().saturating_sub(PROBE_MIN_KEPT));
    if max_drop == 0 {
        if noisy {
            return Err(ArmReject::TooNoisy);
        }
        return Err(ArmReject::Outlier);
    }
    let mut order: Vec<usize> = (0..watts.len()).collect();
    order.sort_by(|a, b| {
        (watts[*b] - median)
            .abs()
            .partial_cmp(&(watts[*a] - median).abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    /* Try one dropped, then two dropped, keep least dropped pass. */
    let mut last_err = if noisy {
        ArmReject::TooNoisy
    } else {
        ArmReject::Outlier
    };
    for drop in 1..=max_drop {
        let mut dropped = vec![false; watts.len()];
        for k in 0..drop {
            dropped[order[k]] = true;
        }
        let mut tw: Vec<f64> = Vec::with_capacity(watts.len() - drop);
        let mut tj = 0.0;
        let mut ts = 0.0;
        let mut tmin = f64::INFINITY;
        let mut tmax = f64::NEG_INFINITY;
        for (i, w) in watts.iter().enumerate() {
            if dropped[i] {
                continue;
            }
            tw.push(*w);
            tj += kept_joules[i];
            ts += kept_dt[i];
            if *w < tmin {
                tmin = *w;
            }
            if *w > tmax {
                tmax = *w;
            }
        }
        let tmedian = probe_median(&tw);
        let tmean = probe_mean(&tw);
        let tstd = probe_std(&tw, tmean);
        if tstd > PROBE_STD_FLOOR_W.max(PROBE_STD_REL * tmedian) {
            last_err = ArmReject::TooNoisy;
            continue;
        }
        if tmax - tmedian > PROBE_OUTLIER_FLOOR_W.max(PROBE_OUTLIER_REL * tmedian) {
            last_err = ArmReject::Outlier;
            continue;
        }
        let wall_ns = (arm_wall_s * 1e9) as u64;
        let mut bad = false;
        for end in active_end {
            if let Some(start) = active_start.iter().find(|c| c.id == end.id)
                && end.active_delta(start) > wall_ns.saturating_add(PROBE_ACTIVE_SLACK_NS)
            {
                bad = true;
                break;
            }
        }
        if bad {
            return Err(ArmReject::Implausible);
        }
        return Ok(ArmStats {
            joules: tj,
            secs: ts,
            kept: tw.len() as u64,
            mean_w: tmean,
            median_w: tmedian,
            p99_w: probe_p99(&tw),
            std_w: tstd,
            min_w: tmin,
            max_w: tmax,
            trimmed: drop as u64,
        });
    }
    /* Storm keeps failing past two dropped with no pass. */
    if last_err == ArmReject::TooNoisy {
        return Err(ArmReject::TooNoisy);
    }
    Err(ArmReject::Outlier)
}

/*
 * Saved percent from the ratio of sums. Needs three accepted pairs and perf
 * joules past one millijoule, else nothing. Ratio of sums, never the mean of
 * ratios.
 */
pub(crate) fn headline_pct(sum_d_j: f64, sum_perf_j: f64, accepted: u64) -> Option<f64> {
    if accepted < PROBE_MIN_PAIRS {
        return None;
    }
    if sum_perf_j < PROBE_MIN_J {
        return None;
    }
    Some(sum_d_j / sum_perf_j * 100.0)
}

/*
 * Saved W from per arm means. Perf mean minus strict
 * mean over kept seconds in all accepted pairs, so
 * unequal kept durations carry no bias by construction.
 */
pub(crate) fn saved_watts(
    sum_perf_j: f64,
    sum_perf_secs: f64,
    sum_strict_j: f64,
    sum_strict_secs: f64,
) -> f64 {
    if sum_perf_secs <= 0.0 || sum_strict_secs <= 0.0 {
        return 0.0;
    }
    sum_perf_j / sum_perf_secs - sum_strict_j / sum_strict_secs
}

/* Energy in kWh from W over hours. */
pub(crate) fn energy_kwh(watts: f64, hours: f64) -> f64 {
    watts * hours / 1000.0
}

/* One snapshot tick for the probe. */
pub(crate) struct ProbeSample<'a> {
    pub rapl_present: bool,
    pub delta_uj: Option<u64>,
    pub dt_s: f64,
    pub perf_governor: bool,
    pub online_changed: bool,
    pub active: &'a [stats::PerCpuMetrics],
}

/*
 * A/B probe over package joules. Alternates strict and perf arms with settle
 * gaps, judges each pair as a unit, and keeps the ratio of sums once three
 * pairs land. Idle parks in waiting on low W with no pair cost, load returns on
 * high W, timeout tries one pair with re wait. Suspend, resume, hotplug, and
 * gaps discard the in flight pair with no partial credit. Restart clears all
 * history, since nothing is stored off process.
 */
pub(crate) struct EnergyProbe {
    state: ProbeState,
    phase: ProbePhase,
    phase_left: u64,
    perf_first: bool,
    pending_perf: bool,
    arm: Vec<ArmSample>,
    arm_wall_s: f64,
    settle_wall_s: f64,
    backoff_wall_s: f64,
    pending_miss_s: f64,
    arm_active_start: Vec<stats::PerCpuMetrics>,
    first: Option<ArmStats>,
    first_is_perf: bool,
    accepted_pairs: u64,
    rejected_pairs: u64,
    sum_d_j: f64,
    sum_perf_j: f64,
    sum_secs: f64,
    sum_perf_secs: f64,
    sum_strict_secs: f64,
    last_pair: Option<PairRecord>,
    last_strict: Option<ArmStats>,
    last_perf: Option<ArmStats>,
    last_active: Option<(u32, f64)>,
    last_reject: Option<ArmReject>,
    consec_invalid: u32,
    backoff_left: u64,
    /* Low W ticks toward waiting entry while collecting. */
    wait_enter: u32,
    /* High W ticks toward collecting exit while waiting. */
    wait_exit: u32,
    /* Seconds parked in waiting toward timeout. */
    wait_wall_s: f64,
    want_force: bool,
    trace: String,
}

impl EnergyProbe {
    /* Fresh probe opening with settle into a strict arm. */
    pub(crate) fn new() -> Self {
        let mut p = Self {
            state: ProbeState::Collecting,
            phase: ProbePhase::Settle,
            phase_left: PROBE_SETTLE_SECS,
            perf_first: true,
            pending_perf: false,
            arm: Vec::new(),
            arm_wall_s: 0.0,
            settle_wall_s: 0.0,
            backoff_wall_s: 0.0,
            pending_miss_s: 0.0,
            arm_active_start: Vec::new(),
            first: None,
            first_is_perf: false,
            accepted_pairs: 0,
            rejected_pairs: 0,
            sum_d_j: 0.0,
            sum_perf_j: 0.0,
            sum_secs: 0.0,
            sum_perf_secs: 0.0,
            sum_strict_secs: 0.0,
            last_pair: None,
            last_strict: None,
            last_perf: None,
            last_active: None,
            last_reject: None,
            consec_invalid: 0,
            backoff_left: 0,
            wait_enter: 0,
            wait_exit: 0,
            wait_wall_s: 0.0,
            want_force: false,
            trace: String::new(),
        };
        p.begin_pair();
        p.render_trace();
        p
    }

    /* True while the perf arm wants the internal force. */
    pub(crate) fn want_force(&self) -> bool {
        self.want_force
    }

    /* True once the in flight pair holds any arm data. */
    fn pair_started(&self) -> bool {
        self.first.is_some() || !self.arm.is_empty()
    }

    /* Drop the in flight pair with one reject when started. */
    fn discard_pair(&mut self) {
        if self.pair_started() {
            self.rejected_pairs += 1;
            self.last_reject = None;
        }
        self.first = None;
        self.arm.clear();
        self.arm_wall_s = 0.0;
        self.settle_wall_s = 0.0;
        self.pending_miss_s = 0.0;
        self.arm_active_start.clear();
    }

    /* Open one arm with a fresh window. */
    fn begin_arm(&mut self, perf: bool) {
        self.arm.clear();
        self.arm_wall_s = 0.0;
        self.settle_wall_s = 0.0;
        self.pending_miss_s = 0.0;
        self.arm_active_start.clear();
        self.phase = if perf {
            ProbePhase::Perf
        } else {
            ProbePhase::Strict
        };
        self.phase_left = PROBE_ARM_SECS.max(PROBE_MIN_ARM_SECS);
        self.want_force = perf;
    }

    /* Open one pair through settle with alternating order. */
    fn begin_pair(&mut self) {
        self.perf_first = !self.perf_first;
        self.first = None;
        self.arm.clear();
        self.arm_wall_s = 0.0;
        self.settle_wall_s = 0.0;
        self.pending_miss_s = 0.0;
        self.arm_active_start.clear();
        self.pending_perf = self.perf_first;
        self.phase = ProbePhase::Settle;
        self.phase_left = PROBE_SETTLE_SECS;
        self.want_force = false;
    }

    /* Watts of one tick from joules and time. Missed yields nothing. */
    fn tick_watts(delta_uj: Option<u64>, dt_s: f64) -> Option<f64> {
        let uj = delta_uj?;
        if dt_s <= 0.0 {
            return None;
        }
        Some(uj as f64 / dt_s / 1_000_000.0)
    }

    /* Enter waiting at pair boundary with no reject and strict force. */
    fn enter_waiting(&mut self) {
        self.state = ProbeState::Waiting;
        self.wait_enter = 0;
        self.wait_exit = 0;
        self.wait_wall_s = 0.0;
        self.want_force = false;
    }

    /* Leave waiting into collecting with a fresh pair and strict force. */
    fn exit_waiting(&mut self) {
        self.state = ProbeState::Collecting;
        self.wait_enter = 0;
        self.wait_exit = 0;
        self.wait_wall_s = 0.0;
        self.begin_pair();
    }

    /* Text of one reject reason for the trace. */
    fn reject_text(reason: ArmReject) -> &'static str {
        match reason {
            ArmReject::TooFew => "too few kept samples",
            ArmReject::TooNoisy => "arm too noisy",
            ArmReject::Outlier => "outlier over median",
            ArmReject::Implausible => "active implausible",
        }
    }

    /* Close one arm and move the pair forward. */
    fn finish_arm(&mut self, active_end: &[stats::PerCpuMetrics]) {
        let is_perf = self.phase == ProbePhase::Perf;
        let wall = self.arm_wall_s;
        self.last_active = Self::active_hint(&self.arm_active_start, active_end, wall);
        match evaluate_arm(&self.arm, wall, &self.arm_active_start, active_end) {
            Ok(stats) => {
                if self.first.is_none() {
                    self.first = Some(stats);
                    self.first_is_perf = is_perf;
                    self.pending_perf = !is_perf;
                    self.phase = ProbePhase::Settle;
                    self.phase_left = PROBE_SETTLE_SECS;
                    self.want_force = false;
                    self.arm.clear();
                    self.arm_wall_s = 0.0;
                    self.settle_wall_s = 0.0;
                    self.pending_miss_s = 0.0;
                    self.arm_active_start.clear();
                } else {
                    let first = self.first.unwrap_or_default();
                    let (strict, perf) = if self.first_is_perf {
                        (stats, first)
                    } else {
                        (first, stats)
                    };
                    let delta = perf.joules - strict.joules;
                    self.sum_d_j += delta;
                    self.sum_perf_j += perf.joules;
                    self.sum_secs += strict.secs + perf.secs;
                    self.sum_perf_secs += perf.secs;
                    self.sum_strict_secs += strict.secs;
                    self.accepted_pairs += 1;
                    self.last_pair = Some(PairRecord {
                        strict_j: strict.joules,
                        perf_j: perf.joules,
                        delta_j: delta,
                        secs: strict.secs + perf.secs,
                    });
                    self.last_strict = Some(strict);
                    self.last_perf = Some(perf);
                    self.last_reject = None;
                    self.begin_pair();
                }
            }
            Err(reason) => {
                self.last_reject = Some(reason);
                self.rejected_pairs += 1;
                self.begin_pair();
            }
        }
    }

    /* CPU with the largest active share over one arm. */
    fn active_hint(
        start: &[stats::PerCpuMetrics],
        end: &[stats::PerCpuMetrics],
        wall_s: f64,
    ) -> Option<(u32, f64)> {
        if wall_s <= 0.0 {
            return None;
        }
        let wall_ns = wall_s * 1e9;
        let mut best: Option<(u32, f64)> = None;
        for e in end {
            if let Some(s) = start.iter().find(|c| c.id == e.id) {
                let share = e.active_delta(s) as f64 / wall_ns * 100.0;
                if best.is_none_or(|(_, b)| share > b) {
                    best = Some((e.id, share));
                }
            }
        }
        best
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

    /* Seconds left in the running phase from wall clock. */
    fn countdown(&self) -> u64 {
        match self.state {
            ProbeState::Backoff => self.backoff_left,
            ProbeState::Collecting => self.phase_left,
            _ => 0,
        }
    }

    /* Refresh the wall derived countdown from true elapsed. */
    fn refresh_countdown(&mut self) {
        if self.state == ProbeState::Backoff {
            let left = PROBE_BACKOFF_SECS as f64 - self.backoff_wall_s;
            self.backoff_left = left.ceil().clamp(0.0, PROBE_BACKOFF_SECS as f64) as u64;
            return;
        }
        if self.state != ProbeState::Collecting {
            return;
        }
        let total = match self.phase {
            ProbePhase::Settle => PROBE_SETTLE_SECS as f64,
            ProbePhase::Strict | ProbePhase::Perf => PROBE_ARM_SECS.max(PROBE_MIN_ARM_SECS) as f64,
        };
        let elapsed = match self.phase {
            ProbePhase::Settle => self.settle_wall_s,
            ProbePhase::Strict | ProbePhase::Perf => self.arm_wall_s,
        };
        let left = total - elapsed;
        self.phase_left = left.ceil().clamp(0.0, total) as u64;
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
                let phase = match self.phase {
                    ProbePhase::Strict => "strict arm",
                    ProbePhase::Perf => "perf arm",
                    ProbePhase::Settle => "settle",
                };
                t.push_str(&format!(
                    "state collecting {} {}s left\n",
                    phase, self.phase_left
                ));
            }
        }
        t.push_str(&format!(
            "pairs accepted {} rejected {}\n",
            self.accepted_pairs, self.rejected_pairs
        ));
        if let Some(p) = &self.last_pair {
            let dw = if p.secs > 0.0 {
                p.delta_j / p.secs
            } else {
                0.0
            };
            t.push_str(&format!(
                "last pair strict {:.2}J perf {:.2}J delta {:+.2}J ({:+.2}W)\n",
                p.strict_j, p.perf_j, p.delta_j, dw
            ));
        } else {
            t.push_str("last pair none yet\n");
        }
        if let Some(r) = &self.last_reject {
            t.push_str(&format!("last pair rejected, {}\n", Self::reject_text(*r)));
        }
        if let (Some(s), Some(p)) = (&self.last_strict, &self.last_perf) {
            t.push_str(&format!(
                "arms strict {:.2}W perf {:.2}W dW {:+.2}W\n",
                s.mean_w,
                p.mean_w,
                p.mean_w - s.mean_w
            ));
            t.push_str(&format!(
                "spread strict kept {} std {:.2} median {:.2} p50 {:.2} p99 {:.2} min {:.2} max {:.2}\n",
                s.kept, s.std_w, s.median_w, s.median_w, s.p99_w, s.min_w, s.max_w
            ));
            t.push_str(&format!(
                "spread perf kept {} std {:.2} median {:.2} p50 {:.2} p99 {:.2} min {:.2} max {:.2}\n",
                p.kept, p.std_w, p.median_w, p.median_w, p.p99_w, p.min_w, p.max_w
            ));
            /* Trimmed count from the one retry on noise and outlier fails. */
            t.push_str(&format!(
                "trimmed strict {} perf {}\n",
                s.trimmed, p.trimmed
            ));
        }
        if let Some((id, share)) = &self.last_active {
            t.push_str(&format!("active max CPU{id} {share:.1} percent of wall\n"));
        }
        match headline_pct(self.sum_d_j, self.sum_perf_j, self.accepted_pairs) {
            Some(pct) => {
                t.push_str(&format!(
                    "headline {pct:+.2} percent over {} pairs",
                    self.accepted_pairs
                ));
                if self.accepted_pairs <= 4 {
                    t.push_str(", low confidence");
                }
                t.push('\n');
            }
            None => {
                t.push_str(&format!(
                    "headline needs {} pairs, have {}\n",
                    PROBE_MIN_PAIRS, self.accepted_pairs
                ));
            }
        }
        if self.state != ProbeState::Unavailable {
            t.push_str(
                "perf arms widen placement with natural hints at about 45 percent duty, headline extrapolates strict versus forced perf\n",
            );
        }
        self.trace = t;
    }

    /*
     * Drive one snapshot tick. Missing RAPL parks the probe unavailable. Perf
     * governor suspends into baseline with the force cleared. Hotplug, gaps,
     * and resume drop the in flight pair and open a fresh one. Five straight
     * bad intervals park the probe in backoff for a minute. Idle parks in
     * waiting on low W at pair boundary with no reject and strict force, load
     * returns on high W, timeout tries one pair with re wait. Missed ticks
     * freeze waiting counts with no reset and no advance. One missed read keeps
     * its wall in pending and wall, so the next good delta over the gap keeps
     * true mean. Countdown follows wall clock, not tick count.
     */
    pub(crate) fn tick(&mut self, s: &ProbeSample) {
        if !s.rapl_present {
            if self.state != ProbeState::Unavailable {
                self.discard_pair();
                self.state = ProbeState::Unavailable;
                self.wait_enter = 0;
                self.wait_exit = 0;
                self.wait_wall_s = 0.0;
                self.want_force = false;
            }
            self.render_trace();
            return;
        }
        if s.perf_governor {
            if self.state != ProbeState::Baseline {
                self.discard_pair();
                self.state = ProbeState::Baseline;
                self.wait_enter = 0;
                self.wait_exit = 0;
                self.wait_wall_s = 0.0;
                self.want_force = false;
            }
            self.render_trace();
            return;
        }
        match self.state {
            ProbeState::Unavailable | ProbeState::Baseline => {
                self.state = ProbeState::Collecting;
                self.begin_pair();
                self.wait_enter = 0;
                self.wait_exit = 0;
                self.wait_wall_s = 0.0;
            }
            ProbeState::Waiting => {
                /* Hotplug, gaps, and bad time stay waiting. Missed ticks */
                /* freeze exit counts with wall kept. */
                if s.online_changed || s.dt_s > PROBE_MAX_GAP_S || s.dt_s <= 0.0 {
                    self.wait_exit = 0;
                    self.want_force = false;
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
                self.want_force = false;
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
                    self.begin_pair();
                    self.refresh_countdown();
                }
                self.render_trace();
                return;
            }
            ProbeState::Collecting => {}
        }
        if s.online_changed || s.dt_s > PROBE_MAX_GAP_S || s.dt_s <= 0.0 {
            self.discard_pair();
            self.begin_pair();
            self.refresh_countdown();
            self.render_trace();
            return;
        }
        /* Waiting entry on low W at pair boundary only. */
        /* Missed ticks freeze entry counts with no reset. */
        if let Some(w) = Self::tick_watts(s.delta_uj, s.dt_s) {
            if w < PROBE_WAIT_ENTER_W {
                self.wait_enter = self.wait_enter.saturating_add(1);
            } else {
                self.wait_enter = 0;
            }
        }
        if self.wait_enter >= PROBE_WAIT_ENTER_TICKS && !self.pair_started() {
            self.enter_waiting();
            self.refresh_countdown();
            self.render_trace();
            return;
        }
        match self.phase {
            ProbePhase::Settle => {
                self.want_force = false;
                self.settle_wall_s += s.dt_s;
                self.refresh_countdown();
                if self.settle_wall_s >= PROBE_SETTLE_SECS as f64 {
                    self.begin_arm(self.pending_perf);
                    self.refresh_countdown();
                }
            }
            ProbePhase::Strict | ProbePhase::Perf => {
                self.want_force = self.phase == ProbePhase::Perf;
                if self.arm.is_empty() && self.arm_wall_s == 0.0 {
                    self.arm_active_start = s.active.to_vec();
                }
                match s.delta_uj {
                    Some(uj) => {
                        self.consec_invalid = 0;
                        let eff_dt = s.dt_s + self.pending_miss_s;
                        let use_dt = if eff_dt > 0.0 { eff_dt } else { s.dt_s };
                        self.arm_wall_s += s.dt_s;
                        self.arm.push(ArmSample {
                            offset_s: self.arm_wall_s,
                            dt_s: use_dt,
                            watts: uj as f64 / use_dt / 1_000_000.0,
                            joules: uj as f64 / 1_000_000.0,
                        });
                        self.pending_miss_s = 0.0;
                    }
                    None => {
                        self.consec_invalid += 1;
                        self.arm_wall_s += s.dt_s;
                        self.pending_miss_s += s.dt_s;
                        if self.consec_invalid >= PROBE_MAX_CONSEC_INVALID {
                            self.discard_pair();
                            self.state = ProbeState::Backoff;
                            self.backoff_wall_s = 0.0;
                            self.backoff_left = PROBE_BACKOFF_SECS;
                            self.want_force = false;
                            self.refresh_countdown();
                            self.render_trace();
                            return;
                        }
                    }
                }
                self.refresh_countdown();
                if self.arm_wall_s >= PROBE_ARM_SECS.max(PROBE_MIN_ARM_SECS) as f64 {
                    self.finish_arm(s.active);
                    self.refresh_countdown();
                }
            }
        }
        self.render_trace();
    }

    /* Snapshot view for the dashboard schema. */
    pub(crate) fn output(&self, uptime_s: f64) -> EnergyMetrics {
        let pct = headline_pct(self.sum_d_j, self.sum_perf_j, self.accepted_pairs);
        let has = pct.is_some();
        let sum_strict_j = self.sum_perf_j - self.sum_d_j;
        let save_w = if has {
            saved_watts(
                self.sum_perf_j,
                self.sum_perf_secs,
                sum_strict_j,
                self.sum_strict_secs,
            )
        } else {
            0.0
        };
        let p = pct.unwrap_or(0.0);
        let (daily_kwh, yearly_kwh, since_kwh) = if has {
            (
                energy_kwh(save_w, 24.0),
                energy_kwh(save_w, 8760.0),
                energy_kwh(save_w, uptime_s / 3600.0),
            )
        } else {
            (0.0, 0.0, 0.0)
        };
        EnergyMetrics {
            state: self.state_text().to_string(),
            has_headline: has,
            low_confidence: has && self.accepted_pairs <= 4,
            headline_pct: p,
            accepted_pairs: self.accepted_pairs,
            rejected_pairs: self.rejected_pairs,
            daily_pct: p,
            daily_kwh,
            yearly_pct: p,
            yearly_kwh,
            since_running_kwh: since_kwh,
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
            wheel_skips: s.wheel_skips,
            wheel_overflow: s.wheel_overflow,
            token_boosts: s.token_boosts,
            wheel_head_hits: s.wheel_head_hits,
            wheel_fine_hits: s.wheel_fine_hits,
            wheel_coarse_hits: s.wheel_coarse_hits,
            wheel_empty: s.wheel_empty,
            slot_kicks: s.slot_kicks,
            token_cas_fails: s.token_cas_fails,
            slot_moves: s.slot_moves,
            slot_defer: s.slot_defer,
            steal_xmoves: s.steal_xmoves,
        }
    }

    /*
     * Read one CPU state without heap use. Failed lookups yield an idle view
     * with fixed slice and zero EMA. Slice stays fixed at 1ms. Zero EMA matches
     * BSS and init with no trap.
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
         * Energy probe tick at 1s cadence. Samples package joules and per CPU
         * active time, then drives the strict and perf arms. The BSS force
         * follows arm transitions only, so strict stays quiet.
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
                active: &per_cpu,
            });
            let want: u8 = if self.probe.want_force() { 1 } else { 0 };
            if want != self.probe_force {
                self.probe_force = want;
                if let Some(bss) = self.skel.maps.bss_data.as_mut() {
                    bss.flow_probe_perf = want;
                }
                log::info!("probe force {want}");
            }
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

    /* One quiet tick at fixed W with no active data. */
    fn quiet(watts: f64) -> ProbeSample<'static> {
        let uj = (watts * 1_000_000.0) as u64;
        ProbeSample {
            rapl_present: true,
            delta_uj: Some(uj),
            dt_s: 1.0,
            perf_governor: false,
            online_changed: false,
            active: &[],
        }
    }

    /* Drive one arm of constant W to completion. */
    fn run_arm(p: &mut EnergyProbe, watts: f64) {
        for _ in 0..PROBE_ARM_SECS {
            let q = quiet(watts);
            p.tick(&q);
        }
    }

    /* Drive settle ticks with ignored samples. */
    fn run_settle(p: &mut EnergyProbe) {
        for _ in 0..PROBE_SETTLE_SECS {
            let q = quiet(0.0);
            p.tick(&q);
        }
    }

    /* Drive one full pair with the given arm order. */
    fn run_pair(p: &mut EnergyProbe, first_w: f64, second_w: f64) {
        run_settle(p);
        run_arm(p, first_w);
        run_settle(p);
        run_arm(p, second_w);
    }

    /* Ticks since a fresh probe with no pair done. */
    fn fresh_ticks(p: &mut EnergyProbe, n: u64) {
        for _ in 0..n {
            let q = quiet(50.0);
            p.tick(&q);
        }
    }

    /* Cadence constants hold the honest floor. */
    #[test]
    fn probe_consts_hold_honest_floor() {
        assert_eq!(PROBE_ARM_SECS, 30);
        let arm = PROBE_ARM_SECS;
        let floor = PROBE_MIN_ARM_SECS;
        assert!(arm >= floor);
        assert_eq!(PROBE_MIN_ARM_SECS, 20);
        assert_eq!(PROBE_DISCARD_LEAD_S, 3.0);
        assert_eq!(PROBE_DISCARD_TAIL_S, 2.0);
        assert_eq!(PROBE_MIN_KEPT, 20);
        assert_eq!(PROBE_SETTLE_SECS, 3);
        let kept = PROBE_ARM_SECS - PROBE_DISCARD_LEAD_S as u64 - PROBE_DISCARD_TAIL_S as u64;
        assert_eq!(kept, 25);
        assert_eq!(
            PROBE_ARM_SECS + PROBE_SETTLE_SECS + PROBE_ARM_SECS + PROBE_SETTLE_SECS,
            66
        );
        assert_eq!(PROBE_STD_REL, 0.15);
        assert_eq!(PROBE_STD_FLOOR_W, 1.5);
        assert_eq!(PROBE_OUTLIER_REL, 0.35);
        assert_eq!(PROBE_OUTLIER_FLOOR_W, 3.0);
        assert_eq!(PROBE_TRIM_MAX, 2);
        assert_eq!(PROBE_WAIT_ENTER_W, 15.0);
        assert_eq!(PROBE_WAIT_EXIT_W, 20.0);
        assert_eq!(PROBE_WAIT_ENTER_TICKS, 5);
        assert_eq!(PROBE_WAIT_EXIT_TICKS, 5);
        assert_eq!(PROBE_WAIT_TIMEOUT_SECS, 180);
        assert_eq!(PROBE_MIN_PAIRS, 3);
        assert_eq!(PROBE_BACKOFF_SECS, 60);
        assert_eq!(PROBE_MAX_CONSEC_INVALID, 5);
    }

    /* Mean, median, p99, and std match hand math. */
    #[test]
    fn probe_stats_match_hand_math() {
        assert_eq!(probe_mean(&[]), 0.0);
        assert_eq!(probe_mean(&[2.0, 4.0]), 3.0);
        assert_eq!(probe_median(&[]), 0.0);
        assert_eq!(probe_median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(probe_median(&[4.0, 1.0, 2.0, 3.0]), 2.5);
        assert_eq!(probe_p99(&[]), 0.0);
        assert_eq!(probe_p99(&[5.0]), 5.0);
        let v: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        assert_eq!(probe_p99(&v), 99.0);
        assert_eq!(probe_std(&[], 0.0), 0.0);
        assert!((probe_std(&[2.0, 4.0], 3.0) - 1.0).abs() < 1e-9);
    }

    /* Thirty one second samples keep twenty five. */
    #[test]
    fn discard_window_keeps_twenty_five() {
        let mut samples = Vec::new();
        for i in 1..=30 {
            samples.push(ArmSample {
                offset_s: i as f64,
                dt_s: 1.0,
                watts: 50.0,
                joules: 50.0,
            });
        }
        let got = evaluate_arm(&samples, 30.0, &[], &[]).unwrap();
        assert_eq!(got.kept, 25);
        assert_eq!(got.secs, 25.0);
        assert_eq!(got.joules, 1250.0);
        assert_eq!(got.mean_w, 50.0);
    }

    /* Window edges hold at three and twenty eight. */
    #[test]
    fn discard_window_edges_hold() {
        let mut samples = Vec::new();
        for off in [2.9, 3.0, 27.9, 28.0] {
            samples.push(ArmSample {
                offset_s: off,
                dt_s: 1.0,
                watts: 50.0,
                joules: 50.0,
            });
        }
        for i in 0..20 {
            samples.push(ArmSample {
                offset_s: 10.0 + i as f64 * 0.1,
                dt_s: 1.0,
                watts: 50.0,
                joules: 50.0,
            });
        }
        let got = evaluate_arm(&samples, 30.0, &[], &[]).unwrap();
        assert_eq!(got.kept, 22);
    }

    /* Nineteen kept samples reject the arm. */
    #[test]
    fn too_few_samples_reject() {
        let mut samples = Vec::new();
        for i in 1..=21 {
            samples.push(ArmSample {
                offset_s: i as f64,
                dt_s: 1.0,
                watts: 50.0,
                joules: 50.0,
            });
        }
        assert_eq!(
            evaluate_arm(&samples, 30.0, &[], &[]).unwrap_err(),
            ArmReject::TooFew
        );
    }

    /* Relative noise bound splits steady arms from churn. */
    #[test]
    fn noise_bound_rejects_past_two_watts() {
        let mut loud = Vec::new();
        let mut edge = Vec::new();
        for i in 1..=30 {
            let w = if i % 2 == 0 { 35.0 } else { 25.0 };
            loud.push(ArmSample {
                offset_s: i as f64,
                dt_s: 1.0,
                watts: w,
                joules: w,
            });
            let e = if i % 2 == 0 { 32.0 } else { 28.0 };
            edge.push(ArmSample {
                offset_s: i as f64,
                dt_s: 1.0,
                watts: e,
                joules: e,
            });
        }
        /* Loud std 5.0 W tops the max of 1.5 W and 0.15 times 30 W. */
        assert_eq!(
            evaluate_arm(&loud, 30.0, &[], &[]).unwrap_err(),
            ArmReject::TooNoisy
        );
        /* Edge std 2.0 W stays under the max of 1.5 W and 0.15 times 30 W. */
        let got = evaluate_arm(&edge, 30.0, &[], &[]).unwrap();
        assert_eq!(got.trimmed, 0);
    }

    /* Single spike trims to pass, light hump passes clean. */
    #[test]
    fn outlier_replay_matches_probe_data() {
        let mut spike = Vec::new();
        let mut hump = Vec::new();
        for i in 1..=30 {
            let idle = if i == 15 { 15.9 } else { 7.0 };
            spike.push(ArmSample {
                offset_s: i as f64,
                dt_s: 1.0,
                watts: idle,
                joules: idle,
            });
            let light = if i == 15 { 35.6 } else { 30.0 };
            hump.push(ArmSample {
                offset_s: i as f64,
                dt_s: 1.0,
                watts: light,
                joules: light,
            });
        }
        /* Idle spike 127 percent over median trims one and passes. */
        let got = evaluate_arm(&spike, 30.0, &[], &[]).unwrap();
        assert_eq!(got.trimmed, 1);
        assert!((got.median_w - 7.0).abs() < 1e-9);
        /* Light hump 18.7 percent stays under the max of 3.0 W and 0.35 times median. */
        let h = evaluate_arm(&hump, 30.0, &[], &[]).unwrap();
        assert_eq!(h.trimmed, 0);
    }

    /* Idle steady near 7 W holds under floor and relative. */
    #[test]
    fn idle_replay_passes_near_floor() {
        let mut v = Vec::new();
        for i in 1..=30 {
            let w = if i % 2 == 0 { 8.5 } else { 5.5 };
            v.push(ArmSample {
                offset_s: i as f64,
                dt_s: 1.0,
                watts: w,
                joules: w,
            });
        }
        /* Idle CV 21.7 percent maps near 1.5 W at 7 W median. */
        let got = evaluate_arm(&v, 30.0, &[], &[]).unwrap();
        assert_eq!(got.trimmed, 0);
        assert!((got.mean_w - 7.0).abs() < 0.5);
    }

    /* Light steady near 30 W holds well under relative. */
    #[test]
    fn light_replay_passes_with_margin() {
        let mut v = Vec::new();
        for i in 1..=30 {
            let w = if i % 2 == 0 { 31.3 } else { 28.7 };
            v.push(ArmSample {
                offset_s: i as f64,
                dt_s: 1.0,
                watts: w,
                joules: w,
            });
        }
        /* Light CV 4.2 percent maps near 1.3 W at 30 W median. */
        let got = evaluate_arm(&v, 30.0, &[], &[]).unwrap();
        assert_eq!(got.trimmed, 0);
        assert!((got.mean_w - 30.0).abs() < 0.5);
    }

    /* Load steady near 100 W holds well under relative. */
    #[test]
    fn load_replay_passes_with_margin() {
        let mut v = Vec::new();
        for i in 1..=30 {
            let w = if i % 2 == 0 { 102.0 } else { 98.0 };
            v.push(ArmSample {
                offset_s: i as f64,
                dt_s: 1.0,
                watts: w,
                joules: w,
            });
        }
        /* Load CV 2.0 percent maps near 2.0 W at 100 W median. */
        let got = evaluate_arm(&v, 30.0, &[], &[]).unwrap();
        assert_eq!(got.trimmed, 0);
        assert!((got.mean_w - 100.0).abs() < 0.5);
    }

    /* Close idle arms accept with no headline bias by construction. */
    #[test]
    fn close_idle_arms_accept_with_small_bias() {
        /* Bias under 0.5 W carries no headline bias by construction, since */
        /* ratio of sums weights by kept seconds and per arm means with equal */
        /* windows. */
        let mut a = Vec::new();
        let mut b = Vec::new();
        for i in 1..=30 {
            a.push(ArmSample {
                offset_s: i as f64,
                dt_s: 1.0,
                watts: 7.05,
                joules: 7.05,
            });
            b.push(ArmSample {
                offset_s: i as f64,
                dt_s: 1.0,
                watts: 7.37,
                joules: 7.37,
            });
        }
        let ga = evaluate_arm(&a, 30.0, &[], &[]).unwrap();
        let gb = evaluate_arm(&b, 30.0, &[], &[]).unwrap();
        assert_eq!(ga.trimmed, 0);
        assert_eq!(gb.trimmed, 0);
        assert!((gb.mean_w - ga.mean_w - 0.32).abs() < 1e-9);
    }

    /* Storm with five spikes still rejects past two dropped. */
    #[test]
    fn storm_with_five_spikes_rejects() {
        let mut v = Vec::new();
        for i in 1..=30 {
            let w = if [10, 13, 15, 18, 20].contains(&i) {
                15.9
            } else {
                7.0
            };
            v.push(ArmSample {
                offset_s: i as f64,
                dt_s: 1.0,
                watts: w,
                joules: w,
            });
        }
        /* Five spikes need five dropped, two leave three and fail. */
        assert!(evaluate_arm(&v, 30.0, &[], &[]).is_err());
    }

    /* Idle parks in waiting at pair boundary with no reject. */
    #[test]
    fn waiting_enters_at_boundary_with_no_reject() {
        let mut p = EnergyProbe::new();
        for _ in 0..70 {
            let q = quiet(7.0);
            p.tick(&q);
        }
        assert_eq!(p.output(100.0).state, "waiting");
        assert_eq!(p.rejected_pairs, 0);
        assert!(!p.want_force());
        assert!(p.trace.contains("waiting"));
    }

    /* Load returns from waiting with a fresh pair and strict start. */
    #[test]
    fn waiting_exits_on_load_with_fresh_pair() {
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
        assert!(!p.want_force());
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

    /* Timeout tries one pair then re waits on still idle W. */
    #[test]
    fn waiting_timeout_tries_one_pair_then_rewaits() {
        let mut p = EnergyProbe::new();
        for _ in 0..70 {
            let q = quiet(7.0);
            p.tick(&q);
        }
        assert_eq!(p.output(100.0).state, "waiting");
        for _ in 0..PROBE_WAIT_TIMEOUT_SECS {
            let q = quiet(7.0);
            p.tick(&q);
        }
        assert_eq!(p.output(300.0).state, "collecting");
        let have = p.accepted_pairs;
        for _ in 0..(PROBE_ARM_SECS + PROBE_SETTLE_SECS + PROBE_ARM_SECS + PROBE_SETTLE_SECS + 10) {
            let q = quiet(7.0);
            p.tick(&q);
        }
        assert_eq!(p.output(500.0).state, "waiting");
        assert!(p.accepted_pairs >= have);
    }

    /* Waiting holds strict force with no perf widen. */
    #[test]
    fn waiting_holds_strict_force() {
        let mut p = EnergyProbe::new();
        for _ in 0..70 {
            let q = quiet(7.0);
            p.tick(&q);
        }
        assert_eq!(p.output(100.0).state, "waiting");
        for _ in 0..10 {
            let q = quiet(7.0);
            p.tick(&q);
            assert!(!p.want_force());
        }
        assert_eq!(p.output(200.0).state, "waiting");
    }

    /* Three light pairs span three times sixty six seconds. */
    #[test]
    fn throughput_three_light_pairs_take_198s() {
        /* Pair cycle of thirty, three, thirty, and three is sixty six, three cycles are */
        /* one hundred ninety eight with no waiting on 30 W. */
        let mut p = EnergyProbe::new();
        run_pair(&mut p, 30.0, 30.0);
        run_pair(&mut p, 30.0, 30.0);
        run_pair(&mut p, 30.0, 30.0);
        assert_eq!(p.accepted_pairs, 3);
        assert_eq!(
            3 * (PROBE_ARM_SECS + PROBE_SETTLE_SECS + PROBE_ARM_SECS + PROBE_SETTLE_SECS),
            198
        );
        assert_eq!(p.output(500.0).state, "collecting");
    }

    /* Active past wall and slack rejects, zeros pass. */
    #[test]
    fn plausibility_flags_impossible_active() {
        let mut samples = Vec::new();
        for i in 1..=30 {
            samples.push(ArmSample {
                offset_s: i as f64,
                dt_s: 1.0,
                watts: 50.0,
                joules: 50.0,
            });
        }
        /* One card with fixed active nanos for plausibility. */
        fn card(id: u32, active_ns: u64) -> stats::PerCpuMetrics {
            stats::PerCpuMetrics {
                id,
                active_ns,
                ..Default::default()
            }
        }
        let start = vec![card(0, 1_000), card(1, 2_000)];
        let over = vec![card(0, 1_000 + 30_010_000_001), card(1, 2_000)];
        assert_eq!(
            evaluate_arm(&samples, 30.0, &start, &over).unwrap_err(),
            ArmReject::Implausible
        );
        let ok_end = vec![card(0, 1_000 + 29_000_000_000), card(1, 2_000)];
        assert!(evaluate_arm(&samples, 30.0, &start, &ok_end).is_ok());
        assert!(evaluate_arm(&samples, 30.0, &[], &[]).is_ok());
    }

    /* One pair never headlines, three pairs do. */
    #[test]
    fn one_pair_never_headlines() {
        let mut p = EnergyProbe::new();
        run_pair(&mut p, 50.0, 49.0);
        assert_eq!(p.accepted_pairs, 1);
        let e = p.output(3600.0);
        assert_eq!(e.state, "collecting");
        assert!(!e.has_headline);
        assert_eq!(e.headline_pct, 0.0);
        run_pair(&mut p, 50.0, 49.0);
        assert!(!p.output(3600.0).has_headline);
        run_pair(&mut p, 49.0, 50.0);
        let e3 = p.output(3600.0);
        assert!(e3.has_headline);
        assert!(e3.low_confidence);
        assert_eq!(e3.accepted_pairs, 3);
        assert_eq!(e3.rejected_pairs, 0);
    }

    /* Headline is the ratio of sums, not the mean of ratios. */
    #[test]
    fn headline_uses_ratio_of_sums() {
        let mut p = EnergyProbe::new();
        run_pair(&mut p, 100.0, 90.0);
        run_pair(&mut p, 45.0, 50.0);
        run_pair(&mut p, 200.0, 190.0);
        let e = p.output(7200.0);
        assert!(e.has_headline);
        let want = -625.0 / 8125.0 * 100.0;
        assert!(
            (e.headline_pct - want).abs() < 1e-6,
            "got {}",
            e.headline_pct
        );
        assert!((e.daily_pct - want).abs() < 1e-9);
        assert!((e.yearly_pct - want).abs() < 1e-9);
    }

    /* Daily, yearly, and since running share one saved W. */
    #[test]
    fn energies_share_one_saved_watts() {
        assert_eq!(saved_watts(100.0, 50.0, 200.0, 50.0), -2.0);
        assert_eq!(saved_watts(1.0, 1.0, 1.0, 0.0), 0.0);
        assert_eq!(saved_watts(1.0, 0.0, 1.0, 1.0), 0.0);
        assert_eq!(energy_kwh(-2.0, 24.0), -0.048);
        assert_eq!(energy_kwh(-2.0, 8760.0), -17.52);
        assert_eq!(energy_kwh(-2.0, 1.0), -0.002);
        let mut p = EnergyProbe::new();
        run_pair(&mut p, 50.0, 49.0);
        run_pair(&mut p, 49.0, 50.0);
        run_pair(&mut p, 50.0, 49.0);
        let e = p.output(3600.0);
        assert!((e.daily_kwh - -0.024).abs() < 1e-9, "got {}", e.daily_kwh);
        assert!((e.yearly_kwh - -8.76).abs() < 1e-9, "got {}", e.yearly_kwh);
        assert!((e.since_running_kwh - -0.001).abs() < 1e-12);
    }

    /* Per arm means carry no bias with unequal kept durations. */
    #[test]
    fn saved_watts_uses_per_arm_means() {
        let perf_j = 49.0 * 25.0;
        let strict_j = 50.0 * 20.0;
        let got = saved_watts(perf_j, 25.0, strict_j, 20.0);
        assert!((got - -1.0).abs() < 1e-9, "got {got}");
        let even = saved_watts(49.0 * 25.0, 25.0, 50.0 * 25.0, 25.0);
        assert!((even - -1.0).abs() < 1e-9, "got {even}");
        assert_eq!(PROBE_MIN_J, 1e-3);
    }

    /* One or two pairs keep all kWh at zero with no headline. */
    #[test]
    fn no_headline_keeps_kwh_at_zero() {
        let mut p = EnergyProbe::new();
        run_pair(&mut p, 50.0, 49.0);
        let one = p.output(3600.0);
        assert!(!one.has_headline);
        assert_eq!(one.daily_kwh, 0.0);
        assert_eq!(one.yearly_kwh, 0.0);
        assert_eq!(one.since_running_kwh, 0.0);
        run_pair(&mut p, 50.0, 49.0);
        let two = p.output(7200.0);
        assert!(!two.has_headline);
        assert_eq!(two.daily_kwh, 0.0);
        assert_eq!(two.yearly_kwh, 0.0);
        assert_eq!(two.since_running_kwh, 0.0);
    }

    /* One missed read keeps true mean with no spike and no waste. */
    #[test]
    fn missed_tick_keeps_true_mean() {
        let mut p = EnergyProbe::new();
        run_settle(&mut p);
        for i in 0..PROBE_ARM_SECS {
            if i == 10 {
                let miss = ProbeSample {
                    delta_uj: None,
                    ..quiet(50.0)
                };
                p.tick(&miss);
                continue;
            }
            if i == 11 {
                let cover = ProbeSample {
                    rapl_present: true,
                    delta_uj: Some(100_000_000),
                    dt_s: 1.0,
                    perf_governor: false,
                    online_changed: false,
                    active: &[],
                };
                p.tick(&cover);
                continue;
            }
            let q = quiet(50.0);
            p.tick(&q);
        }
        run_settle(&mut p);
        run_arm(&mut p, 50.0);
        assert_eq!(p.accepted_pairs, 1);
        assert_eq!(p.rejected_pairs, 0);
        let strict = p.last_strict.expect("pair keeps strict arm");
        let perf = p.last_perf.expect("pair keeps perf arm");
        assert!((strict.mean_w - 50.0).abs() < 1e-9, "got {}", strict.mean_w);
        assert!((perf.mean_w - 50.0).abs() < 1e-9, "got {}", perf.mean_w);
    }

    /* Tiny perf joules never headline with no absurd percent. */
    #[test]
    fn tiny_perf_joules_never_headline() {
        assert!(headline_pct(1.0, 0.0, 5).is_none());
        assert!(headline_pct(1.0, 0.0005, 5).is_none());
        assert!(headline_pct(1.0, 0.001, 5).is_some());
        let mut p = EnergyProbe::new();
        p.sum_d_j = -0.0004;
        p.sum_perf_j = 0.0005;
        p.accepted_pairs = 3;
        assert!(p.output(60.0).has_headline == false);
    }

    /* Countdown follows wall clock with jittered dt. */
    #[test]
    fn countdown_follows_wall_clock() {
        let mut p = EnergyProbe::new();
        for _ in 0..PROBE_SETTLE_SECS {
            let q = quiet(50.0);
            p.tick(&q);
        }
        assert_eq!(p.phase, ProbePhase::Strict);
        let jit = ProbeSample {
            rapl_present: true,
            delta_uj: Some(100_000_000),
            dt_s: 2.0,
            perf_governor: false,
            online_changed: false,
            active: &[],
        };
        p.tick(&jit);
        let want = (PROBE_ARM_SECS as f64 - 2.0).ceil() as u64;
        assert_eq!(p.output(10.0).countdown_s, want);
        assert_eq!(want, 28);
        let small = ProbeSample {
            rapl_present: true,
            delta_uj: Some(25_000_000),
            dt_s: 0.5,
            perf_governor: false,
            online_changed: false,
            active: &[],
        };
        p.tick(&small);
        let want2 = (PROBE_ARM_SECS as f64 - 2.5).ceil() as u64;
        assert_eq!(p.output(10.0).countdown_s, want2);
    }

    /* Governor flip inside settle drops the pair with one reject. */
    #[test]
    fn settle_governor_flip_rejects_pair() {
        let mut p = EnergyProbe::new();
        run_settle(&mut p);
        run_arm(&mut p, 50.0);
        assert!(p.first.is_some());
        assert_eq!(p.phase, ProbePhase::Settle);
        let g = ProbeSample {
            perf_governor: true,
            ..quiet(50.0)
        };
        p.tick(&g);
        assert_eq!(p.output(10.0).state, "baseline");
        assert_eq!(p.rejected_pairs, 1);
        assert_eq!(p.accepted_pairs, 0);
    }

    /* Five pairs clear the low confidence hint. */
    #[test]
    fn five_pairs_clear_low_confidence() {
        let mut p = EnergyProbe::new();
        for _ in 0..5 {
            run_pair(&mut p, 50.0, 49.0);
        }
        let e = p.output(3600.0);
        assert!(e.has_headline);
        assert!(!e.low_confidence);
        assert_eq!(e.accepted_pairs, 5);
    }

    /* Perf governor suspends into baseline with force clear. */
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
        assert!(!p.want_force());
        p.tick(&g);
        assert_eq!(p.rejected_pairs, 1);
        assert_eq!(p.accepted_pairs, 0);
        let q = quiet(50.0);
        p.tick(&q);
        assert_eq!(p.output(20.0).state, "collecting");
        assert!(p.trace.contains("collecting"));
    }

    /* Hotplug and gaps discard the in flight pair. */
    #[test]
    fn hotplug_and_gap_discard_pair() {
        let mut p = EnergyProbe::new();
        fresh_ticks(&mut p, 10);
        let h = ProbeSample {
            online_changed: true,
            ..quiet(50.0)
        };
        p.tick(&h);
        assert_eq!(p.rejected_pairs, 1);
        fresh_ticks(&mut p, 10);
        let gap = ProbeSample {
            rapl_present: true,
            delta_uj: Some(300_000_000),
            dt_s: 6.0,
            perf_governor: false,
            online_changed: false,
            active: &[],
        };
        p.tick(&gap);
        assert_eq!(p.rejected_pairs, 2);
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
        assert!(!p.want_force());
        for _ in 0..PROBE_BACKOFF_SECS {
            let q = quiet(50.0);
            p.tick(&q);
        }
        assert_eq!(p.output(200.0).state, "collecting");
    }

    /* Order alternates strict first then perf first. */
    #[test]
    fn order_alternates_per_pair() {
        let mut p = EnergyProbe::new();
        let mut force_seen = Vec::new();
        for _ in 0..(66 * 2 + 5) {
            let q = quiet(50.0);
            p.tick(&q);
            force_seen.push(p.want_force());
        }
        assert!(!force_seen[10]);
        assert!(force_seen[70]);
        assert_eq!(p.accepted_pairs, 2);
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
        assert!(!e.has_headline);
        assert!(e.trace.contains("unavailable"));
    }

    /* Trace carries state, counts, and derivation. */
    #[test]
    fn trace_carries_derivation() {
        let mut p = EnergyProbe::new();
        run_pair(&mut p, 50.0, 49.0);
        run_pair(&mut p, 50.0, 49.0);
        run_pair(&mut p, 49.0, 50.0);
        assert!(p.trace.contains("collecting"));
        assert!(p.trace.contains("accepted 3"));
        assert!(p.trace.contains("rejected 0"));
        assert!(p.trace.contains("last pair"));
        assert!(p.trace.contains("median"));
        assert!(p.trace.contains("p50"));
        assert!(p.trace.contains("p99"));
        assert!(p.trace.contains("headline"));
        assert!(p.trace.contains("perf arms widen placement"));
        assert!(p.trace.contains("45 percent duty"));
        assert!(p.trace.contains("strict versus forced perf"));
        assert!(!p.trace.contains("cpu0"));
    }

    /* Active hint names the CPU in upper case. */
    #[test]
    fn trace_names_cpu_in_upper_case() {
        fn card(id: u32, active_ns: u64) -> stats::PerCpuMetrics {
            stats::PerCpuMetrics {
                id,
                active_ns,
                ..Default::default()
            }
        }
        let start = vec![card(0, 1_000), card(1, 2_000)];
        let end = vec![card(0, 2_000_000_000), card(1, 3_000_000_000)];
        let got = EnergyProbe::active_hint(&start, &end, 30.0).unwrap();
        assert_eq!(got.0, 1);
        let mut p = EnergyProbe::new();
        p.last_active = Some(got);
        p.render_trace();
        assert!(p.trace.contains("CPU1"));
        assert!(!p.trace.contains("cpu1"));
    }

    /* Default energy view reads unavailable. */
    #[test]
    fn energy_default_is_unavailable() {
        let e = EnergyMetrics::default();
        assert_eq!(e.state, "unavailable");
        assert!(!e.has_headline);
        assert_eq!(e.accepted_pairs, 0);
    }
}
