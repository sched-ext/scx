// SPDX-License-Identifier: GPL-2.0
//
// Reports printed after detach: the probe census, the pool counters at exit,
// kernel event counts and the kernel-signals CSV.

use std::io::Write;

use anyhow::Context;
use anyhow::Result;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use log::info;
use log::warn;

use crate::BpfSkel;
use crate::bpf_intf;
use crate::bpf_intf::*;
use crate::bpf_skel::types;

fn signal_counter_names() -> Vec<String> {
    let mut names: Vec<String> = [
        "select_input",
        "select_fence",
        "select_unknown",
        "running_input",
        "running_fence",
        "running_unknown",
        "expired_select",
        "clock_error",
        "irq_samples",
        "irq_unknown",
        "irq_hot_samples",
        "input_wake_ns_sum",
        "fence_wake_ns_sum",
        "input_wake_ns_max",
        "fence_wake_ns_max",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    for cause in ["input", "fence"] {
        for bucket in 0..bpf_intf::consts_CAKE_SIGNAL_LOG2_BANDS {
            names.push(format!("{cause}_wake_ns_log2_{bucket}"));
        }
    }
    for hop in 1..=bpf_intf::consts_CAKE_SIGNAL_HOPS {
        names.push(format!("input_inherit_hop_{hop}"));
    }
    names.extend(["inherit_irq_waker", "inherit_hop_limit", "inherit_cleared"].map(String::from));
    names
}

/// The two latency maxima: merged across CPUs by maximum, not summed.
const SIGNAL_MAX_ROWS: std::ops::Range<usize> = {
    let first = bpf_intf::cake_signal_stat_CAKE_SIGNAL_WAKE_NS_MAX as usize;
    first..first + 2
};

fn aggregate_signal_counters(per_cpu: &[Vec<u8>]) -> Result<Vec<u64>> {
    let mut result = vec![0u64; bpf_intf::cake_signal_stat_CAKE_SIGNAL_STATS as usize];
    for values in per_cpu {
        anyhow::ensure!(
            values.len() == result.len() * 8,
            "invalid signal counter layout"
        );
        for (i, bytes) in values.chunks_exact(8).enumerate() {
            let value = u64::from_ne_bytes(bytes.try_into()?);
            if SIGNAL_MAX_ROWS.contains(&i) {
                result[i] = result[i].max(value);
            } else {
                result[i] = result[i].saturating_add(value);
            }
        }
    }
    Ok(result)
}

/// Black box: the placement context of the last waits over 10 ms.
fn blackbox(bss: &types::bss) {
    let n = bss.cake_blackbox_n;
    for i in 0..n.min(bss.cake_blackbox.len() as u32) {
        let b = &bss.cake_blackbox[i as usize];
        let comm = String::from_utf8_lossy(
            &b.comm
                .iter()
                .map(|c| *c as u8)
                .take_while(|c| *c != 0)
                .collect::<Vec<u8>>(),
        )
        .to_string();
        info!(
            "   BLACKBOX wait {:.2} ms  {} pid {} kind {} target cpu{} caller cpu{} waker {} ran_on cpu{}  seats {:#018x} core_free {:#018x} idle {:#018x}",
            b.wait_ns as f64 / 1e6,
            comm,
            b.pid,
            b.kind,
            b.target,
            b.caller,
            b.waker_pid,
            b.ran_on,
            b.seats,
            b.core_free,
            b.idle_word
        );
    }
}

/// Release census: by arrival path x displacer band, by reason; holds by band.
fn release_census(bss: &types::bss) {
    let bands: Vec<String> = (0..bss.cake_acquire_hist.len())
        .map(|b| format!("{}us", 1u64 << b))
        .collect();
    info!("   release bands (>=) {}", bands.join(" "));
    for (path, name) in ["non-immed", "immed", "slice-0"].iter().enumerate() {
        let row: Vec<String> = bss.cake_release_census[path]
            .iter()
            .map(|v| v.to_string())
            .collect();
        info!("   release {:9} {}", name, row.join(" "));
    }
    let reasons: Vec<String> = bss
        .cake_release_reason
        .iter()
        .map(|v| v.to_string())
        .collect();
    info!(
        "   release by reason rt/dl/stop/unknown {}",
        reasons.join(" ")
    );
    let holds: Vec<String> = bss
        .cake_acquire_hist
        .iter()
        .map(|v| v.to_string())
        .collect();
    info!("   release hold      {}", holds.join(" "));
}

fn histograms(bss: &types::bss) {
    // Observe-only histograms: bands summed over CPUs, the antimode split
    // (the emptiest band between the two largest modes) and the median band.
    let shift = bpf_intf::consts_CAKE_HIST_SHIFT;
    for (kind, name) in ["hop", "handoff", "burst"].iter().enumerate() {
        let bands = bss.cake_hist[0][kind].len();
        let sum: Vec<u64> = (0..bands)
            .map(|b| bss.cake_hist.iter().map(|cpu| cpu[kind][b]).sum())
            .collect();
        let total: u64 = sum.iter().sum();
        if total == 0 {
            continue;
        }
        let mut peaks: Vec<usize> = (0..bands).collect();
        peaks.sort_by_key(|b| std::cmp::Reverse(sum[*b]));
        let (lo, hi) = (peaks[0].min(peaks[1]), peaks[0].max(peaks[1]));
        let valley = (lo..=hi).min_by_key(|b| sum[*b]).unwrap_or(lo);
        let mut acc = 0u64;
        let median = (0..bands)
            .find(|b| {
                acc += sum[*b];
                acc * 2 >= total
            })
            .unwrap_or(0);
        let rows: Vec<String> = sum.iter().map(|v| v.to_string()).collect();
        info!(
            "   hist    {name:7} n={total} median>={}ns split>={}ns  {}",
            1u64 << (median as u32 + shift),
            1u64 << (valley as u32 + shift),
            rows.join(" ")
        );
    }
}

fn gates(bss: &types::bss) {
    // Gates reached; fired counts are the stats rows serial, seat_retake,
    // probe_fired, rej_tick.
    let tried: Vec<String> = (0..cake_tried_gate_CAKE_TRIED_NR as usize)
        .map(|g| {
            bss.cake_tried
                .iter()
                .map(|row| row[g])
                .sum::<u64>()
                .to_string()
        })
        .collect();
    info!("   tried   serial/retake/probe/tick {}", tried.join(" "));
}

/// The census name of every probe counter. The length is the enum's, so a
/// counter without a name does not build; a test pins the order.
const CENSUS: [(cake_stat, &str); cake_stat_CAKE_STAT_NR as usize] = [
    (cake_stat_CAKE_STAT_SELECT, "select_calls"),
    (cake_stat_CAKE_STAT_SERIAL, "serial"),
    (cake_stat_CAKE_STAT_HOME, "home_warm"),
    (cake_stat_CAKE_STAT_WP_ATTEMPT, "wp_attempt"),
    (cake_stat_CAKE_STAT_WP_TINY, "wp_tiny"),
    (cake_stat_CAKE_STAT_WP_SMALL, "wp_small"),
    (cake_stat_CAKE_STAT_WP_PROTECT, "wp_protect"),
    (cake_stat_CAKE_STAT_WP_VTIME, "wp_vtime"),
    (cake_stat_CAKE_STAT_WP_STARVED, "wp_starved"),
    (cake_stat_CAKE_STAT_WP_FIRED, "wp_fired"),
    (cake_stat_CAKE_STAT_PL_LOCAL, "pl_local"),
    (cake_stat_CAKE_STAT_PL_LOCAL_ON, "pl_local_on"),
    (cake_stat_CAKE_STAT_PL_CPUQ_WAKE, "pl_cpuq_wake"),
    (cake_stat_CAKE_STAT_PL_CPUQ_CONT, "pl_cpuq_cont"),
    (cake_stat_CAKE_STAT_PL_GLOBAL, "pl_global"),
    (cake_stat_CAKE_STAT_H3_LOCAL, "h300_local"),
    (cake_stat_CAKE_STAT_H3_LOCAL_ON, "h300_local_on"),
    (cake_stat_CAKE_STAT_H3_CPUQ_WAKE, "h300_cpuq_wake"),
    (cake_stat_CAKE_STAT_H3_CPUQ_CONT, "h300_cpuq_cont"),
    (cake_stat_CAKE_STAT_H3_GLOBAL, "h300_global"),
    (cake_stat_CAKE_STAT_H10_LOCAL, "h1ms_local"),
    (cake_stat_CAKE_STAT_H10_LOCAL_ON, "h1ms_local_on"),
    (cake_stat_CAKE_STAT_H10_CPUQ_WAKE, "h1ms_cpuq_wake"),
    (cake_stat_CAKE_STAT_H10_CPUQ_CONT, "h1ms_cpuq_cont"),
    (cake_stat_CAKE_STAT_H10_GLOBAL, "h1ms_global"),
    (cake_stat_CAKE_STAT_PL_SELF, "pl_self"),
    (cake_stat_CAKE_STAT_H3_SELF, "h300_self"),
    (cake_stat_CAKE_STAT_H10_SELF, "h1ms_self"),
    (cake_stat_CAKE_STAT_HD_SYNC, "hd_sync"),
    (cake_stat_CAKE_STAT_HD_STARVED, "hd_starved"),
    (cake_stat_CAKE_STAT_HD_IRQ, "hd_irq"),
    (cake_stat_CAKE_STAT_HD_AFF, "hd_aff"),
    (cake_stat_CAKE_STAT_HD_CONTENDED, "hd_contended"),
    (cake_stat_CAKE_STAT_HD_NOTIDLE, "hd_notidle"),
    (cake_stat_CAKE_STAT_HOME_BUSY, "home_busy"),
    (cake_stat_CAKE_STAT_HOME_LOCALQ, "home_localq"),
    (cake_stat_CAKE_STAT_H3_HOME_BUSY, "h300_home_busy"),
    (cake_stat_CAKE_SITE_QMARK_SET, "qmark_set"),
    (cake_stat_CAKE_SITE_QMARK_SET_SKIP, "qmark_set_skip"),
    (cake_stat_CAKE_SITE_QMARK_CLR, "qmark_clr"),
    (cake_stat_CAKE_SITE_QMARK_CLR_SKIP, "qmark_clr_skip"),
    (cake_stat_CAKE_SITE_RUNNING, "running"),
    (cake_stat_CAKE_SITE_FRONTIER_ST, "frontier_st"),
    (cake_stat_CAKE_SITE_WAKE_SERVED_ST, "wake_served_st"),
    (cake_stat_CAKE_SITE_WAKE_MARK_ST, "wake_mark_st"),
    (cake_stat_CAKE_SITE_TACI, "taci"),
    (cake_stat_CAKE_SITE_TACI_WIN, "taci_win"),
    (cake_stat_CAKE_SITE_TACI_HOME, "taci_home"),
    (cake_stat_CAKE_SITE_TACI_GROOVE, "taci_groove"),
    (cake_stat_CAKE_SITE_TACI_WARM, "taci_warm"),
    (cake_stat_CAKE_SITE_TACI_NOTIFY, "taci_notify"),
    (cake_stat_CAKE_SITE_TACI_PINNED, "taci_pinned"),
    (cake_stat_CAKE_SITE_PICK_IDLE, "pick_idle"),
    (cake_stat_CAKE_SITE_KICK, "kick"),
    (cake_stat_CAKE_SITE_NRQ, "nrq"),
    (cake_stat_CAKE_SITE_DSQ_INSERT, "dsq_insert"),
    (cake_stat_CAKE_SITE_MOVE_LOCAL, "move_local"),
    (cake_stat_CAKE_SITE_KT, "kt"),
    (cake_stat_CAKE_SITE_KT_PERIOD, "kt_period"),
    (cake_stat_CAKE_SITE_KT_TICKSOON, "kt_ticksoon"),
    (cake_stat_CAKE_SITE_KT_OCCUPANT, "kt_occupant"),
    (cake_stat_CAKE_SITE_KT_HANDOFF, "kt_handoff"),
    (cake_stat_CAKE_SITE_KT_WAKECLOCK, "kt_wakeclock"),
    (cake_stat_CAKE_SITE_KT_RUNNING, "kt_running"),
    (cake_stat_CAKE_SITE_KT_PROBE, "kt_probe"),
    (cake_stat_CAKE_SITE_TASK_STORAGE, "task_storage"),
    (cake_stat_CAKE_SITE_CPU_CURR, "cpu_curr"),
    (cake_stat_CAKE_SITE_CORE_CONTENDED, "core_contended"),
    (cake_stat_CAKE_SITE_STAGE_PROBE, "stage_probe"),
    (cake_stat_CAKE_SITE_TACIW_HOME, "taciw_home"),
    (cake_stat_CAKE_SITE_TACIW_GROOVE, "taciw_groove"),
    (cake_stat_CAKE_SITE_TACIW_WARM, "taciw_warm"),
    (cake_stat_CAKE_SITE_TACIW_NOTIFY, "taciw_notify"),
    (cake_stat_CAKE_SITE_TACIW_PINNED, "taciw_pinned"),
    (cake_stat_CAKE_SITE_T_NRQ, "t_nrq"),
    (cake_stat_CAKE_SITE_T_TACI, "t_taci"),
    (cake_stat_CAKE_SITE_T_PICK, "t_pick"),
    (cake_stat_CAKE_SITE_T_KICK, "t_kick"),
    (cake_stat_CAKE_SITE_T_CPU_CURR, "t_cpu_curr"),
    (cake_stat_CAKE_SITE_T_TASK_STORAGE, "t_task_storage"),
    (cake_stat_CAKE_SITE_T_MOVE, "t_move"),
    (cake_stat_CAKE_SITE_T_INSERT, "t_insert"),
    (cake_stat_CAKE_SITE_T_QMARK, "t_qmark"),
    (cake_stat_CAKE_SITE_T_CAL, "t_cal"),
    (cake_stat_CAKE_SITE_LEAK_HOME, "leak_home"),
    (cake_stat_CAKE_SITE_LEAK_DISPATCH, "leak_dispatch"),
    (cake_stat_CAKE_SITE_SEAT_IMMUNE, "seat_immune"),
    (cake_stat_CAKE_SITE_SEAT_RETAKE, "seat_retake"),
    (cake_stat_CAKE_SITE_SEAT_REROUTE, "seat_reroute"),
    (cake_stat_CAKE_SITE_SEAT_DECLINE, "seat_decline"),
    (cake_stat_CAKE_SITE_POOL_FORWARD, "pool_forward"),
    (cake_stat_CAKE_SITE_KT_POOL, "kt_pool"),
    (cake_stat_CAKE_SITE_SERIAL_X, "x_serial"),
    (cake_stat_CAKE_SITE_KT_LOCAL, "kt_local"),
    (cake_stat_CAKE_SITE_KT_LOCAL_X, "x_kt_local"),
    (cake_stat_CAKE_SITE_CLAIM_X, "x_claim"),
    (cake_stat_CAKE_SITE_NOTIFY_KICK, "notify_kick"),
    (cake_stat_CAKE_SITE_NOTIFY_KICK_X, "x_notify_kick"),
    (cake_stat_CAKE_SITE_PROBE_FIRED, "probe_fired"),
    (cake_stat_CAKE_SITE_PROBE_FIRED_X, "x_probe_fired"),
    (cake_stat_CAKE_SITE_POOL_SERVED, "pool_served"),
    (cake_stat_CAKE_SITE_POOL_SERVED_X, "x_pool_served"),
    (cake_stat_CAKE_SITE_STEAL_MOVED, "steal_moved"),
    (cake_stat_CAKE_SITE_STEAL_MOVED_X, "x_steal_moved"),
    (cake_stat_CAKE_STAT_POOL_DIRECT, "pool_direct"),
    (cake_stat_CAKE_SITE_KICK_ALONE, "kick_alone"),
    (cake_stat_CAKE_SITE_GRANT_VACANT, "grant_vacant"),
    (cake_stat_CAKE_SITE_GRANT_EXPIRED, "grant_expired"),
    (cake_stat_CAKE_SITE_GRANT_LT_TICK, "grant_lt_tick"),
    (cake_stat_CAKE_SITE_GRANT_GE_TICK, "grant_ge_tick"),
    (cake_stat_CAKE_STAT_HD_COREBUSY, "hd_corebusy"),
    (cake_stat_CAKE_SITE_REJ_IRQ, "rej_irq"),
    (cake_stat_CAKE_SITE_REJ_TICK, "rej_tick"),
    (cake_stat_CAKE_SITE_EXPIRY_PREEMPT, "expiry_preempt"),
    (cake_stat_CAKE_SITE_RELEASE, "release"),
    (cake_stat_CAKE_SITE_ACQUIRE, "acquire"),
    (cake_stat_CAKE_STAT_SELECT_DIRECT, "select_direct"),
    (cake_stat_CAKE_SITE_UI_KICK, "ui_kick"),
    (cake_stat_CAKE_SITE_PEND_KICK, "pend_kick"),
    (cake_stat_CAKE_SITE_PEND_HEAL, "pend_heal"),
    (cake_stat_CAKE_SITE_RELEASE_SERVE, "release_serve"),
    (cake_stat_CAKE_SITE_PINNED_PREEMPT, "pinned_preempt"),
    (cake_stat_CAKE_SITE_PINNED_CLAIM, "pinned_claim"),
    (cake_stat_CAKE_SITE_PINNED_KICK, "pinned_kick"),
    (cake_stat_CAKE_SITE_YIELD_KEEP, "yield_keep"),
    (cake_stat_CAKE_SITE_YIELD_GIVE, "yield_give"),
];

/// The placement census by name, and the identities it must keep.
fn census(skel: &BpfSkel<'_>) {
    let names: Vec<&str> = CENSUS.iter().map(|(_, name)| *name).collect();
    let mut tot = [0u64; CENSUS.len()];
    for (i, t) in tot.iter_mut().enumerate() {
        let key = (i as u32).to_ne_bytes();
        if let Ok(Some(percpu)) = skel.maps.cake_stats.lookup_percpu(&key, MapFlags::ANY) {
            for cpu in &percpu {
                if cpu.len() >= 8 {
                    *t += u64::from_ne_bytes(cpu[..8].try_into().unwrap());
                }
            }
        }
    }
    let sel = tot[0].max(1) as f64;
    for (i, name) in names.iter().enumerate() {
        info!(
            "   census  {name:<13} {:>12}  {:>6.2}% of select",
            tot[i],
            tot[i] as f64 * 100.0 / sel
        );
    }
    for broken in census_violations(&names, &tot) {
        warn!("   census  identity broken: {broken}");
    }
}

/// Diagnostics (--toggle probe=1): black box, release census, histograms, gates, census.
pub fn probe(skel: &BpfSkel<'_>) {
    if let Some(bss) = skel.maps.bss_data.as_ref() {
        blackbox(bss);
        release_census(bss);
        histograms(bss);
        gates(bss);
    }
    census(skel);
}

/// Pool counters as ops.exit copied them.
pub fn pools(skel: &BpfSkel<'_>, verbose: bool) {
    if let (Some(bss), Some(ro)) = (skel.maps.bss_data.as_ref(), skel.maps.rodata_data.as_ref()) {
        let nr = (ro.nr_llcs as usize).min(bss.cake_exit_pending.len());
        let pending: Vec<i64> = bss.cake_exit_pending[..nr]
            .iter()
            .map(|v| *v as i64)
            .collect();
        for (pool, left) in pending.iter().enumerate().filter(|(_, v)| **v < 0) {
            warn!("   pool    {pool}: pending {left} at exit; more tokens returned than taken");
        }
        if verbose {
            info!(
                "   pool    exit pending {:?} unserved {:?}",
                pending,
                &bss.cake_exit_unserved[..nr]
            );
        }
    }
}

/// Core event counts as ops.exit copied them.
pub fn events(skel: &BpfSkel<'_>) {
    if let Some(bss) = skel.maps.bss_data.as_ref() {
        let ev = &bss.cake_events;
        info!(
            "   events  select_fallback {} keep_last {} enq_skip_exiting {}",
            ev.SCX_EV_SELECT_CPU_FALLBACK, ev.SCX_EV_DISPATCH_KEEP_LAST, ev.SCX_EV_ENQ_SKIP_EXITING
        );
    }
}

/// The kernel-signals counters as CSV.
pub fn signals(skel: &BpfSkel<'_>, mut report: std::fs::File, enabled: bool) -> Result<()> {
    let values = skel
        .maps
        .cake_signal_stats
        .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)?
        .context("signal counter map missing")?;
    let counters = aggregate_signal_counters(&values)?;
    writeln!(report, "# enabled={}", enabled)?;
    writeln!(
        report,
        "# clock=CLOCK_MONOTONIC; origin=accepted_blocked_wake; end=ops.running"
    )?;
    writeln!(report, "metric,value")?;
    for (name, value) in signal_counter_names().iter().zip(counters) {
        writeln!(report, "{name},{value}")?;
    }
    report.flush()?;
    Ok(())
}

/// Census identities that hold by construction, read after detach. A broken
/// one is a probe or accounting bug, not a scheduling result.
fn census_violations(names: &[&str], tot: &[u64]) -> Vec<String> {
    let get = |name: &str| {
        names
            .iter()
            .position(|n| *n == name)
            .and_then(|i| tot.get(i).copied())
    };
    let sum = |parts: &[String]| -> Option<u64> { parts.iter().map(|n| get(n)).sum() };
    let sites = ["home", "groove", "warm", "notify", "pinned"];
    let clocks = [
        "period",
        "ticksoon",
        "occupant",
        "handoff",
        "wakeclock",
        "running",
        "probe",
    ];
    let tries: Vec<String> = sites.iter().map(|s| format!("taci_{s}")).collect();
    let wins: Vec<String> = sites.iter().map(|s| format!("taciw_{s}")).collect();
    let reads: Vec<String> = clocks.iter().map(|s| format!("kt_{s}")).collect();
    let equal = [
        ("taci", get("taci"), sum(&tries)),
        ("taci_win", get("taci_win"), sum(&wins)),
        ("home_warm", get("home_warm"), get("taciw_home")),
        ("pinned_claim", get("pinned_claim"), get("taciw_pinned")),
        ("kt", get("kt"), sum(&reads)),
        ("running", get("running"), get("kt_running")),
    ];
    let mut broken = Vec::new();
    for (name, whole, parts) in equal {
        match (whole, parts) {
            (Some(w), Some(p)) if w != p => broken.push(format!("{name} {w} != sum of parts {p}")),
            (Some(_), Some(_)) => {}
            _ => broken.push(format!("{name}: a counter is missing from the name table")),
        }
    }
    for (t, w) in tries.iter().zip(&wins) {
        if let (Some(tried), Some(won)) = (get(t), get(w))
            && won > tried
        {
            broken.push(format!("{w} {won} > {t} {tried}"));
        }
    }
    broken
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catches a census name bound to the wrong counter, which mislabels that row.
    #[test]
    fn census_rows_follow_the_bpf_enum() {
        for (index, (id, _)) in CENSUS.iter().enumerate() {
            assert_eq!(*id as usize, index);
        }
    }

    #[test]
    fn counters_sum_counts_but_merge_latency_maxima_by_maximum() {
        let len = signal_counter_names().len();
        // A name list out of step with the BPF enum mislabels every later row.
        assert_eq!(len, bpf_intf::cake_signal_stat_CAKE_SIGNAL_STATS as usize);
        let (input, fence) = (SIGNAL_MAX_ROWS.start, SIGNAL_MAX_ROWS.start + 1);
        let mut a = vec![1u64; len];
        let mut b = vec![2u64; len];
        a[input] = 900;
        b[input] = 200;
        a[fence] = 100;
        b[fence] = 800;
        let encode = |values: Vec<u64>| values.into_iter().flat_map(u64::to_ne_bytes).collect();
        let got = aggregate_signal_counters(&[encode(a), encode(b)]).unwrap();
        assert_eq!(got[0], 3);
        assert_eq!((got[input], got[fence]), (900, 800));
        assert_eq!(got[len - 1], 3);
        assert!(aggregate_signal_counters(&[vec![0; 8]]).is_err());
    }

    /// An appsim census; `taci_win` as read while still attached.
    fn appsim_census(taci_win: u64) -> (Vec<&'static str>, Vec<u64>) {
        let rows = [
            ("select_calls", 3071675),
            ("home_warm", 813870),
            ("running", 3124740),
            ("taci", 3125109),
            ("taci_win", taci_win),
            ("taci_home", 817872),
            ("taci_groove", 4742),
            ("taci_warm", 2247710),
            ("taci_notify", 54785),
            ("taci_pinned", 0),
            ("kt", 9453561),
            ("kt_period", 3132465),
            ("kt_ticksoon", 53550),
            ("kt_occupant", 13969),
            ("kt_handoff", 2),
            ("kt_wakeclock", 2911),
            ("kt_running", 3124740),
            ("kt_probe", 3125924),
            ("taciw_home", 813870),
            ("taciw_groove", 4699),
            ("taciw_warm", 2206488),
            ("taciw_notify", 53754),
            ("taciw_pinned", 0),
            ("pinned_claim", 0),
        ];
        rows.iter().copied().unzip()
    }

    #[test]
    fn census_identities_hold_on_a_frozen_read() {
        let (names, tot) = appsim_census(3078811);
        assert!(census_violations(&names, &tot).is_empty());
    }

    #[test]
    fn census_identities_catch_a_read_taken_while_attached() {
        // Two wins landed between the total and its sites.
        let (names, tot) = appsim_census(3078809);
        let broken = census_violations(&names, &tot);
        assert_eq!(broken.len(), 1, "{broken:?}");
        assert!(broken[0].starts_with("taci_win 3078809"), "{broken:?}");
    }

    #[test]
    fn census_identities_report_wins_above_tries_and_missing_names() {
        let (names, mut tot) = appsim_census(3078811);
        let groove = names.iter().position(|n| *n == "taciw_groove").unwrap();
        tot[groove] = 4743;
        let broken = census_violations(&names, &tot);
        assert!(
            broken
                .iter()
                .any(|b| b.starts_with("taciw_groove 4743 > taci_groove 4742"))
        );
        let broken = census_violations(&names[..3], &tot[..3]);
        assert!(broken.iter().all(|b| b.contains("missing")), "{broken:?}");
    }
}
