/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Snapshot reads for the flow scheduler. Builds the
 * metrics view and the dashboard view from the BPF
 * maps and the static cards. Gauges only, no deltas.
 * Frequency plus LLC plus CPU cards stay display only
 * and never shape placement.
 */
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

use crate::Scheduler;
use crate::stats;

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
        }
    }

    /*
     * Read one CPU state without heap use. Failed
     * lookups yield an idle view with fixed slice
     * plus zero EMA. Slice stays fixed at 1ms.
     * Zero EMA matches BSS plus init with no trap.
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
        };
        if cpu >= crate::MAX_CPUS {
            return idle;
        }
        let fd = self.skel.maps.cpu_state_stor.as_fd().as_raw_fd();
        let key = cpu as u32;
        let mut out = MaybeUninit::<crate::flow_cpu_state>::uninit();
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
     * Dashboard snapshot. Merges the static cards with
     * live state by online rank. Gauges only, no deltas.
     * Frequency plus LLC plus CPU cards stay display only
     * and never feed placement or division. Slice stays
     * fixed at 1ms. Group follows the live table when
     * ready, else halves fallback with no trap. Offline
     * stays out, so per CPU count matches online count.
     * Version plus timestamp plus topology plus depths
     * plus allowance plus mode plus governor join the
     * counters for one screenshot plus one JSON log.
     * Governor polls online only on the 1s tick with a
     * transition only BSS write, so strict stays quiet.
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
            let governors: Vec<String> = online
                .iter()
                .map(|&id| crate::topology::read_governor(id))
                .collect();
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
            per_cpu.push(e);
        }
        let topology = if self.cpu_static.is_empty() {
            crate::topology::describe_topology(&per_cpu)
        } else {
            crate::topology::describe_topology(&self.cpu_static)
        };
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
        }
    }
}
