// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::c_int;
use std::ffi::CStr;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::mem;
use std::mem::MaybeUninit;
use std::str;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::ThreadId;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel;
use crossbeam::channel::Receiver;
use crossbeam::channel::RecvTimeoutError;
use crossbeam::channel::Sender;
use crossbeam::channel::TrySendError;
use itertools::iproduct;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use libc::c_char;
use log::debug;
use log::info;
use log::warn;
use plain::Plain;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use stats::SchedSample;
use stats::SchedSamples;
use stats::StatsReq;
use stats::StatsRes;
use stats::SysStats;

const LAVD_CPU_ID_MAX: usize = bpf_intf::consts_LAVD_CPU_ID_MAX as usize;

/// scx_lavd: Latency-criticality Aware Virtual Deadline (LAVD) scheduler
///
/// The rust part is minimal. It processes command line options and logs out
/// scheduling statistics. The BPF part makes all the scheduling decisions.
/// See the more detailed overview of the LAVD design at main.bpf.c.
#[derive(Debug, Parser)]
struct Opts {
    /// Automatically decide the scheduler's power mode based on system load.
    /// This is a default mode if you don't specify the following options:
    #[clap(long = "autopilot", action = clap::ArgAction::SetTrue)]
    autopilot: bool,

    /// Automatically decide the scheduler's power mode based on the system's energy profile.
    #[clap(long = "autopower", action = clap::ArgAction::SetTrue)]
    autopower: bool,

    /// Run in performance mode to get maximum performance.
    #[clap(long = "performance", action = clap::ArgAction::SetTrue)]
    performance: bool,

    /// Run in powersave mode to minimize power consumption.
    #[clap(long = "powersave", action = clap::ArgAction::SetTrue)]
    powersave: bool,

    /// Run in balanced mode aiming for sweetspot between power and performance (default).
    #[clap(long = "balanced", action = clap::ArgAction::SetTrue)]
    balanced: bool,

    /// Disable core compaction and schedule tasks across all online CPUs. Core compaction attempts
    /// to keep idle CPUs idle in favor of scheduling tasks on CPUs that are already
    /// awake. See main.bpf.c for more info. Normally set by the power mode, but can be set independently if
    /// desired.
    #[clap(long = "no-core-compaction", action = clap::ArgAction::SetTrue)]
    no_core_compaction: bool,

    /// Schedule tasks on SMT siblings before using other physcial cores when core compaction is
    /// enabled. Normally set by the power mode, but can be set independently if desired.
    #[clap(long = "prefer-smt-core", action = clap::ArgAction::SetTrue)]
    prefer_smt_core: bool,

    /// Schedule tasks on little (efficiency) cores before big (performance) cores when core compaction is
    /// enabled. Normally set by the power mode, but can be set independently if desired.
    #[clap(long = "prefer-little-core", action = clap::ArgAction::SetTrue)]
    prefer_little_core: bool,

    /// Do not specifically prefer to schedule on turbo cores. Normally set by the power mode, but
    /// can be set independently if desired.
    #[clap(long = "no-prefer-turbo-core", action = clap::ArgAction::SetTrue)]
    no_prefer_turbo_core: bool,

    /// Disable controlling the CPU frequency. In order to improve latency and responsiveness of
    /// performance-critical tasks, scx_lavd increases the CPU frequency even if CPU usage is low.
    /// See main.bpf.c for more info. Normally set by the power mode, but can be set independently
    /// if desired.
    #[clap(long = "no-freq-scaling", action = clap::ArgAction::SetTrue)]
    no_freq_scaling: bool,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Run in monitoring mode. Show the specified number of scheduling
    /// samples every second.
    #[clap(long)]
    monitor_sched_samples: Option<u64>,

    /// Enable verbose output, including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,
}

impl Opts {
    fn nothing_specified(&self) -> bool {
        return self.autopilot == false
            && self.autopower == false
            && self.performance == false
            && self.powersave == false
            && self.balanced == false
            && self.no_core_compaction == false
            && self.prefer_smt_core == false
            && self.prefer_little_core == false
            && self.no_prefer_turbo_core == false
            && self.no_freq_scaling == false
            && self.monitor == None
            && self.monitor_sched_samples == None;
    }

    fn proc(&mut self) -> Option<&mut Self> {
        if self.nothing_specified() {
            self.autopilot = true;
            info!("Autopilot mode is enabled by default.");
            return Some(self);
        }

        if self.performance {
            self.no_core_compaction = true;
            self.prefer_smt_core = false;
            self.prefer_little_core = false;
            self.no_prefer_turbo_core = false;
            self.no_freq_scaling = true;
        } else if self.powersave {
            self.no_core_compaction = false;
            self.prefer_smt_core = true;
            self.prefer_little_core = true;
            self.no_prefer_turbo_core = true;
            self.no_freq_scaling = false;
        } else if self.balanced {
            self.no_core_compaction = false;
            self.prefer_smt_core = false;
            self.prefer_little_core = false;
            self.no_prefer_turbo_core = false;
            self.no_freq_scaling = false;
        }

        Some(self)
    }
}

unsafe impl Plain for msg_task_ctx {}

impl msg_task_ctx {
    fn from_bytes(buf: &[u8]) -> &msg_task_ctx {
        plain::from_bytes(buf).expect("The buffer is either too short or not aligned!")
    }
}

impl introspec {
    fn new() -> Self {
        let intrspc = unsafe { mem::MaybeUninit::<introspec>::zeroed().assume_init() };
        intrspc
    }
}

#[derive(Debug)]
struct CpuFlatId {
    node_id: usize,
    llc_pos: usize,
    max_freq: usize,
    core_pos: usize,
    cpu_pos: usize,
    cpu_id: usize,
    cpu_cap: usize,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
struct ComputeDomainKey {
    node_id: usize,
    llc_pos: usize,
    is_big: bool,
}

#[derive(Debug, Clone)]
struct ComputeDomainValue {
    cpdom_id: usize,
    cpdom_alt_id: Cell<usize>,
    cpu_ids: Vec<usize>,
    neighbor_map: RefCell<BTreeMap<usize, RefCell<Vec<usize>>>>,
}

#[derive(Debug)]
struct FlatTopology {
    cpu_fids_performance: Vec<CpuFlatId>,
    cpu_fids_powersave: Vec<CpuFlatId>,
    cpdom_map: BTreeMap<ComputeDomainKey, ComputeDomainValue>,
}

impl fmt::Display for FlatTopology {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for cpu_fid in self.cpu_fids_performance.iter() {
            write!(f, "\nCPU in performance: {:?}", cpu_fid).ok();
        }
        for cpu_fid in self.cpu_fids_powersave.iter() {
            write!(f, "\nCPU in powersave: {:?}", cpu_fid).ok();
        }
        for (k, v) in self.cpdom_map.iter() {
            write!(f, "\nCPDOM: {:?} {:?}", k, v).ok();
        }
        Ok(())
    }
}

impl FlatTopology {
    /// Build a flat-structured topology
    pub fn new() -> Result<FlatTopology> {
        let (cpu_fids_performance, avg_freq) = Self::build_cpu_fids(false, false).unwrap();
        let (cpu_fids_powersave, _) = Self::build_cpu_fids(true, true).unwrap();

        // Note that building compute domain is not dependent to CPU orer
        // so it is okay to use any cpu_fids_*.
        let cpdom_map = Self::build_cpdom(&cpu_fids_performance, avg_freq).unwrap();

        Ok(FlatTopology {
            cpu_fids_performance,
            cpu_fids_powersave,
            cpdom_map,
        })
    }

    /// Check if SMT is enabled or not
    pub fn is_smt_active() -> std::io::Result<i32> {
        let mut file = File::open("/sys/devices/system/cpu/smt/active")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let smt_active: i32 = contents.trim().parse().unwrap_or(0);

        Ok(smt_active)
    }

    /// Build a flat-structured list of CPUs in a preference order
    fn build_cpu_fids(
        prefer_smt_core: bool,
        prefer_little_core: bool,
    ) -> Option<(Vec<CpuFlatId>, usize)> {
        let topo = Topology::new().expect("Failed to build host topology");
        let mut cpu_fids = Vec::new();

        // Build a vector of cpu flat ids.
        let mut base_freq = 0;
        let mut avg_freq = 0;
        for (node_id, node) in topo.nodes().iter().enumerate() {
            for (llc_pos, (_llc_id, llc)) in node.llcs().iter().enumerate() {
                for (core_pos, (_core_id, core)) in llc.cores().iter().enumerate() {
                    for (cpu_pos, (cpu_id, cpu)) in core.cpus().iter().enumerate() {
                        let cpu_fid = CpuFlatId {
                            node_id,
                            llc_pos,
                            max_freq: cpu.max_freq(),
                            core_pos,
                            cpu_pos,
                            cpu_id: *cpu_id,
                            cpu_cap: 0,
                        };
                        cpu_fids.push(cpu_fid);
                        if base_freq < cpu.max_freq() {
                            base_freq = cpu.max_freq();
                        }
                        avg_freq += cpu.max_freq();
                    }
                }
            }
        }
        avg_freq /= cpu_fids.len() as usize;

        // Initialize cpu capacity
        if base_freq > 0 {
            for cpu_fid in cpu_fids.iter_mut() {
                cpu_fid.cpu_cap = ((cpu_fid.max_freq * 1024) / base_freq) as usize;
            }
        } else {
            // Unfortunately, the frequency information in sysfs seems not
            // always correct in some distributions.
            for cpu_fid in cpu_fids.iter_mut() {
                cpu_fid.cpu_cap = 1024 as usize;
            }
            warn!("System does not provide proper CPU frequency infomation.");
        }

        // Sort the cpu_fids
        match (prefer_smt_core, prefer_little_core) {
            (true, false) => {
                // Sort the cpu_fids by node, llc, ^max_freq, core, and cpu order
                cpu_fids.sort_by(|a, b| {
                    a.node_id
                        .cmp(&b.node_id)
                        .then_with(|| a.llc_pos.cmp(&b.llc_pos))
                        .then_with(|| b.max_freq.cmp(&a.max_freq))
                        .then_with(|| a.core_pos.cmp(&b.core_pos))
                        .then_with(|| a.cpu_pos.cmp(&b.cpu_pos))
                });
            }
            (true, true) => {
                // Sort the cpu_fids by node, llc, max_freq, core, and cpu order
                cpu_fids.sort_by(|a, b| {
                    a.node_id
                        .cmp(&b.node_id)
                        .then_with(|| a.llc_pos.cmp(&b.llc_pos))
                        .then_with(|| a.max_freq.cmp(&b.max_freq))
                        .then_with(|| a.core_pos.cmp(&b.core_pos))
                        .then_with(|| a.cpu_pos.cmp(&b.cpu_pos))
                });
            }
            (false, false) => {
                // Sort the cpu_fids by cpu, node, llc, ^max_freq, and core order
                cpu_fids.sort_by(|a, b| {
                    a.cpu_pos
                        .cmp(&b.cpu_pos)
                        .then_with(|| a.node_id.cmp(&b.node_id))
                        .then_with(|| a.llc_pos.cmp(&b.llc_pos))
                        .then_with(|| b.max_freq.cmp(&a.max_freq))
                        .then_with(|| a.core_pos.cmp(&b.core_pos))
                });
            }
            (false, true) => {
                // Sort the cpu_fids by cpu, node, llc, max_freq, and core order
                cpu_fids.sort_by(|a, b| {
                    a.cpu_pos
                        .cmp(&b.cpu_pos)
                        .then_with(|| a.node_id.cmp(&b.node_id))
                        .then_with(|| a.llc_pos.cmp(&b.llc_pos))
                        .then_with(|| a.max_freq.cmp(&b.max_freq))
                        .then_with(|| a.core_pos.cmp(&b.core_pos))
                });
            }
        }

        Some((cpu_fids, avg_freq))
    }

    /// Build a list of compute domains
    fn build_cpdom(
        cpu_fids: &Vec<CpuFlatId>,
        avg_freq: usize,
    ) -> Option<BTreeMap<ComputeDomainKey, ComputeDomainValue>> {
        // Creat a compute domain map
        let mut cpdom_id = 0;
        let mut cpdom_map: BTreeMap<ComputeDomainKey, ComputeDomainValue> = BTreeMap::new();
        for cpu_fid in cpu_fids.iter() {
            let key = ComputeDomainKey {
                node_id: cpu_fid.node_id,
                llc_pos: cpu_fid.llc_pos,
                is_big: cpu_fid.max_freq >= avg_freq,
            };
            let mut value;
            match cpdom_map.get(&key) {
                Some(v) => {
                    value = v.clone();
                }
                None => {
                    value = ComputeDomainValue {
                        cpdom_id,
                        cpdom_alt_id: Cell::new(cpdom_id),
                        cpu_ids: Vec::new(),
                        neighbor_map: RefCell::new(BTreeMap::new()),
                    };
                    cpdom_id += 1;
                }
            }
            value.cpu_ids.push(cpu_fid.cpu_id);
            cpdom_map.insert(key, value);
        }

        // Fill up cpdom_alt_id for each compute domain
        for (k, v) in cpdom_map.iter() {
            let mut key = k.clone();
            key.is_big = !k.is_big;

            if let Some(alt_v) = cpdom_map.get(&key) {
                v.cpdom_alt_id.set(alt_v.cpdom_id);
            }
        }

        // Build a neighbor map for each compute domain
        for ((from_k, from_v), (to_k, to_v)) in iproduct!(cpdom_map.iter(), cpdom_map.iter()) {
            if from_k == to_k {
                continue;
            }

            let d = Self::dist(from_k, to_k);
            let mut map = from_v.neighbor_map.borrow_mut();
            match map.get(&d) {
                Some(v) => {
                    v.borrow_mut().push(to_v.cpdom_id);
                }
                None => {
                    map.insert(d, RefCell::new(vec![to_v.cpdom_id]));
                }
            }
        }

        Some(cpdom_map)
    }

    /// Calculate distance from two compute domains
    fn dist(from: &ComputeDomainKey, to: &ComputeDomainKey) -> usize {
        let mut d = 0;
        // code type > numa node > llc
        if from.is_big != to.is_big {
            d += 3;
        }
        if from.node_id != to.node_id {
            d += 2;
        } else {
            if from.llc_pos != to.llc_pos {
                d += 1;
            }
        }
        d
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    rb_mgr: libbpf_rs::RingBuffer<'static>,
    intrspc: introspec,
    intrspc_rx: Receiver<SchedSample>,
    monitor_tid: Option<ThreadId>,
    stats_server: StatsServer<StatsReq, StatsRes>,
    mseq_id: u64,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        if *NR_CPU_IDS > LAVD_CPU_ID_MAX {
            panic!(
                "Num possible CPU IDs ({}) exceeds maximum of ({})",
                *NR_CPU_IDS, LAVD_CPU_ID_MAX
            );
        }

        // Increase MEMLOCK size since the BPF scheduler might use
        // more than the current limit
        set_rlimit_infinity();

        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 0);
        let mut skel = scx_ops_open!(skel_builder, open_object, lavd_ops)?;

        // Initialize CPU topology
        let topo = FlatTopology::new().unwrap();
        Self::init_cpus(&mut skel, &topo);

        // Initialize skel according to @opts.
        Self::init_globals(&mut skel, &opts);

        // Attach.
        let mut skel = scx_ops_load!(skel, lavd_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, lavd_ops)?);
        let stats_server = StatsServer::new(stats::server_data(*NR_CPU_IDS as u64)).launch()?;

        // Build a ring buffer for instrumentation
        let (intrspc_tx, intrspc_rx) = channel::bounded(65536);
        let rb_map = &mut skel.maps.introspec_msg;
        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder
            .add(rb_map, move |data| {
                Scheduler::relay_introspec(data, &intrspc_tx)
            })
            .unwrap();
        let rb_mgr = builder.build().unwrap();

        Ok(Self {
            skel,
            struct_ops,
            rb_mgr,
            intrspc: introspec::new(),
            intrspc_rx,
            monitor_tid: None,
            stats_server,
            mseq_id: 0,
        })
    }

    fn init_cpus(skel: &mut OpenBpfSkel, topo: &FlatTopology) {
        // Initialize CPU order topologically sorted
        // by a cpu, node, llc, max_freq, and core order
        for (pos, cpu) in topo.cpu_fids_performance.iter().enumerate() {
            skel.maps.rodata_data.cpu_order_performance[pos] = cpu.cpu_id as u16;
            skel.maps.rodata_data.__cpu_capacity_hint[cpu.cpu_id] = cpu.cpu_cap as u16;
        }
        for (pos, cpu) in topo.cpu_fids_powersave.iter().enumerate() {
            skel.maps.rodata_data.cpu_order_powersave[pos] = cpu.cpu_id as u16;
        }
        debug!("{:#?}", topo);

        // Initialize compute domain contexts
        for (k, v) in topo.cpdom_map.iter() {
            skel.maps.bss_data.cpdom_ctxs[v.cpdom_id].id = v.cpdom_id as u64;
            skel.maps.bss_data.cpdom_ctxs[v.cpdom_id].alt_id = v.cpdom_alt_id.get() as u64;
            skel.maps.bss_data.cpdom_ctxs[v.cpdom_id].is_big = k.is_big as u8;
            skel.maps.bss_data.cpdom_ctxs[v.cpdom_id].is_active = 1;
            for cpu_id in v.cpu_ids.iter() {
                let i = cpu_id / 64;
                let j = cpu_id % 64;
                skel.maps.bss_data.cpdom_ctxs[v.cpdom_id].__cpumask[i] |= 0x01 << j;
            }

            const LAVD_CPDOM_MAX_NR: u8 = 32;
            const LAVD_CPDOM_MAX_DIST: usize = 4;
            if v.neighbor_map.borrow().iter().len() > LAVD_CPDOM_MAX_DIST {
                panic!("The processor topology is too complex to handle in BPF.");
            }

            for (k, (_d, neighbors)) in v.neighbor_map.borrow().iter().enumerate() {
                let nr_neighbors = neighbors.borrow().len() as u8;
                if nr_neighbors > LAVD_CPDOM_MAX_NR {
                    panic!("The processor topology is too complex to handle in BPF.");
                }
                skel.maps.bss_data.cpdom_ctxs[v.cpdom_id].nr_neighbors[k] = nr_neighbors;
                for n in neighbors.borrow().iter() {
                    skel.maps.bss_data.cpdom_ctxs[v.cpdom_id].neighbor_bits[k] |= 0x1 << n;
                }
            }
        }
    }

    fn is_powersave_mode(opts: &Opts) -> bool {
        opts.prefer_smt_core && opts.prefer_little_core
    }

    fn init_globals(skel: &mut OpenBpfSkel, opts: &Opts) {
        skel.maps.bss_data.no_core_compaction = opts.no_core_compaction;
        skel.maps.bss_data.no_freq_scaling = opts.no_freq_scaling;
        skel.maps.bss_data.no_prefer_turbo_core = opts.no_prefer_turbo_core;
        skel.maps.bss_data.is_powersave_mode = Self::is_powersave_mode(&opts);
        skel.maps.rodata_data.nr_cpu_ids = *NR_CPU_IDS as u64;
        skel.maps.rodata_data.is_smt_active = match FlatTopology::is_smt_active() {
            Ok(ret) => (ret == 1) as u32,
            Err(_) => 0,
        };
        skel.maps.rodata_data.is_autopilot_on = opts.autopilot;
        skel.maps.rodata_data.verbose = opts.verbose;
    }

    fn get_msg_seq_id() -> u64 {
        static mut MSEQ: u64 = 0;
        unsafe {
            MSEQ += 1;
            MSEQ
        }
    }

    fn relay_introspec(data: &[u8], intrspc_tx: &Sender<SchedSample>) -> i32 {
        let mt = msg_task_ctx::from_bytes(data);
        let tx = mt.taskc_x;
        let tc = mt.taskc;

        // No idea how to print other types than LAVD_MSG_TASKC
        if mt.hdr.kind != LAVD_MSG_TASKC {
            return 0;
        }

        let mseq = Scheduler::get_msg_seq_id();

        let c_tx_cm: *const c_char = (&tx.comm as *const [c_char; 17]) as *const c_char;
        let c_tx_cm_str: &CStr = unsafe { CStr::from_ptr(c_tx_cm) };
        let tx_comm: &str = c_tx_cm_str.to_str().unwrap();

        let c_tx_st: *const c_char = (&tx.stat as *const [c_char; 6]) as *const c_char;
        let c_tx_st_str: &CStr = unsafe { CStr::from_ptr(c_tx_st) };
        let tx_stat: &str = c_tx_st_str.to_str().unwrap();

        match intrspc_tx.try_send(SchedSample {
            mseq,
            pid: tx.pid,
            comm: tx_comm.into(),
            stat: tx_stat.into(),
            cpu_id: tx.cpu_id,
            victim_cpu: tc.victim_cpu,
            vdeadline_delta_ns: tc.vdeadline_delta_ns,
            slice_ns: tc.slice_ns,
            greedy_ratio: tc.greedy_ratio,
            lat_cri: tc.lat_cri,
            avg_lat_cri: tx.avg_lat_cri,
            static_prio: tx.static_prio,
            slice_boost_prio: tc.slice_boost_prio,
            run_freq: tc.run_freq,
            run_time_ns: tc.run_time_ns,
            wait_freq: tc.wait_freq,
            wake_freq: tc.wake_freq,
            perf_cri: tc.perf_cri,
            thr_perf_cri: tx.thr_perf_cri,
            cpuperf_cur: tx.cpuperf_cur,
            cpu_util: tx.cpu_util,
            nr_active: tx.nr_active,
        }) {
            Ok(()) | Err(TrySendError::Full(_)) => 0,
            Err(e) => panic!("failed to send on intrspc_tx ({})", &e),
        }
    }

    fn prep_introspec(&mut self) {
        self.skel.maps.bss_data.intrspc.cmd = self.intrspc.cmd;
        self.skel.maps.bss_data.intrspc.arg = self.intrspc.arg;
    }

    fn cleanup_introspec(&mut self) {
        self.skel.maps.bss_data.intrspc.cmd = LAVD_CMD_NOP;
    }

    fn get_pc(x: u64, y: u64) -> f64 {
        return 100. * x as f64 / y as f64;
    }

    fn get_power_mode(power_mode: s32) -> &'static str {
        const LAVD_PM_PERFORMANCE: s32 = 0;
        const LAVD_PM_BALANCED: s32 = 1;
        const LAVD_PM_POWERSAVE: s32 = 2;

        match power_mode {
            LAVD_PM_PERFORMANCE => {
                return &"performance";
            }
            LAVD_PM_BALANCED => {
                return &"balanced";
            }
            LAVD_PM_POWERSAVE => {
                return &"powersave";
            }
            _ => {
                return &"unknown";
            }
        }
    }

    fn stats_req_to_res(&mut self, req: &StatsReq) -> Result<StatsRes> {
        Ok(match req {
            StatsReq::NewSampler(tid) => {
                self.rb_mgr.consume().unwrap();
                self.monitor_tid = Some(*tid);
                StatsRes::Ack
            }
            StatsReq::SysStatsReq { tid } => {
                if Some(*tid) != self.monitor_tid {
                    return Ok(StatsRes::Bye);
                }
                self.mseq_id += 1;

                let bss_data = &self.skel.maps.bss_data;
                let st = bss_data.__sys_stats[0];

                let mseq = self.mseq_id;
                let avg_svc_time = st.avg_svc_time;
                let nr_queued_task = st.nr_queued_task;
                let nr_active = st.nr_active;
                let nr_sched = st.nr_sched;
                let pc_migration = Self::get_pc(st.nr_migration, nr_sched);
                let pc_preemption = Self::get_pc(st.nr_preemption, nr_sched);
                let pc_greedy = Self::get_pc(st.nr_greedy, nr_sched);
                let pc_pc = Self::get_pc(st.nr_perf_cri, nr_sched);
                let pc_lc = Self::get_pc(st.nr_lat_cri, nr_sched);
                let nr_big = st.nr_big;
                let pc_big = Self::get_pc(nr_big, nr_sched);
                let pc_pc_on_big = Self::get_pc(st.nr_pc_on_big, nr_big);
                let pc_lc_on_big = Self::get_pc(st.nr_lc_on_big, nr_big);
                let power_mode = Self::get_power_mode(bss_data.power_mode);
                let total_time = bss_data.performance_mode_ns
                    + bss_data.balanced_mode_ns
                    + bss_data.powersave_mode_ns;
                let pc_performance = Self::get_pc(bss_data.performance_mode_ns, total_time);
                let pc_balanced = Self::get_pc(bss_data.balanced_mode_ns, total_time);
                let pc_powersave = Self::get_pc(bss_data.powersave_mode_ns, total_time);

                StatsRes::SysStats(SysStats {
                    mseq,
                    avg_svc_time,
                    nr_queued_task,
                    nr_active,
                    nr_sched,
                    pc_migration,
                    pc_preemption,
                    pc_greedy,
                    pc_pc,
                    pc_lc,
                    pc_big,
                    pc_pc_on_big,
                    pc_lc_on_big,
                    power_mode: power_mode.to_string(),
                    pc_performance,
                    pc_balanced,
                    pc_powersave,
                })
            }
            StatsReq::SchedSamplesNr {
                tid,
                nr_samples,
                interval_ms,
            } => {
                if Some(*tid) != self.monitor_tid {
                    return Ok(StatsRes::Bye);
                }

                self.intrspc.cmd = LAVD_CMD_SCHED_N;
                self.intrspc.arg = *nr_samples;
                self.prep_introspec();
                std::thread::sleep(Duration::from_millis(*interval_ms));
                self.rb_mgr.poll(Duration::from_millis(100)).unwrap();

                let mut samples = vec![];
                while let Ok(ts) = self.intrspc_rx.try_recv() {
                    samples.push(ts);
                }

                self.cleanup_introspec();

                StatsRes::SchedSamples(SchedSamples { samples })
            }
        })
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn set_power_profile(&mut self, mode: u32) -> Result<(), u32> {
        let prog = &mut self.skel.progs.set_power_profile;
        let mut args = power_arg {
            power_mode: mode as c_int,
        };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }

        Ok(())
    }

    fn read_energy_profile() -> String {
        let res =
            File::open("/sys/devices/system/cpu/cpufreq/policy0/energy_performance_preference")
                .and_then(|mut file| {
                    let mut contents = String::new();
                    file.read_to_string(&mut contents)?;
                    Ok(contents.trim().to_string())
                });

        res.unwrap_or_else(|_| "none".to_string())
    }

    fn update_power_profile(&mut self, prev_profile: String) -> (bool, String) {
        let profile = Self::read_energy_profile();
        if profile == prev_profile {
            // If the profile is the same, skip updaring the profile for BPF.
            return (true, profile);
        }

        if profile == "performance" {
            let _ = self.set_power_profile(LAVD_PM_PERFORMANCE);
            info!("Set the scheduler's power profile to performance mode.");
        } else if profile == "balance_performance" {
            let _ = self.set_power_profile(LAVD_PM_BALANCED);
            info!("Set the scheduler's power profile to balanced mode.");
        } else if profile == "power" {
            let _ = self.set_power_profile(LAVD_PM_POWERSAVE);
            info!("Set the scheduler's power profile to power-save mode.");
        } else {
            // We don't know how to handle an unknown energy profile,
            // so we just give up updating the profile from now on.
            return (false, profile);
        }

        (true, profile)
    }

    fn run(&mut self, opts: &Opts, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        let mut autopower = opts.autopower;
        let mut profile = "unknown".to_string();

        if opts.performance {
            let _ = self.set_power_profile(LAVD_PM_PERFORMANCE);
        } else if opts.powersave {
            let _ = self.set_power_profile(LAVD_PM_POWERSAVE);
        } else {
            let _ = self.set_power_profile(LAVD_PM_BALANCED);
        }

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            if autopower {
                (autopower, profile) = self.update_power_profile(profile);
            }

            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(req) => {
                    let res = self.stats_req_to_res(&req)?;
                    res_ch.send(res)?;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
            self.cleanup_introspec();
        }
        self.rb_mgr.consume().unwrap();

        self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
    }
}

fn init_log(opts: &Opts) {
    let llv = match opts.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        llv,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )
    .unwrap();
}

fn main() -> Result<()> {
    let mut opts = Opts::parse();

    if opts.version {
        println!("scx_lavd {}", *build_id::SCX_FULL_VERSION);
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data(0).describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    init_log(&opts);

    opts.proc().unwrap();
    debug!("{:#?}", opts);

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(nr_samples) = opts.monitor_sched_samples {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            stats::monitor_sched_samples(nr_samples, shutdown_copy).unwrap()
        });
        let _ = jh.join();
        return Ok(());
    }

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            stats::monitor(Duration::from_secs_f64(intv), shutdown_copy).unwrap()
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        info!(
            "scx_lavd scheduler is initialized (build ID: {})",
            *build_id::SCX_FULL_VERSION
        );
        info!("scx_lavd scheduler starts running.");
        if !sched.run(&opts, shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
