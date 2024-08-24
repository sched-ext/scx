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

use libc::c_char;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fmt;
use std::mem;
use std::mem::MaybeUninit;
use std::str;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::OpenObject;
use log::debug;
use log::info;
use log::warn;
use scx_utils::build_id;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;

use nix::sys::signal;
use plain::Plain;
use rlimit::{getrlimit, setrlimit, Resource};

static RUNNING: AtomicBool = AtomicBool::new(true);

/// scx_lavd: Latency-criticality Aware Virtual Deadline (LAVD) scheduler
///
/// The rust part is minimal. It processes command line options and logs out
/// scheduling statistics. The BPF part makes all the scheduling decisions.
/// See the more detailed overview of the LAVD design at main.bpf.c.
#[derive(Debug, Parser)]
struct Opts {
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

    /// Disable controlling the CPU frequency. In order to improve latency and responsiveness of
    /// performance-critical tasks, scx_lavd increases the CPU frequency even if CPU usage is low.
    /// See main.bpf.c for more info. Normally set by the power mode, but can be set independently
    /// if desired.
    #[clap(long = "no-freq-scaling", action = clap::ArgAction::SetTrue)]
    no_freq_scaling: bool,

    /// The number of scheduling samples to be reported every second.
    /// (default: 1, 0 = disable logging)
    #[clap(short = 's', long, default_value = "1")]
    nr_sched_samples: u64,

    /// Enable verbose output including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

impl Opts {
    fn proc(&mut self) -> Option<&mut Self> {

        if self.performance {
            self.no_core_compaction = true;
            self.prefer_smt_core = false;
            self.prefer_little_core = false;
            self.no_freq_scaling = true;
        }
        if self.powersave {
            self.no_core_compaction = false;
            self.prefer_smt_core = true;
            self.prefer_little_core = true;
            self.no_freq_scaling = false;
        }
        if self.balanced{
            self.no_core_compaction = false;
            self.prefer_smt_core = false;
            self.prefer_little_core = false;
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

    fn init(opts: &Opts) -> Self {
        let mut intrspc = introspec::new();
        if opts.nr_sched_samples > 0 {
            intrspc.cmd = LAVD_CMD_SCHED_N;
            intrspc.arg = opts.nr_sched_samples;
        } else {
            intrspc.cmd = LAVD_CMD_NOP;
        }
        intrspc.requested = false as u8;
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
    cpu_fids: Vec<CpuFlatId>,
    cpdom_map: BTreeMap<ComputeDomainKey, ComputeDomainValue>,
    nr_cpus_online: usize,
}

impl fmt::Display for FlatTopology {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for cpu_fid in self.cpu_fids.iter() {
            write!(f, "\nCPU: {:?}", cpu_fid).ok();
        }
        for (k, v) in self.cpdom_map.iter() {
            write!(f, "\nCPDOM: {:?} {:?}", k, v).ok();
        }
        Ok(())
    }
}

impl FlatTopology {
    /// Build a flat-structured topology
    pub fn new(opts: &Opts) -> Result<FlatTopology> {
        let (cpu_fids, avg_freq, nr_cpus_online) =
            Self::build_cpu_fids(opts.prefer_smt_core, opts.prefer_little_core).unwrap();
        let cpdom_map = Self::build_cpdom(&cpu_fids, avg_freq).unwrap();

        Ok(FlatTopology {
            cpu_fids,
            cpdom_map,
            nr_cpus_online,
        })
    }

    /// Build a flat-structured list of CPUs in a preference order
    fn build_cpu_fids(prefer_smt_core: bool, prefer_little_core: bool) ->
        Option<(Vec<CpuFlatId>, usize, usize)> {
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
            // Unfortunately, the frequency information in sysfs seems not always correct in some
            // distributions.
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

        Some((cpu_fids, avg_freq, topo.nr_cpus_online()))
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
        for (from_k, from_v) in cpdom_map.iter() {
            for (to_k, to_v) in cpdom_map.iter() {
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
    nr_cpus_onln: u64,
    rb_mgr: libbpf_rs::RingBuffer<'static>,
    intrspc: introspec,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        // Increase MEMLOCK size since the BPF scheduler might use
        // more than the current limit
        let (soft_limit, _) = getrlimit(Resource::MEMLOCK).unwrap();
        setrlimit(Resource::MEMLOCK, soft_limit, rlimit::INFINITY).unwrap();

        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 0);
        let mut skel = scx_ops_open!(skel_builder, open_object, lavd_ops)?;

        // Initialize CPU topology
        let topo = FlatTopology::new(&opts).unwrap();
        Self::init_cpus(&mut skel, &topo);

        // Initialize skel according to @opts.
        let nr_cpus_onln = topo.nr_cpus_online as u64;
        Self::init_globals(&mut skel, &opts, nr_cpus_onln);

        // Attach.
        let mut skel = scx_ops_load!(skel, lavd_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, lavd_ops)?);

        // Build a ring buffer for instrumentation
        let rb_map = &mut skel.maps.introspec_msg;
        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder.add(rb_map, Scheduler::print_bpf_msg).unwrap();
        let rb_mgr = builder.build().unwrap();

        Ok(Self {
            skel,
            struct_ops,
            nr_cpus_onln,
            rb_mgr,
            intrspc: introspec::init(opts),
        })
    }

    fn init_cpus(skel: &mut OpenBpfSkel, topo: &FlatTopology) {
        // Initialize CPU order topologically sorted
        // by a cpu, node, llc, max_freq, and core order
        for (pos, cpu) in topo.cpu_fids.iter().enumerate() {
            skel.maps.rodata_data.cpu_order[pos] = cpu.cpu_id as u16;
            skel.maps.rodata_data.__cpu_capacity_hint[cpu.cpu_id] = cpu.cpu_cap as u16;
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
                skel.maps.bss_data.cpdom_ctxs[v.cpdom_id].cpumask[i] |= 0x01 << j;
            }

            for (k, (_d, neighbors)) in v.neighbor_map.borrow().iter().enumerate() {
                skel.maps.bss_data.cpdom_ctxs[v.cpdom_id].nr_neighbors[k] =
                    neighbors.borrow().len() as u8;
                for n in neighbors.borrow().iter() {
                    skel.maps.bss_data.cpdom_ctxs[v.cpdom_id].neighbor_bits[k] = 0x1 << n;
                }
            }
        }
    }

    fn init_globals(skel: &mut OpenBpfSkel, opts: &Opts, nr_cpus_onln: u64) {
        skel.maps.bss_data.nr_cpus_onln = nr_cpus_onln;
        skel.maps.rodata_data.no_core_compaction = opts.no_core_compaction;
        skel.maps.rodata_data.no_freq_scaling = opts.no_freq_scaling;
        skel.maps.rodata_data.verbose = opts.verbose;
    }

    fn get_msg_seq_id() -> u64 {
        static mut MSEQ: u64 = 0;
        unsafe {
            MSEQ += 1;
            MSEQ
        }
    }

    fn print_bpf_msg(data: &[u8]) -> i32 {
        let mt = msg_task_ctx::from_bytes(data);
        let tx = mt.taskc_x;
        let tc = mt.taskc;

        // No idea how to print other types than LAVD_MSG_TASKC
        if mt.hdr.kind != LAVD_MSG_TASKC {
            return 0;
        }

        // Print a message from the BPF scheduler
        let mseq = Scheduler::get_msg_seq_id();

        if mseq % 32 == 1 {
            info!(
                "| {:6} | {:7} | {:17} \
                   | {:5} | {:4} | {:4} \
                   | {:14} | {:8} | {:7} \
                   | {:8} | {:7} | {:8} \
                   | {:7} | {:9} | {:9} \
                   | {:9} | {:9} | {:8} \
                   | {:8} | {:8} | {:8} \
                   | {:6} |",
                "mseq",
                "pid",
                "comm",
                "stat",
                "cpu",
                "vtmc",
                "vddln_ns",
                "slc_ns",
                "grdy_rt",
                "lat_cri",
                "avg_lc",
                "st_prio",
                "slc_bst",
                "run_freq",
                "run_tm_ns",
                "wait_freq",
                "wake_freq",
                "perf_cri",
                "avg_pc",
                "cpufreq",
                "cpu_util",
                "nr_act",
            );
        }

        let c_tx_cm: *const c_char = (&tx.comm as *const [c_char; 17]) as *const c_char;
        let c_tx_cm_str: &CStr = unsafe { CStr::from_ptr(c_tx_cm) };
        let tx_comm: &str = c_tx_cm_str.to_str().unwrap();

        let c_tx_st: *const c_char = (&tx.stat as *const [c_char; 6]) as *const c_char;
        let c_tx_st_str: &CStr = unsafe { CStr::from_ptr(c_tx_st) };
        let tx_stat: &str = c_tx_st_str.to_str().unwrap();

        info!(
            "| {:6} | {:7} | {:17} \
               | {:5} | {:4} | {:4} \
               | {:14} | {:8} | {:7} \
               | {:8} | {:7} | {:8} \
               | {:7} | {:9} | {:9} \
               | {:9} | {:9} | {:8} \
               | {:8} | {:8} | {:8} \
               | {:6} |",
            mseq,
            tx.pid,
            tx_comm,
            tx_stat,
            tx.cpu_id,
            tc.victim_cpu,
            tc.vdeadline_delta_ns,
            tc.slice_ns,
            tc.greedy_ratio,
            tc.lat_cri,
            tx.avg_lat_cri,
            tx.static_prio,
            tc.slice_boost_prio,
            tc.run_freq,
            tc.run_time_ns,
            tc.wait_freq,
            tc.wake_freq,
            tc.perf_cri,
            tx.avg_perf_cri,
            tx.cpuperf_cur,
            tx.cpu_util,
            tx.nr_active,
        );

        0
    }

    fn prep_introspec(&mut self) -> u64 {
        let mut interval_ms = 1000;

        if self.intrspc.cmd == LAVD_CMD_SCHED_N && self.intrspc.arg > self.nr_cpus_onln {
            // More samples, shorter sampling interval.
            let f = self.intrspc.arg / self.nr_cpus_onln * 2;
            interval_ms /= f;
        }
        self.intrspc.requested = true as u8;

        self.skel.maps.bss_data.intrspc.cmd = self.intrspc.cmd;
        self.skel.maps.bss_data.intrspc.arg = self.intrspc.arg;
        self.skel.maps.bss_data.intrspc.requested = self.intrspc.requested;

        interval_ms
    }

    fn cleanup_introspec(&mut self) {
        // If not yet requested, do nothing.
        if self.intrspc.requested == false as u8 {
            return;
        }
    }

    fn running(&mut self) -> bool {
        RUNNING.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei)
    }

    fn run(&mut self) -> Result<UserExitInfo> {
        while self.running() {
            let interval_ms = self.prep_introspec();
            std::thread::sleep(Duration::from_millis(interval_ms));
            self.rb_mgr.poll(Duration::from_millis(100)).unwrap();
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

extern "C" fn handle_sigint(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn init_signal_handlers() {
    // Ctrl-c for termination
    unsafe {
        let sigint_action = signal::SigAction::new(
            signal::SigHandler::SigAction(handle_sigint),
            signal::SaFlags::empty(),
            signal::SigSet::empty(),
        );
        signal::sigaction(signal::SIGINT, &sigint_action).unwrap();
    }
}

fn main() -> Result<()> {
    let mut opts = Opts::parse();
    opts.proc().unwrap();

    init_log(&opts);
    init_signal_handlers();
    debug!("{:#?}", opts);

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        info!(
            "scx_lavd scheduler is initialized (build ID: {})",
            *build_id::SCX_FULL_VERSION
        );
        info!(
            "    stat: ('L'atency-critical, 'R'egular) (performance-'H'ungry, performance-'I'nsensitive) ('B'ig, li'T'tle) ('E'ligigle, 'G'reedy) ('P'reempting, 'N'ot)");
        info!("scx_lavd scheduler starts running.");
        if !sched.run()?.should_restart() {
            break;
        }
    }

    Ok(())
}
