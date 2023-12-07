// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::CStr;
use std::ops::Bound::Included;
use std::ops::Bound::Unbounded;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use ::fb_procfs as procfs;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitvec::prelude::*;
use clap::Parser;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::Skel as _;
use libbpf_rs::skel::SkelBuilder as _;
use log::debug;
use log::info;
use log::trace;
use log::warn;
use ordered_float::OrderedFloat;
use scx_utils::ravg::ravg_read;

const RAVG_FRAC_BITS: u32 = bpf_intf::ravg_consts_RAVG_FRAC_BITS;
const MAX_DOMS: usize = bpf_intf::consts_MAX_DOMS as usize;
const MAX_CPUS: usize = bpf_intf::consts_MAX_CPUS as usize;

/// scx_rusty: A multi-domain BPF / userspace hybrid scheduler
///
/// The BPF part does simple vtime or round robin scheduling in each domain
/// while tracking average load of each domain and duty cycle of each task.
///
/// The userspace part performs two roles. First, it makes higher frequency
/// (100ms) tuning decisions. It identifies CPUs which are not too heavily
/// loaded and mark them so that they can pull tasks from other overloaded
/// domains on the fly.
///
/// Second, it drives lower frequency (2s) load balancing. It determines
/// whether load balancing is necessary by comparing domain load averages.
/// If there are large enough load differences, it examines upto 1024
/// recently active tasks on the domain to determine which should be
/// migrated.
///
/// The overhead of userspace operations is low. Load balancing is not
/// performed frequently but work-conservation is still maintained through
/// tuning and greedy execution. Load balancing itself is not that expensive
/// either. It only accesses per-domain load metrics to determine the
/// domains that need load balancing and limited number of per-task metrics
/// for each pushing domain.
///
/// An earlier variant of this scheduler was used to balance across six
/// domains, each representing a chiplet in a six-chiplet AMD processor, and
/// could match the performance of production setup using CFS.
///
/// WARNING: Very high weight (low nice value) tasks can throw off load
/// balancing due to infeasible weight problem. This problem will be solved
/// in the near future.
///
/// WARNING: scx_rusty currently assumes that all domains have equal
/// processing power and at similar distances from each other. This
/// limitation will be removed in the future.
#[derive(Debug, Parser)]
struct Opts {
    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "20000")]
    slice_us: u64,

    /// Monitoring and load balance interval in seconds.
    #[clap(short = 'i', long, default_value = "2.0")]
    interval: f64,

    /// Tuner runs at higher frequency than the load balancer to dynamically
    /// tune scheduling behavior. Tuning interval in seconds.
    #[clap(short = 'I', long, default_value = "0.1")]
    tune_interval: f64,

    /// The half-life of task and domain load running averages in seconds.
    #[clap(short = 'l', long, default_value = "1.0")]
    load_half_life: f64,

    /// Build domains according to how CPUs are grouped at this cache level
    /// as determined by /sys/devices/system/cpu/cpuX/cache/indexI/id.
    #[clap(short = 'c', long, default_value = "3")]
    cache_level: u32,

    /// Instead of using cache locality, set the cpumask for each domain
    /// manually, provide multiple --cpumasks, one for each domain. E.g.
    /// --cpumasks 0xff_00ff --cpumasks 0xff00 will create two domains with
    /// the corresponding CPUs belonging to each domain. Each CPU must
    /// belong to precisely one domain.
    #[clap(short = 'C', long, num_args = 1.., conflicts_with = "cache_level")]
    cpumasks: Vec<String>,

    /// When non-zero, enable greedy task stealing. When a domain is idle, a
    /// cpu will attempt to steal tasks from a domain with at least
    /// greedy_threshold tasks enqueued. These tasks aren't permanently
    /// stolen from the domain.
    #[clap(short = 'g', long, default_value = "1")]
    greedy_threshold: u32,

    /// Disable load balancing. Unless disabled, periodically userspace will
    /// calculate the load factor of each domain and instruct BPF which
    /// processes to move.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_load_balance: bool,

    /// Put per-cpu kthreads directly into local dsq's.
    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    kthreads_local: bool,

    /// In recent kernels (>=v6.6), the kernel is responsible for balancing
    /// kworkers across L3 cache domains. Exclude them from load-balancing
    /// to avoid conflicting operations. Greedy executions still apply.
    #[clap(short = 'b', long, action = clap::ArgAction::SetTrue)]
    balanced_kworkers: bool,

    /// Use FIFO scheduling instead of weighted vtime scheduling.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    fifo_sched: bool,

    /// Idle CPUs with utilization lower than this will get remote tasks
    /// directly pushed on them. 0 disables, 100 enables always.
    #[clap(short = 'D', long, default_value = "90.0")]
    direct_greedy_under: f64,

    /// Idle CPUs with utilization lower than this may get kicked to
    /// accelerate stealing when a task is queued on a saturated remote
    /// domain. 0 disables, 100 enables always.
    #[clap(short = 'K', long, default_value = "100.0")]
    kick_greedy_under: f64,

    /// If specified, only tasks which have their scheduling policy set to
    /// SCHED_EXT using sched_setscheduler(2) are switched. Otherwise, all
    /// tasks are switched.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    partial: bool,

    /// Enable verbose output including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn now_monotonic() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) };
    assert!(ret == 0);
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

fn clear_map(map: &libbpf_rs::Map) {
    for key in map.keys() {
        let _ = map.delete(&key);
    }
}

fn format_cpumask(cpumask: &[u64], nr_cpus: usize) -> String {
    cpumask
        .iter()
        .take((nr_cpus + 64) / 64)
        .rev()
        .fold(String::new(), |acc, x| format!("{} {:016X}", acc, x))
}

fn read_total_cpu(reader: &procfs::ProcReader) -> Result<procfs::CpuStat> {
    reader
        .read_stat()
        .context("Failed to read procfs")?
        .total_cpu
        .ok_or_else(|| anyhow!("Could not read total cpu stat in proc"))
}

fn calc_util(curr: &procfs::CpuStat, prev: &procfs::CpuStat) -> Result<f64> {
    match (curr, prev) {
        (
            procfs::CpuStat {
                user_usec: Some(curr_user),
                nice_usec: Some(curr_nice),
                system_usec: Some(curr_system),
                idle_usec: Some(curr_idle),
                iowait_usec: Some(curr_iowait),
                irq_usec: Some(curr_irq),
                softirq_usec: Some(curr_softirq),
                stolen_usec: Some(curr_stolen),
                ..
            },
            procfs::CpuStat {
                user_usec: Some(prev_user),
                nice_usec: Some(prev_nice),
                system_usec: Some(prev_system),
                idle_usec: Some(prev_idle),
                iowait_usec: Some(prev_iowait),
                irq_usec: Some(prev_irq),
                softirq_usec: Some(prev_softirq),
                stolen_usec: Some(prev_stolen),
                ..
            },
        ) => {
            let idle_usec = curr_idle - prev_idle;
            let iowait_usec = curr_iowait - prev_iowait;
            let user_usec = curr_user - prev_user;
            let system_usec = curr_system - prev_system;
            let nice_usec = curr_nice - prev_nice;
            let irq_usec = curr_irq - prev_irq;
            let softirq_usec = curr_softirq - prev_softirq;
            let stolen_usec = curr_stolen - prev_stolen;

            let busy_usec =
                user_usec + system_usec + nice_usec + irq_usec + softirq_usec + stolen_usec;
            let total_usec = idle_usec + busy_usec + iowait_usec;
            if total_usec > 0 {
                Ok(((busy_usec as f64) / (total_usec as f64)).clamp(0.0, 1.0))
            } else {
                Ok(1.0)
            }
        }
        _ => {
            bail!("Missing stats in cpustat");
        }
    }
}

#[derive(Debug)]
struct Topology {
    nr_cpus: usize,
    nr_doms: usize,
    dom_cpus: Vec<BitVec<u64, Lsb0>>,
    cpu_dom: Vec<Option<usize>>,
}

impl Topology {
    fn from_cpumasks(cpumasks: &[String], nr_cpus: usize) -> Result<Self> {
        if cpumasks.len() > MAX_DOMS {
            bail!(
                "Number of requested domains ({}) is greater than MAX_DOMS ({})",
                cpumasks.len(),
                MAX_DOMS
            );
        }
        let mut cpu_dom = vec![None; nr_cpus];
        let mut dom_cpus = vec![bitvec![u64, Lsb0; 0; MAX_CPUS]; cpumasks.len()];
        for (dom, cpumask) in cpumasks.iter().enumerate() {
            let hex_str = {
                let mut tmp_str = cpumask
                    .strip_prefix("0x")
                    .unwrap_or(cpumask)
                    .replace('_', "");
                if tmp_str.len() % 2 != 0 {
                    tmp_str = "0".to_string() + &tmp_str;
                }
                tmp_str
            };
            let byte_vec = hex::decode(&hex_str)
                .with_context(|| format!("Failed to parse cpumask: {}", cpumask))?;

            for (index, &val) in byte_vec.iter().rev().enumerate() {
                let mut v = val;
                while v != 0 {
                    let lsb = v.trailing_zeros() as usize;
                    v &= !(1 << lsb);
                    let cpu = index * 8 + lsb;
                    if cpu > nr_cpus {
                        bail!(
                            concat!(
                                "Found cpu ({}) in cpumask ({}) which is larger",
                                " than the number of cpus on the machine ({})"
                            ),
                            cpu,
                            cpumask,
                            nr_cpus
                        );
                    }
                    if let Some(other_dom) = cpu_dom[cpu] {
                        bail!(
                            "Found cpu ({}) with domain ({}) but also in cpumask ({})",
                            cpu,
                            other_dom,
                            cpumask
                        );
                    }
                    cpu_dom[cpu] = Some(dom);
                    dom_cpus[dom].set(cpu, true);
                }
            }
            dom_cpus[dom].set_uninitialized(false);
        }

        for (cpu, dom) in cpu_dom.iter().enumerate() {
            if dom.is_none() {
                bail!(
                    "CPU {} not assigned to any domain. Make sure it is covered by some --cpumasks argument.",
                    cpu
                );
            }
        }

        Ok(Self {
            nr_cpus,
            nr_doms: dom_cpus.len(),
            dom_cpus,
            cpu_dom,
        })
    }

    fn from_cache_level(level: u32, nr_cpus: usize) -> Result<Self> {
        let mut cpu_to_cache = vec![]; // (cpu_id, Option<cache_id>)
        let mut cache_ids = BTreeSet::<usize>::new();
        let mut nr_offline = 0;

        // Build cpu -> cache ID mapping.
        for cpu in 0..nr_cpus {
            let path = format!("/sys/devices/system/cpu/cpu{}/cache/index{}/id", cpu, level);
            let id = match std::fs::read_to_string(&path) {
                Ok(val) => Some(val.trim().parse::<usize>().with_context(|| {
                    format!("Failed to parse {:?}'s content {:?}", &path, &val)
                })?),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    nr_offline += 1;
                    None
                }
                Err(e) => return Err(e).with_context(|| format!("Failed to open {:?}", &path)),
            };

            cpu_to_cache.push(id);
            if let Some(id) = id {
                cache_ids.insert(id);
            }
        }

        info!(
            "CPUs: online/possible = {}/{}",
            nr_cpus - nr_offline,
            nr_cpus
        );

        // Cache IDs may have holes. Assign consecutive domain IDs to
        // existing cache IDs.
        let mut cache_to_dom = BTreeMap::<usize, usize>::new();
        let mut nr_doms = 0;
        for cache_id in cache_ids.iter() {
            cache_to_dom.insert(*cache_id, nr_doms);
            nr_doms += 1;
        }

        if nr_doms > MAX_DOMS {
            bail!(
                "Total number of doms {} is greater than MAX_DOMS ({})",
                nr_doms,
                MAX_DOMS
            );
        }

        // Build and return dom -> cpumask and cpu -> dom mappings.
        let mut dom_cpus = vec![bitvec![u64, Lsb0; 0; MAX_CPUS]; nr_doms];
        let mut cpu_dom = vec![];

        for (cpu, cache) in cpu_to_cache.iter().enumerate().take(nr_cpus) {
            match cache {
                Some(cache_id) => {
                    let dom_id = cache_to_dom[cache_id];
                    dom_cpus[dom_id].set(cpu, true);
                    cpu_dom.push(Some(dom_id));
                }
                None => {
                    dom_cpus[0].set(cpu, true);
                    cpu_dom.push(None);
                }
            }
        }

        Ok(Self {
            nr_cpus,
            nr_doms: dom_cpus.len(),
            dom_cpus,
            cpu_dom,
        })
    }
}

struct Tuner {
    top: Arc<Topology>,
    direct_greedy_under: f64,
    kick_greedy_under: f64,
    proc_reader: procfs::ProcReader,
    prev_cpu_stats: BTreeMap<u32, procfs::CpuStat>,
    dom_utils: Vec<f64>,
}

impl Tuner {
    fn new(top: Arc<Topology>, opts: &Opts) -> Result<Self> {
        let proc_reader = procfs::ProcReader::new();
        let prev_cpu_stats = proc_reader
            .read_stat()?
            .cpus_map
            .ok_or_else(|| anyhow!("Expected cpus_map to exist"))?;
        Ok(Self {
            direct_greedy_under: opts.direct_greedy_under / 100.0,
            kick_greedy_under: opts.kick_greedy_under / 100.0,
            proc_reader,
            prev_cpu_stats,
            dom_utils: vec![0.0; top.nr_doms],
            top,
        })
    }

    fn step(&mut self, skel: &mut BpfSkel) -> Result<()> {
        let curr_cpu_stats = self
            .proc_reader
            .read_stat()?
            .cpus_map
            .ok_or_else(|| anyhow!("Expected cpus_map to exist"))?;
        let ti = &mut skel.bss().tune_input;
        let mut dom_nr_cpus = vec![0; self.top.nr_doms];
        let mut dom_util_sum = vec![0.0; self.top.nr_doms];

        for cpu in 0..self.top.nr_cpus {
            let cpu32 = cpu as u32;
            // None domain indicates the CPU was offline during
            // initialization and None CpuStat indicates the CPU has gone
            // down since then. Ignore both.
            if let (Some(dom), Some(curr), Some(prev)) = (
                self.top.cpu_dom[cpu],
                curr_cpu_stats.get(&cpu32),
                self.prev_cpu_stats.get(&cpu32),
            ) {
                dom_nr_cpus[dom] += 1;
                dom_util_sum[dom] += calc_util(curr, prev)?;
            }
        }

        for dom in 0..self.top.nr_doms {
            // Calculate the domain avg util. If there are no active CPUs,
            // it doesn't really matter. Go with 0.0 as that's less likely
            // to confuse users.
            let util = match dom_nr_cpus[dom] {
                0 => 0.0,
                nr => dom_util_sum[dom] / nr as f64,
            };

            self.dom_utils[dom] = util;

            // This could be implemented better.
            let update_dom_bits = |target: &mut [u64; 8], val: bool| {
                for cpu in 0..self.top.nr_cpus {
                    if let Some(cdom) = self.top.cpu_dom[cpu] {
                        if cdom == dom {
                            if val {
                                target[cpu / 64] |= 1u64 << (cpu % 64);
                            } else {
                                target[cpu / 64] &= !(1u64 << (cpu % 64));
                            }
                        }
                    }
                }
            };

            update_dom_bits(
                &mut ti.direct_greedy_cpumask,
                self.direct_greedy_under > 0.99999 || util < self.direct_greedy_under,
            );
            update_dom_bits(
                &mut ti.kick_greedy_cpumask,
                self.kick_greedy_under > 0.99999 || util < self.kick_greedy_under,
            );
        }

        ti.gen += 1;
        self.prev_cpu_stats = curr_cpu_stats;
        Ok(())
    }
}

#[derive(Debug)]
struct TaskInfo {
    pid: i32,
    dom_mask: u64,
    migrated: Cell<bool>,
    is_kworker: bool,
}

struct LoadBalancer<'a, 'b, 'c> {
    skel: &'a mut BpfSkel<'b>,
    top: Arc<Topology>,
    skip_kworkers: bool,

    tasks_by_load: Vec<Option<BTreeMap<OrderedFloat<f64>, TaskInfo>>>,
    load_avg: f64,
    dom_loads: Vec<f64>,

    imbal: Vec<f64>,
    doms_to_push: BTreeMap<OrderedFloat<f64>, u32>,
    doms_to_pull: BTreeMap<OrderedFloat<f64>, u32>,

    nr_lb_data_errors: &'c mut u64,
}

impl<'a, 'b, 'c> LoadBalancer<'a, 'b, 'c> {
    // If imbalance gets higher than this ratio, try to balance the loads.
    const LOAD_IMBAL_HIGH_RATIO: f64 = 0.10;

    // Aim to transfer this fraction of the imbalance on each round. We want
    // to be gradual to avoid unnecessary oscillations. While this can delay
    // convergence, greedy execution should be able to bridge the temporary
    // gap.
    const LOAD_IMBAL_XFER_TARGET_RATIO: f64 = 0.50;

    // Don't push out more than this ratio of load on each round. While this
    // overlaps with XFER_TARGET_RATIO, XFER_TARGET_RATIO only defines the
    // target and doesn't limit the total load. As long as the transfer
    // reduces load imbalance between the two involved domains, it'd happily
    // transfer whatever amount that can be transferred. This limit is used
    // as the safety cap to avoid draining a given domain too much in a
    // single round.
    const LOAD_IMBAL_PUSH_MAX_RATIO: f64 = 0.50;

    fn new(
        skel: &'a mut BpfSkel<'b>,
        top: Arc<Topology>,
        skip_kworkers: bool,
        nr_lb_data_errors: &'c mut u64,
    ) -> Self {
        Self {
            skel,
            skip_kworkers,

            tasks_by_load: (0..top.nr_doms).map(|_| None).collect(),
            load_avg: 0f64,
            dom_loads: vec![0.0; top.nr_doms],

            imbal: vec![0.0; top.nr_doms],
            doms_to_pull: BTreeMap::new(),
            doms_to_push: BTreeMap::new(),

            nr_lb_data_errors,

            top,
        }
    }

    fn read_dom_loads(&mut self) -> Result<()> {
        let now_mono = now_monotonic();
        let load_half_life = self.skel.rodata().load_half_life;
        let maps = self.skel.maps();
        let dom_data = maps.dom_data();
        let mut load_sum = 0.0f64;

        for i in 0..self.top.nr_doms {
            let key = unsafe { std::mem::transmute::<u32, [u8; 4]>(i as u32) };

            if let Some(dom_ctx_map_elem) = dom_data
                .lookup(&key, libbpf_rs::MapFlags::ANY)
                .context("Failed to lookup dom_ctx")?
            {
                let dom_ctx =
                    unsafe { &*(dom_ctx_map_elem.as_slice().as_ptr() as *const bpf_intf::dom_ctx) };

                let rd = &dom_ctx.load_rd;
                self.dom_loads[i] = ravg_read(
                    rd.val,
                    rd.val_at,
                    rd.old,
                    rd.cur,
                    now_mono,
                    load_half_life,
                    RAVG_FRAC_BITS,
                );

                load_sum += self.dom_loads[i];
            }
        }

        self.load_avg = load_sum / self.top.nr_doms as f64;

        Ok(())
    }

    /// To balance dom loads, identify doms with lower and higher load than
    /// average.
    fn calculate_dom_load_balance(&mut self) -> Result<()> {
        for (dom, dom_load) in self.dom_loads.iter().enumerate() {
            let imbal = dom_load - self.load_avg;
            if imbal.abs() >= self.load_avg * Self::LOAD_IMBAL_HIGH_RATIO {
                if imbal > 0f64 {
                    self.doms_to_push.insert(OrderedFloat(imbal), dom as u32);
                } else {
                    self.doms_to_pull.insert(OrderedFloat(-imbal), dom as u32);
                }
                self.imbal[dom] = imbal;
            }
        }
        Ok(())
    }

    /// @dom needs to push out tasks to balance loads. Make sure its
    /// tasks_by_load is populated so that the victim tasks can be picked.
    fn populate_tasks_by_load(&mut self, dom: u32) -> Result<()> {
        if self.tasks_by_load[dom as usize].is_some() {
            return Ok(());
        }

        // Read active_pids and update write_idx and gen.
        //
        // XXX - We can't read task_ctx inline because self.skel.bss()
        // borrows mutably and thus conflicts with self.skel.maps().
        const MAX_PIDS: u64 = bpf_intf::consts_MAX_DOM_ACTIVE_PIDS as u64;
        let active_pids = &mut self.skel.bss().dom_active_pids[dom as usize];
        let mut pids = vec![];

        let (mut ridx, widx) = (active_pids.read_idx, active_pids.write_idx);
        if widx - ridx > MAX_PIDS {
            ridx = widx - MAX_PIDS;
        }

        for idx in ridx..widx {
            let pid = active_pids.pids[(idx % MAX_PIDS) as usize];
            pids.push(pid);
        }

        active_pids.read_idx = active_pids.write_idx;
        active_pids.gen += 1;

        // Read task_ctx and load.
        let load_half_life = self.skel.rodata().load_half_life;
        let maps = self.skel.maps();
        let task_data = maps.task_data();
        let now_mono = now_monotonic();
        let mut tasks_by_load = BTreeMap::new();

        for pid in pids.iter() {
            let key = unsafe { std::mem::transmute::<i32, [u8; 4]>(*pid) };

            if let Some(task_data_elem) = task_data.lookup(&key, libbpf_rs::MapFlags::ANY)? {
                let task_ctx =
                    unsafe { &*(task_data_elem.as_slice().as_ptr() as *const bpf_intf::task_ctx) };

                if task_ctx.dom_id != dom {
                    continue;
                }

                let rd = &task_ctx.dcyc_rd;
                let load = task_ctx.weight as f64
                    * ravg_read(
                        rd.val,
                        rd.val_at,
                        rd.old,
                        rd.cur,
                        now_mono,
                        load_half_life,
                        RAVG_FRAC_BITS,
                    );

                tasks_by_load.insert(
                    OrderedFloat(load),
                    TaskInfo {
                        pid: *pid,
                        dom_mask: task_ctx.dom_mask,
                        migrated: Cell::new(false),
                        is_kworker: task_ctx.is_kworker,
                    },
                );
            }
        }

        debug!(
            "DOM[{:02}] read load for {} tasks",
            dom,
            &tasks_by_load.len(),
        );
        trace!("DOM[{:02}] tasks_by_load={:?}", dom, &tasks_by_load);

        self.tasks_by_load[dom as usize] = Some(tasks_by_load);
        Ok(())
    }

    // Find the first candidate pid which hasn't already been migrated and
    // can run in @pull_dom.
    fn find_first_candidate<'d, I>(
        tasks_by_load: I,
        pull_dom: u32,
        skip_kworkers: bool,
    ) -> Option<(f64, &'d TaskInfo)>
    where
        I: IntoIterator<Item = (&'d OrderedFloat<f64>, &'d TaskInfo)>,
    {
        match tasks_by_load
            .into_iter()
            .skip_while(|(_, task)| {
                task.migrated.get()
                    || (task.dom_mask & (1 << pull_dom) == 0)
                    || (skip_kworkers && task.is_kworker)
            })
            .next()
        {
            Some((OrderedFloat(load), task)) => Some((*load, task)),
            None => None,
        }
    }

    fn pick_victim(
        &mut self,
        (push_dom, to_push): (u32, f64),
        (pull_dom, to_pull): (u32, f64),
    ) -> Result<Option<(&TaskInfo, f64)>> {
        let to_xfer = to_pull.min(to_push) * Self::LOAD_IMBAL_XFER_TARGET_RATIO;

        debug!(
            "considering dom {}@{:.2} -> {}@{:.2}",
            push_dom, to_push, pull_dom, to_pull
        );

        let calc_new_imbal = |xfer: f64| (to_push - xfer).abs() + (to_pull - xfer).abs();

        self.populate_tasks_by_load(push_dom)?;

        // We want to pick a task to transfer from push_dom to pull_dom to
        // reduce the load imbalance between the two closest to $to_xfer.
        // IOW, pick a task which has the closest load value to $to_xfer
        // that can be migrated. Find such task by locating the first
        // migratable task while scanning left from $to_xfer and the
        // counterpart while scanning right and picking the better of the
        // two.
        let (load, task, new_imbal) = match (
            Self::find_first_candidate(
                self.tasks_by_load[push_dom as usize]
                    .as_ref()
                    .unwrap()
                    .range((Unbounded, Included(&OrderedFloat(to_xfer))))
                    .rev(),
                pull_dom,
                self.skip_kworkers,
            ),
            Self::find_first_candidate(
                self.tasks_by_load[push_dom as usize]
                    .as_ref()
                    .unwrap()
                    .range((Included(&OrderedFloat(to_xfer)), Unbounded)),
                pull_dom,
                self.skip_kworkers,
            ),
        ) {
            (None, None) => return Ok(None),
            (Some((load, task)), None) | (None, Some((load, task))) => {
                (load, task, calc_new_imbal(load))
            }
            (Some((load0, task0)), Some((load1, task1))) => {
                let (new_imbal0, new_imbal1) = (calc_new_imbal(load0), calc_new_imbal(load1));
                if new_imbal0 <= new_imbal1 {
                    (load0, task0, new_imbal0)
                } else {
                    (load1, task1, new_imbal1)
                }
            }
        };

        // If the best candidate can't reduce the imbalance, there's nothing
        // to do for this pair.
        let old_imbal = to_push + to_pull;
        if old_imbal < new_imbal {
            debug!(
                "skipping pid {}, dom {} -> {} won't improve imbal {:.2} -> {:.2}",
                task.pid, push_dom, pull_dom, old_imbal, new_imbal
            );
            return Ok(None);
        }

        debug!(
            "migrating pid {}, dom {} -> {}, imbal={:.2} -> {:.2}",
            task.pid, push_dom, pull_dom, old_imbal, new_imbal,
        );

        Ok(Some((task, load)))
    }

    // Actually execute the load balancing. Concretely this writes pid -> dom
    // entries into the lb_data map for bpf side to consume.
    fn load_balance(&mut self) -> Result<()> {
        clear_map(self.skel.maps().lb_data());

        debug!("imbal={:?}", &self.imbal);
        debug!("doms_to_push={:?}", &self.doms_to_push);
        debug!("doms_to_pull={:?}", &self.doms_to_pull);

        // Push from the most imbalanced to least.
        while let Some((OrderedFloat(mut to_push), push_dom)) = self.doms_to_push.pop_last() {
            let push_max = self.dom_loads[push_dom as usize] * Self::LOAD_IMBAL_PUSH_MAX_RATIO;
            let mut pushed = 0f64;

            // Transfer tasks from push_dom to reduce imbalance.
            loop {
                let last_pushed = pushed;

                // Pull from the most imbalaned to least.
                let mut doms_to_pull = BTreeMap::<_, _>::new();
                std::mem::swap(&mut self.doms_to_pull, &mut doms_to_pull);
                let mut pull_doms = doms_to_pull.into_iter().rev().collect::<Vec<(_, _)>>();

                for (to_pull, pull_dom) in pull_doms.iter_mut() {
                    if let Some((task, load)) =
                        self.pick_victim((push_dom, to_push), (*pull_dom, f64::from(*to_pull)))?
                    {
                        // Execute migration.
                        task.migrated.set(true);
                        to_push -= load;
                        *to_pull -= load;
                        pushed += load;

                        // Ask BPF code to execute the migration.
                        let pid = task.pid;
                        let cpid = (pid as libc::pid_t).to_ne_bytes();
                        if let Err(e) = self.skel.maps_mut().lb_data().update(
                            &cpid,
                            &pull_dom.to_ne_bytes(),
                            libbpf_rs::MapFlags::NO_EXIST,
                        ) {
                            warn!(
                                "Failed to update lb_data map for pid={} error={:?}",
                                pid, &e
                            );
                            *self.nr_lb_data_errors += 1;
                        }

                        // Always break after a successful migration so that
                        // the pulling domains are always considered in the
                        // descending imbalance order.
                        break;
                    }
                }

                pull_doms
                    .into_iter()
                    .map(|(k, v)| self.doms_to_pull.insert(k, v))
                    .count();

                // Stop repeating if nothing got transferred or pushed enough.
                if pushed == last_pushed || pushed >= push_max {
                    break;
                }
            }
        }
        Ok(())
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,

    sched_interval: Duration,
    tune_interval: Duration,
    balance_load: bool,
    balanced_kworkers: bool,

    top: Arc<Topology>,
    proc_reader: procfs::ProcReader,

    prev_at: Instant,
    prev_total_cpu: procfs::CpuStat,

    nr_lb_data_errors: u64,

    tuner: Tuner,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts) -> Result<Self> {
        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 0);
        let mut skel = skel_builder.open().context("Failed to open BPF program")?;

        let nr_cpus = libbpf_rs::num_possible_cpus().unwrap();
        if nr_cpus > MAX_CPUS {
            bail!(
                "nr_cpus ({}) is greater than MAX_CPUS ({})",
                nr_cpus,
                MAX_CPUS
            );
        }

        // Initialize skel according to @opts.
        let top = Arc::new(if !opts.cpumasks.is_empty() {
            Topology::from_cpumasks(&opts.cpumasks, nr_cpus)?
        } else {
            Topology::from_cache_level(opts.cache_level, nr_cpus)?
        });

        skel.rodata().nr_doms = top.nr_doms as u32;
        skel.rodata().nr_cpus = top.nr_cpus as u32;

        for (cpu, dom) in top.cpu_dom.iter().enumerate() {
            skel.rodata().cpu_dom_id_map[cpu] = dom.unwrap_or(0) as u32;
        }

        for (dom, cpus) in top.dom_cpus.iter().enumerate() {
            let raw_cpus_slice = cpus.as_raw_slice();
            let dom_cpumask_slice = &mut skel.rodata().dom_cpumasks[dom];
            let (left, _) = dom_cpumask_slice.split_at_mut(raw_cpus_slice.len());
            left.clone_from_slice(cpus.as_raw_slice());
            info!(
                "DOM[{:02}] cpumask{} ({} cpus)",
                dom,
                &format_cpumask(dom_cpumask_slice, nr_cpus),
                cpus.count_ones()
            );
        }

        skel.rodata().slice_ns = opts.slice_us * 1000;
        skel.rodata().load_half_life = (opts.load_half_life * 1000000000.0) as u32;
        skel.rodata().kthreads_local = opts.kthreads_local;
        skel.rodata().fifo_sched = opts.fifo_sched;
        skel.rodata().switch_partial = opts.partial;
        skel.rodata().greedy_threshold = opts.greedy_threshold;
        skel.rodata().debug = opts.verbose as u32;

        // Attach.
        let mut skel = skel.load().context("Failed to load BPF program")?;
        skel.attach().context("Failed to attach BPF program")?;
        let struct_ops = Some(
            skel.maps_mut()
                .rusty()
                .attach_struct_ops()
                .context("Failed to attach rusty struct ops")?,
        );
        info!("Rusty Scheduler Attached");

        // Other stuff.
        let proc_reader = procfs::ProcReader::new();
        let prev_total_cpu = read_total_cpu(&proc_reader)?;

        Ok(Self {
            skel,
            struct_ops, // should be held to keep it attached

            sched_interval: Duration::from_secs_f64(opts.interval),
            tune_interval: Duration::from_secs_f64(opts.tune_interval),
            balance_load: !opts.no_load_balance,
            balanced_kworkers: opts.balanced_kworkers,

            top: top.clone(),
            proc_reader,

            prev_at: Instant::now(),
            prev_total_cpu,

            nr_lb_data_errors: 0,

            tuner: Tuner::new(top, opts)?,
        })
    }

    fn get_cpu_busy(&mut self) -> Result<f64> {
        let total_cpu = read_total_cpu(&self.proc_reader)?;
        let busy = match (&self.prev_total_cpu, &total_cpu) {
            (
                procfs::CpuStat {
                    user_usec: Some(prev_user),
                    nice_usec: Some(prev_nice),
                    system_usec: Some(prev_system),
                    idle_usec: Some(prev_idle),
                    iowait_usec: Some(prev_iowait),
                    irq_usec: Some(prev_irq),
                    softirq_usec: Some(prev_softirq),
                    stolen_usec: Some(prev_stolen),
                    guest_usec: _,
                    guest_nice_usec: _,
                },
                procfs::CpuStat {
                    user_usec: Some(curr_user),
                    nice_usec: Some(curr_nice),
                    system_usec: Some(curr_system),
                    idle_usec: Some(curr_idle),
                    iowait_usec: Some(curr_iowait),
                    irq_usec: Some(curr_irq),
                    softirq_usec: Some(curr_softirq),
                    stolen_usec: Some(curr_stolen),
                    guest_usec: _,
                    guest_nice_usec: _,
                },
            ) => {
                let idle_usec = curr_idle - prev_idle;
                let iowait_usec = curr_iowait - prev_iowait;
                let user_usec = curr_user - prev_user;
                let system_usec = curr_system - prev_system;
                let nice_usec = curr_nice - prev_nice;
                let irq_usec = curr_irq - prev_irq;
                let softirq_usec = curr_softirq - prev_softirq;
                let stolen_usec = curr_stolen - prev_stolen;

                let busy_usec =
                    user_usec + system_usec + nice_usec + irq_usec + softirq_usec + stolen_usec;
                let total_usec = idle_usec + busy_usec + iowait_usec;
                busy_usec as f64 / total_usec as f64
            }
            _ => {
                bail!("Some procfs stats are not populated!");
            }
        };

        self.prev_total_cpu = total_cpu;
        Ok(busy)
    }

    fn read_bpf_stats(&mut self) -> Result<Vec<u64>> {
        let mut maps = self.skel.maps_mut();
        let stats_map = maps.stats();
        let mut stats: Vec<u64> = Vec::new();
        let zero_vec = vec![vec![0u8; stats_map.value_size() as usize]; self.top.nr_cpus];

        for stat in 0..bpf_intf::stat_idx_RUSTY_NR_STATS {
            let cpu_stat_vec = stats_map
                .lookup_percpu(&stat.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
                .with_context(|| format!("Failed to lookup stat {}", stat))?
                .expect("per-cpu stat should exist");
            let sum = cpu_stat_vec
                .iter()
                .map(|val| {
                    u64::from_ne_bytes(
                        val.as_slice()
                            .try_into()
                            .expect("Invalid value length in stat map"),
                    )
                })
                .sum();
            stats_map
                .update_percpu(&stat.to_ne_bytes(), &zero_vec, libbpf_rs::MapFlags::ANY)
                .context("Failed to zero stat")?;
            stats.push(sum);
        }
        Ok(stats)
    }

    fn report(
        &mut self,
        stats: &[u64],
        cpu_busy: f64,
        processing_dur: Duration,
        load_avg: f64,
        dom_loads: &[f64],
        imbal: &[f64],
    ) {
        let stat = |idx| stats[idx as usize];
        let total = stat(bpf_intf::stat_idx_RUSTY_STAT_WAKE_SYNC)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_PREV_IDLE)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_GREEDY_IDLE)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_PINNED)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_DISPATCH)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_GREEDY)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_GREEDY_FAR)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_DSQ_DISPATCH)
            + stat(bpf_intf::stat_idx_RUSTY_STAT_GREEDY);

        info!(
            "cpu={:7.2} bal={} load_avg={:8.2} task_err={} lb_data_err={} proc={:?}ms",
            cpu_busy * 100.0,
            stats[bpf_intf::stat_idx_RUSTY_STAT_LOAD_BALANCE as usize],
            load_avg,
            stats[bpf_intf::stat_idx_RUSTY_STAT_TASK_GET_ERR as usize],
            self.nr_lb_data_errors,
            processing_dur.as_millis(),
        );

        let stat_pct = |idx| stat(idx) as f64 / total as f64 * 100.0;

        info!(
            "tot={:7} wsync={:5.2} prev_idle={:5.2} greedy_idle={:5.2} pin={:5.2}",
            total,
            stat_pct(bpf_intf::stat_idx_RUSTY_STAT_WAKE_SYNC),
            stat_pct(bpf_intf::stat_idx_RUSTY_STAT_PREV_IDLE),
            stat_pct(bpf_intf::stat_idx_RUSTY_STAT_GREEDY_IDLE),
            stat_pct(bpf_intf::stat_idx_RUSTY_STAT_PINNED),
        );

        info!(
            "dir={:5.2} dir_greedy={:5.2} dir_greedy_far={:5.2}",
            stat_pct(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_DISPATCH),
            stat_pct(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_GREEDY),
            stat_pct(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_GREEDY_FAR),
        );

        info!(
            "dsq={:5.2} greedy={:5.2} kick_greedy={:5.2} rep={:5.2}",
            stat_pct(bpf_intf::stat_idx_RUSTY_STAT_DSQ_DISPATCH),
            stat_pct(bpf_intf::stat_idx_RUSTY_STAT_GREEDY),
            stat_pct(bpf_intf::stat_idx_RUSTY_STAT_KICK_GREEDY),
            stat_pct(bpf_intf::stat_idx_RUSTY_STAT_REPATRIATE),
        );

        let ti = &self.skel.bss().tune_input;
        info!(
            "direct_greedy_cpumask={}",
            format_cpumask(&ti.direct_greedy_cpumask, self.top.nr_cpus)
        );
        info!(
            "  kick_greedy_cpumask={}",
            format_cpumask(&ti.kick_greedy_cpumask, self.top.nr_cpus)
        );

        for i in 0..self.top.nr_doms {
            info!(
                "DOM[{:02}] util={:6.2} load={:8.2} imbal={}",
                i,
                self.tuner.dom_utils[i] * 100.0,
                dom_loads[i],
                if imbal[i] == 0.0 {
                    format!("{:9.2}", 0.0)
                } else {
                    format!("{:+9.2}", imbal[i])
                },
            );
        }
    }

    fn lb_step(&mut self) -> Result<()> {
        let started_at = Instant::now();
        let bpf_stats = self.read_bpf_stats()?;
        let cpu_busy = self.get_cpu_busy()?;

        let mut lb = LoadBalancer::new(
            &mut self.skel,
            self.top.clone(),
            self.balanced_kworkers,
            &mut self.nr_lb_data_errors,
        );

        lb.read_dom_loads()?;
        lb.calculate_dom_load_balance()?;

        if self.balance_load {
            lb.load_balance()?;
        }

        // Extract fields needed for reporting and drop lb to release
        // mutable borrows.
        let (load_avg, dom_loads, imbal) = (lb.load_avg, lb.dom_loads, lb.imbal);

        self.report(
            &bpf_stats,
            cpu_busy,
            Instant::now().duration_since(started_at),
            load_avg,
            &dom_loads,
            &imbal,
        );

        self.prev_at = started_at;
        Ok(())
    }

    fn read_bpf_exit_kind(&mut self) -> i32 {
        unsafe { std::ptr::read_volatile(&self.skel.bss().exit_kind as *const _) }
    }

    fn report_bpf_exit_kind(&mut self) -> Result<()> {
        // Report msg if EXT_OPS_EXIT_ERROR.
        match self.read_bpf_exit_kind() {
            0 => Ok(()),
            etype if etype == 2 => {
                let cstr = unsafe { CStr::from_ptr(self.skel.bss().exit_msg.as_ptr() as *const _) };
                let msg = cstr
                    .to_str()
                    .context("Failed to convert exit msg to string")
                    .unwrap();
                bail!("BPF exit_kind={} msg={}", etype, msg);
            }
            etype => {
                info!("BPF exit_kind={}", etype);
                Ok(())
            }
        }
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        let now = Instant::now();
        let mut next_tune_at = now + self.tune_interval;
        let mut next_sched_at = now + self.sched_interval;

        while !shutdown.load(Ordering::Relaxed) && self.read_bpf_exit_kind() == 0 {
            let now = Instant::now();

            if now >= next_tune_at {
                self.tuner.step(&mut self.skel)?;
                next_tune_at += self.tune_interval;
                if next_tune_at < now {
                    next_tune_at = now + self.tune_interval;
                }
            }

            if now >= next_sched_at {
                self.lb_step()?;
                next_sched_at += self.sched_interval;
                if next_sched_at < now {
                    next_sched_at = now + self.sched_interval;
                }
            }

            std::thread::sleep(
                next_sched_at
                    .min(next_tune_at)
                    .duration_since(Instant::now()),
            );
        }

        self.report_bpf_exit_kind()
    }
}

impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

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
    )?;

    let mut sched = Scheduler::init(&opts)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    sched.run(shutdown)
}
