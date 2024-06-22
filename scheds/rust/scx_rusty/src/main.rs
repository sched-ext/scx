// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

mod domain;
use domain::DomainGroup;

pub mod tuner;
use tuner::Tuner;

pub mod load_balance;
use load_balance::LoadBalancer;
use load_balance::NumaStat;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

#[macro_use]
extern crate static_assertions;

use ::fb_procfs as procfs;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use log::info;
use metrics::counter;
use metrics::Counter;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics::histogram;
use metrics::Histogram;
use metrics::gauge;
use metrics::Gauge;
use scx_utils::LogRecorderBuilder;
use scx_utils::compat;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Cpumask;
use scx_utils::Topology;
use scx_utils::UserExitInfo;

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
/// WARNING: scx_rusty currently assumes that all domains have equal
/// processing power and at similar distances from each other. This
/// limitation will be removed in the future.
#[derive(Debug, Parser)]
struct Opts {
    /// Scheduling slice duration for under-utilized hosts, in microseconds.
    #[clap(short = 'u', long, default_value = "20000")]
    slice_us_underutil: u64,

    /// Scheduling slice duration for over-utilized hosts, in microseconds.
    #[clap(short = 'o', long, default_value = "1000")]
    slice_us_overutil: u64,

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

    /// When non-zero, enable greedy task stealing. When a domain is idle, a cpu
    /// will attempt to steal tasks from another domain as follows:
    ///
    /// 1. Try to consume a task from the current domain
    /// 2. Try to consume a task from another domain in the current NUMA node
    ///    (or globally, if running on a single-socket system), if the domain
    ///    has at least this specified number of tasks enqueued.
    ///
    /// See greedy_threshold_x_numa to enable task stealing across NUMA nodes.
    /// Tasks stolen in this manner are not permanently stolen from their
    /// domain.
    #[clap(short = 'g', long, default_value = "1")]
    greedy_threshold: u32,

    /// When non-zero, enable greedy task stealing across NUMA nodes. The order
    /// of greedy task stealing follows greedy-threshold as described above, and
    /// greedy-threshold must be nonzero to enable task stealing across NUMA
    /// nodes.
    #[clap(long, default_value = "0")]
    greedy_threshold_x_numa: u32,

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

    /// Whether tasks can be pushed directly to idle CPUs on NUMA nodes
    /// different than its domain's node. If direct-greedy-under is disabled,
    /// this option is a no-op. Otherwise, if this option is set to false
    /// (default), tasks will only be directly pushed to idle CPUs if they
    /// reside on the same NUMA node as the task's domain.
    #[clap(short = 'r', long, action = clap::ArgAction::SetTrue)]
    direct_greedy_numa: bool,

    /// If specified, only tasks which have their scheduling policy set to
    /// SCHED_EXT using sched_setscheduler(2) are switched. Otherwise, all
    /// tasks are switched.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    partial: bool,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Enable verbose output including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Enable the Prometheus endpoint for metrics on port 9000.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    enable_prometheus: bool,
}

fn read_total_cpu(reader: &procfs::ProcReader) -> Result<procfs::CpuStat> {
    reader
        .read_stat()
        .context("Failed to read procfs")?
        .total_cpu
        .ok_or_else(|| anyhow!("Could not read total cpu stat in proc"))
}

pub fn sub_or_zero(curr: &u64, prev: &u64) -> u64 {
    if let Some(res) = curr.checked_sub(*prev) {
        res
    } else {
        0
    }
}

struct Metrics {
    wsync: Counter,
    wsync_prev_idle: Counter,
    prev_idle: Counter,
    greedy_idle: Counter,
    pinned: Counter,
    direct_dispatch: Counter,
    direct_greedy: Counter,
    direct_greedy_far: Counter,
    dsq: Counter,
    greedy_local: Counter,
    greedy_xnuma: Counter,
    kick_greedy: Counter,
    repatriate: Counter,
    dl_clamped: Counter,
    dl_preset: Counter,
    task_errors: Counter,
    lb_data_errors: Counter,
    load_balance: Counter,
    slice_length: Gauge,
    cpu_busy_pct: Histogram,
    processing_duration: Histogram,
}

impl Metrics {
    fn new() -> Self {
        Self {
            wsync: counter!("dispatched_tasks_total", "type" => "wsync"),
            wsync_prev_idle: counter!("dispatched_tasks_total", "type" => "wsync_prev_idle"),
            prev_idle: counter!("dispatched_tasks_total", "type" => "prev_idle"),
            greedy_idle: counter!("dispatched_tasks_total", "type" => "greedy_idle"),
            pinned: counter!("dispatched_tasks_total", "type" => "pinned"),
            direct_dispatch: counter!("dispatched_tasks_total", "type" => "direct_dispatch"),
            direct_greedy: counter!("dispatched_tasks_total", "type" => "direct_greedy"),
            direct_greedy_far: counter!("dispatched_tasks_total", "type" => "direct_greedy_far"),
            dsq: counter!("dispatched_tasks_total", "type" => "dsq"),
            greedy_local: counter!("dispatched_tasks_total", "type" => "greedy_local"),
            greedy_xnuma: counter!("dispatched_tasks_total", "type" => "greedy_xnuma"),
            kick_greedy: counter!("kick_greedy_total"),
            repatriate: counter!("repatriate_total"),
            dl_clamped: counter!("dl_clamped_total"),
            dl_preset: counter!("dl_preset_total"),
            task_errors: counter!("task_errors_total"),
            lb_data_errors: counter!("lb_data_errors_total"),
            load_balance: counter!("load_balance_total"),

            slice_length: gauge!("slice_length_us"),

            cpu_busy_pct: histogram!("cpu_busy_pct"),
            processing_duration: histogram!("processing_duration_us"),
        }
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

    dom_group: Arc<DomainGroup>,

    proc_reader: procfs::ProcReader,

    prev_at: Instant,
    prev_total_cpu: procfs::CpuStat,

    nr_lb_data_errors: u64,

    tuner: Tuner,

    metrics: Metrics,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts) -> Result<Self> {
        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 0);
        init_libbpf_logging(None);
        let mut skel = scx_ops_open!(skel_builder, rusty).unwrap();

        // Initialize skel according to @opts.
        let top = Arc::new(Topology::new()?);

        let domains = Arc::new(DomainGroup::new(top.clone(), &opts.cpumasks)?);

        if top.nr_cpu_ids() > MAX_CPUS {
            bail!(
                "Num possible CPU IDs ({}) exceeds maximum of ({})",
                top.nr_cpu_ids(),
                MAX_CPUS
            );
        }

        if domains.nr_doms() > MAX_DOMS {
            bail!(
                "nr_doms ({}) is greater than MAX_DOMS ({})",
                domains.nr_doms(),
                MAX_DOMS
            );
        }

        skel.rodata_mut().nr_nodes = domains.nr_nodes() as u32;
        skel.rodata_mut().nr_doms = domains.nr_doms() as u32;
        skel.rodata_mut().nr_cpu_ids = top.nr_cpu_ids() as u32;

        // Any CPU with dom > MAX_DOMS is considered offline by default. There
        // are a few places in the BPF code where we skip over offlined CPUs
        // (e.g. when initializing or refreshing tune params), and elsewhere the
        // scheduler will error if we try to schedule from them.
        for cpu in 0..top.nr_cpu_ids() {
            skel.rodata_mut().cpu_dom_id_map[cpu] = u32::MAX;
        }

        for (id, dom) in domains.doms().iter() {
            for cpu in dom.mask().into_iter() {
                skel.rodata_mut().cpu_dom_id_map[cpu] = id
                    .clone()
                    .try_into()
                    .expect("Domain ID could not fit into 32 bits");
            }
        }

        for numa in 0..domains.nr_nodes() {
            let mut numa_mask = Cpumask::new()?;
            let node_domains = domains.numa_doms(&numa);
            for dom in node_domains.iter() {
                let dom_mask = dom.mask();
                numa_mask = numa_mask.or(&dom_mask);
            }

            let raw_numa_slice = numa_mask.as_raw_slice();
            let node_cpumask_slice = &mut skel.rodata_mut().numa_cpumasks[numa];
            let (left, _) = node_cpumask_slice.split_at_mut(raw_numa_slice.len());
            left.clone_from_slice(raw_numa_slice);
            info!("NUMA[{:02}] mask= {}", numa, numa_mask);

            for dom in node_domains.iter() {
                let raw_dom_slice = dom.mask_slice();
                let dom_cpumask_slice = &mut skel.rodata_mut().dom_cpumasks[dom.id()];
                let (left, _) = dom_cpumask_slice.split_at_mut(raw_dom_slice.len());
                left.clone_from_slice(raw_dom_slice);
                skel.rodata_mut().dom_numa_id_map[dom.id()] =
                    numa.try_into().expect("NUMA ID could not fit into 32 bits");

                info!("  DOM[{:02}] mask= {}", dom.id(), dom.mask());
            }
        }

        if opts.partial {
            skel.struct_ops.rusty_mut().flags |= *compat::SCX_OPS_SWITCH_PARTIAL;
        }
        skel.struct_ops.rusty_mut().exit_dump_len = opts.exit_dump_len;

        skel.rodata_mut().load_half_life = (opts.load_half_life * 1000000000.0) as u32;
        skel.rodata_mut().kthreads_local = opts.kthreads_local;
        skel.rodata_mut().fifo_sched = opts.fifo_sched;
        skel.rodata_mut().greedy_threshold = opts.greedy_threshold;
        skel.rodata_mut().greedy_threshold_x_numa = opts.greedy_threshold_x_numa;
        skel.rodata_mut().direct_greedy_numa = opts.direct_greedy_numa;
        skel.rodata_mut().debug = opts.verbose as u32;

        // Attach.
        let mut skel = scx_ops_load!(skel, rusty, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, rusty)?);
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

            top,
            dom_group: domains.clone(),
            proc_reader,

            prev_at: Instant::now(),
            prev_total_cpu,

            nr_lb_data_errors: 0,

            tuner: Tuner::new(
                domains,
                opts.direct_greedy_under,
                opts.kick_greedy_under,
                opts.slice_us_underutil * 1000,
                opts.slice_us_overutil * 1000,
            )?,

            metrics: Metrics::new(),
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
                let idle_usec = sub_or_zero(curr_idle, prev_idle);
                let iowait_usec = sub_or_zero(curr_iowait, prev_iowait);
                let user_usec = sub_or_zero(curr_user, prev_user);
                let system_usec = sub_or_zero(curr_system, prev_system);
                let nice_usec = sub_or_zero(curr_nice, prev_nice);
                let irq_usec = sub_or_zero(curr_irq, prev_irq);
                let softirq_usec = sub_or_zero(curr_softirq, prev_softirq);
                let stolen_usec = sub_or_zero(curr_stolen, prev_stolen);

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
        let zero_vec =
            vec![vec![0u8; stats_map.value_size() as usize]; self.top.nr_cpu_ids()];

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
        &self,
        bpf_stats: &[u64],
        lb_stats: &[NumaStat],
    ) {
        let stat = |idx| bpf_stats[idx as usize];

        let wsync = stat(bpf_intf::stat_idx_RUSTY_STAT_WAKE_SYNC);
        let wsync_prev_idle = stat(bpf_intf::stat_idx_RUSTY_STAT_SYNC_PREV_IDLE);
        let prev_idle = stat(bpf_intf::stat_idx_RUSTY_STAT_PREV_IDLE);
        let greedy_idle = stat(bpf_intf::stat_idx_RUSTY_STAT_GREEDY_IDLE);
        let pinned = stat(bpf_intf::stat_idx_RUSTY_STAT_PINNED);
        let direct_dispatch = stat(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_DISPATCH);
        let direct_greedy = stat(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_GREEDY);
        let direct_greedy_far = stat(bpf_intf::stat_idx_RUSTY_STAT_DIRECT_GREEDY_FAR);
        let dsq = stat(bpf_intf::stat_idx_RUSTY_STAT_DSQ_DISPATCH);
        let greedy_local = stat(bpf_intf::stat_idx_RUSTY_STAT_GREEDY_LOCAL);
        let greedy_xnuma = stat(bpf_intf::stat_idx_RUSTY_STAT_GREEDY_XNUMA);
        
        self.metrics.wsync_prev_idle.increment(wsync_prev_idle);
        self.metrics.wsync.increment(wsync);
        self.metrics.prev_idle.increment(prev_idle);
        self.metrics.greedy_idle.increment(greedy_idle);
        self.metrics.pinned.increment(pinned);
        self.metrics.direct_dispatch.increment(direct_dispatch);
        self.metrics.direct_greedy.increment(direct_greedy);
        self.metrics.direct_greedy_far.increment(direct_greedy_far);
        self.metrics.dsq.increment(dsq);
        self.metrics.greedy_local.increment(greedy_local);
        self.metrics.greedy_xnuma.increment(greedy_xnuma);

        let kick_greedy = stat(bpf_intf::stat_idx_RUSTY_STAT_KICK_GREEDY);
        let repatriate = stat(bpf_intf::stat_idx_RUSTY_STAT_REPATRIATE);
        let dl_clamped = stat(bpf_intf::stat_idx_RUSTY_STAT_DL_CLAMP);
        let dl_preset = stat(bpf_intf::stat_idx_RUSTY_STAT_DL_PRESET);
        
        self.metrics.kick_greedy.increment(kick_greedy);
        self.metrics.repatriate.increment(repatriate);
        self.metrics.dl_clamped.increment(dl_clamped);
        self.metrics.dl_preset.increment(dl_preset);

        self.metrics.task_errors.increment(stat(bpf_intf::stat_idx_RUSTY_STAT_TASK_GET_ERR));
        self.metrics.lb_data_errors.increment(self.nr_lb_data_errors);
        self.metrics.load_balance.increment(stat(bpf_intf::stat_idx_RUSTY_STAT_LOAD_BALANCE));
        
        self.metrics.slice_length.set(self.tuner.slice_ns as f64 / 1000.0);

        // We need to dynamically create the metrics for each node and domain 
        // because we don't know how many there are at compile time. Metrics 
        // will be cached and reused so this is not a performance issue.
        for node in lb_stats.iter() {
            histogram!("load_avg", "node" => node.id.to_string())
                .record(node.load.load_avg() as f64);
            for dom in node.domains.iter() {
                histogram!("load_avg", "node" => node.id.to_string(), "dom" => dom.id.to_string())
                    .record(dom.load.load_avg() as f64);
            }
        }
    }

    fn lb_step(&mut self) -> Result<()> {
        let started_at = Instant::now();
        let bpf_stats = self.read_bpf_stats()?;
        let cpu_busy = self.get_cpu_busy()?;
        self.metrics.cpu_busy_pct.record(cpu_busy * 100.0);

        let mut lb = LoadBalancer::new(
            &mut self.skel,
            self.dom_group.clone(),
            self.balanced_kworkers,
            self.tuner.fully_utilized.clone(),
            self.balance_load.clone(),
        );

        lb.load_balance()?;
        self.metrics.processing_duration.record(started_at.elapsed().as_micros() as f64);

        let stats = lb.get_stats();
        self.report(
            &bpf_stats,
            &stats,
        );

        self.prev_at = started_at;
        Ok(())
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let now = Instant::now();
        let mut next_tune_at = now + self.tune_interval;
        let mut next_sched_at = now + self.sched_interval;

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
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

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if opts.enable_prometheus {
        info!("Enabling Prometheus endpoint: http://localhost:9000");
        PrometheusBuilder::new()
            .install()
            .expect("failed to install Prometheus recorder");
    } else {
        LogRecorderBuilder::new()
            .with_reporting_interval(Duration::from_secs(3))
            .install()
            .expect("failed to install log recorder");
    }

    loop {
        let mut sched = Scheduler::init(&opts)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }
    Ok(())
}
