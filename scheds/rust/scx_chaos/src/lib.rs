// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_intf;
mod bpf_skel;
pub mod stats;

use bpf_skel::BpfSkel;
use stats::Metrics;

use log::warn;

use scx_p2dq::SchedulerOpts as P2dqOpts;
use scx_userspace_arena::alloc::Allocator;
use scx_userspace_arena::alloc::HeapAllocator;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::compat::tracefs_mount;
use scx_utils::init_libbpf_logging;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;

use libbpf_rs::skel::Skel;
use scx_arena::ArenaLib;
use scx_p2dq::types;
use scx_utils::NR_CPU_IDS;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::libbpf_sys::bpf_program__set_autoattach;
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::Link;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use log::debug;
use log::info;
use nix::unistd::Pid;
use scx_stats::prelude::*;

use std::alloc::Layout;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::marker::PhantomPinned;
use std::mem::MaybeUninit;
use std::panic;
use std::pin::Pin;
use std::process::Command;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::RwLock;
use std::thread;
use std::time::Duration;
use std::time::Instant;

const SCHEDULER_NAME: &str = "scx_chaos";
struct ArenaAllocator(Pin<Rc<SkelWithObject>>);

unsafe impl Allocator for ArenaAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, anyhow::Error> {
        let skel = self.0.skel.read().unwrap();
        unsafe {
            // SAFETY: this helper requires the BPF program to have a specific signature. this one
            // does.
            scx_userspace_arena::alloc::call_allocate_program(
                &skel.progs.scx_userspace_arena_alloc_pages,
                layout,
            )
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        let skel = self.0.skel.read().unwrap();
        unsafe {
            // SAFETY: this helper requires the BPF program to have a specific signature. this one
            // does.
            scx_userspace_arena::alloc::call_deallocate_program(
                &skel.progs.scx_userspace_arena_free_pages,
                ptr,
                layout,
            )
        }
    }
}

#[derive(Debug)]
pub enum Trait {
    RandomDelays {
        frequency: f64,
        min_us: u64,
        max_us: u64,
    },
    CpuFreq {
        frequency: f64,
        min_freq: u32,
        max_freq: u32,
    },
    PerfDegradation {
        frequency: f64,
        degradation_frac7: u64,
    },
}

impl Trait {
    pub fn kind(&self) -> u32 {
        match self {
            Self::RandomDelays { .. } => bpf_intf::chaos_trait_kind_CHAOS_TRAIT_RANDOM_DELAYS,
            Self::CpuFreq { .. } => bpf_intf::chaos_trait_kind_CHAOS_TRAIT_CPU_FREQ,
            Self::PerfDegradation { .. } => bpf_intf::chaos_trait_kind_CHAOS_TRAIT_DEGRADATION,
        }
    }

    pub fn frequency(&self) -> f64 {
        match self {
            Self::RandomDelays { frequency, .. } => *frequency,
            Self::CpuFreq { frequency, .. } => *frequency,
            Self::PerfDegradation { frequency, .. } => *frequency,
        }
    }
}

#[derive(Debug)]
pub enum RequiresPpid {
    ExcludeParent(Pid),
    IncludeParent(Pid),
}

#[derive(Debug)]
pub struct KprobeRandomDelays {
    pub kprobes: Vec<String>,
    pub freq: f64,
    pub min_us: u64,
    pub max_us: u64,
}

#[derive(Debug)]
/// State required to build a Scheduler configuration.
pub struct Builder<'a> {
    pub traits: Vec<Trait>,
    pub verbose: u8,
    pub kprobe_random_delays: Option<KprobeRandomDelays>,
    pub p2dq_opts: &'a P2dqOpts,
    pub requires_ppid: Option<RequiresPpid>,
}

pub struct SkelWithObject {
    open_object: MaybeUninit<OpenObject>,
    skel: RwLock<BpfSkel<'static>>,

    // Skel holds a reference to the OpenObject, so the address must not change.
    _pin: PhantomPinned,
}

pub struct Scheduler {
    _arena: HeapAllocator<ArenaAllocator>,
    _struct_ops: libbpf_rs::Link,
    _links: Vec<Link>,
    stats_server: StatsServer<(), Metrics>,

    // Fields are dropped in declaration order, this must be last as arena holds a reference to the
    // skel
    skel: Pin<Rc<SkelWithObject>>,
}

impl Scheduler {
    fn get_metrics(&self) -> Metrics {
        let mut stats = vec![0u64; bpf_intf::chaos_stat_idx_CHAOS_NR_STATS as usize];
        let stats_map = &self.skel.skel.read().unwrap().maps.chaos_stats;

        for stat in 0..bpf_intf::chaos_stat_idx_CHAOS_NR_STATS {
            let cpu_stat_vec: Vec<Vec<u8>> = stats_map
                .lookup_percpu(&stat.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
                .unwrap_or(None)
                .unwrap_or_default();
            let sum: u64 = cpu_stat_vec
                .iter()
                .map(|val| u64::from_ne_bytes(val.as_slice().try_into().unwrap_or([0; 8])))
                .sum();
            stats[stat as usize] = sum;
        }

        Metrics {
            trait_random_delays: stats
                [bpf_intf::chaos_stat_idx_CHAOS_STAT_TRAIT_RANDOM_DELAYS as usize],
            trait_cpu_freq: stats[bpf_intf::chaos_stat_idx_CHAOS_STAT_TRAIT_CPU_FREQ as usize],
            trait_degradation: stats
                [bpf_intf::chaos_stat_idx_CHAOS_STAT_TRAIT_DEGRADATION as usize],
            chaos_excluded: stats[bpf_intf::chaos_stat_idx_CHAOS_STAT_CHAOS_EXCLUDED as usize],
            chaos_skipped: stats[bpf_intf::chaos_stat_idx_CHAOS_STAT_CHAOS_SKIPPED as usize],
            kprobe_random_delays: stats
                [bpf_intf::chaos_stat_idx_CHAOS_STAT_KPROBE_RANDOM_DELAYS as usize],
            timer_kicks: stats[bpf_intf::chaos_stat_idx_CHAOS_STAT_TIMER_KICKS as usize],
        }
    }

    pub fn observe(
        &self,
        shutdown: &(Mutex<bool>, Condvar),
        timeout: Option<Duration>,
    ) -> Result<()> {
        let (lock, cvar) = shutdown;
        let (res_ch, req_ch) = self.stats_server.channels();

        let start_time = Instant::now();

        let mut guard = lock.lock().unwrap();
        while !*guard {
            let skel = &self.skel.skel.read().unwrap();

            if uei_exited!(&skel, uei) {
                return uei_report!(&skel, uei)
                    .and_then(|_| Err(anyhow::anyhow!("scheduler exited unexpectedly")));
            }

            match req_ch.recv_timeout(Duration::from_millis(500)) {
                Ok(()) => {
                    let _ = res_ch.send(self.get_metrics());
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(_) => {} // ignore other errors
            }

            if timeout.is_some_and(|x| Instant::now().duration_since(start_time) >= x) {
                break;
            }

            guard = cvar
                .wait_timeout(guard, Duration::from_millis(100))
                .unwrap()
                .0;
        }

        Ok(())
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

impl Builder<'_> {
    fn attach_kprobes(&self, skel: &mut BpfSkel) -> Result<Vec<Link>> {
        let Some(kd) = &self.kprobe_random_delays else {
            return Ok(vec![]);
        };

        if kd.kprobes.is_empty() {
            return Ok(vec![]);
        }

        validate_kprobes(&kd.kprobes).context("Failed to validate kprobes passed by user")?;

        let mut links = vec![];
        for k in &kd.kprobes {
            links.push(
                skel.progs
                    .generic
                    .attach_kprobe(false, k)
                    .context(format!("Failed to attach kprobe {k:?}"))?,
            );
        }
        Ok(links)
    }

    fn load_skel(&self) -> Result<Pin<Rc<SkelWithObject>>> {
        let mut out: Rc<MaybeUninit<SkelWithObject>> = Rc::new_uninit();
        let uninit_skel = Rc::get_mut(&mut out).expect("brand new rc should be unique");

        let open_object = &mut unsafe {
            // SAFETY: We're extracting a MaybeUninit field from a MaybeUninit which is always
            // safe.
            let ptr = uninit_skel.as_mut_ptr();
            (&raw mut (*ptr).open_object).as_mut().unwrap()
        };

        let open_object = unsafe {
            // SAFETY: Scheduler is pinned so this reference will not be invalidated for the
            // lifetime of Scheduler. Dropping MaybeUninit is a no-op, so it doesn't matter who
            // gets first. The use site (BpfSkel) is also in Scheduler and has the same lifetime.
            // Therefore it is safe to treat this reference as 'static from BpfSkel's perspective.
            std::mem::transmute::<&mut MaybeUninit<OpenObject>, &'static mut MaybeUninit<OpenObject>>(
                open_object,
            )
        };

        let mut skel_builder = bpf_skel::BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(self.verbose > 1);
        init_libbpf_logging(None);

        let topo = if self.p2dq_opts.virt_llc_enabled {
            Topology::with_args(&self.p2dq_opts.topo)?
        } else {
            Topology::new()?
        };
        let open_opts = LibbpfOpts::default().into_bpf_open_opts();
        let mut open_skel = scx_ops_open!(skel_builder, open_object, chaos, open_opts)?;
        let hw_profile = scx_p2dq::HardwareProfile::detect();
        scx_p2dq::init_open_skel!(
            &mut open_skel,
            &topo,
            self.p2dq_opts,
            self.verbose,
            &hw_profile
        )?;

        let rodata = open_skel.maps.rodata_data.as_mut().unwrap();

        if self.p2dq_opts.queued_wakeup {
            open_skel.struct_ops.chaos_mut().flags |= *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;
        }
        open_skel.struct_ops.chaos_mut().flags |= *compat::SCX_OPS_KEEP_BUILTIN_IDLE;

        match self.requires_ppid {
            None => {
                rodata.ppid_targeting_ppid = -1;
            }
            Some(RequiresPpid::ExcludeParent(p)) => {
                rodata.ppid_targeting_inclusive = false;
                rodata.ppid_targeting_ppid = p.as_raw();
            }
            Some(RequiresPpid::IncludeParent(p)) => {
                rodata.ppid_targeting_inclusive = true;
                rodata.ppid_targeting_ppid = p.as_raw();
            }
        };

        if let Some(kprobe_random_delays) = &self.kprobe_random_delays {
            rodata.kprobe_delays_freq_frac32 =
                (kprobe_random_delays.freq * 2_f64.powf(32_f64)) as u32;
            rodata.kprobe_delays_min_ns = kprobe_random_delays.min_us * 1000;
            rodata.kprobe_delays_max_ns = kprobe_random_delays.max_us * 1000;
        }

        // Set up the frequency array. The first element means nothing, so should be what's
        // required to add up to 100%. The rest should be cumulative frequencies.
        let freq_array = &mut rodata.trait_delay_freq_frac32;
        freq_array.fill(0);
        for tr in &self.traits {
            let kind = tr.kind();
            if freq_array[kind as usize] != 0 {
                bail!("trait of kind {} specified multiple times!", kind);
            }

            let fixed_point = (tr.frequency() * 2_f64.powf(32_f64)) as u32;
            freq_array[kind as usize] = fixed_point;
        }
        freq_array[bpf_intf::chaos_trait_kind_CHAOS_TRAIT_NONE as usize] =
            u32::MAX - freq_array.iter().sum::<u32>();
        for i in 1..freq_array.len() {
            freq_array[i] = freq_array[i]
                .checked_add(freq_array[i - 1])
                .ok_or_else(|| {
                    let err =
                        concat!("frequencies overflowed! please ensure that frequencies sum to",
                    " <=1. as these are floating point numbers, you may have to decrease by",
                    " slightly more than you expect.");
                    anyhow::anyhow!(err)
                })?;
        }

        debug!(
            "frequencies calculated as: {:?}",
            rodata.trait_delay_freq_frac32
        );

        for tr in &self.traits {
            match tr {
                Trait::RandomDelays {
                    frequency: _,
                    min_us,
                    max_us,
                } => {
                    rodata.random_delays_min_ns = min_us * 1000;
                    rodata.random_delays_max_ns = max_us * 1000;
                }
                Trait::CpuFreq {
                    frequency: _,
                    min_freq,
                    max_freq,
                } => {
                    rodata.cpu_freq_min = *min_freq;
                    rodata.cpu_freq_max = *max_freq;
                    // Don't let p2dq control frequency
                    rodata.p2dq_config.freq_control = MaybeUninit::new(false);
                }
                Trait::PerfDegradation {
                    frequency,
                    degradation_frac7,
                } => {
                    rodata.degradation_freq_frac32 = (frequency * 2_f64.powf(32_f64)) as u32;
                    rodata.degradation_frac7 = *degradation_frac7;
                }
            }
        }

        // For now, we'll do it in this way. However, once we upgrade to libbpf_rs 0.25.0,
        // we can use the set_autoattach method on the OpenProgramImpl to do this.
        unsafe {
            bpf_program__set_autoattach(open_skel.progs.generic.as_libbpf_object().as_ptr(), false)
        };

        let mut skel = scx_ops_load!(open_skel, chaos, uei)?;
        scx_p2dq::init_skel!(&mut skel, topo);

        let task_size = std::mem::size_of::<types::task_p2dq>();
        let arenalib = ArenaLib::init(skel.object_mut(), task_size, *NR_CPU_IDS)?;
        arenalib.setup()?;

        let out = unsafe {
            // SAFETY: initialising field by field. open_object is already "initialised" (it's
            // permanently MaybeUninit so any state is fine), hence the structure will be
            // initialised after initialising `skel`.
            let ptr: *mut SkelWithObject = uninit_skel.as_mut_ptr();

            (&raw mut (*ptr).skel).write(RwLock::new(skel));

            Pin::new_unchecked(out.assume_init())
        };

        Ok(out)
    }
}

impl<'a> TryFrom<Builder<'a>> for Scheduler {
    type Error = anyhow::Error;

    fn try_from(b: Builder<'a>) -> Result<Scheduler> {
        let skel = b.load_skel()?;

        let arena = HeapAllocator::new(ArenaAllocator(skel.clone()));
        let stats_server = StatsServer::new(stats::server_data()).launch()?;
        let (links, struct_ops) = {
            let mut skel_guard = skel.skel.write().unwrap();
            let struct_ops = scx_ops_attach!(skel_guard, chaos)?;
            let links = b.attach_kprobes(&mut skel_guard)?;
            (links, struct_ops)
        };
        debug!("scx_chaos scheduler started");

        Ok(Scheduler {
            _arena: arena,
            _struct_ops: struct_ops,
            _links: links,
            stats_server,
            skel,
        })
    }
}

/// Randomly delay a process.
#[derive(Debug, Parser)]
pub struct RandomDelayArgs {
    /// Chance of randomly delaying a process.
    #[clap(long, requires = "random_delay_min_us")]
    pub random_delay_frequency: Option<f64>,

    /// Minimum time to add for random delay.
    #[clap(long, requires = "random_delay_max_us")]
    pub random_delay_min_us: Option<u64>,

    /// Maximum time to add for random delay.
    #[clap(long, requires = "random_delay_frequency")]
    pub random_delay_max_us: Option<u64>,
}

/// Randomly CPU frequency scale a process.
#[derive(Debug, Parser)]
pub struct CpuFreqArgs {
    /// Chance of randomly delaying a process.
    #[clap(long, requires = "cpufreq_max")]
    pub cpufreq_frequency: Option<f64>,

    /// Minimum CPU frequency for scaling.
    #[clap(long, requires = "cpufreq_frequency")]
    pub cpufreq_min: Option<u32>,

    /// Maximum CPU frequency for scaling.
    #[clap(long, requires = "cpufreq_min")]
    pub cpufreq_max: Option<u32>,
}

/// Introduces a perf degradation
#[derive(Debug, Parser)]
pub struct PerfDegradationArgs {
    /// Chance of degradating a process.
    #[clap(long)]
    pub degradation_frequency: Option<f64>,

    /// Amount to degradate a process.
    #[clap(long, default_value = "0", value_parser = clap::value_parser!(u64).range(0..129))]
    pub degradation_frac7: u64,
}

/// Delay a process when a kprobe is hit.
#[derive(Debug, Parser)]
pub struct KprobeArgs {
    /// Introduce random delays in the scheduler whenever a provided kprobe is hit.
    #[clap(long, num_args = 1.., value_parser, requires = "kprobe_random_delay_min_us")]
    pub kprobes_for_random_delays: Vec<String>,

    /// Chance of kprobe random delays. Must be between 0 and 1. [default=0.1]
    #[clap(long, requires = "kprobes_for_random_delays")]
    pub kprobe_random_delay_frequency: Option<f64>,

    /// Minimum time to add for kprobe random delay.
    #[clap(long, requires = "kprobe_random_delay_max_us")]
    pub kprobe_random_delay_min_us: Option<u64>,

    /// Maximum time to add for kprobe random delay.
    #[clap(long, requires = "kprobes_for_random_delays")]
    pub kprobe_random_delay_max_us: Option<u64>,
}

/// scx_chaos: A general purpose sched_ext scheduler designed to amplify race conditions
///
/// WARNING: This scheduler is a very early alpha, and hasn't been production tested yet. The CLI
/// in particular is likely very unstable and does not guarantee compatibility between versions.
///
/// scx_chaos is a general purpose scheduler designed to run apps with acceptable performance. It
/// has a series of features designed to add latency in paths in an application. All control is
/// through the CLI. Running without arguments will not attempt to introduce latency and can set a
/// baseline for performance impact. The other command line arguments allow for specifying latency
/// inducing behaviours which attempt to induce a crash.
///
/// Unlike most other schedulers, you can also run scx_chaos with a named target. For example:
///     scx_chaos -- ./app_that_might_crash --arg1 --arg2
/// In this mode the scheduler will automatically detach after the application exits, unless run
/// with `--repeat-failure` where it will restart the application on failure.
#[derive(Debug, Parser)]
pub struct Args {
    /// Whether to continue on failure of the command under test.
    #[clap(long, action = clap::ArgAction::SetTrue, requires = "args")]
    pub repeat_failure: bool,

    /// Whether to continue on successful exit of the command under test.
    #[clap(long, action = clap::ArgAction::SetTrue, requires = "args")]
    pub repeat_success: bool,

    /// Whether to focus on the named task and its children instead of the entire system. Only
    /// takes effect if pid or args provided.
    #[clap(long, default_value = "true", action = clap::ArgAction::Set)]
    pub ppid_targeting: bool,

    /// Enable verbose output, including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Print version and exit.
    #[clap(long)]
    pub version: bool,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    pub stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    pub monitor: Option<f64>,

    #[command(flatten, next_help_heading = "Random Delays")]
    pub random_delay: RandomDelayArgs,

    #[command(flatten, next_help_heading = "Perf Degradation")]
    pub perf_degradation: PerfDegradationArgs,

    #[command(flatten, next_help_heading = "CPU Frequency")]
    pub cpu_freq: CpuFreqArgs,

    #[command(flatten, next_help_heading = "Kprobe Random Delays")]
    pub kprobe_random_delays: KprobeArgs,

    #[command(flatten, next_help_heading = "General Scheduling")]
    pub p2dq: P2dqOpts,

    /// Stop the scheduler if specified process terminates
    #[arg(
        long,
        short = 'p',
        help_heading = "Test Command",
        conflicts_with = "args"
    )]
    pub pid: Option<libc::pid_t>,

    /// Program to run under the chaos scheduler
    ///
    /// Runs a program under test and tracks when it terminates, similar to most debuggers. Note
    /// that the scheduler still attaches for every process on the system.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help_heading = "Test Command"
    )]
    pub args: Vec<String>,
}

struct BuilderIterator<'a> {
    args: &'a Args,
    idx: u32,
}

impl<'a> From<&'a Args> for BuilderIterator<'a> {
    fn from(args: &'a Args) -> BuilderIterator<'a> {
        BuilderIterator { args, idx: 0 }
    }
}

impl<'a> Iterator for BuilderIterator<'a> {
    type Item = Builder<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.idx += 1;

        if self.idx > 1 {
            None
        } else {
            let mut traits = vec![];

            if let RandomDelayArgs {
                random_delay_frequency: Some(frequency),
                random_delay_min_us: Some(min_us),
                random_delay_max_us: Some(max_us),
            } = self.args.random_delay
            {
                traits.push(Trait::RandomDelays {
                    frequency,
                    min_us,
                    max_us,
                });
            };
            if let CpuFreqArgs {
                cpufreq_frequency: Some(frequency),
                cpufreq_min: Some(min_freq),
                cpufreq_max: Some(max_freq),
            } = self.args.cpu_freq
            {
                traits.push(Trait::CpuFreq {
                    frequency,
                    min_freq,
                    max_freq,
                });
            };

            let requires_ppid = if self.args.ppid_targeting {
                if let Some(p) = self.args.pid {
                    Some(RequiresPpid::IncludeParent(Pid::from_raw(p)))
                } else if !self.args.args.is_empty() {
                    Some(RequiresPpid::ExcludeParent(Pid::this()))
                } else {
                    None
                }
            } else {
                None
            };

            let kprobe_random_delays = match &self.args.kprobe_random_delays {
                KprobeArgs {
                    kprobes_for_random_delays,
                    kprobe_random_delay_frequency,
                    kprobe_random_delay_min_us: Some(min_us),
                    kprobe_random_delay_max_us: Some(max_us),
                } if !kprobes_for_random_delays.is_empty() => Some(KprobeRandomDelays {
                    kprobes: kprobes_for_random_delays.clone(),
                    freq: kprobe_random_delay_frequency.unwrap_or(0.1),
                    min_us: *min_us,
                    max_us: *max_us,
                }),
                _ => None,
            };

            Some(Builder {
                traits,
                verbose: self.args.verbose,
                kprobe_random_delays,
                p2dq_opts: &self.args.p2dq,
                requires_ppid,
            })
        }
    }
}

pub fn validate_kprobes(kprobes: &[String]) -> Result<()> {
    let path = tracefs_mount()?;
    let file = File::open(path.join("available_filter_functions"))?;
    let reader = BufReader::new(file);

    let available_kprobes: HashSet<_> = reader
        .lines()
        .filter_map(|line| line.ok()?.split_whitespace().next().map(String::from))
        .collect();

    let missing: Vec<_> = kprobes
        .iter()
        .filter(|probe| !available_kprobes.contains(*probe))
        .collect();

    if !missing.is_empty() {
        return Err(anyhow::anyhow!(
            "The following kprobes are not available: {:?}",
            missing
        ));
    }

    Ok(())
}

pub fn run(args: Args) -> Result<()> {
    if args.version {
        println!(
            "scx_chaos: {}",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    let args = Arc::new(args);

    let shutdown = Arc::new((Mutex::new(false), Condvar::new()));

    ctrlc::set_handler({
        let shutdown = shutdown.clone();
        move || {
            let (lock, cvar) = &*shutdown;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
    })
    .context("Error setting Ctrl-C handler")?;

    info!(
        "Running scx_chaos (build ID: {})",
        build_id::full_version(env!("CARGO_PKG_VERSION"))
    );

    if let Some(intv) = args.monitor {
        return stats::monitor(Duration::from_secs_f64(intv), shutdown);
    }

    let stats_thread = args.stats.map(|intv| {
        let shutdown = shutdown.clone();

        thread::spawn(move || -> Result<()> {
            stats::monitor(Duration::from_secs_f64(intv), shutdown)
        })
    });

    let scheduler_thread = thread::spawn({
        let args = args.clone();
        let shutdown = shutdown.clone();

        move || -> Result<()> {
            for builder in BuilderIterator::from(&*args) {
                info!("{:?}", &builder);

                let sched: Scheduler = builder.try_into()?;

                sched.observe(&shutdown, None)?;
            }

            Ok(())
        }
    });

    if let Some(pid) = args.pid {
        info!("Monitoring process with PID: {pid}");

        let is_process_running = |pid: libc::pid_t| -> bool {
            unsafe {
                // SAFETY: kill with signal 0 only runs validity checks. There's no chance of
                // memory unsafety here.
                libc::kill(pid, 0) == 0
            }
        };

        while is_process_running(pid) && !*shutdown.0.lock().unwrap() {
            if scheduler_thread.is_finished() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        if !is_process_running(pid) {
            info!("app under test terminated, exiting...");
        }
    }

    let mut should_run_app = !args.args.is_empty();
    while should_run_app {
        let (cmd, vargs) = args.args.split_first().unwrap();

        let mut child = Command::new(cmd).args(vargs).spawn()?;
        loop {
            should_run_app &= !*shutdown.0.lock().unwrap();

            if scheduler_thread.is_finished() {
                child.kill()?;
                break;
            }
            if let Some(s) = child.try_wait()? {
                if s.success() && args.repeat_success {
                    should_run_app &= !*shutdown.0.lock().unwrap();
                    if should_run_app {
                        info!("app under test terminated successfully, restarting...");
                    };
                } else if s.success() {
                    info!("app under test terminated successfully, exiting...");
                    should_run_app = false;
                } else {
                    info!("TODO: report what the scheduler was doing when it crashed");
                    should_run_app &= !*shutdown.0.lock().unwrap() && args.repeat_failure;
                };

                break;
            };

            thread::sleep(Duration::from_millis(100));
        }
    }

    // Notify shutdown if we're exiting due to args or pid termination
    if !args.args.is_empty() || args.pid.is_some() {
        let (lock, cvar) = &*shutdown;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }

    match scheduler_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(e) => panic::resume_unwind(e),
    }

    match stats_thread.map(|t| t.join()).unwrap_or(Ok(Ok(()))) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(e) => panic::resume_unwind(e),
    }

    Ok(())
}
