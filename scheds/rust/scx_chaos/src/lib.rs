// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_intf;
mod bpf_skel;

use bpf_skel::BpfSkel;

use scx_p2dq::SchedulerOpts as P2dqOpts;
use scx_userspace_arena::alloc::Allocator;
use scx_userspace_arena::alloc::HeapAllocator;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Core;
use scx_utils::Llc;
use scx_utils::Topology;

use scx_p2dq::bpf_intf::consts_STATIC_ALLOC_PAGES_GRANULARITY;
use scx_p2dq::types;
use std::ffi::c_ulong;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::debug;
use log::info;
use nix::unistd::Pid;

use std::alloc::Layout;
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
/// State required to build a Scheduler configuration.
pub struct Builder<'a> {
    pub traits: Vec<Trait>,
    pub verbose: u8,
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

    // Fields are dropped in declaration order, this must be last as arena holds a reference to the
    // skel
    skel: Pin<Rc<SkelWithObject>>,
}

impl Scheduler {
    pub fn observe(
        &self,
        shutdown: &(Mutex<bool>, Condvar),
        timeout: Option<Duration>,
    ) -> Result<()> {
        let (lock, cvar) = shutdown;

        let start_time = Instant::now();

        let mut guard = lock.lock().unwrap();
        while !*guard {
            let skel = &self.skel.skel.read().unwrap();

            if uei_exited!(&skel, uei) {
                return uei_report!(&skel, uei)
                    .and_then(|_| Err(anyhow::anyhow!("scheduler exited unexpectedly")));
            }

            if timeout.is_some_and(|x| Instant::now().duration_since(start_time) >= x) {
                break;
            }

            guard = cvar
                .wait_timeout(guard, Duration::from_millis(500))
                .unwrap()
                .0;
        }

        Ok(())
    }
}

impl Builder<'_> {
    fn setup_arenas(&self, skel: &mut BpfSkel) -> Result<()> {
        // Allocate the arena memory from the BPF side so userspace initializes it before starting
        // the scheduler. Despite the function call's name this is neither a test nor a test run,
        // it's the recommended way of executing SEC("syscall") probes.
        let mut args = types::arena_init_args {
            static_pages: consts_STATIC_ALLOC_PAGES_GRANULARITY as c_ulong,
            task_ctx_size: std::mem::size_of::<types::task_p2dq>() as c_ulong,
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

        let output = skel.progs.arena_init.test_run(input)?;
        if output.return_value != 0 {
            bail!(
                "Could not initialize arenas, p2dq_setup returned {}",
                output.return_value as i32
            );
        }

        Ok(())
    }

    fn setup_topology_node(&self, skel: &mut BpfSkel, mask: &[u64]) -> Result<()> {
        // Copy the address of ptr to the kernel to populate it from BPF with the arena pointer.
        let input = ProgramInput {
            ..Default::default()
        };

        let output = skel.progs.arena_alloc_mask.test_run(input)?;
        if output.return_value != 0 {
            bail!(
                "Could not initialize arenas, setup_topology_node returned {}",
                output.return_value as i32
            );
        }

        let ptr = unsafe {
            std::mem::transmute::<u64, &mut [u64; 10]>(skel.maps.bss_data.arena_topo_setup_ptr)
        };

        let (valid_mask, _) = ptr.split_at_mut(mask.len());
        valid_mask.clone_from_slice(mask);

        let input = ProgramInput {
            ..Default::default()
        };
        let output = skel.progs.arena_topology_node_init.test_run(input)?;
        if output.return_value != 0 {
            bail!(
                "p2dq_topology_node_init returned {}",
                output.return_value as i32
            );
        }

        Ok(())
    }

    fn setup_topology(&self, skel: &mut BpfSkel) -> Result<()> {
        let topo = Topology::new().expect("Failed to build host topology");

        self.setup_topology_node(skel, topo.span.as_raw_slice())?;

        for (_, node) in topo.nodes {
            self.setup_topology_node(skel, node.span.as_raw_slice())?;
        }

        for (_, llc) in topo.all_llcs {
            self.setup_topology_node(
                skel,
                Arc::<Llc>::into_inner(llc)
                    .expect("missing llc")
                    .span
                    .as_raw_slice(),
            )?;
        }

        for (_, core) in topo.all_cores {
            self.setup_topology_node(
                skel,
                Arc::<Core>::into_inner(core)
                    .expect("missing core")
                    .span
                    .as_raw_slice(),
            )?;
        }
        for (_, cpu) in topo.all_cpus {
            let mut mask = [0; 9];
            mask[cpu.id.checked_shr(64).unwrap_or(0)] |= 1 << (cpu.id % 64);
            self.setup_topology_node(skel, &mask)?;
        }

        Ok(())
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

        let mut open_skel = scx_ops_open!(skel_builder, open_object, chaos)?;
        scx_p2dq::init_open_skel!(&mut open_skel, self.p2dq_opts, self.verbose)?;

        // TODO: figure out how to abstract waking a CPU in enqueue properly, but for now disable
        // this codepath
        open_skel.maps.rodata_data.select_idle_in_enqueue = false;

        match self.requires_ppid {
            None => {
                open_skel.maps.rodata_data.ppid_targeting_ppid = -1;
            }
            Some(RequiresPpid::ExcludeParent(p)) => {
                open_skel.maps.rodata_data.ppid_targeting_inclusive = false;
                open_skel.maps.rodata_data.ppid_targeting_ppid = p.as_raw();
            }
            Some(RequiresPpid::IncludeParent(p)) => {
                open_skel.maps.rodata_data.ppid_targeting_inclusive = true;
                open_skel.maps.rodata_data.ppid_targeting_ppid = p.as_raw();
            }
        };

        // Set up the frequency array. The first element means nothing, so should be what's
        // required to add up to 100%. The rest should be cumulative frequencies.
        let freq_array = &mut open_skel.maps.rodata_data.trait_delay_freq_frac32;
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
            open_skel.maps.rodata_data.trait_delay_freq_frac32
        );

        for tr in &self.traits {
            match tr {
                Trait::RandomDelays {
                    frequency: _,
                    min_us,
                    max_us,
                } => {
                    open_skel.maps.rodata_data.random_delays_min_ns = min_us * 1000;
                    open_skel.maps.rodata_data.random_delays_max_ns = max_us * 1000;
                }
                Trait::CpuFreq {
                    frequency: _,
                    min_freq,
                    max_freq,
                } => {
                    open_skel.maps.rodata_data.cpu_freq_min = *min_freq;
                    open_skel.maps.rodata_data.cpu_freq_max = *max_freq;
                    // Don't let p2dq control frequency
                    open_skel.maps.rodata_data.freq_control = false;
                }
                Trait::PerfDegradation {
                    frequency,
                    degradation_frac7,
                } => {
                    open_skel.maps.rodata_data.degradation_freq_frac32 =
                        (frequency * 2_f64.powf(32_f64)) as u32;
                    open_skel.maps.rodata_data.degradation_frac7 = *degradation_frac7;
                }
            }
        }

        let mut skel = scx_ops_load!(open_skel, chaos, uei)?;
        scx_p2dq::init_skel!(&mut skel);

        self.setup_arenas(&mut skel)?;
        self.setup_topology(&mut skel)?;

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

        let struct_ops = {
            let mut skel_guard = skel.skel.write().unwrap();
            scx_ops_attach!(skel_guard, chaos)?
        };
        debug!("scx_chaos scheduler started");

        Ok(Scheduler {
            _arena: arena,
            _struct_ops: struct_ops,
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

    /// Minimum CPU frequency for scaling.
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

    #[command(flatten, next_help_heading = "Random Delays")]
    pub random_delay: RandomDelayArgs,

    #[command(flatten, next_help_heading = "Perf Degradation")]
    pub perf_degradation: PerfDegradationArgs,

    #[command(flatten, next_help_heading = "CPU Frequency")]
    pub cpu_freq: CpuFreqArgs,

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

            Some(Builder {
                traits,
                verbose: self.args.verbose,
                p2dq_opts: &self.args.p2dq,
                requires_ppid,
            })
        }
    }
}

pub fn run(args: Args) -> Result<()> {
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
        info!("Monitoring process with PID: {}", pid);

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

    if let Err(e) = scheduler_thread.join() {
        panic::resume_unwind(e);
    }

    Ok(())
}
