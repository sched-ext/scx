// SPDX-License-Identifier: GPL-2.0
//
// scx_cake — a clean-slate sched_ext scheduler.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

#[cfg(cake_multi_ccd)]
use std::collections::BTreeMap;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
#[cfg(any(cake_mdbls_telemetry, cake_irq_shadow))]
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use log::info;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;

const SCHEDULER_NAME: &str = "scx_cake";

/// scx_cake: a gaming-first sched_ext scheduler — one master algorithm on
/// kernel primitives, no feature flags, no knobs, no runtime telemetry.
/// Placement is the kernel's idle-CPU pick with direct dispatch on a hit.
/// Under saturation, wakeups queue on one global vtime queue while
/// slice-expired tasks requeue on their own CPU's queue ("wakeups global,
/// continuations local"), and each CPU dispatches the earliest eligible of
/// the two. The time slice is a compile-time constant.
#[derive(Debug, Parser)]
struct Opts {
    /// Enable verbose libbpf output.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print the version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    #[cfg(cake_irq_shadow)]
    irq_shadow_targets: Vec<u32>,
}

#[cfg(cake_irq_shadow)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IrqShadowStats {
    samples: u64,
    dfl_idle_samples: u64,
    direct_dispatch_samples: u64,
    enqueue_samples: u64,
    wake_sync_samples: u64,
    clock_unavailable_samples: u64,
    sibling_unavailable_samples: u64,
    first_wall_ns: u64,
    last_wall_ns: u64,
    first_target_irq_ns: u64,
    last_target_irq_ns: u64,
    first_sibling_irq_ns: u64,
    last_sibling_irq_ns: u64,
    sibling_cpu: u64,
}

#[cfg(cake_irq_shadow)]
const _: () = assert!(std::mem::size_of::<IrqShadowStats>() == 14 * std::mem::size_of::<u64>());

#[cfg(cake_irq_shadow_observer)]
#[derive(Clone, Copy)]
struct IrqShadowEndpoint {
    wall_ns: u64,
    target_irq_ns: u64,
    sibling_irq_ns: u64,
    sibling_cpu: u64,
}

#[cfg(cake_irq_shadow_observer)]
fn irq_util_1024_milli(delta_ns: u64, elapsed_ns: u64) -> Option<u64> {
    if elapsed_ns == 0 || delta_ns > elapsed_ns {
        return None;
    }
    Some(((delta_ns as u128 * 1024 * 1000) / elapsed_ns as u128) as u64)
}

#[cfg(cake_mdbls_telemetry)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MdblsStats {
    runnable: u64,
    quiescent: u64,
    prediction_samples: u64,
    confident_samples: u64,
    burst_ns_sum: u64,
    period_ns_sum: u64,
    error_ns_sum: u64,
    preempt_eval: u64,
    preempt_cold: u64,
    golden_preempt: u64,
    learned_preempt: u64,
    learned_only: u64,
    golden_only: u64,
    slice_eval: u64,
    slice_cold: u64,
    slice_short: u64,
    slice_base: u64,
    slice_long: u64,
    burst_hist: [u64; 8],
    error_hist: [u64; 8],
    pressure_hist: [u64; 8],
    confidence_hist: [u64; 8],
    slice_hist: [u64; 8],
}

#[cfg(cake_mdbls_telemetry)]
const _: () = assert!(std::mem::size_of::<MdblsStats>() == 58 * std::mem::size_of::<u64>());

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        // The startup banner is the only "telemetry" cake emits, and it is
        // one-shot: version, machine shape, the compiled constants, and
        // which kernel fast paths the RUNNING kernel provides (probed from
        // BTF, not what the source requested) — so every log is
        // self-describing about what actually loaded.
        let topo = Topology::new().context("failed to read topology")?;
        let physical = topo.all_cores.len();
        let total = topo.all_cpus.len();
        let smt = total.saturating_sub(physical);
        #[cfg(cake_irq_shadow)]
        let irq_shadow_targets = topo.all_cpus.keys().map(|cpu| *cpu as u32).collect();

        let slice_us = bpf_intf::consts_SLICE_NS as u64 / bpf_intf::consts_NSEC_PER_USEC as u64;
        let queued_wakeup = *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP != 0;
        let dsq_peek = compat::ksym_exists("scx_bpf_dsq_peek").unwrap_or(false);

        info!(
            "🍰 {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        info!("   cores   {physical} physical + {smt} SMT = {total} CPUs");
        info!("   slice   {slice_us}µs · queues {total} per-CPU vtime + 1 global wake");
        info!(
            "   kernel  queued_wakeup {} · dsq_peek {}",
            if queued_wakeup { "on" } else { "UNSUPPORTED" },
            if dsq_peek {
                "native"
            } else {
                "iterator fallback"
            },
        );

        // Open the BPF program.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let mut skel = scx_ops_open!(skel_builder, open_object, cake_ops, None)?;

        // Linux CPU numbering does not guarantee that an SMT sibling is
        // cpu +/- nr_cpus/2. Populate the immutable BPF lookup from sysfs
        // topology and cycle within wider-than-SMT2 cores. The fallback path
        // treats -1 as "no online sibling" and uses the kernel idle picker.
        let siblings = &mut skel
            .maps
            .rodata_data
            .as_mut()
            .context("BPF rodata unavailable for CPU topology")?
            .cpu_sibling;
        siblings.fill(-1);
        for core in topo.all_cores.values() {
            let cpu_ids: Vec<usize> = core.cpus.keys().copied().collect();

            if cpu_ids.len() < 2 {
                continue;
            }
            for (idx, cpu) in cpu_ids.iter().copied().enumerate() {
                let sibling = cpu_ids[(idx + 1) % cpu_ids.len()];

                anyhow::ensure!(
                    cpu < siblings.len() && sibling <= i32::MAX as usize,
                    "CPU topology id exceeds Cake's compiled sibling map"
                );
                siblings[cpu] = sibling as i32;
            }
        }

        #[cfg(cake_multi_ccd)]
        {
            let rodata = skel
                .maps
                .rodata_data
                .as_mut()
                .context("BPF rodata unavailable for cache topology")?;
            let order = &mut rodata.cpu_steal_order;
            let nr_span = bpf_intf::consts_BUILD_NR_CPUS as usize;
            anyhow::ensure!(
                topo.all_cpus
                    .keys()
                    .next_back()
                    .is_none_or(|cpu| *cpu < nr_span),
                "runtime CPU topology exceeds Cake's build-host CPU span"
            );
            order.fill(0);

            let llc_cache: BTreeMap<usize, usize> = topo
                .all_llcs
                .iter()
                .map(|(id, llc)| {
                    (
                        *id,
                        llc.all_cpus
                            .values()
                            .map(|cpu| cpu.cache_size)
                            .max()
                            .unwrap_or(0),
                    )
                })
                .collect();
            let policy = bpf_intf::consts_CCD_STEAL_POLICY;

            for src in topo.all_cpus.values() {
                let mut candidates: Vec<_> = topo
                    .all_cpus
                    .values()
                    .filter(|dst| dst.id != src.id)
                    .collect();
                candidates.sort_by_key(|dst| {
                    let class = if dst.llc_id == src.llc_id {
                        0
                    } else if policy > 1 && llc_cache[&dst.llc_id] == llc_cache[&src.llc_id] {
                        1
                    } else {
                        2
                    };
                    (class, (dst.id + nr_span - src.id) % nr_span)
                });
                let base = src.id * nr_span;
                for (slot, dst) in candidates.into_iter().enumerate() {
                    order[base + slot] = dst.id as u16;
                }
            }
        }

        // Load and attach.
        let mut skel = scx_ops_load!(skel, cake_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, cake_ops)?);

        info!("🍰 attached — wakeups queue globally, continuations locally");

        // The file capabilities (cap_bpf,cap_perfmon,cap_sys_nice) are only
        // needed to load and attach; detach and map access use already-open
        // fds. Drop them all: while any elevated capability stays in the
        // permitted set, the kernel's ptrace access check denies
        // /proc/<pid>/exe to unprivileged observers even with dumpable
        // restored, which breaks the sudoless bench runner's hash-of-exe
        // identity verification (and holding dead privileges is bad hygiene).
        drop_all_capabilities();

        Ok(Self {
            skel,
            struct_ops,
            #[cfg(cake_irq_shadow)]
            irq_shadow_targets,
        })
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    #[cfg(cake_mdbls_telemetry)]
    fn report_mdbls_stats(&self) {
        let Ok(Some(values)) = self
            .skel
            .maps
            .mdbls_stats
            .lookup_percpu(&0u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
        else {
            info!("MDBLS_TELEMETRY unavailable");
            return;
        };
        let mut total = MdblsStats::default();
        for value in values {
            if value.len() < std::mem::size_of::<MdblsStats>() {
                continue;
            }
            let row = unsafe { std::ptr::read_unaligned(value.as_ptr() as *const MdblsStats) };
            total.runnable += row.runnable;
            total.quiescent += row.quiescent;
            total.prediction_samples += row.prediction_samples;
            total.confident_samples += row.confident_samples;
            total.burst_ns_sum += row.burst_ns_sum;
            total.period_ns_sum += row.period_ns_sum;
            total.error_ns_sum += row.error_ns_sum;
            total.preempt_eval += row.preempt_eval;
            total.preempt_cold += row.preempt_cold;
            total.golden_preempt += row.golden_preempt;
            total.learned_preempt += row.learned_preempt;
            total.learned_only += row.learned_only;
            total.golden_only += row.golden_only;
            total.slice_eval += row.slice_eval;
            total.slice_cold += row.slice_cold;
            total.slice_short += row.slice_short;
            total.slice_base += row.slice_base;
            total.slice_long += row.slice_long;
            for idx in 0..8 {
                total.burst_hist[idx] += row.burst_hist[idx];
                total.error_hist[idx] += row.error_hist[idx];
                total.pressure_hist[idx] += row.pressure_hist[idx];
                total.confidence_hist[idx] += row.confidence_hist[idx];
                total.slice_hist[idx] += row.slice_hist[idx];
            }
        }
        info!(
            "MDBLS_TELEMETRY events runnable={} quiescent={} prediction_samples={} confident_samples={} preempt_eval={} preempt_cold={} golden_preempt={} learned_preempt={} learned_only={} golden_only={} slice_eval={} slice_cold={} slice_short={} slice_base={} slice_long={}",
            total.runnable,
            total.quiescent,
            total.prediction_samples,
            total.confident_samples,
            total.preempt_eval,
            total.preempt_cold,
            total.golden_preempt,
            total.learned_preempt,
            total.learned_only,
            total.golden_only,
            total.slice_eval,
            total.slice_cold,
            total.slice_short,
            total.slice_base,
            total.slice_long,
        );
        info!(
            "MDBLS_TELEMETRY sums burst_ns={} period_ns={} error_ns={} burst_hist={:?} error_hist={:?} pressure_hist={:?} confidence_hist={:?} slice_hist={:?}",
            total.burst_ns_sum,
            total.period_ns_sum,
            total.error_ns_sum,
            total.burst_hist,
            total.error_hist,
            total.pressure_hist,
            total.confidence_hist,
            total.slice_hist,
        );
    }

    #[cfg(cake_irq_shadow)]
    fn report_irq_shadow_stats(&self) {
        let mut total_samples = 0u64;
        let mut total_idle = 0u64;
        let mut total_direct = 0u64;
        let mut total_enqueue = 0u64;
        let mut total_wake_sync = 0u64;
        let mut total_clock_unavailable = 0u64;
        let mut total_sibling_unavailable = 0u64;

        for target in &self.irq_shadow_targets {
            let Ok(Some(values)) = self
                .skel
                .maps
                .irq_shadow_stats
                .lookup_percpu(&target.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
            else {
                info!("IRQ_SHADOW target={target} unavailable");
                continue;
            };

            let mut target_samples = 0u64;
            let mut target_idle = 0u64;
            let mut target_direct = 0u64;
            let mut target_enqueue = 0u64;
            let mut target_wake_sync = 0u64;
            let mut target_clock_unavailable = 0u64;
            let mut target_sibling_unavailable = 0u64;
            #[cfg(cake_irq_shadow_observer)]
            let mut first: Option<IrqShadowEndpoint> = None;
            #[cfg(cake_irq_shadow_observer)]
            let mut last: Option<IrqShadowEndpoint> = None;

            for value in values {
                if value.len() < std::mem::size_of::<IrqShadowStats>() {
                    continue;
                }
                let row =
                    unsafe { std::ptr::read_unaligned(value.as_ptr() as *const IrqShadowStats) };
                if row.samples == 0 {
                    continue;
                }
                target_samples += row.samples;
                target_idle += row.dfl_idle_samples;
                target_direct += row.direct_dispatch_samples;
                target_enqueue += row.enqueue_samples;
                target_wake_sync += row.wake_sync_samples;
                target_clock_unavailable += row.clock_unavailable_samples;
                target_sibling_unavailable += row.sibling_unavailable_samples;

                #[cfg(cake_irq_shadow_observer)]
                {
                    let row_first = IrqShadowEndpoint {
                        wall_ns: row.first_wall_ns,
                        target_irq_ns: row.first_target_irq_ns,
                        sibling_irq_ns: row.first_sibling_irq_ns,
                        sibling_cpu: row.sibling_cpu,
                    };
                    let row_last = IrqShadowEndpoint {
                        wall_ns: row.last_wall_ns,
                        target_irq_ns: row.last_target_irq_ns,
                        sibling_irq_ns: row.last_sibling_irq_ns,
                        sibling_cpu: row.sibling_cpu,
                    };
                    if first.is_none_or(|current| row_first.wall_ns < current.wall_ns) {
                        first = Some(row_first);
                    }
                    if last.is_none_or(|current| row_last.wall_ns > current.wall_ns) {
                        last = Some(row_last);
                    }
                }
            }

            total_samples += target_samples;
            total_idle += target_idle;
            total_direct += target_direct;
            total_enqueue += target_enqueue;
            total_wake_sync += target_wake_sync;
            total_clock_unavailable += target_clock_unavailable;
            total_sibling_unavailable += target_sibling_unavailable;

            #[cfg(cake_irq_shadow_observer)]
            if target_samples > 0 {
                if let (Some(first), Some(last)) = (first, last) {
                    let elapsed_ns = last.wall_ns.checked_sub(first.wall_ns);
                    let target_delta_ns = last.target_irq_ns.checked_sub(first.target_irq_ns);
                    let sibling_delta_ns = last.sibling_irq_ns.checked_sub(first.sibling_irq_ns);
                    let sibling_stable =
                        first.sibling_cpu == last.sibling_cpu && first.sibling_cpu != u64::MAX;
                    let target_util = if target_clock_unavailable == 0 {
                        elapsed_ns
                            .zip(target_delta_ns)
                            .and_then(|(elapsed, delta)| irq_util_1024_milli(delta, elapsed))
                    } else {
                        None
                    };
                    let sibling_util = if sibling_stable
                        && target_clock_unavailable == 0
                        && target_sibling_unavailable == 0
                    {
                        elapsed_ns
                            .zip(sibling_delta_ns)
                            .and_then(|(elapsed, delta)| irq_util_1024_milli(delta, elapsed))
                    } else {
                        None
                    };
                    info!(
                        "IRQ_SHADOW target={} sibling={:?} samples={} idle={} direct={} enqueue={} wake_sync={} elapsed_ns={:?} target_irq_delta_ns={:?} target_util_1024_milli={:?} sibling_irq_delta_ns={:?} sibling_util_1024_milli={:?} clock_unavailable={} sibling_unavailable={}",
                        target,
                        sibling_stable.then_some(first.sibling_cpu),
                        target_samples,
                        target_idle,
                        target_direct,
                        target_enqueue,
                        target_wake_sync,
                        elapsed_ns,
                        target_delta_ns,
                        target_util,
                        sibling_delta_ns,
                        sibling_util,
                        target_clock_unavailable,
                        target_sibling_unavailable,
                    );
                }
            }
        }

        #[cfg(cake_irq_shadow_observer)]
        info!(
            "IRQ_SHADOW mode=observer samples={} idle={} direct={} enqueue={} wake_sync={} clock_unavailable={} sibling_unavailable={}",
            total_samples,
            total_idle,
            total_direct,
            total_enqueue,
            total_wake_sync,
            total_clock_unavailable,
            total_sibling_unavailable,
        );
        #[cfg(not(cake_irq_shadow_observer))]
        info!(
            "IRQ_SHADOW mode=cost_control samples={} idle={} direct={} enqueue={} wake_sync={} clock_unavailable={} sibling_unavailable={} raw_pressure_interpretation=disabled",
            total_samples,
            total_idle,
            total_direct,
            total_enqueue,
            total_wake_sync,
            total_clock_unavailable,
            total_sibling_unavailable,
        );
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            std::thread::sleep(Duration::from_secs(1));
        }

        #[cfg(cake_mdbls_telemetry)]
        self.report_mdbls_stats();
        #[cfg(cake_irq_shadow)]
        self.report_irq_shadow_stats();
        self.struct_ops.take();
        info!("🍰 {SCHEDULER_NAME} detached — default scheduler restored");
        uei_report!(&self.skel, uei)
    }
}

/// Re-execute this image to service a kernel-requested restart.
///
/// `drop_all_capabilities()` runs after every successful attach, and a
/// permitted set cleared through `capset` cannot be regained in-process —
/// file capabilities are applied only at `execve`. Re-entering
/// `Scheduler::init` would therefore fail `BPF_PROG_LOAD` with `EPERM` and
/// kill the scheduler instead of restarting it. Exec'ing ourselves restores
/// the file capabilities from the bounding set (which `capset` never
/// touched), keeps the PID and `/proc/<pid>/exe` identity the bench runner
/// verifies, and re-runs `PR_SET_DUMPABLE` on the way in. The struct_ops link
/// is already dropped by `run()`, so the scheduler is detached before we
/// replace the image.
fn reexec_self() -> Result<()> {
    use std::os::unix::process::CommandExt;

    let exe = std::fs::read_link("/proc/self/exe")
        .context("failed to resolve /proc/self/exe for restart")?;
    /* exec() only returns on failure. */
    let err = std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .exec();

    Err(anyhow::Error::new(err).context("re-exec after kernel restart request failed"))
}

/// Clear the effective, permitted, and inheritable capability sets.
fn drop_all_capabilities() {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()) };
    if rc != 0 {
        log::warn!("capset drop failed ({})", std::io::Error::last_os_error());
    }
}

fn main() -> Result<()> {
    // File capabilities (cap_bpf,cap_perfmon,cap_sys_nice) clear the dumpable
    // flag, which makes /proc/self/exe root-only and defeats the sudoless
    // bench runner's process-identity verification (hash of /proc/<pid>/exe).
    // The binary holds no secrets, so restore normal /proc introspection.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
    }

    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        simplelog::LevelFilter::Info,
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

    let mut open_object = MaybeUninit::uninit();
    let mut sched = Scheduler::init(&opts, &mut open_object)?;

    if sched.run(shutdown.clone())?.should_restart() {
        info!("🍰 restart requested by the kernel — re-executing");
        reexec_self()?;
    }

    Ok(())
}
