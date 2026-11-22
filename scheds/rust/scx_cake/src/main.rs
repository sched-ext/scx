// SPDX-License-Identifier: GPL-2.0
//
// scx_cake — a sched_ext CPU scheduler tuned for games.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
mod build_identity;
mod core_performance;
mod exit_report;
mod inspect_bpf;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::OpenObject;
use log::info;
use log::warn;
use scx_utils::NR_CPU_IDS;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;

const SCHEDULER_NAME: &str = "scx_cake";

/// ops.cpu_acquire exists for the probe hold census only; a release run does
/// not pay a BPF entry per RT-to-SCX switch to record nothing.
fn configure_acquire_census(skel: &mut OpenBpfSkel<'_>, probe_on: bool) {
    if !probe_on {
        skel.struct_ops.cake_ops_mut().cpu_acquire = std::ptr::null_mut();
        skel.progs.cake_cpu_acquire.set_autoload(false);
    }
}

/// scx_cake: a sched_ext CPU scheduler tuned for games.
#[derive(Debug, PartialEq, Eq, Parser)]
#[command(after_help = TOGGLE_HELP)]
struct Opts {
    /// Experimental device wake/IRQ signals: off, observe, or on. Missing support falls back.
    #[clap(long, value_enum, default_value_t = KernelSignals::Off)]
    kernel_signals: KernelSignals,

    /// Save device wake-to-running histograms and IRQ sample counters as CSV at exit.
    #[clap(long, value_name = "NEW_CSV")]
    signal_report: Option<std::path::PathBuf>,

    /// Require native CTZ/POPCNT. By default, detect support at startup and fall back.
    #[clap(long)]
    native_bitops: bool,

    /// Use portable CTZ/POPCNT even when the CPU and kernel support native operations.
    #[clap(long, conflicts_with = "native_bitops")]
    portable_bitops: bool,

    /// Load and export BPF instructions to a new directory, then exit without attaching.
    #[clap(long, value_name = "NEW_DIRECTORY")]
    inspect_bpf: Option<std::path::PathBuf>,

    /// Print startup core topology and platform performance preferences without attaching.
    #[clap(long)]
    print_topology: bool,

    /// Verbose libbpf output and runtime diagnostics: slice and queue
    /// layout, kernel fast paths, the full toggle line, interrupt sinks as
    /// they change, kernel event counts at exit.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print the version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Override one construct toggle, NAME=0|1, repeatable; the list is
    /// below. Rodata, so the verifier deletes an off arm. An unknown name
    /// or value is dropped with a warning.
    #[clap(long = "toggle", value_name = "NAME=0|1")]
    toggle: Vec<String>,

    /// Test only: override the handoff floor (32 to 750000 ns, default 1464). It moves
    /// the slice floor, serial handoff, sub-handoff and deep-idle cutoffs.
    #[clap(long = "handoff-ns", value_name = "NS", value_parser = clap::value_parser!(u64).range(
        u64::from(bpf_intf::consts_CAKE_POOL_TAG_MASK + 1)..=u64::from(bpf_intf::consts_CAKE_GRANT_CAP_NS / 2)
    ))]
    handoff_ns: Option<u64>,
}

/// The one construct toggle, as --help prints it. Its BPF default is the
/// zeroed rodata byte cake_tog_probe.
const TOGGLE_HELP: &str =
    "Toggles (--toggle NAME=0|1, repeatable):\n  probe     diagnostics          default 0\n";

/// Whether `--toggle probe=1` asked for diagnostics; the last valid one wins.
/// A bad toggle is reported and ignored, never fatal: a stale flag from an
/// old config must not keep the scheduler off.
fn probe_toggle(specs: &[String]) -> bool {
    let mut probe = false;
    for spec in specs {
        let Some((name, val)) = spec.split_once('=') else {
            warn!("   toggle  ignored `{spec}`: expected NAME=0|1");
            continue;
        };
        let on = match val {
            "0" => false,
            "1" => true,
            _ => {
                warn!("   toggle  ignored `{spec}`: value must be 0 or 1");
                continue;
            }
        };
        if name == "probe" {
            probe = on;
        } else {
            warn!("   toggle  ignored `{spec}`: no toggle named {name}");
        }
    }
    probe
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
enum KernelSignals {
    #[default]
    Off,
    Observe,
    On,
}

fn signal_mode(requested: KernelSignals, supported: bool) -> (bool, bool) {
    (
        supported && requested != KernelSignals::Off,
        supported && requested == KernelSignals::On,
    )
}

#[cfg(test)]
mod signal_tests {
    use super::*;

    #[test]
    fn modes_preserve_fallback_and_observation_does_not_enable_policy() {
        for mode in [
            KernelSignals::Off,
            KernelSignals::Observe,
            KernelSignals::On,
        ] {
            assert_eq!(signal_mode(mode, false), (false, false));
        }
        assert_eq!(signal_mode(KernelSignals::Off, true), (false, false));
        assert_eq!(signal_mode(KernelSignals::Observe, true), (true, false));
        assert_eq!(signal_mode(KernelSignals::On, true), (true, true));
        assert!(parse_opts_lenient(["cake", "--kernel-signals", "invalid"]).is_err());
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NativeBitops {
    ctz: bool,
    popcnt: bool,
}

impl NativeBitops {
    fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            let kernel_supports = |name| match compat::ksym_exists(name) {
                Ok(found) => found,
                Err(err) => {
                    warn!("Cannot detect {name}; using portable operation: {err:#}");
                    false
                }
            };
            Self {
                ctz: std::is_x86_feature_detected!("bmi1") && kernel_supports("bpf_ctz64"),
                popcnt: std::is_x86_feature_detected!("popcnt") && kernel_supports("bpf_popcnt64"),
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        Self::default()
    }

    fn select(self, opts: &Opts) -> Result<Self> {
        if opts.portable_bitops {
            return Ok(Self::default());
        }
        let requested = Self {
            ctz: opts.native_bitops,
            popcnt: opts.native_bitops,
        };
        if !requested.ctz && !requested.popcnt {
            return Ok(self);
        }
        anyhow::ensure!(
            !requested.ctz || self.ctz,
            "native CTZ requires x86_64 BMI1 and bpf_ctz64 in the running kernel"
        );
        anyhow::ensure!(
            !requested.popcnt || self.popcnt,
            "native POPCNT requires x86_64 POPCNT and bpf_popcnt64 in the running kernel"
        );
        Ok(requested)
    }
}

/// Retain complete pairs only, ordered for entry-first teardown.
fn attach_irq_pair<L>(
    leave: impl FnOnce() -> Result<L>,
    enter: impl FnOnce() -> Result<L>,
) -> Result<[L; 2]> {
    let leave = leave().context("exit hook failed")?;
    let enter = enter().context("entry hook failed")?;
    Ok([enter, leave])
}

/// Create the --signal-report file before anything is loaded.
fn open_signal_report(opts: &Opts) -> Result<Option<std::fs::File>> {
    anyhow::ensure!(
        opts.signal_report.is_none() || opts.kernel_signals != KernelSignals::Off,
        "--signal-report requires --kernel-signals observe or on"
    );
    let signal_report = opts
        .signal_report
        .as_ref()
        .map(|path| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .with_context(|| format!("create signal report {}", path.display()))
        })
        .transpose()?;
    Ok(signal_report)
}

/// What the kernel-signals request resolves to on the running kernel.
struct SignalSetup {
    /// SCX_OPS_WAKE_SIGNAL, 0 when the kernel has none.
    flag: u64,
    enabled: bool,
    policy: bool,
    /// Count the signals: observe mode, or any mode with a report.
    observe: bool,
}

fn detect_signals(opts: &Opts) -> SignalSetup {
    let signal_flag = compat::read_enum("scx_ops_flags", "SCX_OPS_WAKE_SIGNAL").unwrap_or(0);
    let signal_support = signal_flag != 0
        && compat::ksym_exists("scx_bpf_task_wake_signal_v1").unwrap_or(false)
        && compat::ksym_exists("scx_bpf_cpu_irq_ns_v1").unwrap_or(false);
    let (signals_enabled, signals_policy) = signal_mode(opts.kernel_signals, signal_support);
    let signals_observe = signals_enabled
        && (opts.kernel_signals == KernelSignals::Observe || opts.signal_report.is_some());
    if opts.verbose {
        info!(
            "Kernel signals requested={:?} available={signal_support} enabled={signals_enabled} policy={signals_policy} counters={signals_observe}",
            opts.kernel_signals
        );
    }
    if opts.kernel_signals != KernelSignals::Off && !signal_support {
        warn!("Kernel signal v1 support absent; using existing Cake policy");
    }
    SignalSetup {
        flag: signal_flag,
        enabled: signals_enabled,
        policy: signals_policy,
        observe: signals_observe,
    }
}

/// Version and build hash: the first lines of every start.
fn log_identity() {
    info!(
        "{} {}",
        SCHEDULER_NAME,
        build_id::full_version(env!("CARGO_PKG_VERSION"))
    );
    match build_identity::binary_sha256() {
        Ok(hash) => info!("Build SHA256 {hash}"),
        Err(err) => warn!("Build SHA256 unavailable: {err:#}"),
    }
}

/// Machine size; the bit-math choice under --verbose or when a flag chose it.
fn log_host(opts: &Opts, topo: &Topology, bitops: NativeBitops) {
    let (native_ctz, native_popcnt) = (bitops.ctz, bitops.popcnt);
    let physical = topo.all_cores.len();
    let total = topo.all_cpus.len();
    info!("CPU          {physical} cores / {total} hardware threads");
    if opts.verbose {
        info!(
            "Cache        {} shared last-level cache domain{}",
            topo.all_llcs.len(),
            if topo.all_llcs.len() == 1 { "" } else { "s" }
        );
    }
    if opts.verbose || opts.native_bitops || opts.portable_bitops {
        info!("Native bitops {}", native_ctz && native_popcnt);
        info!("Native CTZ {native_ctz}");
        info!("Native POPCNT {native_popcnt}");
    }
}

/// Open the BPF object with every hook left for the loader to attach by hand.
fn open_skel<'a>(
    verbose: bool,
    open_object: &'a mut MaybeUninit<OpenObject>,
) -> Result<OpenBpfSkel<'a>> {
    let mut skel_builder = BpfSkelBuilder::default();
    skel_builder.obj_builder.debug(verbose);
    // debug(false) disables every libbpf message, including verifier
    // failures. Keep errors visible without the verbose loader chatter.
    if !verbose {
        scx_utils::init_libbpf_logging(Some(libbpf_rs::PrintLevel::Warn));
    }
    let mut skel = scx_ops_open!(skel_builder, open_object, cake_ops, None)?;
    // scx_ops_attach! attaches this map explicitly after the accounting hooks.
    // The generated skeleton has no map link slot for automatic attachment.
    // SAFETY: cake_ops is a live struct_ops map owned by the open skeleton.
    let ret = unsafe {
        libbpf_rs::libbpf_sys::bpf_map__set_autoattach(
            skel.maps.cake_ops.as_libbpf_object().as_ptr(),
            false,
        )
    };
    anyhow::ensure!(ret == 0, "Failed to disable cake_ops auto-attach: {ret}");
    // The handler-edge hooks attach by hand, exit first (below); the skeleton's
    // auto-attach ran them in section order and a second time.
    for prog in [
        &mut skel.progs.cake_irq_enter,
        &mut skel.progs.cake_irq_leave,
        &mut skel.progs.cake_softirq_enter,
        &mut skel.progs.cake_softirq_leave,
        &mut skel.progs.cake_cpu_idle,
    ] {
        prog.set_autoattach(false);
    }
    Ok(skel)
}

/// The startup lines that follow the host shape: placement, cache bias,
/// slice, kernel paths and the toggle.
fn log_startup_detail(
    opts: &Opts,
    topo: &Topology,
    rank_tiers: u32,
    core_performance: &core_performance::CorePerformanceLayout,
    pref_die: &PreferredDie,
    x3d_mode: Option<&str>,
    probe_on: bool,
) {
    let total = topo.all_cpus.len();
    let usec = bpf_intf::consts_NSEC_PER_USEC as u64;
    let slice_us = bpf_intf::consts_SLICE_NS as u64 / usec;
    let grant_us = bpf_intf::consts_CAKE_GRANT_CAP_NS as u64 / usec;
    let queued_wakeup = *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP != 0;
    let dsq_peek = dsq_peek_native();

    if rank_tiers > 1 {
        info!(
            "Placement    Platform core preferences enabled ({} levels)",
            rank_tiers
        );
    } else {
        info!("Placement    No additional core ranking applied");
    }
    if opts.verbose {
        info!("Core order   {}", core_performance.summary());
    }
    if opts.verbose || pref_die.word != 0 {
        info!("Cache bias   {}", pref_die.summary(x3d_mode));
    }
    if opts.verbose {
        for core in core_performance.details() {
            info!("   {core}");
        }
    }
    if opts.verbose {
        info!(
            "   slice   grants to {grant_us}µs, kthreads {slice_us}µs, {total} per-CPU vtime queues + one wake pool per LLC"
        );
    }
    let kernel_line = format!(
        "   kernel  queued_wakeup {}, dsq_peek {}",
        if queued_wakeup { "on" } else { "UNSUPPORTED" },
        if dsq_peek { "native" } else { "iterator" }
    );
    if !queued_wakeup {
        warn!("{kernel_line}");
    } else if opts.verbose {
        info!("{kernel_line}");
    }
    // Stock start says nothing about the toggle; the identity line is --verbose only.
    if opts.verbose {
        info!("   toggle  probe={}", u8::from(probe_on));
    }
    if probe_on {
        info!("   toggle  probe=1 diagnostics");
    } else if !opts.toggle.is_empty() {
        info!("   toggle  all at default");
    }
}

/// Set the tick predictor horizon from the measured wake hop.
fn tune_tick_predictor(rodata: &mut bpf_skel::types::rodata, verbose: bool) {
    // The hop p99 sets the tick predictor horizon. It never sets cake_handoff_max_ns:
    // a clean ping-pong does not measure a contended handoff.
    match probe_handoff_hop_ns() {
        Some(probe) => {
            let (med, p99) = (probe.median, probe.p99);
            let hm = rodata.cake_handoff_max_ns;
            // A hop past a quarter tick would call every CPU tick-soon: off.
            let hop_max = rodata.cake_tick_ns / 4;
            rodata.cake_wake_hop_ns = if rodata.cake_tick_ns == 0 {
                0
            } else if p99 <= hop_max {
                p99
            } else {
                warn!("   probe   hop p99 {p99}ns exceeds {hop_max}ns; tick predictor off");
                0
            };
            if verbose {
                info!("Handoff      Hop median {med} ns / p99 {p99} ns; handoff limit {hm} ns");
            }
        }
        None => {
            warn!("   probe   handoff probe failed; tick predictor off");
        }
    }
}

/// Attach the handler-edge and cpu_idle tracepoints; the links live as long as the scheduler.
fn attach_hooks(skel: &BpfSkel<'_>, idle_exit_max_ns: u64) -> Vec<libbpf_rs::Link> {
    // Handler-edge tracepoints feed the in-handler depth. The exit hook of each
    // pair attaches FIRST (an entry counted before its exit hook exists leaves
    // that CPU mid-handler for the run); a pair whose exit fails skips its entry.
    let mut irq_links = Vec::with_capacity(4);
    for (name, leave, enter) in [
        (
            "irq",
            &skel.progs.cake_irq_leave,
            &skel.progs.cake_irq_enter,
        ),
        (
            "softirq",
            &skel.progs.cake_softirq_leave,
            &skel.progs.cake_softirq_enter,
        ),
    ] {
        match attach_irq_pair(|| Ok(leave.attach()?), || Ok(enter.attach()?)) {
            Ok(links) => irq_links.extend(links),
            Err(e) => warn!("   irq     {name} {e:#}; this source uses chronic steering only"),
        }
    }

    if idle_exit_max_ns > 0 {
        match skel.progs.cake_cpu_idle.attach() {
            Ok(link) => irq_links.push(link),
            Err(e) => warn!("   idle    cpu_idle tracepoint {e:#}; idle depth unknown"),
        }
    }
    irq_links
}

/// The lines printed once the scheduler is attached.
fn log_running(skel: &BpfSkel<'_>, verbose: bool) {
    if let Some(bss) = skel.maps.bss_data.as_ref() {
        let on_cpu = match bss.cake_compat_on_cpu_size {
            1 => "u8",
            4 => "32-bit",
            _ => "unknown (idle kick retained)",
        };
        let cpu_curr = if bss.cake_compat_cpu_curr_kfunc {
            "kfunc"
        } else {
            "rq fallback"
        };
        // The native path is the quiet one; a fallback is always said.
        match (bss.cake_compat_on_cpu_size, bss.cake_compat_cpu_curr_kfunc) {
            (1 | 4, true) if verbose => info!("Task state   Native kernel support"),
            (1 | 4, true) => {}
            (1 | 4, false) => info!("Task state   Compatibility fallback for this kernel"),
            _ => warn!("Task state   Unknown task-state layout; conservative idle kicks enabled"),
        }
        if verbose {
            info!("Kernel paths on_cpu={on_cpu} / cpu_curr={cpu_curr}");
        }
    }
    info!("🍰 Running");
    // Say which task-age clock the loader chose, under -v.
    let tick_ns = skel.maps.rodata_data.as_ref().map_or(0, |r| r.cake_tick_ns);
    if verbose {
        if tick_ns > 0 {
            info!("   age     tick clock ({tick_ns} ns per tick)");
        } else {
            info!("   age     precise clock (no tick-sized coarse clock resolution)");
        }
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    /// Handler-edge tracepoint links; dropped on exit with the rest.
    _irq_links: Vec<libbpf_rs::Link>,
    /// Diagnostics on (--toggle probe=1): census, hold attribution, black box.
    probe_on: bool,
    /// Print runtime diagnostics. Off by default: a release run is not a
    /// measurement session, and a scheduler logging into a game is noise.
    verbose: bool,
    /// Live IRQ-sink tracking state.
    sinks: SinkMonitor,
    signal_report: Option<std::fs::File>,
    signals_enabled: bool,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Option<Self>> {
        try_set_rlimit_infinity();
        log_identity();

        let signal_report = open_signal_report(opts)?;
        let signals = detect_signals(opts);
        // Record the kernel's hotplug sequence before sampling the online topology.
        let mut skel = open_skel(opts.verbose, open_object)?;
        let topo = Topology::new().context("failed to read topology")?;
        let bitops = NativeBitops::detect().select(opts)?;
        log_host(opts, &topo, bitops);

        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("BPF rodata unavailable for CPU topology")?;
        rodata.cake_native_ctz = bitops.ctz;
        rodata.cake_native_popcnt = bitops.popcnt;
        rodata.cake_signals_enabled = signals.enabled;
        rodata.cake_signals_policy = signals.policy;
        rodata.cake_signals_observe = signals.observe;
        if let Some(ns) = opts.handoff_ns {
            rodata.cake_handoff_max_ns = ns;
            warn!("   sweep   handoff_max {ns} ns (policy override)");
        }
        let (idle_driver, idle_states) = cpuidle_states();
        match &idle_driver {
            Some(d) if opts.verbose => info!(
                "Idle         {d}: {} power-saving states, up to {} us exit latency",
                idle_states.len(),
                idle_states.iter().copied().max().unwrap_or(0) / 1000
            ),
            None if opts.verbose => {
                info!("Idle         No CPU idle driver; no idle-exit cost applied")
            }
            _ => {}
        }
        let core_performance = core_performance::CorePerformanceLayout::discover(&topo);
        let host = HostShape::read(&topo, &core_performance, idle_states);
        let ranks = skel
            .maps
            .data_cake_ranks_data
            .as_mut()
            .context("BPF rank table unavailable")?;
        host.publish(rodata, ranks)?;
        let one_word = host.one_word();
        // The deep-idle word is read only by the one-word pickers: a wider host
        // leaves the cpu_idle tracepoint unloaded rather than fed for nobody.
        let idle_exit_max_ns = if one_word {
            rodata.cake_idle_exit_max_ns
        } else {
            0
        };

        // The toggle lands in rodata before load, so the verifier prunes the off arm.
        let probe_on = probe_toggle(&opts.toggle);
        rodata.cake_tog_probe = u8::from(probe_on);

        let x3d_mode = amd_x3d_mode();
        let pref_die = preferred_die(
            &topo,
            &core_performance,
            &host.rank_words,
            x3d_mode.as_deref(),
        );
        rodata.cake_llc_pref_word = pref_die.word;
        log_startup_detail(
            opts,
            &topo,
            rodata.cake_rank_tiers,
            &core_performance,
            &pref_die,
            x3d_mode.as_deref(),
            probe_on,
        );
        tune_tick_predictor(rodata, opts.verbose);

        configure_acquire_census(&mut skel, probe_on);
        if signals.enabled {
            skel.struct_ops.cake_ops_mut().flags |= signals.flag;
        }
        // One-word hosts claim on their own word: the kernel can stop updating its masks.
        if one_word {
            skel.struct_ops.cake_ops_mut().flags &= !*compat::SCX_OPS_KEEP_BUILTIN_IDLE;
        }
        if idle_exit_max_ns == 0 {
            skel.progs.cake_cpu_idle.set_autoload(false);
        }

        // Load and attach.
        let mut skel = scx_ops_load!(skel, cake_ops, uei)?;

        if let Some(path) = &opts.inspect_bpf {
            inspect_bpf::dump(libbpf_rs::skel::Skel::object(&skel), path)?;
            info!(
                "BPF inspection saved to {}; nothing attached",
                path.display()
            );
            return Ok(None);
        }

        let irq_links = attach_hooks(&skel, idle_exit_max_ns);

        // Begin scheduling only after handler accounting is installed.
        let struct_ops = Some(scx_ops_attach!(skel, cake_ops)?);

        log_running(&skel, opts.verbose);

        // File capabilities are needed only to load and attach. Drop them all: any
        // elevated capability left in the permitted set makes the kernel deny
        // /proc/<pid>/exe to unprivileged observers, breaking hash-of-exe identity.
        if let Err(err) = drop_privileges_for_observers() {
            warn!("post-attach capability drop failed: {err}");
        }

        Ok(Some(Self {
            skel,
            struct_ops,
            _irq_links: irq_links,
            probe_on,
            verbose: opts.verbose,
            sinks: SinkMonitor::new(*NR_CPU_IDS),
            signal_report,
            signals_enabled: signals.enabled,
        }))
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let mut polls: u32 = 0;
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            std::thread::sleep(Duration::from_secs(1));
            polls += 1;

            if self.verbose && (polls == 2 || polls == 6) {
                self.log_stuck_irq_depth(polls);
            }

            if let Some(set) = self.sinks.tick(*NR_CPU_IDS) {
                self.publish_sinks(&set);
            }
        }

        // Detach first: ops.exit copies the event and pool counters, and no record is mid-write.
        self.struct_ops.take();
        if self.probe_on {
            exit_report::probe(&self.skel);
        }
        exit_report::pools(&self.skel, self.verbose);
        if self.verbose {
            exit_report::events(&self.skel);
        }
        if let Some(report) = self.signal_report.take() {
            exit_report::signals(&self.skel, report, self.signals_enabled)?;
        }
        info!("Stopped");
        uei_report!(&self.skel, uei)
    }

    /// Self-check: a CPU mid-handler across two reads 50 ms apart is an entry
    /// counted before its exit hook existed. The healthy answer is zero.
    fn log_stuck_irq_depth(&self, polls: u32) {
        let depths = |bss: &bpf_skel::types::bss| -> Vec<u32> {
            bss.cake_irq_live
                .iter()
                .take(*NR_CPU_IDS)
                .map(|s| s.depth)
                .collect()
        };
        let first = self.skel.maps.bss_data.as_ref().map(|b| depths(b));
        std::thread::sleep(Duration::from_millis(50));
        let second = self.skel.maps.bss_data.as_ref().map(|b| depths(b));
        if let (Some(a), Some(b)) = (first, second) {
            let stuck: Vec<String> = a
                .iter()
                .zip(&b)
                .enumerate()
                .filter(|(_, (x, y))| **x != 0 && **y != 0)
                .map(|(cpu, (x, y))| format!("cpu{cpu}:{x}/{y}"))
                .collect();
            info!(
                "   irq     in-handler depth stuck on {} CPU(s) at {polls} s {}",
                stuck.len(),
                stuck.join(" ")
            );
        }
    }

    /// Publish the existing IRQ measurements as aligned CPU-mask words.
    /// Wide hosts may observe different publication epochs across words;
    /// these are placement preferences, never CPU admission or reservations.
    fn publish_sinks(&mut self, set: &[bool]) {
        const N: usize = bpf_intf::consts_QMASK_WORDS as usize;
        let words = sink_words::<N>(set);
        // The whole-core expansion, computed once per publication instead of on
        // every claim walk in BPF: a sink's SMT sibling shares its core.
        let siblings: Vec<i32> = self
            .skel
            .maps
            .rodata_data
            .as_ref()
            .map(|ro| ro.cpu_sibling.to_vec())
            .unwrap_or_default();
        let mut cores = words;
        for (cpu, hot) in set.iter().take(N * 64).enumerate() {
            if let (true, Some(&sib)) = (*hot, siblings.get(cpu))
                && sib >= 0
                && (sib as usize) < N * 64
            {
                cores[sib as usize / 64] |= 1u64 << (sib as usize % 64);
            }
        }
        let Some(bss) = self.skel.maps.bss_data.as_mut() else {
            return;
        };
        for (published, word) in bss.cpu_irq_hot_words.iter_mut().zip(words) {
            // SAFETY: the skeleton maps writable, u64-aligned BSS that BPF
            // reads concurrently; the atomic view lives no longer than the
            // &mut it is built from. No cross-word atomicity assumed.
            unsafe { AtomicU64::from_ptr(published) }.store(word, Ordering::Relaxed);
        }
        for (published, word) in bss.cpu_irq_hot_cores.iter_mut().zip(cores) {
            // SAFETY: as above.
            unsafe { AtomicU64::from_ptr(published) }.store(word, Ordering::Relaxed);
        }

        // Verbose only: the flip rate is a covariate of a frame capture, and a
        // release run is not a measurement session.
        if self.verbose {
            let named: Vec<usize> = set
                .iter()
                .enumerate()
                .filter_map(|(cpu, hot)| hot.then_some(cpu))
                .collect();
            info!("   irq     sinks {named:?} steered around");
        }
    }
}

fn sink_words<const N: usize>(set: &[bool]) -> [u64; N] {
    let mut words = [0; N];
    for (cpu, hot) in set.iter().take(N * 64).enumerate() {
        if *hot {
            words[cpu / 64] |= 1u64 << (cpu % 64);
        }
    }
    words
}

/// One host's wake+block+switch hop, as a distribution rather than a mean.
struct HandoffProbe {
    /// Typical hop, logged under -v.
    median: u64,
    /// Tail hop: the tick predictor's pick-to-landing horizon.
    p99: u64,
}

/// Per-CPU time spent in interrupt handlers, in kernel ticks, from
/// `/proc/stat` (irq + softirq columns, CONFIG_IRQ_TIME_ACCOUNTING). Handler
/// TIME is the harm itself: a wake suffers when it lands on a running handler,
/// so line counts mis-price it; softirq is included because NAPI shadows wakes.
fn read_irq_ticks(nr_cpus: usize) -> Option<Vec<Option<u64>>> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    let mut ticks = vec![None; nr_cpus];
    let mut seen = false;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(cpu) = fields
            .next()
            .and_then(|l| l.strip_prefix("cpu"))
            .and_then(|n| n.parse::<usize>().ok())
        else {
            continue;
        };
        if cpu >= nr_cpus {
            continue;
        }
        // cpuN user nice system idle iowait irq softirq ...
        let vals: Vec<u64> = fields.filter_map(|v| v.parse().ok()).collect();
        if vals.len() < 7 {
            continue;
        }
        ticks[cpu] = Some(vals[5] + vals[6]);
        seen = true;
    }
    seen.then_some(ticks)
}

/// The highest CPU id in a sysfs cpulist ("0-15", "0-3,8-11", "0").
fn last_cpu_id(list: &str) -> Option<usize> {
    list.trim()
        .rsplit(',')
        .next()?
        .rsplit('-')
        .next()?
        .parse()
        .ok()
}

/// The CPUs `/proc/stat` reported in both reads, and their handler-time
/// deltas in that order. Only those are ranked: a possible-but-offline id has
/// no handler time and would push the whole online set above the widest gap.
fn sink_deltas(current: &[Option<u64>], before: &[Option<u64>]) -> (Vec<usize>, Vec<u64>) {
    current
        .iter()
        .zip(before)
        .enumerate()
        .filter_map(|(cpu, (c, b))| Some((cpu, (*c)?.checked_sub((*b)?)?)))
        .unzip()
}

/// Split the host's handler-time distribution at its widest gap: sinks are the
/// CPUs above the cut. No unit-carrying threshold, so it adapts to any host. A
/// zero delta enters at half a tick so every ratio stays finite. A flat set has
/// no sinks; a cut condemning half the machine is load, not affinity (None).
fn sinks_by_widest_gap(deltas: &[u64]) -> Option<Vec<bool>> {
    let mut ranked: Vec<(f64, usize)> = deltas
        .iter()
        .enumerate()
        .map(|(cpu, &d)| ((d as f64).max(0.5), cpu))
        .collect();
    ranked.sort_by(|a, b| b.0.total_cmp(&a.0));

    let mut cut = 0;
    let mut widest = 1.0f64;
    for i in 1..ranked.len() {
        let ratio = ranked[i - 1].0 / ranked[i].0;
        if ratio > widest {
            widest = ratio;
            cut = i;
        }
    }
    if cut == 0 {
        return Some(vec![false; deltas.len()]);
    }
    if cut * 2 >= deltas.len() {
        return None;
    }

    let mut hot = vec![false; deltas.len()];
    for &(_, cpu) in &ranked[..cut] {
        hot[cpu] = true;
    }
    Some(hot)
}

/// Live IRQ-sink tracking riding the 1 s run loop. Each window the handler-time
/// deltas are split at their widest gap; a CPU above the cut for FLAG_POLLS
/// windows is published, released after UNFLAG_POLLS below it (a loading screen
/// must not flap the mask). An unchanged set doubles the interval up to
/// INTERVAL_MAX; a disagreeing window resets to tick rate. All four are counts.
/// Nothing is sampled at attach (that measures launch), so the scheduler starts
/// sink-free.
struct SinkMonitor {
    /// Last accepted read; deltas span the full gap between accepted reads,
    /// so a slower cadence measures a longer, smoother window.
    prev: Option<Vec<Option<u64>>>,
    /// The set currently pushed to the scheduler.
    published: Vec<bool>,
    /// Consecutive windows each CPU has ranked above the cut.
    hot_streak: Vec<u32>,
    /// Consecutive windows each published sink has ranked below the cut.
    quiet: Vec<u32>,
    /// Windows since the published set last changed.
    stable: u32,
    /// Current sampling interval in run-loop ticks.
    interval: u32,
    ticks: u32,
}

impl SinkMonitor {
    /// Unchanged windows that earn an interval doubling.
    const STABLE_POLLS: u32 = 8;
    /// Sampling never slows past this many ticks: one window of lag before a
    /// moved sink is seen, then FLAG_POLLS or UNFLAG_POLLS at tick rate.
    const INTERVAL_MAX: u32 = 4;
    /// Above-cut windows before a CPU is published.
    const FLAG_POLLS: u32 = 2;
    /// Below-cut windows before a published sink is removed.
    const UNFLAG_POLLS: u32 = 3;

    fn new(nr_cpus: usize) -> Self {
        Self {
            prev: None,
            published: vec![false; nr_cpus],
            hot_streak: vec![0; nr_cpus],
            quiet: vec![0; nr_cpus],
            stable: 0,
            interval: 1,
            ticks: 0,
        }
    }

    /// One run-loop tick; Some(set) when the published set changed.
    fn tick(&mut self, nr_cpus: usize) -> Option<Vec<bool>> {
        self.ticks = self.ticks.wrapping_add(1);
        if !self.ticks.is_multiple_of(self.interval) {
            return None;
        }
        self.observe(read_irq_ticks(nr_cpus))
    }

    /// Unknown windows are not consecutive evidence for either direction.
    /// Keep the last published preference, but restart confidence promptly.
    fn uncertain(&mut self) {
        self.hot_streak.fill(0);
        self.quiet.fill(0);
        self.stable = 0;
        self.interval = 1;
    }

    fn observe(&mut self, sample: Option<Vec<Option<u64>>>) -> Option<Vec<bool>> {
        let Some(sample) = sample else {
            self.prev = None;
            self.uncertain();
            return None;
        };
        let before = self.prev.replace(sample)?;
        let current = self.prev.as_ref()?;
        let (present, deltas) = sink_deltas(current, &before);
        if present.is_empty() {
            self.uncertain();
            return None;
        }
        let Some(ranked) = sinks_by_widest_gap(&deltas) else {
            self.uncertain();
            return None;
        };
        let mut hot = vec![false; self.published.len()];
        for (&cpu, &is_hot) in present.iter().zip(&ranked) {
            if cpu < hot.len() {
                hot[cpu] = is_hot;
            }
        }

        let mut changed = false;
        let mut disagree = false;
        for (cpu, &is_hot) in hot.iter().enumerate() {
            if present.binary_search(&cpu).is_err() {
                self.hot_streak[cpu] = 0;
                self.quiet[cpu] = 0;
                continue;
            }
            disagree |= is_hot != self.published[cpu];
            if is_hot {
                self.quiet[cpu] = 0;
                self.hot_streak[cpu] = (self.hot_streak[cpu] + 1).min(Self::FLAG_POLLS);
                // The cut wanders under load, so flagged CPUs accrete across polls; bound
                // the UNION here so the published set stays a strict minority.
                if !self.published[cpu]
                    && self.hot_streak[cpu] >= Self::FLAG_POLLS
                    && (self.published.iter().filter(|h| **h).count() + 1) * 2 < present.len()
                {
                    self.published[cpu] = true;
                    changed = true;
                }
            } else {
                self.hot_streak[cpu] = 0;
                if self.published[cpu] {
                    self.quiet[cpu] += 1;
                    if self.quiet[cpu] >= Self::UNFLAG_POLLS {
                        self.published[cpu] = false;
                        self.quiet[cpu] = 0;
                        changed = true;
                    }
                }
            }
        }

        if changed {
            self.stable = 0;
            self.interval = 1;
            return Some(self.published.clone());
        }
        if disagree {
            // A rank the published set does not show yet: confirm or
            // dismiss it at tick rate instead of after the slowed window.
            self.stable = 0;
            self.interval = 1;
            return None;
        }
        self.stable += 1;
        if self.stable >= Self::STABLE_POLLS {
            self.stable = 0;
            self.interval = (self.interval * 2).min(Self::INTERVAL_MAX);
        }
        None
    }
}

/// The tick period from the coarse clock's resolution, which the kernel sets
/// to one jiffy. 0 when the resolution is not a plausible tick (a VM or an
/// odd clocksource): the precise task-age clock is used instead.
fn coarse_tick_ns() -> u64 {
    const TICK_MIN_NS: u64 = 500_000;
    const TICK_MAX_NS: u64 = bpf_intf::consts_TICK_MAX_NS as u64;
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_getres writes only the timespec it is given.
    if unsafe { libc::clock_getres(libc::CLOCK_MONOTONIC_COARSE, &mut ts) } != 0 {
        return 0;
    }
    let ns = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
    if (TICK_MIN_NS..=TICK_MAX_NS).contains(&ns) {
        ns
    } else {
        0
    }
}

/// Major and minor of a kernel release such as "7.3.1-1-cachyos".
fn release_version(release: &str) -> (u32, u32) {
    let mut fields = release
        .trim()
        .split(['.', '-'])
        .map(|f| f.parse().unwrap_or(0));
    (fields.next().unwrap_or(0), fields.next().unwrap_or(0))
}

/// Whether __COMPAT_scx_bpf_dsq_peek calls the kfunc: it needs the ksym and the
/// v7.1 FIFO fix, and uses the DSQ iterator otherwise.
fn dsq_peek_native() -> bool {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();

    release_version(&release) >= (7, 1) && compat::ksym_exists("scx_bpf_dsq_peek").unwrap_or(false)
}

/// cpuidle exit latency per state index (ns, enabled states only) from cpu0's
/// sysfs, and the driver name; empty on a host without a driver.
fn cpuidle_states() -> (Option<String>, Vec<u64>) {
    let base = std::path::Path::new("/sys/devices/system/cpu");
    let driver = std::fs::read_to_string(base.join("cpuidle/current_driver"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "none");
    let mut states = Vec::new();
    if driver.is_some() {
        let mut idx = 0;
        while let Ok(lat) =
            std::fs::read_to_string(base.join(format!("cpu0/cpuidle/state{idx}/latency")))
        {
            let disabled =
                std::fs::read_to_string(base.join(format!("cpu0/cpuidle/state{idx}/disable")))
                    .is_ok_and(|d| d.trim() == "1");
            let us: u64 = lat.trim().parse().unwrap_or(0);
            states.push(if disabled { 0 } else { us * 1000 });
            idx += 1;
        }
    }
    (driver, states)
}

/// The AMD 3D V-cache mode ("cache" or "frequency") when the platform driver
/// exposes it.
fn amd_x3d_mode() -> Option<String> {
    let dir = std::fs::read_dir("/sys/bus/platform/drivers/amd_x3d_vcache").ok()?;
    for entry in dir.flatten() {
        if let Ok(mode) = std::fs::read_to_string(entry.path().join("amd_x3d_mode")) {
            return Some(mode.trim().to_string());
        }
    }
    None
}

struct PreferredDie {
    word: u64,
    reason: &'static str,
}

impl PreferredDie {
    fn summary(&self, mode: Option<&str>) -> String {
        format!(
            "preferred LLC mask {:#x} ({}), X3D driver mode {}",
            self.word,
            self.reason,
            mode.unwrap_or("unavailable")
        )
    }
}

/// Read the physical L3 size. The topology's per-CPU cache share also varies
/// with the number of online cores and cannot identify a stacked-cache die.
fn l3_size(cpu: usize) -> Option<usize> {
    let caches = std::fs::read_dir(format!("/sys/devices/system/cpu/cpu{cpu}/cache")).ok()?;
    caches.flatten().find_map(|entry| {
        let path = entry.path();
        let level = std::fs::read_to_string(path.join("level")).ok()?;
        let kind = std::fs::read_to_string(path.join("type")).ok()?;
        if level.trim() == "3" && kind.trim() == "Unified" {
            scx_utils::misc::read_file_byte(&path.join("size"))
                .ok()
                .filter(|&size| size > 0)
        } else {
            None
        }
    })
}

fn preferred_die(
    topo: &Topology,
    perf: &core_performance::CorePerformanceLayout,
    tiers: &[u64],
    mode: Option<&str>,
) -> PreferredDie {
    if topo.all_llcs.len() < 2 {
        return PreferredDie {
            word: 0,
            reason: "only one cache domain",
        };
    }
    if *NR_CPU_IDS > 64 || topo.all_llcs.len() > bpf_intf::consts_MAX_LLCS as usize {
        return PreferredDie {
            word: 0,
            reason: "topology exceeds the preferred-LLC mask or pool limit",
        };
    }
    let package = perf.cores.first().map(|core| core.identity.package);
    if perf
        .cores
        .iter()
        .any(|core| Some(core.identity.package) != package)
    {
        return PreferredDie {
            word: 0,
            reason: "multiple CPU packages",
        };
    }
    let mode = mode.filter(|_| !perf.preferences_disabled());
    let read_l3 = mode.is_some() && topo.all_llcs.len() == 2;
    let domains: Vec<_> = topo
        .all_llcs
        .values()
        .map(|llc| {
            let word = llc.span.as_raw_slice()[0];
            let l3 = if read_l3 {
                llc.span.iter().next().and_then(l3_size)
            } else {
                None
            };
            (word, l3)
        })
        .collect();
    select_die(&domains, tiers, mode)
}

fn select_die(domains: &[(u64, Option<usize>)], tiers: &[u64], mode: Option<&str>) -> PreferredDie {
    // Pick by effective performance only when every core of one domain ranks
    // ahead of every core outside it. A larger core count cannot win a tie.
    for &(word, _) in domains {
        let ahead = tiers
            .iter()
            .copied()
            .take_while(|tier| tier & !word == 0)
            .fold(0, |mask, tier| mask | tier);
        if word != 0 && ahead == word {
            return PreferredDie {
                word,
                reason: "effective core tiers",
            };
        }
    }
    if let [(a, Some(a_l3)), (b, Some(b_l3))] = domains
        && a_l3 != b_l3
        && matches!(mode, Some("cache" | "frequency"))
    {
        let pick_a = (a_l3 > b_l3) == (mode == Some("cache"));
        return PreferredDie {
            word: if pick_a { *a } else { *b },
            reason: "X3D mode and L3 size",
        };
    }
    PreferredDie {
        word: 0,
        reason: "no distinct domain preference",
    }
}

/// CPUs online now, from sysfs; every present CPU when the file is unreadable.
fn online_cpu_set(topo: &Topology) -> std::collections::BTreeSet<usize> {
    let all: std::collections::BTreeSet<usize> = topo.all_cpus.keys().copied().collect();
    let Ok(text) = std::fs::read_to_string("/sys/devices/system/cpu/online") else {
        return all;
    };
    let mut set = std::collections::BTreeSet::new();
    for part in text.trim().split(',') {
        let (lo, hi) = match part.split_once('-') {
            Some((a, b)) => (a.parse::<usize>(), b.parse::<usize>()),
            None => (part.parse::<usize>(), part.parse::<usize>()),
        };
        if let (Ok(lo), Ok(hi)) = (lo, hi) {
            set.extend(lo..=hi);
        }
    }
    if set.is_empty() { all } else { set }
}

/// Measure one wake + block + switch hop on THIS host: two threads ping-pong
/// through a condvar, the blocking handoff `cake_handoff_max_ns` is a proxy
/// for. Runs before attach, so it measures the stock kernel path; ~2200 round
/// trips. Returns ns per one-way hop, or None, and callers keep the defaults.
fn probe_handoff_hop_ns() -> Option<HandoffProbe> {
    const WARMUP: u32 = 200;
    const ITERS: u32 = 2_000;
    let total = WARMUP + ITERS;

    let pair = Arc::new((std::sync::Mutex::new(0u32), std::sync::Condvar::new()));
    let peer = Arc::clone(&pair);

    let responder = std::thread::Builder::new()
        .name("cake-probe".into())
        .spawn(move || {
            let (lock, cv) = &*peer;
            let mut turn = lock.lock().ok()?;
            for _ in 0..total {
                while turn.is_multiple_of(2) {
                    turn = cv.wait(turn).ok()?;
                }
                *turn = turn.wrapping_add(1);
                cv.notify_one();
            }
            Some(())
        })
        .ok()?;

    let mut hops: Vec<u64> = Vec::with_capacity(ITERS as usize);
    {
        let (lock, cv) = &*pair;
        let mut turn = lock.lock().ok()?;
        for i in 0..total {
            let t0 = std::time::Instant::now();
            *turn = turn.wrapping_add(1);
            cv.notify_one();
            while *turn % 2 == 1 {
                turn = cv.wait(turn).ok()?;
            }
            if i >= WARMUP {
                // Two hops per round trip: our wake of the peer, its wake of us.
                hops.push(t0.elapsed().as_nanos() as u64 / 2);
            }
        }
    }
    responder.join().ok()?;

    if hops.len() < ITERS as usize / 2 {
        return None;
    }
    hops.sort_unstable();
    let median = hops[hops.len() / 2];
    let p99 = hops[hops.len() * 99 / 100];
    if median == 0 || p99 == 0 {
        return None;
    }
    Some(HandoffProbe { median, p99 })
}

/// Parse the command line, dropping options cake does not have instead of
/// refusing to start (a legacy scx_loader flag must not keep the scheduler
/// off); dropped tokens are reported once logging is up. Real errors keep clap's.
fn parse_opts_lenient(
    args: impl IntoIterator<Item = impl Into<std::ffi::OsString>>,
) -> std::result::Result<(Opts, Vec<String>), clap::Error> {
    use clap::error::ContextKind;
    use clap::error::ErrorKind;

    let mut args: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
    let mut dropped: Vec<String> = Vec::new();
    loop {
        match Opts::try_parse_from(&args) {
            Ok(opts) => return Ok((opts, dropped)),
            Err(e) if e.kind() == ErrorKind::UnknownArgument => {
                let Some(bad) = e
                    .get(ContextKind::InvalidArg)
                    .map(|v| v.to_string())
                    .filter(|s| !s.is_empty())
                else {
                    return Err(e);
                };
                // The offending token, matched on the option name so that
                // both `--x=v` and `--x v` forms are found.
                let name = bad.split('=').next().unwrap_or(&bad).to_string();
                let short = name
                    .strip_prefix('-')
                    .filter(|s| s.chars().count() == 1)
                    .and_then(|s| s.chars().next());
                let Some((pos, split)) = args.iter().enumerate().skip(1).find_map(|(pos, a)| {
                    let s = a.to_string_lossy();
                    if s == bad || s == name || s.starts_with(&format!("{name}=")) {
                        return Some((pos, 0));
                    }
                    // Clap reports only `-p` for `-pgaming` or `-vpgaming`.
                    // Keep the accepted prefix; the unknown option owns the
                    // suffix, which may be its attached value.
                    if s.starts_with('-')
                        && !s.starts_with("--")
                        && let Some(short) = short
                    {
                        return s
                            .char_indices()
                            .skip(1)
                            .find_map(|(split, c)| (c == short).then_some((pos, split)));
                    }
                    None
                }) else {
                    return Err(e);
                };
                let mut tok = args.remove(pos).to_string_lossy().into_owned();
                let mut next_pos = pos;
                if split > 0 {
                    if split > 1 {
                        args.insert(pos, tok[..split].into());
                        next_pos += 1;
                    }
                    tok = format!("-{}", &tok[split..]);
                }
                // `--x v`: the bare value that follows is part of the same
                // mistake; a token starting with `-` is another option.
                if tok == name && tok.starts_with('-') && next_pos < args.len() {
                    let next = args[next_pos].to_string_lossy();
                    if !next.starts_with('-') {
                        tok.push(' ');
                        tok.push_str(&next);
                        args.remove(next_pos);
                    }
                }
                dropped.push(tok);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Drop the calling thread's capability sets and restore process inspection.
/// Call after privileged setup. Earlier-created threads retain their own
/// capabilities; a subsequent privileged initialization requires re-exec.
fn drop_privileges_for_observers() -> std::io::Result<()> {
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
    let header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Restore file capabilities for a requested restart after dropping the link.
fn reexec_self() -> Result<()> {
    use std::os::unix::process::CommandExt;
    let exe = std::fs::read_link("/proc/self/exe")
        .context("failed to resolve /proc/self/exe for restart")?;
    let err = std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .exec();
    Err(anyhow::Error::new(err).context("re-exec after kernel restart request failed"))
}

fn main() -> Result<()> {
    let (opts, ignored_args) = parse_opts_lenient(std::env::args_os()).unwrap_or_else(|e| e.exit());

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
    for a in &ignored_args {
        warn!("   args    ignored unknown option `{a}`; cake has no such option, defaults used");
    }

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        match build_identity::binary_sha256() {
            Ok(hash) => println!("Build SHA256: {hash}"),
            Err(err) => println!("Build SHA256: unavailable ({err:#})"),
        }
        return Ok(());
    }
    if opts.print_topology {
        let topo = Topology::new().context("failed to read topology")?;
        let layout = core_performance::CorePerformanceLayout::discover(&topo);
        println!("{}", layout.summary());
        let mode = amd_x3d_mode();
        let die = preferred_die(&topo, &layout, &layout.rank_words(), mode.as_deref());
        println!("{}", die.summary(mode.as_deref()));
        for core in layout.details() {
            println!("{core}");
        }
        return Ok(());
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        // Terminal Ctrl+C echo has no newline. Finish that line before the
        // run loop starts logging shutdown; leave redirected logs untouched.
        if std::io::stderr().is_terminal() {
            eprintln!();
        }
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    let mut open_object = MaybeUninit::uninit();
    let Some(mut sched) = Scheduler::init(&opts, &mut open_object)? else {
        return Ok(());
    };

    if sched.run(shutdown.clone())?.should_restart() {
        info!("Restart requested by the kernel — re-executing");
        reexec_self()?;
    }

    Ok(())
}

/// Publish each core's threads to the BPF lookups: `siblings` rings them, -1
/// meaning no online sibling, and `mates` holds every other thread of a CPU
/// below id 64, the idle word's range.
fn fill_core_maps(
    cores: impl Iterator<Item = Vec<usize>>,
    siblings: &mut [i32],
    mates: &mut [u64; 64],
) -> Result<()> {
    siblings.fill(-1);
    mates.fill(0);
    for cpu_ids in cores {
        if cpu_ids.len() < 2 {
            continue;
        }
        let core_word = cpu_ids
            .iter()
            .filter(|&&cpu| cpu < 64)
            .fold(0u64, |word, &cpu| word | (1u64 << cpu));
        for (idx, cpu) in cpu_ids.iter().copied().enumerate() {
            let sibling = cpu_ids[(idx + 1) % cpu_ids.len()];

            anyhow::ensure!(
                cpu < siblings.len() && sibling <= i32::MAX as usize,
                "CPU topology id exceeds Cake's compiled sibling map"
            );
            siblings[cpu] = sibling as i32;
            if cpu < 64 {
                mates[cpu] = core_word & !(1u64 << cpu);
            }
        }
    }
    Ok(())
}

/// Factor the narrow sibling map into two shifts when every edge has the
/// same distance. Irregular numbering keeps the exact per-CPU lookup.
fn smt_fold(siblings: &[i32]) -> Option<(u32, u64, u64)> {
    let (mut shift, mut left, mut right) = (0, 0, 0);
    for (cpu, &sib) in siblings.iter().take(64).enumerate() {
        if !(0..64).contains(&sib) || sib as usize == cpu {
            continue;
        }
        let distance = (cpu as u32).abs_diff(sib as u32);
        if shift != 0 && shift != distance {
            return None;
        }
        shift = distance;
        if cpu < sib as usize {
            left |= 1u64 << cpu;
        } else {
            right |= 1u64 << cpu;
        }
    }
    Some((shift, left, right))
}

/// One logical CPU as the loader publishes it.
struct CpuShape {
    id: usize,
    /// Unique core key; SMT siblings share it.
    core: usize,
    llc: usize,
    cache_size: usize,
    /// Not a little core of a hybrid CPU.
    big: bool,
}

/// The host as plain data, so a test can describe a machine it does not run on.
struct HostShape {
    /// Every CPU the topology describes, in ascending id.
    cpus: Vec<CpuShape>,
    /// The kernel's nr_cpu_ids over present CPUs.
    nr_cpu_ids: usize,
    /// The CPU id span the steal ring and neighbour probe scan. It covers the
    /// POSSIBLE ids the kernel counts; ops.init refuses less.
    span: usize,
    online: std::collections::BTreeSet<usize>,
    /// cpuidle exit latency per state, ns; empty without a driver.
    idle_states: Vec<u64>,
    /// coarse_tick_ns().
    tick_ns: u64,
    /// The platform core ranking, best tier first, as CPU words.
    rank_words: Vec<u64>,
}

impl HostShape {
    fn read(
        topo: &Topology,
        perf: &core_performance::CorePerformanceLayout,
        idle_states: Vec<u64>,
    ) -> Self {
        let span = (*NR_CPU_IDS).max(
            std::fs::read_to_string("/sys/devices/system/cpu/possible")
                .ok()
                .and_then(|t| last_cpu_id(&t))
                .map_or(0, |last| last + 1),
        );
        Self {
            cpus: topo
                .all_cpus
                .values()
                .map(|cpu| CpuShape {
                    id: cpu.id,
                    core: cpu.core_id,
                    llc: cpu.llc_id,
                    cache_size: cpu.cache_size,
                    big: perf.big_cpu(cpu),
                })
                .collect(),
            nr_cpu_ids: *NR_CPU_IDS,
            span,
            online: online_cpu_set(topo),
            idle_states,
            tick_ns: coarse_tick_ns(),
            rank_words: perf.rank_words(),
        }
    }

    /// The census word covers PRESENT ids; hotplug headroom past 64 costs
    /// nothing, a present id past 64 turns the one-word paths off.
    fn one_word(&self) -> bool {
        self.nr_cpu_ids <= bpf_intf::consts_CPU_WORD_BITS as usize
    }

    fn nr_llcs(&self) -> usize {
        self.cpus
            .iter()
            .map(|cpu| cpu.llc)
            .collect::<std::collections::BTreeSet<usize>>()
            .len()
    }

    /// Publish the shape to rodata, where the verifier folds it. A runtime
    /// decision, never a build-host property: one binary attaches on any topology.
    fn publish(
        &self,
        ro: &mut bpf_skel::types::rodata,
        ranks: &mut bpf_skel::types::data_cake_ranks,
    ) -> Result<()> {
        anyhow::ensure!(
            self.span <= bpf_intf::consts_MAX_CPUS as usize,
            "host nr_cpu_ids {} exceeds Cake's compiled MAX_CPUS {}",
            self.span,
            bpf_intf::consts_MAX_CPUS
        );
        self.publish_span_and_clocks(ro);
        self.publish_cores(ro, ranks)?;
        self.publish_llcs(ro);
        self.publish_steal_order(ro);
        Ok(())
    }

    /// The id span, the one-word switch, the tick and the cpuidle exit latencies.
    fn publish_span_and_clocks(&self, ro: &mut bpf_skel::types::rodata) {
        let one_word = self.one_word();
        ro.nr_cpu_span = self.span as u32;
        ro.cake_one_word = u8::from(one_word);
        ro.cake_tick_ns = self.tick_ns;
        // Expiry is seen at a tick: the longest grant (a kthread's SLICE_NS) runs a tick over.
        let tick = if self.tick_ns > 0 {
            self.tick_ns
        } else {
            bpf_intf::consts_TICK_MAX_NS as u64
        };
        ro.cake_vcap_unit_ns = bpf_intf::consts_SLICE_NS as u64 + tick;
        for (slot, ns) in ro.cake_idle_state_ns.iter_mut().zip(&self.idle_states) {
            *slot = *ns;
        }
        ro.cake_idle_exit_max_ns = self.idle_states.iter().copied().max().unwrap_or(0);
        if !one_word {
            warn!(
                "   span    {} CPU ids exceed one census word: claim walk, seats, deep-idle avoidance and die-local pools off, kernel idle pick only",
                self.nr_cpu_ids
            );
        }
    }

    /// Big cores, the platform ranking and the SMT maps.
    fn publish_cores(
        &self,
        ro: &mut bpf_skel::types::rodata,
        ranks: &mut bpf_skel::types::data_cake_ranks,
    ) -> Result<()> {
        let one_word = self.one_word();
        // Capacity asymmetry inside one cache domain is the hybrid signature;
        // across dies it is binning or cache, which the die model handles.
        if one_word && self.nr_llcs() == 1 && self.cpus.iter().any(|cpu| !cpu.big) {
            ro.cake_cap_tiers = 1;
            ro.cake_cap_word = self
                .cpus
                .iter()
                .filter(|cpu| cpu.big)
                .fold(0u64, |w, cpu| w | (1u64 << cpu.id));
            info!(
                "Hybrid CPU   {} high-capacity logical CPUs preferred",
                ro.cake_cap_word.count_ones()
            );
        }
        if one_word && self.rank_words.len() > 1 {
            ro.cake_rank_tiers = self.rank_words.len() as u32;
            ro.cpu_perf_known = self.rank_words.iter().fold(0, |all, word| all | word);
            for (slot, word) in ranks.cpu_perf_tier.iter_mut().zip(&self.rank_words) {
                *slot = *word;
            }
        }

        // Linux CPU numbering does not guarantee that an SMT sibling is cpu +/-
        // nr_cpus/2: the BPF lookups come from the topology.
        let mut cores: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for cpu in &self.cpus {
            cores.entry(cpu.core).or_default().push(cpu.id);
        }
        fill_core_maps(
            cores.into_values(),
            &mut ro.cpu_sibling,
            &mut ro.cake_core_mates,
        )?;
        if let Some((shift, left, right)) = smt_fold(&ro.cpu_sibling) {
            ro.cake_smt_shift = shift;
            ro.cake_smt_left = left;
            ro.cake_smt_right = right;
        }
        Ok(())
    }

    /// The pool layout, and the online counts the serial gate and claim tries scale by.
    fn publish_llcs(&self, ro: &mut bpf_skel::types::rodata) {
        let one_word = self.one_word();
        // The per-CPU LLC word, the dense LLC id and the LLC count, from every
        // CPU the topology describes.
        let placed: Vec<(usize, usize)> = self.cpus.iter().map(|cpu| (cpu.id, cpu.llc)).collect();
        // Die-local pools need the one-word census: past it the pool kick is
        // LLC-blind and lands on a die whose dispatch reads its own pool.
        let max_llcs = if one_word {
            bpf_intf::consts_MAX_LLCS as usize
        } else {
            1
        };
        let layout = LlcLayout::build(&placed, max_llcs);
        if let Some(n) = layout.collapsed {
            warn!("   llc     {n} domains, {max_llcs} pool(s) usable here; one pool, LLC-blind");
        }
        ro.cpu_llc_id.fill(0);
        ro.cpu_llc_domain.fill(u16::MAX);
        ro.cpu_llc_word.fill(u64::MAX);
        for (cpu, llc) in &placed {
            if *cpu < ro.cpu_llc_id.len() {
                ro.cpu_llc_id[*cpu] = layout.dense[llc];
                ro.cpu_llc_domain[*cpu] = layout.domain[llc];
                ro.cpu_llc_word[*cpu] = layout.word[llc];
            }
        }
        ro.nr_llcs = layout.nr_llcs;

        // Online CPUs per LLC and per host, tripled for the serial gate's
        // three-quarters test; claim tries scale with the widest die.
        let mut per_llc: BTreeMap<usize, u32> = BTreeMap::new();
        for cpu in &self.cpus {
            if self.online.contains(&cpu.id) {
                *per_llc.entry(cpu.llc).or_insert(0) += 1;
            }
        }
        ro.nr_cpu_online3 = per_llc.values().sum::<u32>() * 3;
        ro.cpu_llc_online3.fill(0);
        let mut die_max = 0u32;
        for cpu in &self.cpus {
            let n = per_llc.get(&cpu.llc).copied().unwrap_or(0);
            die_max = die_max.max(n);
            if cpu.id < ro.cpu_llc_online3.len() {
                ro.cpu_llc_online3[cpu.id] = n * 3;
            }
        }
        ro.cake_claim_tries = (die_max / 4).max(bpf_intf::consts_CLAIM_TRIES_MIN);
    }

    /// Steal order per CPU: same die, then dies with the same cache size, then the rest.
    fn publish_steal_order(&self, ro: &mut bpf_skel::types::rodata) {
        // Hosts wider than the fixed matrix span keep the generic ring walk.
        let span = bpf_intf::consts_STEAL_SPAN as usize;
        let fits = self
            .cpus
            .iter()
            .map(|cpu| cpu.id)
            .max()
            .is_none_or(|last| last < span);
        ro.steal_order_live = u8::from(fits);
        ro.nr_steal_cpus = self.cpus.len().saturating_sub(1) as u32;
        ro.cpu_steal_order.fill(0);

        if self.nr_llcs() > 1 && !fits {
            warn!("   ccd     host wider than steal matrix ({span} CPUs); ring steal only");
        }
        if fits {
            let mut llc_cache: BTreeMap<usize, usize> = BTreeMap::new();
            for cpu in &self.cpus {
                let e = llc_cache.entry(cpu.llc).or_insert(0);
                *e = (*e).max(cpu.cache_size);
            }
            for src in &self.cpus {
                let mut candidates: Vec<&CpuShape> =
                    self.cpus.iter().filter(|dst| dst.id != src.id).collect();
                candidates.sort_by_key(|dst| {
                    let class = if dst.llc == src.llc {
                        0
                    } else if llc_cache[&dst.llc] == llc_cache[&src.llc] {
                        1
                    } else {
                        2
                    };
                    // Own die: the SMT sibling first, then by id distance.
                    (
                        class,
                        u8::from(dst.core != src.core),
                        (dst.id + self.nr_cpu_ids - src.id) % self.nr_cpu_ids,
                    )
                });
                let base = src.id * span;
                for (slot, dst) in candidates.into_iter().enumerate() {
                    ro.cpu_steal_order[base + slot] = dst.id as u16;
                }
            }
        }
    }
}

/// The LLC topology the loader publishes to rodata, built from
/// (cpu id, llc id) pairs so any host shape can be tested without a machine.
struct LlcLayout {
    /// Physical identity is never collapsed to the bounded pool namespace.
    domain: BTreeMap<usize, u16>,
    /// Dense pool index per topology LLC id; every id maps, ids are
    /// assigned in ascending LLC order.
    dense: BTreeMap<usize, u8>,
    /// The CPUs (ids below 64) sharing each LLC, as one word. An LLC
    /// with no CPU below 64 gets all ones: the census paths that read the
    /// word only run inside one word, and all ones is the LLC-blind walk.
    word: BTreeMap<usize, u64>,
    nr_llcs: u32,
    /// Set when more LLCs exist than pools: everything went to pool 0.
    collapsed: Option<usize>,
}

impl LlcLayout {
    fn build(cpus: &[(usize, usize)], max_llcs: usize) -> Self {
        let mut word: BTreeMap<usize, u64> = BTreeMap::new();
        for (cpu, llc) in cpus {
            let w = word.entry(*llc).or_insert(0);
            if *cpu < 64 {
                *w |= 1u64 << cpu;
            }
        }
        for w in word.values_mut() {
            if *w == 0 {
                *w = u64::MAX;
            }
        }
        let n = word.len();
        let collapsed = (n > max_llcs).then_some(n);
        let domain = word
            .keys()
            .enumerate()
            .map(|(i, llc)| (*llc, i as u16))
            .collect();
        let dense: BTreeMap<usize, u8> = word
            .keys()
            .enumerate()
            .map(|(i, llc)| (*llc, if collapsed.is_some() { 0 } else { i as u8 }))
            .collect();
        let nr_llcs = if collapsed.is_some() {
            1
        } else {
            n.max(1) as u32
        };
        Self {
            domain,
            dense,
            word,
            nr_llcs,
            collapsed,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn handoff_floor_preserves_tagged_and_compute_slice_bounds() {
        let min = u64::from(super::bpf_intf::consts_CAKE_POOL_TAG_MASK + 1);
        let max = u64::from(super::bpf_intf::consts_CAKE_GRANT_CAP_NS / 2);
        for value in [0, min - 1, min, 1464, max, max + 1, u64::MAX] {
            let value_arg = value.to_string();
            let parsed = super::parse_opts_lenient(["scx_cake", "--handoff-ns", &value_arg]);
            if (min..=max).contains(&value) {
                assert_eq!(parsed.unwrap().0.handoff_ns, Some(value));
            } else {
                assert!(parsed.is_err(), "accepted {value} ns");
            }
        }
    }

    #[test]
    fn effective_core_order_wins_over_a_conflicting_x3d_mode() {
        let domains = [(0x0f, Some(96)), (0xf0, Some(32))];
        assert_eq!(
            super::select_die(&domains, &[0x03, 0x0c, 0xf0], Some("frequency")).word,
            0x0f
        );
        assert_eq!(
            super::select_die(&domains, &[0xf0, 0x0f], Some("cache")).word,
            0xf0
        );
    }

    #[test]
    fn x3d_fallback_requires_two_distinct_measured_l3_sizes_and_a_mode() {
        let domains = [(0x3, Some(96)), (0xfc, Some(32))];
        let overlapping = [0x05, 0xfa];
        assert_eq!(
            super::select_die(&domains, &overlapping, Some("cache")).word,
            0x03
        );
        assert_eq!(
            super::select_die(&domains, &overlapping, Some("frequency")).word,
            0xfc
        );
        assert_eq!(super::select_die(&domains, &overlapping, None).word, 0);
        assert_eq!(
            super::select_die(&[(3, None), (252, Some(32))], &[255], Some("frequency")).word,
            0
        );
        assert_eq!(
            super::select_die(&[(3, Some(32)), (252, Some(32))], &[255], Some("cache")).word,
            0
        );
    }

    #[test]
    fn bitops_and_inspection_flags_are_recognized() {
        let (defaults, dropped) = super::parse_opts_lenient(["scx_cake"]).unwrap();
        assert!(dropped.is_empty());
        assert!(!defaults.native_bitops && defaults.inspect_bpf.is_none());
        let (opts, dropped) = super::parse_opts_lenient([
            "scx_cake",
            "--native-bitops",
            "--inspect-bpf",
            "inspection-output",
        ])
        .unwrap();
        assert!(dropped.is_empty());
        assert!(opts.native_bitops);
        assert_eq!(
            opts.inspect_bpf.unwrap(),
            std::path::PathBuf::from("inspection-output")
        );
    }

    #[test]
    fn automatic_bitops_follow_available_cpu_and_kernel_support() {
        let (opts, _) = super::parse_opts_lenient(["scx_cake"]).unwrap();
        for ctz in [false, true] {
            for popcnt in [false, true] {
                let available = super::NativeBitops { ctz, popcnt };
                assert_eq!(available.select(&opts).unwrap(), available);
            }
        }
    }

    #[test]
    fn portable_override_disables_supported_bitops_and_rejects_native_flags() {
        let (opts, dropped) = super::parse_opts_lenient(["scx_cake", "--portable-bitops"]).unwrap();
        assert!(dropped.is_empty());
        let available = super::NativeBitops {
            ctz: true,
            popcnt: true,
        };
        assert_eq!(
            available.select(&opts).unwrap(),
            super::NativeBitops::default()
        );
        let err = super::parse_opts_lenient(["scx_cake", "--portable-bitops", "--native-bitops"])
            .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn explicit_bitops_preserve_ablation_and_fail_when_unavailable() {
        let requested = super::NativeBitops {
            ctz: true,
            popcnt: true,
        };
        let (opts, _) = super::parse_opts_lenient(["scx_cake", "--native-bitops"]).unwrap();
        for ctz in [false, true] {
            for popcnt in [false, true] {
                let available = super::NativeBitops { ctz, popcnt };
                let result = available.select(&opts);
                if ctz && popcnt {
                    assert_eq!(result.unwrap(), requested);
                } else {
                    assert!(result.is_err(), "{available:?}");
                }
            }
        }
    }

    // Catches a stale or malformed toggle turning diagnostics on, or the last
    // valid value not winning.
    #[test]
    fn probe_toggle_takes_the_last_valid_value_and_skips_bad_ones() {
        let specs = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(!super::probe_toggle(&[]));
        assert!(super::probe_toggle(&specs(&["probe=1"])));
        assert!(!super::probe_toggle(&specs(&["probe=1", "probe=0"])));
        assert!(super::probe_toggle(&specs(&[
            "probe=1", "probe=2", "probe", "lazy=0"
        ])));
        assert!(!super::probe_toggle(&specs(&["lazy=1", "probe=yes"])));
    }

    #[test]
    fn legacy_profiles_use_default_options() {
        let (defaults, _) = super::parse_opts_lenient(["scx_cake"]).unwrap();
        for args in [
            vec!["--profile", "gaming"],
            vec!["--profile=performance"],
            vec!["-p", "powersave"],
            vec!["-pperformance"],
            vec!["--profile"],
            vec!["--performance", "--powersave"],
        ] {
            let (opts, dropped) =
                super::parse_opts_lenient(std::iter::once("scx_cake").chain(args.clone())).unwrap();
            assert_eq!(opts, defaults, "{args:?}");
            assert!(!dropped.is_empty(), "{args:?}");
        }
    }

    #[test]
    fn legacy_options_preserve_supported_arguments() {
        let (expected, _) =
            super::parse_opts_lenient(["scx_cake", "-v", "--toggle", "g85=0", "--print-topology"])
                .unwrap();
        let (opts, dropped) = super::parse_opts_lenient([
            "scx_cake",
            "--profile",
            "gaming",
            "-v",
            "--obsolete=42",
            "--toggle",
            "g85=0",
            "--powersave",
            "--print-topology",
        ])
        .unwrap();
        assert_eq!(opts, expected);
        assert_eq!(
            dropped,
            ["--profile gaming", "--obsolete=42", "--powersave"]
        );
    }

    #[test]
    fn legacy_short_option_preserves_cluster_prefix() {
        let (opts, dropped) =
            super::parse_opts_lenient(["scx_cake", "-vpperformance", "--toggle=g85=0"]).unwrap();
        assert!(opts.verbose);
        assert_eq!(opts.toggle, ["g85=0"]);
        assert_eq!(dropped, ["-pperformance"]);
    }

    #[test]
    fn supported_option_errors_and_help_remain_errors() {
        use clap::error::ErrorKind;
        for (args, kind) in [
            (vec!["--toggle"], ErrorKind::InvalidValue),
            (vec!["--verbose=garbage"], ErrorKind::TooManyValues),
            (
                vec!["--profile", "gaming", "--help"],
                ErrorKind::DisplayHelp,
            ),
        ] {
            let err = super::parse_opts_lenient(std::iter::once("scx_cake").chain(args.clone()))
                .unwrap_err();
            assert_eq!(err.kind(), kind, "{args:?}");
        }
    }

    #[test]
    fn drop_privileges_in_child() {
        const CHILD: &str = "SCX_CAKE_OBSERVER_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::drop_privileges_in_child"])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        super::drop_privileges_for_observers().unwrap();
        let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        for set in ["CapInh:", "CapPrm:", "CapEff:"] {
            let value = status.lines().find(|line| line.starts_with(set)).unwrap();
            assert_eq!(
                u64::from_str_radix(value.split_whitespace().nth(1).unwrap(), 16).unwrap(),
                0
            );
        }
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 1);
    }

    #[test]
    fn smt_fold_matches_every_single_cpu_mapping() {
        let mut siblings = [-1; 64];
        assert_eq!(super::smt_fold(&siblings), Some((0, 0, 0)));
        // Covers adjacent, split-half, sparse and one-way maps, including
        // the maximum legal shift. OR-linearity extends these checks to
        // every possible combination of reserved CPUs.
        for distance in 1..64 {
            for (cpu, sib) in siblings.iter_mut().enumerate() {
                *sib = if cpu + distance < 64 {
                    (cpu + distance) as i32
                } else if cpu >= distance {
                    (cpu - distance) as i32
                } else {
                    -1
                };
            }
            let (shift, left, right) = super::smt_fold(&siblings).unwrap();
            for (cpu, &sib) in siblings.iter().enumerate() {
                let bit = 1u64 << cpu;
                let actual = bit | ((bit & left) << shift) | ((bit & right) >> shift);
                let expected = bit | if sib >= 0 { 1u64 << sib } else { 0 };
                assert_eq!(actual, expected);
            }
        }
        siblings.fill(-1);
        siblings[0] = 1;
        siblings[1] = 0;
        siblings[2] = 4;
        assert_eq!(super::smt_fold(&siblings), None);
        siblings.fill(64); // beyond-word edges do not affect the narrow mask
        assert_eq!(super::smt_fold(&siblings), Some((0, 0, 0)));
    }

    #[test]
    fn idle_and_release_callbacks_are_registered() {
        use libbpf_rs::skel::SkelBuilder;
        use std::mem::MaybeUninit;

        let mut object = MaybeUninit::uninit();
        let builder = super::BpfSkelBuilder::default();
        let mut skel = builder.open(&mut object).expect("open embedded BPF object");
        assert!(!skel.struct_ops.cake_ops_mut().update_idle.is_null());
        assert!(!skel.struct_ops.cake_ops_mut().quiescent.is_null());
        assert!(!skel.struct_ops.cake_ops_mut().cpu_release.is_null());
        assert!(!skel.struct_ops.cake_ops_mut().disable.is_null());
        assert!(skel.progs.cake_cpu_release.autoload());
    }

    use super::{
        LlcLayout, SinkMonitor, attach_irq_pair, last_cpu_id, sink_deltas, sink_words,
        sinks_by_widest_gap,
    };

    // Synthetic CPU layouts, as each core's thread ids.
    fn pairs_at(cores: usize, stride: usize) -> Vec<Vec<usize>> {
        (0..cores).map(|core| vec![core, core + stride]).collect()
    }

    fn adjacent_pairs(cores: usize) -> Vec<Vec<usize>> {
        (0..cores)
            .map(|core| vec![2 * core, 2 * core + 1])
            .collect()
    }

    fn singles(cores: usize) -> Vec<Vec<usize>> {
        (0..cores).map(|core| vec![core]).collect()
    }

    // Hybrid: SMT pairs, then CPUs with no sibling.
    fn pairs_then_singles(pairs: usize, lone: usize) -> Vec<Vec<usize>> {
        let mut cores = adjacent_pairs(pairs);
        cores.extend((0..lone).map(|core| vec![2 * pairs + core]));
        cores
    }

    // Offlined threads and mixed distances: no single shift expresses this.
    fn uneven_layout() -> Vec<Vec<usize>> {
        vec![vec![0, 1], vec![2, 5], vec![3], vec![4, 7], vec![6]]
    }

    fn four_threads(cores: usize) -> Vec<Vec<usize>> {
        (0..cores)
            .map(|core| (4 * core..4 * core + 4).collect())
            .collect()
    }

    fn core_mask(core: &[usize]) -> u64 {
        core.iter().fold(0u64, |mask, &cpu| mask | (1u64 << cpu))
    }

    /// cake_own_cores() in cake.bpf.c, over the loader's rodata.
    fn own_cores(w: u64, fold: Option<(u32, u64, u64)>, mates: &[u64; 64]) -> u64 {
        match fold {
            Some((0, _, _)) => w,
            Some((shift, left, right)) => {
                w & (((w & left) << shift) | ((w & right) >> shift) | !(left | right))
            }
            None => (0..64)
                .filter(|&cpu| w & (1u64 << cpu) != 0 && mates[cpu] & !w == 0)
                .fold(0u64, |cores, cpu| cores | (1u64 << cpu)),
        }
    }

    /// Every subset up to 16 CPUs; above that the boundaries and a fixed-seed sample.
    fn probe_words(cores: &[Vec<usize>]) -> Vec<u64> {
        let all = cores.iter().fold(0u64, |mask, core| mask | core_mask(core));
        let mut words = vec![0, all];
        if all.count_ones() <= 16 {
            let mut subset = all;
            while subset != 0 {
                words.push(subset);
                subset = (subset - 1) & all;
            }
            return words;
        }
        for core in cores {
            words.push(core_mask(core));
            words.push(all & !core_mask(core));
            words.extend(core.iter().map(|&cpu| all & !(1u64 << cpu)));
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            words.push(state & all);
        }
        words
    }

    // Catches a whole-core word that disagrees with the real threads of a core on
    // some numbering, which sends wakes to a busy core's sibling.
    #[test]
    fn whole_core_word_matches_brute_force_on_every_layout() -> anyhow::Result<()> {
        let layouts = [
            ("siblings at +N", pairs_at(16, 16), Some(16)),
            ("adjacent siblings", adjacent_pairs(8), Some(1)),
            ("no SMT", singles(16), Some(0)),
            ("one CPU", singles(1), Some(0)),
            ("one core, two threads", vec![vec![0, 1]], Some(1)),
            ("pairs plus singles", pairs_then_singles(8, 8), Some(1)),
            ("uneven", uneven_layout(), None),
            ("four threads a core", four_threads(4), None),
            ("64 ids at +32, bit 63", pairs_at(32, 32), Some(32)),
            ("64 ids adjacent, bit 63", adjacent_pairs(32), Some(1)),
        ];
        for (name, cores, shift) in layouts {
            let mut siblings = [-1i32; 64];
            let mut mates = [0u64; 64];
            super::fill_core_maps(cores.iter().cloned(), &mut siblings, &mut mates)?;
            let fold = super::smt_fold(&siblings);
            assert_eq!(fold.map(|(s, _, _)| s), shift, "{name}");
            for w in probe_words(&cores) {
                let expected = cores
                    .iter()
                    .map(|core| core_mask(core))
                    .filter(|&mask| w & mask == mask)
                    .fold(0u64, |all, mask| all | mask);
                assert_eq!(own_cores(w, fold, &mates), expected, "{name} word {w:#x}");
            }
        }
        Ok(())
    }

    // Each of these raises "built-in idle tracking is disabled" and ejects cake on a
    // host without KEEP_BUILTIN_IDLE. Substrings: the _node and __ forms count too.
    const BUILTIN_IDLE_KFUNCS: [&str; 6] = [
        "scx_bpf_pick_idle_cpu",
        "scx_bpf_test_and_clear_cpu_idle",
        "scx_bpf_get_idle_cpumask",
        "scx_bpf_get_idle_smtmask",
        "scx_bpf_select_cpu_dfl",
        "scx_bpf_select_cpu_and",
    ];

    // Exit latencies a host with a cpuidle driver reports.
    const IDLE_STATES_NS: [u64; 3] = [1_000, 18_000, 350_000];

    // Room for any program's level 2 log: untouched pages cost nothing, an overflow refuses the
    // load, and libbpf's own buffer would verify the largest program once per doubling.
    const VERIFIER_LOG_BYTES: usize = 256 << 20;

    // One CPU layout as the loader would describe it to BPF.
    struct LoadShape {
        name: &'static str,
        cores: Vec<Vec<usize>>,
        llcs: usize,
        // Distinct core preference levels, best first; one level means no ranking.
        ranks: usize,
        // Cores from this index on are little, which the loader acts on with one LLC.
        little_from: Option<usize>,
        idle_states: &'static [u64],
        // Read the walked calls from a level 2 log, which costs seconds a shape.
        check_calls: bool,
        // Possible CPU ids when hotplug headroom runs past the present ones.
        possible: Option<usize>,
    }

    fn load_shape(
        name: &'static str,
        cores: Vec<Vec<usize>>,
        llcs: usize,
        ranks: usize,
    ) -> LoadShape {
        LoadShape {
            name,
            cores,
            llcs,
            ranks,
            little_from: None,
            idle_states: &IDLE_STATES_NS,
            check_calls: false,
            possible: None,
        }
    }

    // The host a LoadShape stands for, as the loader would read it.
    fn host_shape(shape: &LoadShape) -> super::HostShape {
        let cores = &shape.cores;
        let nr_cpu_ids = cores.iter().flatten().max().unwrap() + 1;
        let mut cpus: Vec<super::CpuShape> = cores
            .iter()
            .enumerate()
            .flat_map(|(core, threads)| {
                let llc = core * shape.llcs / cores.len();
                let big = shape.little_from.is_none_or(|little| core < little);
                threads.iter().map(move |&id| super::CpuShape {
                    id,
                    core,
                    llc,
                    cache_size: 0,
                    big,
                })
            })
            .collect();
        cpus.sort_by_key(|cpu| cpu.id);
        let mut rank_words = vec![0u64; if shape.ranks > 1 { shape.ranks } else { 0 }];
        for (index, core) in cores.iter().enumerate() {
            if let Some(word) = rank_words.get_mut(index * shape.ranks / cores.len()) {
                *word |= core_mask(core);
            }
        }
        super::HostShape {
            online: cpus.iter().map(|cpu| cpu.id).collect(),
            cpus,
            nr_cpu_ids,
            span: shape.possible.unwrap_or(nr_cpu_ids),
            idle_states: shape.idle_states.to_vec(),
            tick_ns: super::coarse_tick_ns(),
            rank_words,
        }
    }

    // The loader's own publication for this layout, so the load check sees its paths.
    fn fill_shape_rodata(
        ro: &mut super::bpf_skel::types::rodata,
        ranks: &mut super::bpf_skel::types::data_cake_ranks,
        shape: &LoadShape,
    ) -> anyhow::Result<()> {
        let native = super::NativeBitops::detect();
        ro.cake_native_ctz = native.ctz;
        ro.cake_native_popcnt = native.popcnt;
        host_shape(shape).publish(ro, ranks)?;
        if ro.cake_one_word != 0 && ro.nr_llcs > 1 {
            ro.cake_llc_pref_word = ro.cpu_llc_word[shape.cores[0][0]];
        }
        ro.cake_wake_hop_ns = ro.cake_tick_ns / 8;
        Ok(())
    }

    fn verified_insns(fd: std::os::fd::BorrowedFd) -> u32 {
        use libbpf_rs::libbpf_sys::{bpf_obj_get_info_by_fd, bpf_prog_info};
        use std::os::fd::AsRawFd;

        let mut len = size_of::<bpf_prog_info>() as u32;
        let mut info = bpf_prog_info::default();
        // SAFETY: info is valid for len bytes, and the kernel writes no further.
        let ret =
            unsafe { bpf_obj_get_info_by_fd(fd.as_raw_fd(), (&raw mut info).cast(), &mut len) };
        if ret == 0 { info.verified_insns } else { 0 }
    }

    // The calls the verifier walked, so what rodata left reachable. Level 2 first lists every
    // insn, dead ones too; the last list has a column that ": (85) call " cannot match.
    fn walked_calls(
        log: &[u8],
        calls: &mut std::collections::BTreeSet<String>,
    ) -> anyhow::Result<()> {
        let log = std::ffi::CStr::from_bytes_until_nul(log)?.to_string_lossy();
        let walk = log
            .rsplit_once("Live regs before insn:\n")
            .map_or(&*log, |(_, walk)| walk);
        for line in walk.lines() {
            let call = line.split_once(": (85) call ").map(|(_, call)| call);
            if let Some((name, _)) = call.and_then(|call| call.split_once('#')) {
                calls.insert(name.to_string());
            }
        }
        Ok(())
    }

    // Load only: synthetic topology exposes paths pruned on the build host.
    // Never attach struct_ops or tracepoints, or execute the synthetic policy.
    // Catches a verifier rejection on a CPU layout we do not own, and a one-word
    // path that still reaches a kfunc needing builtin idle.
    #[test]
    #[ignore = "requires BPF load capabilities and a sched_ext kernel"]
    fn verifier_load_topologies() -> anyhow::Result<()> {
        let mut wide_uneven = uneven_layout();
        wide_uneven.extend((8..72).map(|cpu| vec![cpu]));
        let shapes = [
            LoadShape {
                check_calls: true,
                ..load_shape("this host, 16 at +8, 7 ranks", pairs_at(8, 8), 1, 7)
            },
            LoadShape {
                idle_states: &[],
                ..load_shape("this host, no cpuidle driver", pairs_at(8, 8), 1, 7)
            },
            LoadShape {
                check_calls: true,
                possible: Some(256),
                ..load_shape("16 at +8, 256 possible", pairs_at(8, 8), 1, 7)
            },
            load_shape("this host, SMT off, 7 ranks", singles(8), 1, 7),
            load_shape("8 no SMT, 8 ranks", singles(8), 1, 8),
            load_shape("4 no SMT, 4 ranks", singles(4), 1, 4),
            load_shape("16 no SMT, 2 LLCs, 16 ranks", singles(16), 2, 16),
            load_shape("16 at +8, no ranks", pairs_at(8, 8), 1, 1),
            load_shape("1 CPU", singles(1), 1, 1),
            load_shape("1 core 2 threads", vec![vec![0, 1]], 1, 1),
            load_shape("2 no SMT, no ranks", singles(2), 1, 1),
            load_shape("12 adjacent, 3 ranks", adjacent_pairs(6), 1, 3),
            load_shape("16 adjacent, 2 LLCs, 8 ranks", adjacent_pairs(8), 2, 8),
            load_shape("24 at +12, 2 LLCs, 12 ranks", pairs_at(12, 12), 2, 12),
            LoadShape {
                check_calls: true,
                ..load_shape("32 at +16, 2 LLCs, 16 ranks", pairs_at(16, 16), 2, 16)
            },
            load_shape("48 at +24, 4 LLCs, 24 ranks", pairs_at(24, 24), 4, 24),
            load_shape("64 at +32, 4 LLCs, 32 ranks", pairs_at(32, 32), 4, 32),
            load_shape("64 at +32, 16 LLCs, 32 ranks", pairs_at(32, 32), 16, 32),
            LoadShape {
                possible: Some(1024),
                ..load_shape(
                    "64 at +32, 16 LLCs, 32 ranks, 1024 possible",
                    pairs_at(32, 32),
                    16,
                    32,
                )
            },
            load_shape("64 no SMT, 8 LLCs, no ranks", singles(64), 8, 1),
            LoadShape {
                little_from: Some(8),
                ..load_shape(
                    "32 hybrid, 8 pairs 16 singles",
                    pairs_then_singles(8, 16),
                    1,
                    3,
                )
            },
            LoadShape {
                little_from: Some(4),
                ..load_shape("8 hybrid, no SMT", singles(8), 1, 2)
            },
            load_shape(
                "22 hybrid, 2 LLCs, 4 ranks",
                pairs_then_singles(6, 10),
                2,
                4,
            ),
            load_shape("uneven, no ranks", uneven_layout(), 1, 1),
            load_shape("uneven, 2 LLCs, 3 ranks", uneven_layout(), 2, 3),
            load_shape("4 threads a core, 2 LLCs, 4 ranks", four_threads(4), 2, 4),
            LoadShape {
                check_calls: true,
                ..load_shape("72 at +36, 2 LLCs", pairs_at(36, 36), 2, 1)
            },
            load_shape("72 uneven", wide_uneven, 1, 1),
            load_shape("96 at +48, 4 LLCs", pairs_at(48, 48), 4, 1),
            load_shape("128 at +64, 8 LLCs", pairs_at(64, 64), 8, 1),
            load_shape("1024 at +512", pairs_at(512, 512), 1, 1),
        ];
        verify_shapes(&shapes)
    }

    #[test]
    #[ignore = "requires BPF load capabilities and a sched_ext kernel"]
    fn verifier_load_preferred_die() -> anyhow::Result<()> {
        verify_shapes(&[
            load_shape("two CCDs, 16 ranked SMT pairs", pairs_at(16, 16), 2, 16),
            load_shape("two LLCs, irregular SMT", uneven_layout(), 2, 3),
        ])
    }

    fn verify_shapes(shapes: &[LoadShape]) -> anyhow::Result<()> {
        use super::BpfSkelBuilder;
        use libbpf_rs::AsRawLibbpf;
        use libbpf_rs::libbpf_sys::bpf_program__set_log_buf;
        use libbpf_rs::skel::{OpenSkel, Skel};
        use scx_utils::{scx_ops_load, scx_ops_open};
        use std::mem::MaybeUninit;
        use std::os::fd::AsFd;

        let mut failures = Vec::new();
        for shape in shapes {
            let one_word = shape.cores.iter().flatten().max().unwrap() < &64;
            let mut object = MaybeUninit::uninit();
            let builder = BpfSkelBuilder::default();
            let mut skel = scx_ops_open!(builder, &mut object, cake_ops, None)?;
            fill_shape_rodata(
                skel.maps.rodata_data.as_mut().unwrap(),
                skel.maps.data_cake_ranks_data.as_mut().unwrap(),
                shape,
            )?;
            super::configure_acquire_census(&mut skel, false);
            if one_word {
                skel.struct_ops.cake_ops_mut().flags &=
                    !*scx_utils::compat::SCX_OPS_KEEP_BUILTIN_IDLE;
            }
            if shape.idle_states.is_empty() || !one_word {
                skel.progs.cake_cpu_idle.set_autoload(false);
            }
            let mut logs = Vec::new();
            if shape.check_calls {
                for mut prog in skel.open_object_mut().progs_mut() {
                    let mut log = vec![0u8; VERIFIER_LOG_BYTES];
                    prog.set_log_level(2);
                    // SAFETY: log stays allocated and unmoved through the load below.
                    let ret = unsafe {
                        bpf_program__set_log_buf(
                            prog.as_libbpf_object().as_ptr(),
                            log.as_mut_ptr().cast(),
                            log.len() as u64,
                        )
                    };
                    anyhow::ensure!(ret == 0, "{}: log buffer refused", shape.name);
                    logs.push(log);
                }
            }
            let started = std::time::Instant::now();
            let loaded = match scx_ops_load!(skel, cake_ops, uei) {
                Ok(loaded) => loaded,
                Err(error) => {
                    failures.push(format!("{}: {error:#}", shape.name));
                    continue;
                }
            };
            let largest = loaded
                .object()
                .progs()
                .filter(|prog| prog.autoload())
                .map(|prog| (verified_insns(prog.as_fd()), prog.name().to_owned()))
                .max();
            eprintln!(
                "{}: largest {largest:?} in {:.2} s",
                shape.name,
                started.elapsed().as_secs_f32()
            );
            if !shape.check_calls {
                continue;
            }
            let mut calls = std::collections::BTreeSet::new();
            for log in &logs {
                walked_calls(log, &mut calls)?;
            }
            let reached = |kfunc: &str| calls.iter().any(|call| call.contains(kfunc));
            let builtin: Vec<&str> = BUILTIN_IDLE_KFUNCS
                .into_iter()
                .filter(|kfunc| reached(kfunc))
                .collect();
            if !reached("scx_bpf_kick_cpu") {
                failures.push(format!("{}: no walked calls in the log", shape.name));
            }
            if one_word && !builtin.is_empty() {
                failures.push(format!("{}: one-word path reaches {builtin:?}", shape.name));
            }
            if !one_word && !builtin.contains(&"scx_bpf_test_and_clear_cpu_idle") {
                failures.push(format!("{}: the wide claim was not walked", shape.name));
            }
        }
        anyhow::ensure!(failures.is_empty(), "{}", failures.join("\n"));
        Ok(())
    }

    #[test]
    fn irq_publication_preserves_sparse_wide_cpu_ids_and_clears_old_bits() {
        let mut set = vec![false; 257];
        for cpu in [0, 63, 64, 127, 128, 255, 256] {
            set[cpu] = true;
        }
        assert_eq!(
            sink_words::<4>(&set),
            [1 | (1 << 63), 1 | (1 << 63), 1, 1 << 63]
        );
        assert_eq!(sink_words::<4>(&[false; 1]), [0; 4]);
        assert_eq!(sink_words::<4>(&[]), [0; 4]);
    }

    #[test]
    fn unknown_irq_windows_break_streaks_without_inventing_quiet() {
        let mut monitor = SinkMonitor::new(8);
        monitor.published[0] = true;
        monitor.hot_streak[1] = 1;
        monitor.quiet[0] = 2;
        monitor.stable = 7;
        monitor.interval = SinkMonitor::INTERVAL_MAX;
        assert_eq!(monitor.observe(None), None);
        assert!(monitor.published[0]);
        assert_eq!(monitor.hot_streak, vec![0; 8]);
        assert_eq!(monitor.quiet, vec![0; 8]);
        assert_eq!((monitor.stable, monitor.interval), (0, 1));
        assert_eq!(monitor.observe(Some(vec![Some(0); 8])), None);
        // Half-machine split is untrusted, not a second confirming sample.
        monitor.hot_streak[1] = 1;
        assert_eq!(
            monitor.observe(Some(vec![
                Some(100),
                Some(100),
                Some(100),
                Some(100),
                Some(0),
                Some(0),
                Some(0),
                Some(0)
            ])),
            None
        );
        assert_eq!(monitor.hot_streak, vec![0; 8]);
        assert!(monitor.published[0]);
    }

    #[test]
    fn irq_counter_reset_and_missing_cpu_are_unknown_not_zero_load() {
        assert_eq!(
            sink_deltas(&[Some(2), Some(5)], &[Some(10), Some(3)]),
            (vec![1], vec![2])
        );
        let mut monitor = SinkMonitor::new(8);
        monitor.observe(Some(vec![Some(100); 8]));
        monitor.published[0] = true;
        monitor.quiet[0] = 2;
        let mut next = vec![Some(101); 8];
        next[0] = None;
        monitor.observe(Some(next));
        assert!(monitor.published[0]);
        assert_eq!(monitor.quiet[0], 0);
    }

    #[test]
    fn irq_rank_disagreement_resets_the_slowed_interval_before_publication() {
        let mut monitor = SinkMonitor::new(8);
        monitor.observe(Some(vec![Some(0); 8]));
        monitor.published[0] = true;
        monitor.stable = SinkMonitor::STABLE_POLLS - 1;
        monitor.interval = SinkMonitor::INTERVAL_MAX;
        // CPU 1 now carries the load: one window is not yet a publication
        // (FLAG_POLLS), but the confirmation must come at tick rate.
        let mut next = vec![Some(1); 8];
        next[1] = Some(1000);
        assert_eq!(monitor.observe(Some(next)), None);
        assert_eq!((monitor.stable, monitor.interval), (0, 1));
        assert!(monitor.published[0]);
        assert!(!monitor.published[1]);
        // An agreeing window keeps the slow-down bookkeeping.
        monitor.published = vec![false; 8];
        monitor.published[1] = true;
        monitor.hot_streak.fill(0);
        let mut next = vec![Some(2); 8];
        next[1] = Some(2000);
        assert_eq!(monitor.observe(Some(next)), None);
        assert_eq!((monitor.stable, monitor.interval), (1, 1));
    }
    use std::{cell::RefCell, rc::Rc};

    #[test]
    fn irq_pair_orders_attach_teardown_and_cleans_partial_failures() {
        struct Link(&'static str, Rc<RefCell<Vec<&'static str>>>);
        impl Drop for Link {
            fn drop(&mut self) {
                self.1.borrow_mut().push(self.0);
            }
        }
        for fail in [None, Some("leave"), Some("enter")] {
            let events = Rc::new(RefCell::new(Vec::new()));
            let pair = attach_irq_pair(
                || {
                    events.borrow_mut().push("attach leave");
                    anyhow::ensure!(fail != Some("leave"), "injected");
                    Ok(Link("drop leave", events.clone()))
                },
                || {
                    events.borrow_mut().push("attach enter");
                    anyhow::ensure!(fail != Some("enter"), "injected");
                    Ok(Link("drop enter", events.clone()))
                },
            );
            assert_eq!(pair.is_ok(), fail.is_none());
            drop(pair);
            let expected = match fail {
                None => vec!["attach leave", "attach enter", "drop enter", "drop leave"],
                Some("leave") => vec!["attach leave"],
                _ => vec!["attach leave", "attach enter", "drop leave"],
            };
            assert_eq!(*events.borrow(), expected);
        }
    }

    #[test]
    fn llc_identity_survives_wide_pool_collapse_and_sparse_llc_ids() {
        let cpus: Vec<_> = (0..128).map(|c| (c, 1000 + (c % 64) / 4)).collect();
        let l = LlcLayout::build(&cpus, 1);
        assert_eq!(l.nr_llcs, 1);
        assert_ne!(l.domain[&cpus[0].1], l.domain[&cpus[80].1]);
        assert_eq!(l.domain[&cpus[0].1], l.domain[&cpus[64].1]);
        assert!(l.dense.values().all(|d| *d == 0));
    }

    #[test]
    fn cpulist_last_id() {
        assert_eq!(last_cpu_id("0-15\n"), Some(15));
        assert_eq!(last_cpu_id("0-3,8-11"), Some(11));
        assert_eq!(last_cpu_id("0"), Some(0));
        assert_eq!(last_cpu_id(""), None);
    }

    fn grid(nr_cpus: usize, per_llc: usize) -> Vec<(usize, usize)> {
        (0..nr_cpus).map(|c| (c, c / per_llc)).collect()
    }

    #[test]
    fn offline_possible_ids_are_not_ranked() {
        // Eight online CPUs at equal handler time and 56 possible-but-
        // offline ids: ranked as zeros they would make every online CPU a
        // sink. Absent ids leave the ranking instead.
        let before: Vec<Option<u64>> = (0..64).map(|c| (c < 8).then_some(100)).collect();
        let current: Vec<Option<u64>> = (0..64).map(|c| (c < 8).then_some(103)).collect();
        let (present, deltas) = sink_deltas(&current, &before);
        assert_eq!(present, (0..8).collect::<Vec<_>>());
        assert_eq!(deltas, vec![3; 8]);
        assert_eq!(sinks_by_widest_gap(&deltas).unwrap(), vec![false; 8]);
    }

    #[test]
    fn llc_layout_counts_domains_above_cpu_63() {
        // 128 CPUs in 16 LLCs of 8: every LLC is a pool, and a CPU above
        // 63 lands in its own LLC's pool, not pool 0.
        let l = LlcLayout::build(&grid(128, 8), 16);
        assert_eq!(l.nr_llcs, 16);
        assert!(l.collapsed.is_none());
        assert_eq!(l.dense[&9], 9);
        assert_eq!(l.word[&0], 0xff);
        assert_eq!(l.word[&7], 0xff << 56);
        // No CPU of LLC 9 fits a word: LLC-blind for the census paths.
        assert_eq!(l.word[&9], u64::MAX);
    }

    #[test]
    fn llc_layout_dual_ccd() {
        let l = LlcLayout::build(&grid(32, 16), 16);
        assert_eq!(l.nr_llcs, 2);
        assert_eq!(l.dense[&0], 0);
        assert_eq!(l.dense[&1], 1);
        assert_eq!(l.word[&1], 0xffff << 16);
    }

    #[test]
    fn llc_layout_collapses_past_max_llcs() {
        let l = LlcLayout::build(&grid(256, 4), 16);
        assert_eq!(l.collapsed, Some(64));
        assert_eq!(l.nr_llcs, 1);
        assert!(l.dense.values().all(|d| *d == 0));
        assert_eq!(l.domain[&0], 0);
        assert_eq!(l.domain[&63], 63);
    }

    #[test]
    fn llc_layout_one_llc_and_sparse_ids() {
        let l = LlcLayout::build(&[(0, 3), (2, 3), (70, 3)], 16);
        assert_eq!(l.nr_llcs, 1);
        assert_eq!(l.dense[&3], 0);
        assert_eq!(l.word[&3], 0b101);
    }

    fn flagged(hot: &[bool]) -> Vec<usize> {
        hot.iter()
            .enumerate()
            .filter_map(|(cpu, h)| h.then_some(cpu))
            .collect()
    }

    #[test]
    fn bimodal_host_cuts_above_the_gap() {
        // The development host under load: nvidia on 13, network on 5,
        // everything else at or under one tick.
        let deltas = [0, 1, 0, 0, 0, 20, 0, 1, 0, 0, 0, 0, 0, 32, 0, 0];
        let hot = sinks_by_widest_gap(&deltas).unwrap();
        assert_eq!(flagged(&hot), vec![5, 13]);
    }

    #[test]
    fn flat_distribution_has_no_sinks() {
        assert_eq!(sinks_by_widest_gap(&[3; 16]).unwrap(), vec![false; 16]);
        assert_eq!(sinks_by_widest_gap(&[0; 16]).unwrap(), vec![false; 16]);
    }

    #[test]
    fn half_machine_cut_is_untrusted() {
        // Eight equally-loud CPUs is host-wide load, not pinned affinity.
        let deltas = [50, 50, 50, 50, 50, 50, 50, 50, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(sinks_by_widest_gap(&deltas).is_none());
    }

    #[test]
    fn lone_loud_cpu_separates_from_quiet_machine() {
        let mut deltas = [0u64; 16];
        deltas[13] = 4;
        let hot = sinks_by_widest_gap(&deltas).unwrap();
        assert_eq!(flagged(&hot), vec![13]);
    }

    /// The banner must not say native below the release where compat calls the kfunc.
    #[test]
    fn release_version_reads_major_and_minor() {
        assert_eq!(super::release_version("7.3.1-1-cachyos\n"), (7, 3));
        assert!(super::release_version("7.0.12") < (7, 1));
        assert!(super::release_version("6.19-rc1") < (7, 1));
        assert_eq!(super::release_version(""), (0, 0));
    }
}
