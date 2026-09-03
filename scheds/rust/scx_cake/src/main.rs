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

use std::collections::BTreeMap;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::OpenObject;
use log::info;
use log::warn;
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
use scx_utils::NR_CPU_IDS;

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
    /// Enable verbose libbpf output and runtime diagnostics. A release run
    /// without this prints only identity, attach and exit.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print the version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Campaign toggle `NAME=0|1` (g43, g44, g45, g46), repeatable. One
    /// binary serves both arms of an on/off pair: the verifier deletes the
    /// off arm at attach. Scaffolding for the 2026-08-22 toggle campaign
    /// (STATE.md); defaults are tip behavior. Unknown names refuse to start.
    #[clap(long = "toggle", value_name = "NAME=0|1")]
    toggle: Vec<String>,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    /// Handler-edge tracepoint links (§G35); dropped on exit with the rest.
    _irq_links: Vec<libbpf_rs::Link>,
    /// Diagnostics on (--toggle probe=1): census, hold attribution, black box.
    probe_on: bool,
    /// Frame-clock incumbent bucket, held against near-ties (§R.22).
    frame_bucket: Option<u32>,
    /// Last published period; the reference for slow-direction hysteresis.
    frame_period: u64,
    /// Consecutive polls a slower candidate has won; slow switches need
    /// agreement, fast ones are instant (§G27.1).
    slow_polls: u32,
    /// Pessimistic frame estimate: fast down, slow up. Feeds the slice cap,
    /// which must not widen when the mode wobbles (§G18).
    frame_floor: u64,
    /// Print runtime diagnostics. Off by default: a release run is not a
    /// measurement session, and a scheduler logging into a game is noise.
    verbose: bool,
    /// Live IRQ-sink tracking state (§G30, §G33).
    sinks: SinkMonitor,
    /// The first live sink set completes the startup banner at INFO; later
    /// changes are diagnostics and follow --verbose.
    sinks_logged: bool,
}

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
            // cake calls scx_bpf_dsq_peek() unconditionally -- the
            // __COMPAT_ iterator arm was deleted with the other compat
            // ladders. On a kernel without the ksym the load fails
            // outright, so "MISSING" is the honest word, not "fallback".
            if dsq_peek { "native" } else { "MISSING" },
        );

        // Open the BPF program.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let mut skel = scx_ops_open!(skel_builder, open_object, cake_ops, None)?;

        // Linux CPU numbering does not guarantee that an SMT sibling is
        // cpu +/- nr_cpus/2. Populate the immutable BPF lookup from sysfs
        // topology and cycle within wider-than-SMT2 cores. The fallback path
        // treats -1 as "no online sibling" and uses the kernel idle picker.
        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("BPF rodata unavailable for CPU topology")?;

        // The CPU id span the steal ring and neighbour probe scan. It is a
        // load-time constant, so it goes in rodata (frozen before load, hence
        // folded by the verifier) instead of being written into mutable BPF
        // state from ops.init. `ops.init` refuses to attach if this is
        // narrower than the kernel's own nr_cpu_ids.
        anyhow::ensure!(
            *NR_CPU_IDS <= bpf_intf::consts_MAX_CPUS as usize,
            "host nr_cpu_ids {} exceeds Cake's compiled MAX_CPUS {}",
            *NR_CPU_IDS,
            bpf_intf::consts_MAX_CPUS
        );
        rodata.nr_cpu_span = *NR_CPU_IDS as u32;
        rodata.cake_span_mask = (*NR_CPU_IDS as u32).next_power_of_two() - 1;

        // Campaign toggles land in rodata before load so the verifier prunes
        // the off arms; the logged line is each arm's identity in an on/off
        // pair (STATE.md, toggle campaign 2026-08-22).
        for spec in &opts.toggle {
            let (name, val) = spec
                .split_once('=')
                .with_context(|| format!("--toggle {spec}: expected NAME=0|1"))?;
            let on = match val {
                "0" => 0u8,
                "1" => 1u8,
                _ => anyhow::bail!("--toggle {spec}: value must be 0 or 1"),
            };
            match name {
                "g39b" => rodata.cake_tog_g39b = on,
                "g46" => rodata.cake_tog_g46 = on,
                "m6" => rodata.cake_tog_m6 = on,
                "g51" => rodata.cake_tog_g51 = on,
                "g52" => rodata.cake_tog_g52 = on,
                "g56" => rodata.cake_tog_g56 = on,
                "g57" => rodata.cake_tog_g57 = on,
                "g58" => rodata.cake_tog_g58 = on,
                "g59" => rodata.cake_tog_g59 = on,
                "g60" => rodata.cake_tog_g60 = on,
                "g61" => rodata.cake_tog_g61 = on,
                "g62" => rodata.cake_tog_g62 = on,
                "g63" => rodata.cake_tog_g63 = on,
                "g64" => rodata.cake_tog_g64 = on,
                "g65" => rodata.cake_tog_g65 = on,
                "g66" => rodata.cake_tog_g66 = on,
                "g67" => rodata.cake_tog_g67 = on,
                "g68" => rodata.cake_tog_g68 = on,
                "g69" => rodata.cake_tog_g69 = on,
                "g70" => rodata.cake_tog_g70 = on,
                "g72" => rodata.cake_tog_g72 = on,
                "g71" => rodata.cake_tog_g71 = on,
                "g73" => rodata.cake_tog_g73 = on,
                "g74" => rodata.cake_tog_g74 = on,
                "g75" => rodata.cake_tog_g75 = on,
                "g77" => rodata.cake_tog_g77 = on,
                "g78" => rodata.cake_tog_g78 = on,
                "g79" => rodata.cake_tog_g79 = on,
                "g81" => rodata.cake_tog_g81 = on,
                "m7" => rodata.cake_tog_m7 = on,
                "probe" => rodata.cake_tog_probe = on,
                _ => anyhow::bail!("--toggle {spec}: unknown name {name}"),
            }
        }
        // §G59 reads the §G51 mirror, so it forces the producer on.
        if rodata.cake_tog_g68 == 1 || rodata.cake_tog_g70 == 1 {
            // EXPERIMENT §G68: the VIP process is found by comm prefix at attach.
            let mut vip = 0u32;
            if let Ok(rd) = std::fs::read_dir("/proc") {
                for e in rd.flatten() {
                    if let Ok(comm) = std::fs::read_to_string(e.path().join("comm")) {
                        if comm.starts_with("FPSAimTrainer") {
                            if let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() {
                                vip = pid;
                                break;
                            }
                        }
                    }
                }
            }
            rodata.cake_vip_tgid = vip;
            info!("   g68     VIP process tgid {vip} (0 = not found, VIP inert)");
        }
        if rodata.cake_tog_g59 == 1 {
            rodata.cake_tog_g51 = 1;
        }
        let probe_on = rodata.cake_tog_probe == 1;
        info!(
            "   toggle  g39b={} g46={} g51={} g52={} g56={} g57={} g58={} g59={} g60={} g61={} g62={} g63={} g64={} g65={} g66={} g67={} g68={} g69={} g70={} g72={} g71={} g73={} g74={} g75={} g77={} g78={} g79={} g81={} m6={} m7={}",
            rodata.cake_tog_g39b,
            rodata.cake_tog_g46,
            rodata.cake_tog_g51,
            rodata.cake_tog_g52,
            rodata.cake_tog_g56,
            rodata.cake_tog_g57,
            rodata.cake_tog_g58,
            rodata.cake_tog_g59,
            rodata.cake_tog_g60,
            rodata.cake_tog_g61,
            rodata.cake_tog_g62,
            rodata.cake_tog_g63,
            rodata.cake_tog_g64,
            rodata.cake_tog_g65,
            rodata.cake_tog_g66,
            rodata.cake_tog_g67,
            rodata.cake_tog_g68,
            rodata.cake_tog_g69,
            rodata.cake_tog_g70,
            rodata.cake_tog_g72,
            rodata.cake_tog_g71,
            rodata.cake_tog_g73,
            rodata.cake_tog_g74,
            rodata.cake_tog_g75,
            rodata.cake_tog_g77,
            rodata.cake_tog_g78,
            rodata.cake_tog_g79,
            rodata.cake_tog_g81,
            rodata.cake_tog_m6,
            rodata.cake_tog_m7
        );

        // §G51: cpuidle exit-latency table from sysfs; absent driver leaves
        // zeros and the depth model inert. §G52: CPPC highest_perf per CPU.
        let mut deepest_us = 0u32;
        for i in 0..bpf_intf::consts_CAKE_CSTATE_TABLE as usize {
            let path = format!("/sys/devices/system/cpu/cpu0/cpuidle/state{i}/latency");
            if let Ok(s) = std::fs::read_to_string(&path) {
                let us: u32 = s.trim().parse().unwrap_or(0);
                rodata.cake_cstate_exit_us[i] = us;
                deepest_us = deepest_us.max(us);
            }
        }
        if rodata.cake_tog_g51 == 1 && deepest_us == 0 {
            info!("   g51     no cpuidle driver: depth model inert");
        }
        // §G58: the lead covers the deepest exit twice over; a host without
        // a cpuidle table gets the fixed default. Never a refusal.
        rodata.cake_prewake_lead_ns = if deepest_us > 0 {
            u64::from(deepest_us) * 2 * 1000
        } else {
            bpf_intf::consts_PREWAKE_LEAD_DEFAULT_NS as u64
        };
        if rodata.cake_tog_g58 == 1 {
            info!(
                "   g58     pre-wake lead {} us ({})",
                rodata.cake_prewake_lead_ns / 1000,
                if deepest_us > 0 {
                    "2x deepest exit"
                } else {
                    "default, no cpuidle"
                }
            );
        }
        if rodata.cake_tog_g59 == 1 && deepest_us == 0 {
            info!("   g59     no cpuidle table: depth pick is first fit");
        }
        let mut perf_seen = false;
        for c in 0..*NR_CPU_IDS {
            let path = format!("/sys/devices/system/cpu/cpu{c}/acpi_cppc/highest_perf");
            if let Ok(s) = std::fs::read_to_string(&path) {
                let v: u64 = s.trim().parse().unwrap_or(0);
                rodata.cpu_perf_rank[c] = v.min(255) as u8;
                perf_seen = perf_seen || v != 0;
            }
        }
        if rodata.cake_tog_g52 == 1 && !perf_seen {
            info!("   g52     no CPPC highest_perf: rank tiebreak inert");
        }

        // §G56 FOLD tables, from RUNTIME topology — never the build host.
        // cpu -> compact LLC index, per-LLC qmask word (narrow hosts), and
        // the per-home band order: own LLC first, then foreign LLCs by
        // descending CPPC rank when g52 is live, id order otherwise. More
        // LLCs than the table degrades the fold off (bands stay id-order,
        // the toggle gate's span check keeps the walk), never a refusal.
        let nr_llcs = topo.all_llcs.len().min(bpf_intf::consts_MAX_LLCS as usize);
        let mut llc_rank = [0u8; bpf_intf::consts_MAX_LLCS as usize];
        for (idx, llc) in topo.all_llcs.values().take(nr_llcs).enumerate() {
            let mut word = 0u64;
            for cpu in llc.all_cpus.keys().copied() {
                if cpu < rodata.cake_cpu_llc.len() {
                    rodata.cake_cpu_llc[cpu] = idx as u8;
                }
                if cpu < 64 {
                    word |= 1u64 << cpu;
                }
                if cpu < *NR_CPU_IDS {
                    llc_rank[idx] = llc_rank[idx].max(rodata.cpu_perf_rank[cpu]);
                }
            }
            rodata.cake_llc_qword[idx] = word;
        }
        rodata.cake_nr_llcs = nr_llcs.max(1) as u32;
        for home in 0..nr_llcs {
            let mut foreign: Vec<usize> = (0..nr_llcs).filter(|&l| l != home).collect();
            if rodata.cake_tog_g52 == 1 {
                foreign.sort_by_key(|&l| std::cmp::Reverse(llc_rank[l]));
            }
            rodata.cake_llc_order[home][0] = home as u8;
            for (b, l) in foreign.iter().enumerate() {
                rodata.cake_llc_order[home][b + 1] = *l as u8;
            }
        }
        if rodata.cake_tog_g56 == 1 {
            info!(
                "   g56     banded steal: {nr_llcs} LLC band(s), order {}",
                if rodata.cake_tog_g52 == 1 {
                    "rank"
                } else {
                    "id"
                }
            );
        }

        // Hardware-anchored thresholds: measured, never derived from the slice.
        // Clamped so a probe perturbed by host load cannot mis-tune the
        // scheduler, and logged so the value used is always on the record.
        match probe_handoff_hop_ns() {
            Some(probe) => {
                // The admission threshold IS the tail of a genuine handoff --
                // used directly, never a mean times an invented multiplier.
                // DIAGNOSTIC ONLY -- deliberately does not drive policy yet.
                //
                // Measured 2026-07-30: driving cake_handoff_max_ns from this
                // probe cost mutex-handoff -35.66% (CI[-40.01,-31.31]) with
                // migrations 2.4-2.7x up, at both `2 * mean` (1240ns) and, by
                // inspection, `p99` (798ns). The known-good threshold is
                // 1464ns = 2.34x this probe's median.
                //
                // The probe is not wrong about the hardware -- its 625ns
                // median cross-validates the independent 606ns rdtscp floor
                // to 3%. It is measuring the wrong DISTRIBUTION: a clean
                // condvar ping-pong on an idle host, where p99 sits just
                // 1.28x the median, while real handoffs under contention
                // carry lock acquisition and cache misses and run far wider.
                // That is a workload property, and no startup probe can see
                // it. Making this threshold host-adaptive needs runtime
                // observation of `used` in ops.stopping, not a boot-time
                // measurement -- same machinery as G9.7.
                let (med, p99) = (probe.median, probe.p99);
                let hm = rodata.cake_handoff_max_ns;
                // The probe's p99 IS the pick-to-landing horizon the tick
                // predictor needs (§G36): how long this host takes to land a
                // wake. Zero (probe failed) leaves the predictor off.
                rodata.cake_wake_hop_ns = p99;
                if opts.verbose {
                    info!("   class   starvation = mean wait > mean burst (no threshold)");
                    info!(
                        "   probe   hop median {med}ns p99 {p99}ns (diagnostic) · handoff_max {hm}ns"
                    );
                }
            }
            None => {
                if opts.verbose {
                    log::warn!("   probe   handoff probe failed (diagnostic only)");
                }
            }
        }

        // Interrupt sinks are measured, never guessed — and measured LIVE:
        // per-CPU handler-time share off the run loop, cut at the
        // distribution's own widest gap (§G30, §G33, §R.26). Nothing is
        // sampled at attach — an attach-time window measures whatever the
        // machine happened to be doing during launch (§G30's observer
        // effect) — so the scheduler starts sink-free and announces the
        // first honest set seconds later.
        info!("   irq     interrupt sinks tracked live by handler-time share");

        let siblings = &mut rodata.cpu_sibling;
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

        // Bootstrap each frame word in its SAFE direction. The clock starts
        // slow so occupant protection is never divided into a zero; the FLOOR
        // starts at the display-class fast end (2 ms, NOT the engine-band min:
        // a vote-free host would keep a 250 µs slice cap forever) so the cap
        // begins tight and relaxes only as evidence arrives (§G18, §G19).
        // Geometry starts at the fixed slice; only votes move it (§G27).
        if let Some(bss) = skel.maps.bss_data.as_mut() {
            bss.cake_frame_ns = bpf_intf::consts_FRAME_PERIOD_MAX_NS as u64;
            bss.cake_frame_floor_ns = bpf_intf::consts_FRAME_FLOOR_BOOT_NS as u64;
            bss.cake_frame_slice_ns = bpf_intf::consts_SLICE_NS as u64;
        }

        // Multi-CCD steal order is a runtime decision, never a build-host
        // property: one binary must attach on any topology. Hosts wider than
        // the fixed matrix span keep the generic ring walk.
        {
            let rodata = skel
                .maps
                .rodata_data
                .as_mut()
                .context("BPF rodata unavailable for cache topology")?;
            let order = &mut rodata.cpu_steal_order;
            let span = bpf_intf::consts_STEAL_SPAN as usize;
            let fits = topo
                .all_cpus
                .keys()
                .next_back()
                .is_none_or(|cpu| *cpu < span);
            let multi_ccd = topo.all_llcs.len() > 1;
            rodata.steal_order_live = u8::from(multi_ccd && fits);
            order.fill(0);

            if multi_ccd && !fits {
                warn!("   ccd     host wider than steal matrix ({span} CPUs); ring steal only");
            }
            if multi_ccd && fits {
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
                let nr_ids = *NR_CPU_IDS;

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
                        (class, (dst.id + nr_ids - src.id) % nr_ids)
                    });
                    let base = src.id * span;
                    for (slot, dst) in candidates.into_iter().enumerate() {
                        order[base + slot] = dst.id as u16;
                    }
                }
            }
        }

        // Load and attach.
        // §G76: the cpuidle mirror tracepoint fires on every idle transition
        // (2.7M/12 s on a polling-idle host); it is loaded only for its consumers.
        let want_cpu_idle = skel
            .maps
            .rodata_data
            .as_ref()
            .map(|r| r.cake_tog_g51 == 1)
            .unwrap_or(false);
        skel.progs.cake_cpu_idle.set_autoload(want_cpu_idle);
        let mut skel = scx_ops_load!(skel, cake_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, cake_ops)?);

        // Handler-edge tracepoints feed the in-handler word (§G35). A failed
        // attach degrades to chronic-only steering, never blocks the
        // scheduler; the word simply stays zero.
        let mut irq_links = Vec::with_capacity(4);
        for (name, res) in [
            ("irq_enter", skel.progs.cake_irq_enter.attach()),
            ("irq_leave", skel.progs.cake_irq_leave.attach()),
            ("softirq_enter", skel.progs.cake_softirq_enter.attach()),
            ("softirq_leave", skel.progs.cake_softirq_leave.attach()),
        ] {
            match res {
                Ok(link) => irq_links.push(link),
                Err(e) => warn!("   irq     {name} hook failed ({e}); chronic steering only"),
            }
        }
        if want_cpu_idle {
            match skel.progs.cake_cpu_idle.attach() {
                Ok(link) => irq_links.push(link),
                Err(e) => warn!("   g51     cpu_idle hook failed ({e}); depth mirror off"),
            }
        }

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
            _irq_links: irq_links,
            probe_on,
            frame_bucket: None,
            frame_period: 0,
            slow_polls: 0,
            frame_floor: 0,
            verbose: opts.verbose,
            sinks: SinkMonitor::new(*NR_CPU_IDS),
            sinks_logged: false,
        })
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        // Frame clock, reported under --verbose on a material change only, so
        // a moving line there means the observed cadence really moved (§G11).
        let mut shown: u64 = 0;
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            std::thread::sleep(Duration::from_secs(1));

            if let Some(set) = self.sinks.tick(*NR_CPU_IDS) {
                self.publish_sinks(&set);
            }

            let observed = self.publish_frame_clock();
            if self.verbose && observed != 0 && observed.abs_diff(shown) > shown / 16 {
                shown = observed;
                info!(
                    "   frame   observed period {}us ({:.1} Hz)",
                    observed / 1000,
                    1e9 / observed as f64
                );
            }
        }

        // Diagnostics (--toggle probe=1): black box of placements that waited > 10 ms, then the census.
        if let (true, Some(bss)) = (self.probe_on, self.skel.maps.bss_data.as_ref()) {
            let n = bss.cake_blackbox_n;
            for i in 0..n.min(4) {
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
                    "   BLACKBOX wait {:.2} ms  {} pid {} kind {} target cpu{} caller cpu{} waker {} ran_on cpu{}  seats {:#018x} core_free {:#018x} thread_free {:#018x} idle {:#018x}",
                    b.wait_ns as f64 / 1e6, comm, b.pid, b.kind, b.target, b.caller, b.waker_pid, b.ran_on, b.seats, b.core_free, b.thread_free, b.idle_word
                );
            }
        }
        if self.probe_on {
            const NAMES: [&str; 47] = [
                "select_calls",
                "serial",
                "home_warm",
                "park_reached",
                "park_prev",
                "park_mbox",
                "opt_reached",
                "opt_hit",
                "ranked",
                "wp_attempt",
                "wp_tiny",
                "wp_small",
                "wp_protect",
                "wp_vtime",
                "wp_starved",
                "wp_fired",
                "free_pick",
                "prewake_fire",
                "reserved_take",
                "pl_local",
                "pl_local_on",
                "pl_cpuq_wake",
                "pl_cpuq_cont",
                "pl_global",
                "h300_local",
                "h300_local_on",
                "h300_cpuq_wake",
                "h300_cpuq_cont",
                "h300_global",
                "h1ms_local",
                "h1ms_local_on",
                "h1ms_cpuq_wake",
                "h1ms_cpuq_cont",
                "h1ms_global",
                "pl_self",
                "h300_self",
                "h1ms_self",
                "hd_skip",
                "hd_sync",
                "hd_starved",
                "hd_irq",
                "hd_aff",
                "hd_contended",
                "hd_notidle",
                "home_busy",
                "home_localq",
                "h300_home_busy",
            ];
            let mut tot = [0u64; NAMES.len()];
            for (i, t) in tot.iter_mut().enumerate() {
                let key = (i as u32).to_ne_bytes();
                if let Ok(Some(percpu)) =
                    self.skel.maps.cake_stats.lookup_percpu(&key, MapFlags::ANY)
                {
                    for cpu in &percpu {
                        if cpu.len() >= 8 {
                            *t += u64::from_ne_bytes(cpu[..8].try_into().unwrap());
                        }
                    }
                }
            }
            let sel = tot[0].max(1) as f64;
            for (i, name) in NAMES.iter().enumerate() {
                info!(
                    "   arms    {name:<13} {:>12}  {:>6.2}% of select",
                    tot[i],
                    tot[i] as f64 * 100.0 / sel
                );
            }
        }

        if let Some(bss) = self.skel.maps.bss_data.as_mut() {
            let ev = &bss.cake_events;
            info!(
                "   events  select_fallback {} keep_last {} enq_skip_exiting {}",
                ev.SCX_EV_SELECT_CPU_FALLBACK,
                ev.SCX_EV_DISPATCH_KEEP_LAST,
                ev.SCX_EV_ENQ_SKIP_EXITING
            );
        }

        self.struct_ops.take();
        info!("🍰 {SCHEDULER_NAME} detached — default scheduler restored");
        uei_report!(&self.skel, uei)
    }

    /// Push a changed sink set live: rewrite the per-CPU flags, then bump
    /// the generation so the next ranked pick rebuilds the nonsink mask
    /// (§G30). Flags settle before the bump; a torn read costs at most one
    /// extra rebuild.
    fn publish_sinks(&mut self, set: &[bool]) {
        let Some(bss) = self.skel.maps.bss_data.as_mut() else {
            return;
        };
        for (cpu, hot) in set.iter().enumerate() {
            if cpu < bss.cpu_irq_hot.len() {
                bss.cpu_irq_hot[cpu] = u8::from(*hot);
            }
        }
        bss.cake_sink_gen = bss.cake_sink_gen.wrapping_add(1);

        if self.verbose || !self.sinks_logged {
            self.sinks_logged = true;
            let named: Vec<usize> = set
                .iter()
                .enumerate()
                .filter_map(|(cpu, hot)| hot.then_some(cpu))
                .collect();
            info!("   irq     interrupt-sink CPUs {named:?} — steered around");
        }
    }

    /// Publish the binding cadence from the vote histogram.
    ///
    /// Every crowd near the biggest is a REAL cadence (a game plus the
    /// desktop coexist legitimately), so no argmax: the FASTEST real crowd
    /// is published, because every consumer of the clock is a bound and the
    /// fastest cadence is the one that binds. The clock moves faster the
    /// moment a faster crowd qualifies; it moves slower only when the fast
    /// crowd actually fades — one noisy poll cannot drag it slower (§G27.1).
    /// Buckets are cleared as read; sum/count keeps the value exact.
    /// Returns the published period, 0 when there are no votes.
    fn publish_frame_clock(&mut self) -> u64 {
        const WIDTH: usize = std::mem::size_of::<u64>() * 2;
        /// A crowd within 2x of the biggest is real, not noise.
        const QUALIFY: u64 = 2;
        /// The incumbent stays alive down to a quarter of the biggest crowd.
        const FADE: u64 = 4;

        let hist = &self.skel.maps.cake_frame_hist;
        let mut crowds: Vec<(u32, u64, u64)> = Vec::new();

        for idx in 0..bpf_intf::consts_FRAME_BUCKETS {
            let key = idx.to_ne_bytes();
            let Ok(Some(percpu)) = hist.lookup_percpu(&key, MapFlags::ANY) else {
                continue;
            };
            let (mut count, mut sum) = (0u64, 0u64);
            for cpu in &percpu {
                if cpu.len() < WIDTH {
                    continue;
                }
                count += u64::from_ne_bytes(cpu[..8].try_into().unwrap());
                sum += u64::from_ne_bytes(cpu[8..16].try_into().unwrap());
            }
            if count == 0 {
                continue;
            }
            crowds.push((idx, count, sum));
            let zeroed = vec![vec![0u8; WIDTH]; percpu.len()];
            let _ = hist.update_percpu(&key, &zeroed, MapFlags::ANY);
        }

        let Some(max_count) = crowds.iter().map(|c| c.1).max() else {
            return 0;
        };
        // Fastest qualified crowd; bucket index is monotone in period.
        let Some((qi, qc, qs)) = crowds
            .iter()
            .copied()
            .filter(|c| c.1 * QUALIFY >= max_count)
            .min_by_key(|c| c.0)
        else {
            return 0;
        };

        let held = self
            .frame_bucket
            .and_then(|hb| crowds.iter().copied().find(|c| c.0 == hb));
        let (bucket, count, sum) = match held {
            // The incumbent holds only while at least as fast as the
            // challenger AND still alive; a faster challenger wins at once.
            Some((hi, hc, hs)) if hi <= qi && hc * FADE >= max_count => (hi, hc, hs),
            _ => (qi, qc, qs),
        };
        let cand = sum / count;

        // Fast up, slow down: a faster cadence binds immediately, a slower
        // one must win SLOW_POLLS in a row — an app's own threads form
        // several fast crowds whose per-second counts wobble, and a one-poll
        // silence must not publish a slow blip (§G27.1; live 2026-08-17).
        const SLOW_POLLS: u32 = 3;
        let (period, bucket) = if self.frame_period == 0 || cand <= self.frame_period {
            self.slow_polls = 0;
            (cand, Some(bucket))
        } else {
            self.slow_polls += 1;
            if self.slow_polls >= SLOW_POLLS {
                self.slow_polls = 0;
                (cand, Some(bucket))
            } else {
                (self.frame_period, self.frame_bucket)
            }
        };
        self.frame_period = period;

        // A bound takes the pessimistic side of a noisy estimate: drop to a new
        // low at once, climb back over ~16 polls. One 17372us excursion off a
        // true 3621us previously doubled the slice cap (§G18).
        self.frame_floor = match self.frame_floor {
            0 => period,
            f if period < f => period,
            f => f + (period - f) / 16,
        };
        self.frame_bucket = bucket;
        if let Some(bss) = self.skel.maps.bss_data.as_mut() {
            bss.cake_frame_ns = period;
            bss.cake_frame_floor_ns = self.frame_floor;
            // Diagnostic only: feeds the --verbose clock line; no policy
            // consumes these — geometry is per task (§R.28).
            bss.cake_frame_slice_ns = ((self.frame_floor >> 1) + (self.frame_floor >> 2))
                .min(bpf_intf::consts_SLICE_NS as u64);
        }
        period
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
/// One host's wake+block+switch hop, as a distribution rather than a mean.
struct HandoffProbe {
    /// Typical hop — the switch-cost anchor for the preempt-protect window.
    median: u64,
    /// Tail of a GENUINE handoff. This is the admission threshold itself, not
    /// a base to multiply: measured 2026-07-30, using `2 * mean` instead cost
    /// mutex-handoff -35.66% (CI[-40.01,-31.31]) with migrations 2.4-2.7x up,
    /// because enough real handoffs land in the tail above the mean that a
    /// mean-derived cut loses them. The in-tree dose-response wanted a 99.67%
    /// firing rate on this workload, so the statistic that matches the
    /// requirement is a high percentile, not an invented multiplier.
    p99: u64,
}

/// Per-CPU time spent in interrupt handlers, in kernel ticks, from
/// `/proc/stat` (irq + softirq columns, CONFIG_IRQ_TIME_ACCOUNTING).
///
/// Handler TIME is the harm itself, not a proxy: a wake suffers exactly
/// when it lands on a CPU whose handler is running, and the time share IS
/// that probability. Counting interrupt lines mis-priced both directions --
/// a 1000 Hz mouse with a ~1 µs handler steals no more time than an
/// unflagged CPU, while a slow line with a heavy handler could never reach
/// a count bar (§G33). Softirq time is included because NAPI network
/// processing shadows wakes the same way and never appeared as line counts.
fn read_irq_ticks(nr_cpus: usize) -> Option<Vec<u64>> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    let mut ticks = vec![0u64; nr_cpus];
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
        ticks[cpu] = vals[5] + vals[6];
        seen = true;
    }
    seen.then_some(ticks)
}

/// Split the host's own handler-time distribution at its widest gap: sinks
/// are the CPUs above the cut (§G33, §R.26).
///
/// No unit-carrying threshold -- the cut is wherever the sorted per-CPU
/// tick deltas separate the most, so it adapts to any host, any device,
/// and any load without claiming to know in advance what "loud" means.
/// Deltas feed ratios directly, so no clock or tick-rate conversion exists.
/// A zero delta means "under one tick this window" and enters the ranking
/// at half a tick -- the midpoint of what the measurement could not
/// resolve -- keeping every ratio finite so a lone loud CPU still
/// separates from an otherwise-quiet machine. A flat distribution has no
/// gap and therefore no sinks; a cut that would condemn half the machine
/// has measured host-wide load, not pinned interrupt affinity (None).
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

/// Live IRQ-sink tracking riding the 1 s run loop (§G30, §G33, §R.25/§R.26).
///
/// Each window the handler-time deltas are split at their widest gap. A CPU
/// above the cut for FLAG_POLLS consecutive windows is published as a sink
/// -- a real sink ranks above the cut every window, ranking noise does not
/// -- and a published sink is released after UNFLAG_POLLS windows below it,
/// because removal merely returns placement freedom and a loading screen
/// must not flap the mask. A set that keeps repeating earns a doubled
/// sampling interval up to INTERVAL_MAX (longer windows accumulate more
/// ticks, so confidence also buys resolution); any change resets to every
/// tick. All four constants are agreement counts: every value that steers
/// comes from the measured distribution alone (§R.26).
struct SinkMonitor {
    /// Last accepted read; deltas span the full gap between accepted reads,
    /// so a slower cadence measures a longer, smoother window.
    prev: Option<Vec<u64>>,
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
    /// Sampling never slows past this many ticks.
    const INTERVAL_MAX: u32 = 16;
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
        // A failed read leaves prev in place, so the next sample just spans
        // a longer window; an untrusted split still advances the baseline.
        let sample = read_irq_ticks(nr_cpus)?;
        let before = self.prev.replace(sample)?;
        let current = self.prev.as_ref()?;
        let deltas: Vec<u64> = current
            .iter()
            .zip(before.iter())
            .map(|(c, b)| c.saturating_sub(*b))
            .collect();
        let hot = sinks_by_widest_gap(&deltas)?;

        let mut changed = false;
        for (cpu, &is_hot) in hot.iter().enumerate().take(self.published.len()) {
            if is_hot {
                self.quiet[cpu] = 0;
                self.hot_streak[cpu] += 1;
                // The cut wanders under load, so flagged CPUs accrete across
                // polls — the per-sample half-machine guard cannot see the
                // UNION. Bound it here: the published set stays a strict
                // minority, so placement always keeps most of the machine.
                if !self.published[cpu]
                    && self.hot_streak[cpu] >= Self::FLAG_POLLS
                    && (self.published.iter().filter(|h| **h).count() + 1) * 2
                        < self.published.len()
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
        self.stable += 1;
        if self.stable >= Self::STABLE_POLLS {
            self.stable = 0;
            self.interval = (self.interval * 2).min(Self::INTERVAL_MAX);
        }
        None
    }
}

/// Measure one wake + block + switch hop on THIS host.
///
/// Two threads ping-pong through a condvar, which exercises exactly the path
/// `cake_handoff_max_ns` is a proxy for: a blocking handoff between two
/// tasks. It used to be a slice divisor (/2048), since removed: that made it
/// made it wrong at any other slice value and wrong on any other CPU -- at a
/// 1 ms slice it evaluated to 488 ns, below this host's ~606 ns sleep floor, so
/// nothing could qualify and the co-location gate silently disabled itself.
///
/// Runs before the scheduler attaches, so it measures the stock kernel path.
/// ~2200 round trips, a few milliseconds of startup. Returns nanoseconds per
/// one-way hop, or None if the probe could not complete -- callers keep the
/// compiled-in defaults rather than trusting a failed measurement.
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
                while *turn % 2 == 0 {
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

#[cfg(test)]
mod tests {
    use super::sinks_by_widest_gap;

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
}
