// SPDX-License-Identifier: GPL-2.0
//
// scx_cake — a clean-slate sched_ext scheduler.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
mod core_performance;
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

/// Narrow placement uses kernel idle masks; its private idle callback is empty.
/// Omit the callback entirely instead of entering BPF just to return.
fn configure_idle_tracking(skel: &mut OpenBpfSkel<'_>, one_word: bool) {
    if one_word {
        skel.struct_ops.cake_ops_mut().update_idle = std::ptr::null_mut();
        skel.progs.cake_update_idle.set_autoload(false);
    }
}

/// scx_cake: a gaming-first sched_ext scheduler.
#[derive(Debug, PartialEq, Eq, Parser)]
#[command(after_help = toggle_help())]
struct Opts {
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
}

/// Every construct toggle: name, construct, BPF default. The default is
/// checked against the compiled rodata at start so the two cannot drift;
/// --help prints this table.
const TOGGLES: [(&str, &str, u8); 5] = [
    ("g85", "seat-rules", 1),
    ("g86", "claim-retry", 1),
    ("g87", "wakee-protect", 1),
    ("g89", "die-local-pool", 1),
    ("probe", "diagnostics", 0),
];

fn toggle_help() -> String {
    let mut s = String::from("Toggles (--toggle NAME=0|1, repeatable):\n");
    for (name, what, dfl) in TOGGLES {
        s.push_str(&format!("  {name:<9} {what:<20} default {dfl}\n"));
    }
    s.push_str("  llcsplit  fake-two-dies        default 0, loader-only test scaffold\n");
    s
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

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    /// Handler-edge tracepoint links (§G35); dropped on exit with the rest.
    _irq_links: Vec<libbpf_rs::Link>,
    /// Diagnostics on (--toggle probe=1): census, hold attribution, black box.
    probe_on: bool,
    /// Print runtime diagnostics. Off by default: a release run is not a
    /// measurement session, and a scheduler logging into a game is noise.
    verbose: bool,
    /// Live IRQ-sink tracking state (§G30, §G33).
    sinks: SinkMonitor,
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

        // Open the BPF program.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        // debug(false) disables every libbpf message, including verifier
        // failures. Keep errors visible without the verbose loader chatter.
        if !opts.verbose {
            scx_utils::init_libbpf_logging(Some(libbpf_rs::PrintLevel::Warn));
        }
        let mut skel = scx_ops_open!(skel_builder, open_object, cake_ops, None)?;
        // The handler-edge hooks attach by hand, exit first (below). The
        // skeleton's auto-attach in scx_ops_attach! attached them too, in
        // section order (entry first, so one CPU started mid-handler for
        // the run) and a second time, so every program ran twice per edge
        // (review 2026-09-06).
        for prog in [
            &mut skel.progs.cake_irq_enter,
            &mut skel.progs.cake_irq_leave,
            &mut skel.progs.cake_softirq_enter,
            &mut skel.progs.cake_softirq_leave,
        ] {
            prog.set_autoattach(false);
        }

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
        // The span must cover the kernel's nr_cpu_ids, which counts POSSIBLE
        // CPUs; the topology only lists present ones, and a guest or a board
        // with disabled entries has more possible than present. ops.init
        // refused such hosts as "narrower than nr_cpu_ids" (audit 2026-09-06).
        let span = (*NR_CPU_IDS).max(
            std::fs::read_to_string("/sys/devices/system/cpu/possible")
                .ok()
                .and_then(|t| last_cpu_id(&t))
                .map_or(0, |last| last + 1),
        );
        anyhow::ensure!(
            span <= bpf_intf::consts_MAX_CPUS as usize,
            "host nr_cpu_ids {} exceeds Cake's compiled MAX_CPUS {}",
            span,
            bpf_intf::consts_MAX_CPUS
        );
        rodata.nr_cpu_span = span as u32;
        // The census word covers PRESENT ids; hotplug headroom past 64 costs
        // nothing, a present id past 64 turns the one-word paths off.
        let one_word = *NR_CPU_IDS <= 64;
        rodata.cake_one_word = u8::from(one_word);
        if !one_word {
            warn!(
                "   span    {} CPU ids exceed one census word: claim walk, seats and die-local pools off, kernel idle pick only",
                *NR_CPU_IDS
            );
        }

        // Campaign toggles land in rodata before load so the verifier prunes
        // the off arms; the logged line is each arm's identity in an on/off
        // pair (STATE.md, toggle campaign 2026-08-22). One table names every
        // toggle; a second line prints only what differs from the build's
        // defaults, which is what a tester needs to read back.
        let mut llcsplit = false;
        let fields: [&mut u8; 5] = [
            &mut rodata.cake_tog_g85,
            &mut rodata.cake_tog_g86,
            &mut rodata.cake_tog_g87,
            &mut rodata.cake_tog_g89,
            &mut rodata.cake_tog_probe,
        ];
        let mut slots: Vec<(&str, &str, &mut u8)> = TOGGLES
            .iter()
            .zip(fields)
            .map(|((name, what, dfl), field)| {
                if *field != *dfl {
                    warn!("   toggle  {name} defaults to {} in BPF but {dfl} in TOGGLES; fix the table", *field);
                }
                (*name, *what, field)
            })
            .collect();
        let defaults: Vec<u8> = slots.iter().map(|s| *s.2).collect();
        for spec in &opts.toggle {
            // A bad toggle is reported and ignored, never fatal: a stale
            // flag from an old config must not keep the scheduler off.
            let Some((name, val)) = spec.split_once('=') else {
                warn!("   toggle  ignored `{spec}`: expected NAME=0|1");
                continue;
            };
            let on = match val {
                "0" => 0u8,
                "1" => 1u8,
                _ => {
                    warn!("   toggle  ignored `{spec}`: value must be 0 or 1");
                    continue;
                }
            };
            if let Some(slot) = slots.iter_mut().find(|s| s.0 == name) {
                *slot.2 = on;
            } else if name == "llcsplit" {
                // Test scaffold: present this host to the BPF side as two
                // dies (lower and upper half of the cores, with siblings) so
                // the routing runs as on a dual-CCD chip. Loader-only.
                llcsplit = on == 1;
            } else {
                warn!("   toggle  ignored `{spec}`: no toggle named {name}");
            }
        }

        // Host identity right under the version line; the LLC count is the
        // same expression the steal and pool setup below uses.
        info!(
            "   host    {physical} cores + {smt} SMT = {total} CPUs, {} LLC{}",
            if llcsplit { 2 } else { topo.all_llcs.len() },
            if llcsplit {
                " (SCAFFOLD: fake split, not the hardware)"
            } else {
                ""
            }
        );
        let core_performance = core_performance::CorePerformanceLayout::discover(&topo);
        let rank_words = core_performance.rank_words();
        if one_word && rank_words.len() > 1 {
            rodata.cake_rank_tiers = rank_words.len() as u32;
            rodata.cpu_perf_known = rank_words.iter().fold(0, |all, word| all | word);
            for (slot, word) in rodata.cpu_perf_tier.iter_mut().zip(rank_words) {
                *slot = word;
            }
        }
        info!("   cores   {}", core_performance.summary());
        if opts.verbose {
            for core in core_performance.details() {
                info!("   {core}");
            }
        }
        if opts.verbose {
            info!("   slice   {slice_us}µs, {total} per-CPU vtime queues + 1 global wake queue");
        }
        // cake calls scx_bpf_dsq_peek() unconditionally; on a kernel without
        // the ksym the load fails outright, so "MISSING" is the honest word.
        let kernel_line = format!(
            "   kernel  queued_wakeup {}, dsq_peek {}",
            if queued_wakeup { "on" } else { "UNSUPPORTED" },
            if dsq_peek { "native" } else { "MISSING" }
        );
        if !queued_wakeup || !dsq_peek {
            warn!("{kernel_line}");
        } else if opts.verbose {
            info!("{kernel_line}");
        }
        let probe_on = slots.iter().any(|s| s.0 == "probe" && *s.2 == 1);
        // Stock start says nothing about toggles. An override prints one
        // line naming what moved; the full identity line is --verbose only.
        let mut changed: Vec<String> = slots
            .iter()
            .zip(&defaults)
            .filter(|(s, d)| *s.2 != **d)
            .map(|(s, _)| format!("{}={} {}", s.0, s.2, s.1))
            .collect();
        if llcsplit {
            changed.push("llcsplit=1 fake-two-dies".to_string());
        }
        if opts.verbose {
            let line: Vec<String> = slots.iter().map(|s| format!("{}={}", s.0, s.2)).collect();
            info!("   toggle  {}", line.join(" "));
        }
        if !changed.is_empty() {
            info!("   toggle  {} (all others at default)", changed.join(", "));
        } else if !opts.toggle.is_empty() {
            info!("   toggle  all at default");
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
                // wake. Zero (probe failed, or a hop too long to predict
                // with) leaves the predictor off.
                rodata.cake_wake_hop_ns = if p99 <= WAKE_HOP_MAX_NS {
                    p99
                } else {
                    warn!(
                        "   probe   hop p99 {p99}ns exceeds {WAKE_HOP_MAX_NS}ns; tick predictor off"
                    );
                    0
                };
                if opts.verbose {
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
        // effect) — so the scheduler starts sink-free; -v announces each
        // set as it changes.

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
        if let Some((shift, left, right)) = smt_fold(siblings) {
            rodata.cake_smt_shift = shift;
            rodata.cake_smt_left = left;
            rodata.cake_smt_right = right;
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
            // §G88 scaffold: with --toggle llcsplit=1 the lower half of the
            // cores (by core id) is die 0 and the upper half die 1.
            let half_core = {
                let mut cores: Vec<usize> = topo.all_cores.keys().copied().collect();
                cores.sort_unstable();
                cores.get(cores.len() / 2).copied().unwrap_or(usize::MAX)
            };
            let llc_of = |cpu: &scx_utils::Cpu| -> usize {
                if llcsplit {
                    usize::from(cpu.core_id >= half_core)
                } else {
                    cpu.llc_id
                }
            };
            let nr_llcs = if llcsplit { 2 } else { topo.all_llcs.len() };
            let multi_ccd = nr_llcs > 1;
            rodata.steal_order_live = u8::from(multi_ccd && fits);
            rodata.nr_steal_cpus = topo.all_cpus.len().saturating_sub(1) as u32;
            order.fill(0);

            // §G88/§G89: the per-CPU LLC word, the dense LLC id and the LLC
            // count, from every CPU the topology describes.
            {
                let cpus: Vec<(usize, usize)> =
                    topo.all_cpus.values().map(|c| (c.id, llc_of(c))).collect();
                // Die-local pools need the one-word census: past it the pool
                // kick is LLC-blind and lands on a die whose dispatch reads
                // its own pool, so the wake waits (audit 2026-09-06).
                let max_llcs = if rodata.cake_one_word != 0 {
                    bpf_intf::consts_MAX_LLCS as usize
                } else {
                    1
                };
                let layout = LlcLayout::build(&cpus, max_llcs);
                if let Some(n) = layout.collapsed {
                    warn!("   llc     {n} domains, {max_llcs} pool(s) usable here; one pool, LLC-blind");
                }
                rodata.cpu_llc_id.fill(0);
                rodata.cpu_llc_domain.fill(u16::MAX);
                rodata.cpu_llc_word.fill(u64::MAX);
                for (cpu, llc) in &cpus {
                    if *cpu < rodata.cpu_llc_id.len() {
                        rodata.cpu_llc_id[*cpu] = layout.dense[llc];
                        rodata.cpu_llc_domain[*cpu] = layout.domain[llc];
                        rodata.cpu_llc_word[*cpu] = layout.word[llc];
                    }
                }
                rodata.nr_llcs = layout.nr_llcs;
            }

            if multi_ccd && !fits {
                warn!("   ccd     host wider than steal matrix ({span} CPUs); ring steal only");
            }
            if multi_ccd && fits {
                let mut llc_cache: BTreeMap<usize, usize> = BTreeMap::new();
                for cpu in topo.all_cpus.values() {
                    let e = llc_cache.entry(llc_of(cpu)).or_insert(0);
                    *e = (*e).max(cpu.cache_size);
                }
                let policy = bpf_intf::consts_CCD_STEAL_POLICY;
                let nr_ids = *NR_CPU_IDS;

                for src in topo.all_cpus.values() {
                    let mut candidates: Vec<_> = topo
                        .all_cpus
                        .values()
                        .filter(|dst| dst.id != src.id)
                        .collect();
                    candidates.sort_by_key(|dst| {
                        let class = if llc_of(dst) == llc_of(src) {
                            0
                        } else if policy > 1 && llc_cache[&llc_of(dst)] == llc_cache[&llc_of(src)] {
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

        configure_idle_tracking(&mut skel, one_word);

        // Load and attach.
        let mut skel = scx_ops_load!(skel, cake_ops, uei)?;

        // Handler-edge tracepoints feed the in-handler depth (§G35). The
        // exit hook of each pair attaches FIRST: cake_irq_edge drops an exit
        // with no entry, so a handler in flight across the attach costs
        // nothing, while an entry counted before its exit hook existed
        // left that CPU mid-handler for the whole run (review 2026-09-06).
        // A pair whose exit hook fails skips its entry hook for the same
        // reason; the depth stays zero and steering is chronic-only.
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

        // Begin scheduling only after handler accounting is installed.
        let struct_ops = Some(scx_ops_attach!(skel, cake_ops)?);

        info!("🍰 attached");

        // The file capabilities (cap_bpf,cap_perfmon,cap_sys_nice) are only
        // needed to load and attach; detach and map access use already-open
        // fds. Drop them all: while any elevated capability stays in the
        // permitted set, the kernel's ptrace access check denies
        // /proc/<pid>/exe to unprivileged observers even with dumpable
        // restored, which breaks the sudoless bench runner's hash-of-exe
        // identity verification (and holding dead privileges is bad hygiene).
        if let Err(err) = drop_privileges_for_observers() {
            warn!("post-attach capability drop failed: {err}");
        }

        Ok(Self {
            skel,
            struct_ops,
            _irq_links: irq_links,
            probe_on,
            verbose: opts.verbose,
            sinks: SinkMonitor::new(*NR_CPU_IDS),
        })
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let mut polls: u32 = 0;
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            std::thread::sleep(Duration::from_secs(1));
            polls += 1;

            // §G35 self-check: a CPU mid-handler across two reads 50 ms
            // apart is the signature of an entry counted before its exit
            // hook existed (review 2026-09-06); a real handler is gone by
            // the second read. The healthy answer is zero.
            if self.verbose && (polls == 2 || polls == 6) {
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

            if let Some(set) = self.sinks.tick(*NR_CPU_IDS) {
                self.publish_sinks(&set);
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
            const NAMES: [&str; 119] = [
                "select_calls",
                "serial",
                "home_warm",
                "wp_attempt",
                "wp_tiny",
                "wp_small",
                "wp_protect",
                "wp_vtime",
                "wp_starved",
                "wp_fired",
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
                "hd_sync",
                "hd_starved",
                "hd_irq",
                "hd_aff",
                "hd_contended",
                "hd_notidle",
                "home_busy",
                "home_localq",
                "h300_home_busy",
                "ui_enter",
                "ui_enter_idlew",
                "ui_exit",
                "ui_exit_idlew",
                "qmark_set",
                "qmark_set_skip",
                "qmark_clr",
                "qmark_clr_skip",
                "seat_clr",
                "seat_set",
                "running",
                "frontier_st",
                "wake_served_st",
                "wake_mark_st",
                "taci",
                "taci_win",
                "taci_stage",
                "taci_home",
                "taci_groove",
                "taci_warm_core",
                "taci_warm_thread",
                "taci_warm",
                "taci_hint",
                "taci_notify",
                "pick_idle",
                "kick",
                "nrq",
                "dsq_insert",
                "move_local",
                "kt",
                "kt_period",
                "kt_ticksoon",
                "kt_occupant",
                "kt_handoff",
                "kt_wakeclock",
                "kt_running",
                "kt_probe",
                "task_storage",
                "cpu_curr",
                "core_contended",
                "stage_probe",
                "taciw_stage",
                "taciw_home",
                "taciw_groove",
                "taciw_warm_core",
                "taciw_warm_thread",
                "taciw_warm",
                "taciw_hint",
                "taciw_notify",
                "t_nrq",
                "t_taci",
                "t_pick",
                "t_kick",
                "t_cpu_curr",
                "t_task_storage",
                "t_move",
                "t_insert",
                "t_ui_idlew",
                "t_qmark",
                "t_cal",
                "leak_home",
                "leak_kick",
                "leak_dispatch",
                "seat_immune",
                "seat_retake",
                "seat_reroute",
                "seat_decline",
                "pool_forward",
                "claim_retry",
                "kt_pool",
                "x_serial",
                "kt_local",
                "x_kt_local",
                "x_claim",
                "notify_kick",
                "x_notify_kick",
                "probe_fired",
                "x_probe_fired",
                "pool_served",
                "x_pool_served",
                "steal_moved",
                "x_steal_moved",
            ];
            // The name table must match the BPF enum exactly; a drift prints
            // zeros silently because out-of-range lookups fail quietly.
            let nr = self
                .skel
                .maps
                .cake_stats
                .info()
                .map(|i| i.info.max_entries)
                .unwrap_or(0) as usize;
            if nr != NAMES.len() {
                warn!(
                    "   census  name table has {} entries, map has {}: names are out of sync",
                    NAMES.len(),
                    nr
                );
            }
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

        if let (true, Some(bss)) = (self.verbose, self.skel.maps.bss_data.as_mut()) {
            let ev = &bss.cake_events;
            info!(
                "   events  select_fallback {} keep_last {} enq_skip_exiting {}",
                ev.SCX_EV_SELECT_CPU_FALLBACK,
                ev.SCX_EV_DISPATCH_KEEP_LAST,
                ev.SCX_EV_ENQ_SKIP_EXITING
            );
        }

        self.struct_ops.take();
        info!("🍰 detached");
        uei_report!(&self.skel, uei)
    }

    /// Publish the existing IRQ measurements as aligned CPU-mask words.
    /// Wide hosts may observe different publication epochs across words;
    /// these are placement preferences, never CPU admission or reservations.
    fn publish_sinks(&mut self, set: &[bool]) {
        let Some(bss) = self.skel.maps.bss_data.as_mut() else {
            return;
        };
        let words = sink_words::<{ bpf_intf::consts_QMASK_WORDS as usize }>(set);
        for (published, word) in bss.cpu_irq_hot_words.iter_mut().zip(words) {
            // SAFETY: the skeleton maps writable, u64-aligned BSS. A volatile
            // word store prevents the compiler from eliding a publication
            // consumed asynchronously by BPF. No cross-word atomicity assumed.
            unsafe { std::ptr::write_volatile(published, word) };
        }

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
/// deltas in that order. Only those are ranked: a possible-but-offline id
/// has no handler time and would sit under every online CPU, turning the
/// whole online set into the loud side of the widest gap (review
/// 2026-09-06).
fn sink_deltas(current: &[Option<u64>], before: &[Option<u64>]) -> (Vec<usize>, Vec<u64>) {
    current
        .iter()
        .zip(before)
        .enumerate()
        .filter_map(|(cpu, (c, b))| Some((cpu, (*c)?.checked_sub((*b)?)?)))
        .unzip()
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
        for (cpu, &is_hot) in hot.iter().enumerate() {
            if present.binary_search(&cpu).is_err() {
                self.hot_streak[cpu] = 0;
                self.quiet[cpu] = 0;
                continue;
            }
            if is_hot {
                self.quiet[cpu] = 0;
                self.hot_streak[cpu] = (self.hot_streak[cpu] + 1).min(Self::FLAG_POLLS);
                // The cut wanders under load, so flagged CPUs accrete across
                // polls — the per-sample half-machine guard cannot see the
                // UNION. Bound it here: the published set stays a strict
                // minority, so placement always keeps most of the machine.
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
        self.stable += 1;
        if self.stable >= Self::STABLE_POLLS {
            self.stable = 0;
            self.interval = (self.interval * 2).min(Self::INTERVAL_MAX);
        }
        None
    }
}

/// The longest wake hop the tick predictor (§G36) can use. The predictor
/// asks whether a CPU's next tick lands inside one hop; a hop at a quarter
/// of the fastest tick period cake runs under (HZ=1000) or longer would call
/// every CPU tick-soon at all times and `cake_cpu_clean` would refuse every
/// candidate. A probe run under a loaded or virtualised host lands here and
/// turns the predictor off instead (review 2026-09-06).
const WAKE_HOP_MAX_NS: u64 = 250_000;

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

/// Parse the command line, dropping options cake does not have instead of
/// refusing to start. A legacy flag in a user's scx_loader config (for
/// example `--profile default`) used to keep the scheduler off entirely;
/// now the option and its bare value are dropped, the rest is parsed, and
/// every dropped token is reported once logging is up. Real errors on real
/// options (a bad value or `--help`) keep clap's behaviour.
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
                    if s.starts_with('-') && !s.starts_with("--") {
                        if let Some(short) = short {
                            return s
                                .char_indices()
                                .skip(1)
                                .find_map(|(split, c)| (c == short).then_some((pos, split)));
                        }
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
        return Ok(());
    }
    if opts.print_topology {
        let topo = Topology::new().context("failed to read topology")?;
        let layout = core_performance::CorePerformanceLayout::discover(&topo);
        println!("{}", layout.summary());
        for core in layout.details() {
            println!("{core}");
        }
        return Ok(());
    }

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

/// The §G88/§G89 LLC topology the loader publishes to rodata, built from
/// (cpu id, llc id) pairs so any host shape can be tested without a machine.
struct LlcLayout {
    /// Physical identity is never collapsed to the bounded pool namespace.
    domain: BTreeMap<usize, u16>,
    /// Dense pool index per topology LLC id; every id maps, ids are
    /// assigned in ascending LLC order.
    dense: BTreeMap<usize, u8>,
    /// §G88: the CPUs (ids below 64) sharing each LLC, as one word. An LLC
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
    fn idle_callback_is_omitted_only_for_kernel_mask_path() {
        use libbpf_rs::skel::SkelBuilder;
        use std::mem::MaybeUninit;

        for one_word in [false, true] {
            let mut object = MaybeUninit::uninit();
            let builder = super::BpfSkelBuilder::default();
            let mut skel = builder.open(&mut object).expect("open embedded BPF object");
            assert!(!skel.struct_ops.cake_ops_mut().update_idle.is_null());
            super::configure_idle_tracking(&mut skel, one_word);
            assert_eq!(
                skel.struct_ops.cake_ops_mut().update_idle.is_null(),
                one_word
            );
            assert_eq!(skel.progs.cake_update_idle.autoload(), !one_word);
            assert!(!skel.struct_ops.cake_ops_mut().cpu_release.is_null());
            assert!(skel.progs.cake_cpu_release.autoload());
        }
    }

    use super::{
        attach_irq_pair, last_cpu_id, sink_deltas, sink_words, sinks_by_widest_gap, LlcLayout,
        SinkMonitor,
    };

    // Load only: synthetic topology exposes paths pruned on the build host.
    // Never attach struct_ops or tracepoints, or execute the synthetic policy.
    #[test]
    #[ignore = "requires BPF load capabilities and a sched_ext kernel"]
    fn verifier_load_topologies() -> anyhow::Result<()> {
        use super::{configure_idle_tracking, BpfSkelBuilder};
        use scx_utils::{scx_ops_load, scx_ops_open};
        use std::mem::MaybeUninit;

        libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Warn, |_, message| {
            eprint!("{message}");
        })));
        let mut failures = Vec::new();
        let steal_span = super::bpf_intf::consts_STEAL_SPAN as usize;
        for (cpus, llcs) in [
            (1usize, 1usize),
            (16, 1),
            (32, 1),
            (32, 2),
            (64, 16),
            (128, 1),
            (1024, 1),
        ] {
            let mut object = MaybeUninit::uninit();
            let builder = BpfSkelBuilder::default();
            let mut skel = scx_ops_open!(builder, &mut object, cake_ops, None)?;
            let one_word = cpus <= 64;
            let cores = cpus.div_ceil(2);
            let ro = skel.maps.rodata_data.as_mut().unwrap();
            ro.nr_cpu_span = cpus as u32;
            ro.nr_llcs = llcs as u32;
            ro.cake_one_word = u8::from(one_word);
            ro.cake_rank_tiers = if one_word { cores as u32 } else { 0 };
            ro.cpu_perf_known = if one_word { u64::MAX >> (64 - cpus) } else { 0 };
            ro.cpu_sibling.fill(-1);
            ro.cpu_llc_domain.fill(u16::MAX);
            ro.cake_smt_shift = if cpus == 1 { 0 } else { cores.min(64) as u32 };
            if cores < 64 {
                ro.cake_smt_left = u64::MAX >> (64 - cores);
                ro.cake_smt_right = ro.cake_smt_left << cores;
            }
            ro.steal_order_live = u8::from(llcs > 1 && cpus <= steal_span);
            ro.nr_steal_cpus = (cpus - 1) as u32;
            for cpu in 0..cpus {
                let domain = (cpu % cores) / (cores / llcs);
                if cpus > 1 {
                    ro.cpu_sibling[cpu] = (cpu ^ cores) as i32;
                }
                ro.cpu_llc_id[cpu] = domain as u8;
                ro.cpu_llc_domain[cpu] = domain as u16;
                if one_word {
                    ro.cpu_perf_tier[cpu % cores] |= 1u64 << cpu;
                }
                for peer in 0..cpus.min(64) {
                    if (peer % cores) / (cores / llcs) == domain {
                        ro.cpu_llc_word[cpu] |= 1u64 << peer;
                    }
                }
                if ro.steal_order_live != 0 {
                    for peer in 1..cpus {
                        ro.cpu_steal_order[cpu * steal_span + peer - 1] =
                            ((cpu + peer) % cpus) as u16;
                    }
                }
            }
            configure_idle_tracking(&mut skel, one_word);
            match scx_ops_load!(skel, cake_ops, uei) {
                Ok(loaded) => {
                    eprintln!("verifier accepted: {cpus} CPUs, {llcs} LLCs");
                    drop(loaded);
                }
                Err(error) => failures.push(format!("{cpus} CPUs, {llcs} LLCs: {error:#}")),
            };
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
        monitor.interval = 16;
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
        // 63 lands in its own LLC's pool, not pool 0 (review 2026-09-06).
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
}
