// PANDEMONIUM SCHEDULER
// WRAPS THE BPF SKELETON: OPEN, CONFIGURE, LOAD, ATTACH, SHUTDOWN
// MONITORING AND ADAPTIVE CONTROL LIVE IN adaptive.rs

use std::mem::MaybeUninit;

use anyhow::Result;
use libbpf_rs::MapCore;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::bpf_skel::*;
use crate::tuning::{OscillatorState, Regime, TuningKnobs, scaled_regime_knobs};
use scx_pandemonium::event::EventLog;

// SCX EXIT CODES (FROM KERNEL)
const SCX_EXIT_NONE: i32 = 0;
const SCX_ECODE_RST_MASK: u64 = 1 << 16;

// SCX DSQ FLAGS (STABLE KERNEL ABI -- sched_ext/sched.h)
const SCX_DSQ_FLAG_BUILTIN: u64 = 1u64 << 63;
const SCX_DSQ_FLAG_LOCAL_ON: u64 = 1u64 << 62;

// MATCHES struct pandemonium_stats IN BPF (intf.h)
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct PandemoniumStats {
    pub nr_dispatches: u64,
    pub nr_idle_hits: u64,
    pub nr_shared: u64,
    pub nr_preempt: u64,
    pub wake_lat_sum: u64,
    pub wake_lat_samples: u64,
    pub nr_keep_running: u64,
    pub nr_hard_kicks: u64,
    pub nr_soft_kicks: u64,
    pub nr_enq_wakeup: u64,
    pub nr_enq_requeue: u64,
    pub wake_lat_idle_sum: u64,
    pub wake_lat_idle_cnt: u64,
    pub wake_lat_kick_sum: u64,
    pub wake_lat_kick_cnt: u64,
    pub nr_l2_hit_batch: u64,
    pub nr_l2_miss_batch: u64,
    pub nr_l2_hit_interactive: u64,
    pub nr_l2_miss_interactive: u64,
    pub nr_reenqueue: u64,
    pub batch_sojourn_ns: u64,
    pub longrun_mode_active: u64,
    pub nr_overflow_rescue: u64,
    // CROSS-DOMAIN SCATTER ATTRIBUTION (PER XDOM_* PATH) -- MATCHES nr_cross_domain[8] IN
    // intf.h. THE PLACEMENT-SIDE PATHS (0..6) SUM TO THE [KNOBS] LINE's scatter_pct.
    pub nr_cross_domain: [u64; 8],
    // OSCILLATOR ENVELOPE PARK ENTRIES (CPU-0 TICK WRITER; intf.h nr_osc_park)
    pub nr_osc_park: u64,
    // SPILL-KICK PREEMPTS (select_cpu seat redirected off the idle pick onto a
    // busy spill CPU; intf.h nr_spill_kick_preempt). Confirms the tick-floor fix.
    pub nr_spill_kick_preempt: u64,
    // TOTAL STEALS (intf.h nr_steal). Every successful STEP 1 peer move_to_local,
    // same-domain included -- nr_cross_domain[XDOM_STEAL] counts only the cross-
    // domain half, which on a two-domain box is the minority. Every steal is a
    // migration by definition, so this is the dispatch side's share of the count.
    pub nr_steal: u64,
    // REFUSED REQUEUE KICKS, SELF-TARGETED (intf.h nr_kick_declined). The bottom
    // rung of the kick ladder: the price refused the act, not just its strength,
    // and only where this CPU is the one that will dispatch. Read beside
    // nr_soft_kicks -- a refusal is not a soft kick and must not be pooled with
    // one, or the kick rate reports IPIs that were never issued. Its magnitude is
    // what says whether the self-only subset is worth keeping.
    pub nr_kick_declined: u64,
}

// PER-CPU QUEUE RING (intf.h struct depth_ring). One slot per bucket of the
// BPF-side time grid; a slot is current for an epoch only when its epoch
// matches. A slot with no ticks carries no depth sample, and one with no runs
// carries no queue-clock sample: absent, not an empty queue.
pub const DEPTH_RING_SLOTS: usize = 512;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DepthSlot {
    pub epoch: u64,
    pub ticks: u32,
    pub own: u32,
    pub dom: u32,
    pub loc: u32,
    pub runs: u32,
    pub wakes: u32,
    pub wait_us: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DepthRing {
    pub domain: u32,
    pub _pad: u32,
    pub slot: [DepthSlot; DEPTH_RING_SLOTS],
}

// COMPILE-TIME ABI SAFETY: MUST MATCH STRUCT LAYOUTS IN intf.h
// 184 (base, after the structurally empty latcrit l2 pair) + 8*8 (nr_cross_domain)
// + 8 (nr_osc_park) + 8 (nr_spill_kick_preempt) + 8 (nr_steal)
// + 8 (nr_kick_declined) = 280.
const _: () = assert!(std::mem::size_of::<PandemoniumStats>() == 280);
// 8 (domain + pad) + 512 * 40 (epoch, ticks, own, dom, loc, runs, wakes,
// wait_us, pad) = 20488.
const _: () = assert!(std::mem::size_of::<DepthRing>() == 20488);
// 88 - 16 (lat_cri_thresh_high/_low, removed with the classifier that read them)
// - 8 (spill_temp_q16, computed every tick and consumed by nothing)
// - 8 (affinity_mode) - 8 (preempt_thresh_ns), both read nowhere in BPF = 48.
const _: () = assert!(std::mem::size_of::<TuningKnobs>() == 48);

// MAX_AFFINITY_CANDIDATES IS DEFINED IN intf.h. THE RUST MIRROR IN
// bpf_intf.rs MUST KEEP THE SAME VALUE; IF THE TWO SIDES DRIFT, THE
// BPF MAP STRIDE AND THE RUST WRITER STRIDE DISAGREE AND THE TABLE
// IS SILENTLY MIS-POPULATED.
const _: () = assert!(crate::bpf_intf::MAX_AFFINITY_CANDIDATES == crate::bpf_intf::MAX_CPUS >> 3);

// TuningKnobs LIVES IN tuning.rs (ZERO BPF DEPENDENCIES, TESTABLE OFFLINE)

const KNOBS_PIN: &str = "/sys/fs/bpf/pandemonium/tuning_knobs";

pub struct Scheduler<'a> {
    skel: MainSkel<'a>,
    _link: libbpf_rs::Link,
    pub log: EventLog,
}

impl<'a> Scheduler<'a> {
    pub fn init(
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
        nr_cpus_override: Option<u64>,
    ) -> Result<Self> {
        // OPEN
        let builder = MainSkelBuilder::default();
        let mut open_skel = builder.open(open_object)?;

        // INJECT VERSION SUFFIX INTO OPS NAME FOR scx_loader GUI
        {
            let ops = open_skel.struct_ops.pandemonium_ops_mut();
            let name_field = &mut ops.name;
            let version_suffix = scx_utils::build_id::ops_version_suffix(env!("CARGO_PKG_VERSION"));
            let bytes = version_suffix.as_bytes();
            let mut i = 0;
            let mut bytes_idx = 0;
            let mut found_null = false;
            while i < name_field.len() - 1 {
                found_null |= name_field[i] == 0;
                if !found_null {
                    i += 1;
                    continue;
                }
                if bytes_idx < bytes.len() {
                    name_field[i] = bytes[bytes_idx] as i8;
                    bytes_idx += 1;
                } else {
                    break;
                }
                i += 1;
            }
            name_field[i] = 0;
        }

        // CONFIGURE RODATA (BEFORE LOAD)
        let rodata = open_skel.maps.rodata_data.as_mut().unwrap();

        let possible = libbpf_rs::num_possible_cpus()? as u64;
        rodata.nr_cpu_ids = nr_cpus_override.unwrap_or(possible);

        // POPULATE SCX ENUM VALUES
        rodata.__SCX_DSQ_FLAG_BUILTIN = SCX_DSQ_FLAG_BUILTIN;
        rodata.__SCX_DSQ_FLAG_LOCAL_ON = SCX_DSQ_FLAG_LOCAL_ON;
        rodata.__SCX_DSQ_INVALID = SCX_DSQ_FLAG_BUILTIN;
        rodata.__SCX_DSQ_GLOBAL = SCX_DSQ_FLAG_BUILTIN | 1;
        rodata.__SCX_DSQ_LOCAL = SCX_DSQ_FLAG_BUILTIN | 2;
        rodata.__SCX_DSQ_LOCAL_ON = SCX_DSQ_FLAG_BUILTIN | SCX_DSQ_FLAG_LOCAL_ON;
        rodata.__SCX_DSQ_LOCAL_CPU_MASK = 0xFFFFFFFF;
        rodata.__SCX_TASK_QUEUED = 1;

        // POPULATE SCX_KICK_* ENUM VALUES
        rodata.__SCX_KICK_IDLE = 1;
        rodata.__SCX_KICK_PREEMPT = 2;
        rodata.__SCX_KICK_WAIT = 4;

        // LOAD (VALIDATES BPF WITH KERNEL)
        let mut skel = open_skel.load()?;

        // ATTACH STRUCT_OPS
        let link = skel.maps.pandemonium_ops.attach_struct_ops()?;

        // PIN MAPS FOR USERSPACE ACCESS (NON-FATAL: bpffs MAY NOT BE MOUNTED)
        let pin_dir = "/sys/fs/bpf/pandemonium";
        let bpffs_ok = std::fs::create_dir_all(pin_dir).is_ok();
        if bpffs_ok {
            std::fs::remove_file(KNOBS_PIN).ok();
            skel.maps.tuning_knobs_map.pin(KNOBS_PIN).ok();

            let cache_pin = "/sys/fs/bpf/pandemonium/cache_domain";
            std::fs::remove_file(cache_pin).ok();
            skel.maps.cache_domain.pin(cache_pin).ok();
        } else {
            log_warn!("BPFFS NOT AVAILABLE: map pinning skipped (scheduler still functional)");
        }

        Ok(Self {
            skel,
            _link: link,
            log: EventLog::new(),
        })
    }

    // PER-CPU STATS, UNCOLLAPSED. The BPF side keeps one PandemoniumStats
    // per CPU and lookup_percpu hands the whole array across the boundary --
    // the syscall, the copy and the cache traffic are paid whether or not the
    // structure survives. It did not: every field was summed into one scalar
    // set inside the loop that first touched it, which destroyed the spatial
    // dimension at the boundary and left the adaptive layer steering a machine
    // it could only see one number of. Keeping the array costs zero additional
    // bytes; it is the absence of a discard, not a new transfer.
    //
    // read_stats() below folds this into the same total it always returned, so
    // the aggregate is DERIVED from the array rather than computed beside it
    // and the two cannot drift.
    pub fn read_stats_percpu(&self) -> Vec<PandemoniumStats> {
        let key = 0u32.to_ne_bytes();
        let percpu_vals = match self
            .skel
            .maps
            .stats_map
            .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(v)) => v,
            _ => return Vec::new(),
        };
        let mut out = Vec::with_capacity(percpu_vals.len());
        for cpu_val in &percpu_vals {
            if cpu_val.len() >= std::mem::size_of::<PandemoniumStats>() {
                out.push(unsafe {
                    std::ptr::read_unaligned(cpu_val.as_ptr() as *const PandemoniumStats)
                });
            }
        }
        out
    }

    // PER-CPU DEPTH RINGS, ONE PER POSSIBLE CPU, INDEXED BY CPU. One map read a
    // second carries every tick's sample since the last one.
    pub fn read_depth_rings(&self) -> Vec<DepthRing> {
        let key = 0u32.to_ne_bytes();
        let percpu_vals = match self
            .skel
            .maps
            .depth_ring
            .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(v)) => v,
            _ => return Vec::new(),
        };
        percpu_vals
            .iter()
            .filter(|v| v.len() >= std::mem::size_of::<DepthRing>())
            .map(|v| unsafe { std::ptr::read_unaligned(v.as_ptr() as *const DepthRing) })
            .collect()
    }

    // THE REDUCE. Separated from the read so the fold is testable without a
    // live BPF map, and so every not-a-sum field is stated in one place:
    // batch_sojourn_ns and longrun_mode_active take a MAX across CPUs (a
    // system's worst sojourn is not the sum of its CPUs' sojourns), and
    // nr_cross_domain is an 8-element per-path array summed elementwise.
    // Returning the raw vec without honoring these would silently change
    // behavior for every existing consumer.
    pub fn fold_stats(percpu: &[PandemoniumStats]) -> PandemoniumStats {
        let mut total = PandemoniumStats::default();
        for stats in percpu {
            {
                total.nr_dispatches += stats.nr_dispatches;
                total.nr_idle_hits += stats.nr_idle_hits;
                total.nr_shared += stats.nr_shared;
                total.nr_preempt += stats.nr_preempt;
                total.wake_lat_sum += stats.wake_lat_sum;
                total.wake_lat_samples += stats.wake_lat_samples;
                total.nr_keep_running += stats.nr_keep_running;
                total.nr_hard_kicks += stats.nr_hard_kicks;
                total.nr_soft_kicks += stats.nr_soft_kicks;
                total.nr_enq_wakeup += stats.nr_enq_wakeup;
                total.nr_enq_requeue += stats.nr_enq_requeue;
                total.wake_lat_idle_sum += stats.wake_lat_idle_sum;
                total.wake_lat_idle_cnt += stats.wake_lat_idle_cnt;
                total.wake_lat_kick_sum += stats.wake_lat_kick_sum;
                total.wake_lat_kick_cnt += stats.wake_lat_kick_cnt;
                total.nr_l2_hit_batch += stats.nr_l2_hit_batch;
                total.nr_l2_miss_batch += stats.nr_l2_miss_batch;
                total.nr_l2_hit_interactive += stats.nr_l2_hit_interactive;
                total.nr_l2_miss_interactive += stats.nr_l2_miss_interactive;
                total.nr_reenqueue += stats.nr_reenqueue;
                if stats.batch_sojourn_ns > total.batch_sojourn_ns {
                    total.batch_sojourn_ns = stats.batch_sojourn_ns;
                }
                if stats.longrun_mode_active > total.longrun_mode_active {
                    total.longrun_mode_active = stats.longrun_mode_active;
                }
                total.nr_overflow_rescue += stats.nr_overflow_rescue;
                for i in 0..8 {
                    total.nr_cross_domain[i] += stats.nr_cross_domain[i];
                }
                total.nr_osc_park += stats.nr_osc_park;
                total.nr_spill_kick_preempt += stats.nr_spill_kick_preempt;
                total.nr_steal += stats.nr_steal;
                total.nr_kick_declined += stats.nr_kick_declined;
            }
        }

        total
    }

    // THE AGGREGATE VIEW, UNCHANGED FOR EVERY EXISTING CALLER. One syscall,
    // one fold, byte-for-byte the same total this returned before the array
    // was preserved.
    pub fn read_stats(&self) -> PandemoniumStats {
        Self::fold_stats(&self.read_stats_percpu())
    }

    // FIELDS THAT MUST BE IDENTICAL ON EVERY CPU.
    //
    // tuning_knobs_map is per-CPU, which makes divergence expressible -- and
    // for these two it would be a defect rather than a feature. tau and
    // codel_eq are topology-owned and drive tau-scaling, which every CPU
    // re-derives from the same constant.
    //
    // Broadcast rather than trusted: the writer overwrites these in every slot
    // from slot 0, so a caller cannot diverge them by omission.
    fn broadcast_global_fields(per_cpu: &mut [TuningKnobs]) {
        let (first, rest) = match per_cpu.split_first_mut() {
            Some(v) => v,
            None => return,
        };
        for k in rest.iter_mut() {
            k.topology_tau_ns = first.topology_tau_ns;
            k.codel_eq_ns = first.codel_eq_ns;
        }
    }

    // WRITE ONE KNOB SET TO EVERY CPU -- CALLED BY MONITOR THREAD.
    // Behaviorally identical to the pre-per-CPU map: every slot holds the same
    // struct, so no CPU can observe a value another CPU does not.
    pub fn write_tuning_knobs(&self, knobs: &TuningKnobs) -> Result<()> {
        let n = libbpf_rs::num_possible_cpus()?;
        self.write_tuning_knobs_percpu(&vec![*knobs; n])
    }

    // WRITE PER-CPU KNOBS. The per-CPU fields (slice, batch and burst ceilings,
    // the CoDel rescue threshold) may differ per slot; the two global fields are
    // broadcast from slot 0 regardless of what the caller put in the others.
    pub fn write_tuning_knobs_percpu(&self, per_cpu: &[TuningKnobs]) -> Result<()> {
        let n = libbpf_rs::num_possible_cpus()?;
        let mut vals: Vec<TuningKnobs> = (0..n)
            .map(|i| per_cpu.get(i).copied().unwrap_or_else(|| per_cpu[0]))
            .collect();
        Self::broadcast_global_fields(&mut vals);
        let key = 0u32.to_ne_bytes();
        let sz = std::mem::size_of::<TuningKnobs>();
        let bytes: Vec<Vec<u8>> = vals
            .iter()
            .map(|k| unsafe {
                std::slice::from_raw_parts(k as *const TuningKnobs as *const u8, sz).to_vec()
            })
            .collect();
        self.skel
            .maps
            .tuning_knobs_map
            .update_percpu(&key, &bytes, libbpf_rs::MapFlags::ANY)?;
        Ok(())
    }

    // WRITE THE TOPOLOGY-OWNED KNOBS: tau_ns, codel_eq_ns AND THE BASE SET,
    // WHICH IS A FUNCTION OF tau ALONE (scaled_regime_knobs AT THE STARTUP
    // REGIME). THE BASE IS TOPOLOGY, SO --no-adaptive RUNS IT TOO AND THE TWO
    // ARMS DIFFER BY THE LOOP ALONE. CALLED AT TOPOLOGY DETECT AND ON HOTPLUG: A
    // HOTPLUG RESETS THE ADAPTIVE LOOP'S KNOBS TO THE NEW BASE, AND ITS NEXT
    // RETUNE RE-DERIVES FROM THERE. A ZERO tau (NO SPECTRUM) WRITES THE TWO
    // TOPOLOGY FIELDS ALONE AND LEAVES THE REST AS THEY ARE.
    pub fn write_topology_fields(&self, tau_ns: u64, codel_eq_ns: u64, nr_cpus: u64) -> Result<()> {
        let mut knobs = if tau_ns > 0 {
            scaled_regime_knobs(Regime::Mixed, nr_cpus, tau_ns)
        } else {
            self.read_tuning_knobs()
        };
        knobs.topology_tau_ns = tau_ns;
        knobs.codel_eq_ns = codel_eq_ns;
        self.write_tuning_knobs(&knobs)
    }

    // READ BPF OSCILLATOR STATE FROM BSS/DATA SECTIONS.
    //
    // The BPF oscillator is the only thing adapting on rescue count. The
    // adaptive loop reads where it sits so a knob write defers while the
    // oscillator is already responding (OscillatorState::responding): two
    // controllers on the same error would fight.
    pub fn read_oscillator_state(&self) -> OscillatorState {
        let bss = match self.skel.maps.bss_data.as_ref() {
            Some(b) => b,
            None => return OscillatorState::default(),
        };
        let data = match self.skel.maps.data_data.as_ref() {
            Some(d) => d,
            None => return OscillatorState::default(),
        };
        OscillatorState {
            codel_target_ns: bss.codel_target_ns,
            codel_target_floor_ns: bss.codel_target_floor_ns,
            codel_target_max_ns: data.codel_target_max_ns,
            // NEAREST-PEER PHI HOLD WARM-STAY PRICES IN (SLOT 0 = CHEAPEST
            // PEER, THE VALUE warm_seat_pick READS FOR THE HOME CPU). CPU 0
            // IS REPRESENTATIVE ON A HOMOGENEOUS TOPOLOGY.
            home_dist_extra_ns: self.read_reff_value(0, 0) as u64,
        }
    }

    // READ PER-CPU TUNING KNOBS. One entry per CPU; the six global fields are
    // identical across slots by construction (broadcast_global_fields).
    pub fn read_tuning_knobs_percpu(&self) -> Vec<TuningKnobs> {
        let key = 0u32.to_ne_bytes();
        let vals = match self
            .skel
            .maps
            .tuning_knobs_map
            .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(v)) => v,
            _ => return Vec::new(),
        };
        let sz = std::mem::size_of::<TuningKnobs>();
        vals.iter()
            .filter(|v| v.len() >= sz)
            .map(|v| unsafe { std::ptr::read_unaligned(v.as_ptr() as *const TuningKnobs) })
            .collect()
    }

    // READ CURRENT TUNING KNOBS -- CPU 0'S SLOT.
    //
    // Every existing caller wants either a global field (tau, codel_eq) or the
    // value it just wrote uniformly, and both are identical on every CPU, so
    // slot 0 is the same answer this returned before the map was per-CPU. A
    // caller that needs a PER-CPU knob must use read_tuning_knobs_percpu() --
    // this one cannot represent divergence and must not be used to look for it.
    pub fn read_tuning_knobs(&self) -> TuningKnobs {
        self.read_tuning_knobs_percpu()
            .first()
            .copied()
            .unwrap_or_default()
    }

    // READ WAKEUP LATENCY HISTOGRAM: 3 TIERS x 12 BUCKETS
    // SUMS ACROSS ALL CPUs (PERCPU_ARRAY). RETURNS CUMULATIVE COUNTS.
    pub fn read_wake_lat_hist(&self) -> [[u64; 12]; 3] {
        let mut result = [[0u64; 12]; 3];
        for key_idx in 0u32..36 {
            let key = key_idx.to_ne_bytes();
            if let Ok(Some(percpu_vals)) = self
                .skel
                .maps
                .wake_lat_hist
                .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
            {
                let tier = (key_idx / 12) as usize;
                let bucket = (key_idx % 12) as usize;
                for cpu_val in &percpu_vals {
                    if cpu_val.len() >= std::mem::size_of::<u64>() {
                        let val: u64 =
                            unsafe { std::ptr::read_unaligned(cpu_val.as_ptr() as *const u64) };
                        result[tier][bucket] += val;
                    }
                }
            }
        }
        result
    }

    // READ SLEEP DURATION HISTOGRAM: 4 BUCKETS
    // SUMS ACROSS ALL CPUs (PERCPU_ARRAY). RETURNS CUMULATIVE COUNTS.
    pub fn read_sleep_hist(&self) -> [u64; 4] {
        let mut result = [0u64; 4];
        for key_idx in 0u32..4 {
            let key = key_idx.to_ne_bytes();
            if let Ok(Some(percpu_vals)) = self
                .skel
                .maps
                .sleep_hist
                .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
            {
                for cpu_val in &percpu_vals {
                    if cpu_val.len() >= std::mem::size_of::<u64>() {
                        let val: u64 =
                            unsafe { std::ptr::read_unaligned(cpu_val.as_ptr() as *const u64) };
                        result[key_idx as usize] += val;
                    }
                }
            }
        }
        result
    }

    // POPULATE CACHE DOMAIN MAP FROM TOPOLOGY DATA AT STARTUP
    pub fn write_cache_domain(&self, cpu: u32, l2_group: u32) -> Result<()> {
        let key = cpu.to_ne_bytes();
        let val = l2_group.to_ne_bytes();
        self.skel
            .maps
            .cache_domain
            .update(&key, &val, libbpf_rs::MapFlags::ANY)?;
        Ok(())
    }

    // POPULATE EMERGENT OVERFLOW-DOMAIN MAP (T3b.2). cpu_domain[cpu] = the
    // emergent domain id from the T2 tree (the discrete domain map replacement).
    pub fn write_cpu_domain(&self, cpu: u32, domain: u32) -> Result<()> {
        let key = cpu.to_ne_bytes();
        let val = domain.to_ne_bytes();
        self.skel
            .maps
            .cpu_domain
            .update(&key, &val, libbpf_rs::MapFlags::ANY)?;
        Ok(())
    }

    // SET nr_overflow_domains (post-load mutable global). Walked from topology at startup.
    // Gates how many of the MAX_OVERFLOW_DOMAINS per-domain overflow DSQs are addressed
    // by dispatch drain loops.
    pub fn write_nr_overflow_domains(&mut self, nr_overflow_domains: u32) {
        if let Some(data) = self.skel.maps.data_data.as_mut() {
            data.nr_overflow_domains = nr_overflow_domains;
        }
    }

    // SET affinity_domain_peers (post-load mutable global). The MINIMUM over CPUs of
    // how many affinity_rank slots stay inside that CPU's own cache domain, floored
    // at 1 by the caller. Bounds the affinity idle-search FLOOR so the walk cannot be
    // forced past a domain narrower than the old constant 3.
    pub fn write_affinity_domain_peers(&mut self, peers: u32) {
        if let Some(data) = self.skel.maps.data_data.as_mut() {
            data.affinity_domain_peers = peers;
        }
    }

    // POPULATE RESISTANCE AFFINITY RANK MAP
    // affinity_rank[cpu * MAX_AFFINITY_CANDIDATES + slot] = target_cpu
    // SORTED BY ASCENDING R_EFF FROM LAPLACIAN PSEUDOINVERSE
    pub fn write_affinity_rank(&self, cpu: u32, slot: u32, target_cpu: u32) -> Result<()> {
        // Stride = MAX_AFFINITY_CANDIDATES. Single source of truth is the
        // C macro in src/bpf/intf.h, mirrored in bpf_intf.rs. The
        // static_assert above catches drift at compile time.
        let stride = crate::bpf_intf::MAX_AFFINITY_CANDIDATES;
        let key = (cpu * stride + slot).to_ne_bytes();
        let val = target_cpu.to_ne_bytes();
        self.skel
            .maps
            .affinity_rank
            .update(&key, &val, libbpf_rs::MapFlags::ANY)?;
        Ok(())
    }

    // POPULATE R_eff COST ORACLE MAP (PAIRS 1:1 WITH affinity_rank).
    // reff_value[cpu * MAX_AFFINITY_CANDIDATES + slot] = quantized R_eff TO THAT TARGET.
    pub fn write_reff_value(&self, cpu: u32, slot: u32, value: u32) -> Result<()> {
        let stride = crate::bpf_intf::MAX_AFFINITY_CANDIDATES;
        let key = (cpu * stride + slot).to_ne_bytes();
        let val = value.to_ne_bytes();
        self.skel
            .maps
            .reff_value
            .update(&key, &val, libbpf_rs::MapFlags::ANY)?;
        Ok(())
    }

    // POPULATE EMERGENT-DOMAIN CROSSING-PRICE MAP (PAIRS 1:1 WITH affinity_rank).
    // domain_phi[cpu * MAX_AFFINITY_CANDIDATES + slot] = (phi * 1e6) OF THE CUT
    // SEPARATING cpu FROM THAT RANKED PEER. (u32)-1 = SAME LEAF / UNUSED SLOT.
    pub fn write_domain_phi(&self, cpu: u32, slot: u32, value: u32) -> Result<()> {
        let stride = crate::bpf_intf::MAX_AFFINITY_CANDIDATES;
        let key = (cpu * stride + slot).to_ne_bytes();
        let val = value.to_ne_bytes();
        self.skel
            .maps
            .domain_phi
            .update(&key, &val, libbpf_rs::MapFlags::ANY)?;
        Ok(())
    }

    // POPULATE THE DIMENSIONLESS R_eff MAP (PAIRS 1:1 WITH affinity_rank).
    // reff_frac[cpu * MAX_AFFINITY_CANDIDATES + slot] = R_eff(cpu, peer) as a Q16
    // fraction of the machine's R_eff span. 0 = adjacent, 65536 = most distant
    // pair. (u32)-1 = unused slot. The wake-path placement price multiplies this
    // by codel_target_ns; the steal keeps reading reff_value's tau fold.
    pub fn write_reff_frac(&self, cpu: u32, slot: u32, value: u32) -> Result<()> {
        let stride = crate::bpf_intf::MAX_AFFINITY_CANDIDATES;
        let key = (cpu * stride + slot).to_ne_bytes();
        let val = value.to_ne_bytes();
        self.skel
            .maps
            .reff_frac
            .update(&key, &val, libbpf_rs::MapFlags::ANY)?;
        Ok(())
    }

    // READ ONE reff_value SLOT (ns PHI HOLD TO THAT RANKED PEER). RETURNS 0 ON
    // MISS OR THE (u32)-1 UNUSED-SLOT SENTINEL. USED BY THE ADAPTIVE LOOP TO
    // LEARN THE NEAREST-PEER HOLD WARM-STAY PRICES IN (SLOT 0 = CHEAPEST PEER).
    pub fn read_reff_value(&self, cpu: u32, slot: u32) -> u32 {
        let stride = crate::bpf_intf::MAX_AFFINITY_CANDIDATES;
        let key = (cpu * stride + slot).to_ne_bytes();
        match self
            .skel
            .maps
            .reff_value
            .lookup(&key, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(bytes)) if bytes.len() >= 4 => {
                let v = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if v == u32::MAX { 0 } else { v }
            }
            _ => 0,
        }
    }

    // READ UEI EXIT INFO. RETURNS (should_restart).
    pub fn read_exit_info(&self) -> bool {
        let data = self.skel.maps.data_data.as_ref().unwrap();
        let kind = data.uei.kind;
        let exit_code = data.uei.exit_code;

        if kind != SCX_EXIT_NONE {
            let reason_bytes: &[u8] =
                unsafe { std::slice::from_raw_parts(data.uei.reason.as_ptr() as *const u8, 128) };
            let msg_bytes: &[u8] =
                unsafe { std::slice::from_raw_parts(data.uei.msg.as_ptr() as *const u8, 1024) };

            let reason = std::str::from_utf8(reason_bytes)
                .unwrap_or("unknown")
                .trim_end_matches('\0');
            let msg = std::str::from_utf8(msg_bytes)
                .unwrap_or("")
                .trim_end_matches('\0');

            log_warn!("BPF exit: kind={} code={}", kind, exit_code);
            if !reason.is_empty() {
                log_warn!("BPF exit reason: {}", reason);
            }
            if !msg.is_empty() {
                log_warn!("BPF exit msg: {}", msg);
            }
        }

        (exit_code as u64 & SCX_ECODE_RST_MASK) != 0
    }

    pub fn exited(&self) -> bool {
        self.skel.maps.data_data.as_ref().unwrap().uei.kind != SCX_EXIT_NONE
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        let _ = self.skel.maps.tuning_knobs_map.unpin(KNOBS_PIN);
        let _ = self
            .skel
            .maps
            .cache_domain
            .unpin("/sys/fs/bpf/pandemonium/cache_domain");
        let _ = std::fs::remove_dir("/sys/fs/bpf/pandemonium");
    }
}
