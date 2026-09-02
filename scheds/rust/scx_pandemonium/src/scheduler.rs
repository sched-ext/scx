// PANDEMONIUM SCHEDULER
// WRAPS THE BPF SKELETON: OPEN, CONFIGURE, LOAD, ATTACH, SHUTDOWN
// MONITORING AND ADAPTIVE CONTROL LIVE IN adaptive.rs

use std::mem::MaybeUninit;

use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::MapCore;

use crate::bpf_skel::*;
use crate::tuning::{OscillatorState, TuningKnobs};
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
    // intf.h. PLACEMENT-SIDE PATHS FEED THE MWU SCATTER LOSS PATHWAY.
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
    // PER-CPU RUNNABLE DEPTH (intf.h rq_depth_sum / rq_depth_samples).
    // Monotonic accumulators sampled at tick rate; difference BOTH across an
    // interval and divide for the mean depth on that CPU, exactly as
    // wake_lat_sum/wake_lat_samples are already consumed. Read per-CPU via
    // read_stats_percpu() -- folding these to a total discards the spatial
    // dimension that is the entire reason they exist.
    pub rq_depth_sum: u64,
    pub rq_depth_samples: u64,
}

// COMPILE-TIME ABI SAFETY: MUST MATCH STRUCT LAYOUTS IN intf.h
// 184 (base, after the structurally empty latcrit l2 pair) + 8*8 (nr_cross_domain)
// + 8 (nr_osc_park) + 8 (nr_spill_kick_preempt) + 8 (nr_steal) + 8 (rq_depth_sum)
// + 8 (rq_depth_samples) = 288.
const _: () = assert!(std::mem::size_of::<PandemoniumStats>() == 288);
// 88 - 16 (lat_cri_thresh_high/_low, removed with the classifier that read them)
// - 8 (spill_temp_q16, computed every tick and consumed by nothing).
const _: () = assert!(std::mem::size_of::<TuningKnobs>() == 64);

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
        rodata.__SCX_DSQ_LOCAL = SCX_DSQ_FLAG_BUILTIN | SCX_DSQ_FLAG_LOCAL_ON;
        rodata.__SCX_DSQ_LOCAL_ON = SCX_DSQ_FLAG_BUILTIN | SCX_DSQ_FLAG_LOCAL_ON | 1;
        rodata.__SCX_DSQ_LOCAL_CPU_MASK = 0xFFFFFFFF;

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
                // Folded so the aggregate stays complete, but the SUMMED value
                // is close to meaningless -- it is the total depth seen across
                // every CPU. The per-CPU pair is the point; read it from
                // read_stats_percpu() and never from here.
                total.rq_depth_sum += stats.rq_depth_sum;
                total.rq_depth_samples += stats.rq_depth_samples;
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
    // for these three it would be a defect rather than a feature. tau and
    // codel_eq are topology-owned and drive tau-scaling, which every CPU
    // re-derives from the same constant; affinity_mode decides how a TASK is
    // placed, so a task would change placement depending on which CPU last
    // looked at it.
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
            k.affinity_mode = first.affinity_mode;
        }
    }

    // WRITE ONE KNOB SET TO EVERY CPU -- CALLED BY MONITOR THREAD.
    // Behaviorally identical to the pre-per-CPU map: every slot holds the same
    // struct, so no CPU can observe a value another CPU does not.
    pub fn write_tuning_knobs(&self, knobs: &TuningKnobs) -> Result<()> {
        let n = libbpf_rs::num_possible_cpus()?;
        self.write_tuning_knobs_percpu(&vec![*knobs; n])
    }

    // WRITE PER-CPU KNOBS. The per-CPU fields (slice, preempt window, batch and
    // burst ceilings, the CoDel rescue threshold) may differ per slot; the six
    // global fields are broadcast from slot 0 regardless of what the caller put
    // in the others.
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

    // WRITE TOPOLOGY-OWNED FIELDS (tau_ns + codel_eq_ns), PRESERVING OTHERS.
    // CALLED AT TOPOLOGY DETECT AND ON HOTPLUG. READ-MODIFY-WRITE BECAUSE THE
    // tuning_knobs_map IS A SINGLE-ENTRY STRUCT AND PARTIAL UPDATES AREN'T A
    // libbpf CONCEPT -- BUT WE NEED A NARROW SETTER SO TOPOLOGY CHANGES DON'T
    // STOMP ON WHATEVER THE ADAPTIVE LOOP'S LATEST KNOB VALUES ARE.
    pub fn write_topology_fields(&self, tau_ns: u64, codel_eq_ns: u64) -> Result<()> {
        let mut knobs = self.read_tuning_knobs();
        knobs.topology_tau_ns = tau_ns;
        knobs.codel_eq_ns = codel_eq_ns;
        self.write_tuning_knobs(&knobs)
    }

    // READ BPF OSCILLATOR STATE FROM BSS/DATA SECTIONS.
    //
    // Unused since MWU was removed, and kept deliberately. MWU read this to
    // avoid double-correcting: two controllers both adapting on
    // global_rescue_count would fight. That hazard is GONE -- the BPF
    // oscillator is now the only thing adapting on rescue count, and the graph
    // derives from depth, shape and persistence instead. The accessor stays
    // because the live-R_eff work reads the same maps.
    // MWU GATES ITS RESCUE-DRIVEN PATHWAYS ON THIS SO IT DOESN'T
    // DOUBLE-CORRECT WHEN THE BPF DAMPED OSCILLATOR HAS ALREADY MOVED.
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
            // PEER, THE VALUE warm_stay_anchor READS FOR THE HOME CPU). CPU 0
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

    // POPULATE L2 SIBLINGS MAP ENTRY
    pub fn write_l2_sibling(&self, group_id: u32, slot: u32, cpu: u32) -> Result<()> {
        let key = (group_id * 8 + slot).to_ne_bytes();
        let val = cpu.to_ne_bytes();
        self.skel
            .maps
            .l2_siblings
            .update(&key, &val, libbpf_rs::MapFlags::ANY)?;
        Ok(())
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

    // WRITE ONE spill_depth SLOT: THE PRE-FOLDED PHI PLACEMENT THRESHOLD (DSQ
    // DEPTH) FOR THE PEER AT affinity_rank[cpu][slot]. THE SPILL HELPER READS IT
    // AS THE PER-PEER DEPTH CAP -- THE PLACEMENT MIRROR OF reff_value's STEAL
    // DELAY.
    pub fn write_spill_depth(&self, cpu: u32, slot: u32, value: u32) -> Result<()> {
        let stride = crate::bpf_intf::MAX_AFFINITY_CANDIDATES;
        let key = (cpu * stride + slot).to_ne_bytes();
        let val = value.to_ne_bytes();
        self.skel
            .maps
            .spill_depth
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
                if v == u32::MAX {
                    0
                } else {
                    v
                }
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

// THE FOLD'S NOT-A-SUM FIELDS
//
// read_stats() returns a total derived from the per-CPU array. Three fields
// do not fold by addition, and getting any of them wrong changes numbers that
// every consumer already trusts, silently and in the safe-looking direction:
// a summed sojourn reads HIGHER than reality, a summed longrun flag reads as
// a count rather than a boolean, and an elementwise array folded as a scalar
// loses per-path attribution entirely. This pins all three against the shape
// the code had before the array was preserved.
#[cfg(test)]
mod fold_tests {
    use super::*;

    fn cpu(dispatches: u64, sojourn: u64, longrun: u64, xdom: [u64; 8]) -> PandemoniumStats {
        let mut s = PandemoniumStats::default();
        s.nr_dispatches = dispatches;
        s.batch_sojourn_ns = sojourn;
        s.longrun_mode_active = longrun;
        s.nr_cross_domain = xdom;
        s
    }

    #[test]
    fn counters_sum_across_cpus() {
        let cpus = [
            cpu(10, 0, 0, [0; 8]),
            cpu(7, 0, 0, [0; 8]),
            cpu(3, 0, 0, [0; 8]),
        ];
        assert_eq!(Scheduler::fold_stats(&cpus).nr_dispatches, 20);
    }

    #[test]
    fn sojourn_takes_the_max_not_the_sum() {
        // A system's worst batch sojourn is the worst any CPU saw, never the
        // sum of what all of them saw. Summing here would report 900ms where
        // the machine's actual worst wait was 500.
        let cpus = [
            cpu(0, 100, 0, [0; 8]),
            cpu(0, 500, 0, [0; 8]),
            cpu(0, 300, 0, [0; 8]),
        ];
        assert_eq!(Scheduler::fold_stats(&cpus).batch_sojourn_ns, 500);
    }

    #[test]
    fn longrun_flag_takes_the_max_not_the_sum() {
        // It is a mode flag. Summed across 20 CPUs it becomes a count and any
        // consumer testing `> 0` still passes, which is exactly why this would
        // survive review unnoticed.
        let cpus = [
            cpu(0, 0, 1, [0; 8]),
            cpu(0, 0, 1, [0; 8]),
            cpu(0, 0, 0, [0; 8]),
        ];
        assert_eq!(Scheduler::fold_stats(&cpus).longrun_mode_active, 1);
    }

    #[test]
    fn cross_domain_folds_elementwise_per_path() {
        let mut a = [0u64; 8];
        let mut b = [0u64; 8];
        a[0] = 5;
        a[3] = 2;
        b[0] = 1;
        b[7] = 9;
        let got = Scheduler::fold_stats(&[cpu(0, 0, 0, a), cpu(0, 0, 0, b)]).nr_cross_domain;
        assert_eq!(got[0], 6, "path 0 must sum across CPUs");
        assert_eq!(got[3], 2);
        assert_eq!(got[7], 9);
        assert_eq!(got[1], 0, "an untouched path stays zero");
    }

    #[test]
    fn empty_array_folds_to_default() {
        // A failed lookup returns an empty vec; the fold of nothing must be
        // the same zeroed struct the old early-return produced.
        let got = Scheduler::fold_stats(&[]);
        assert_eq!(got.nr_dispatches, 0);
        assert_eq!(got.batch_sojourn_ns, 0);
    }
}

// GLOBAL-FIELD COHERENCE ACROSS THE PER-CPU KNOB MAP
//
// Making the knob map per-CPU makes divergence EXPRESSIBLE, and for six of the
// eleven fields divergence is a defect rather than a feature: tau and codel_eq
// are topology-owned and every CPU re-derives its tau-scaled statics from them,
// while affinity_mode and the two lat_cri thresholds decide how a TASK is
// classified, so a task would change class depending on which CPU last looked
// at it. These pin the broadcast so a caller cannot diverge them by omission.
#[cfg(test)]
mod knob_broadcast_tests {
    use super::*;

    fn knobs(slice: u64, tau: u64) -> TuningKnobs {
        let mut k = TuningKnobs::default();
        k.slice_ns = slice;
        k.topology_tau_ns = tau;
        k
    }

    #[test]
    fn global_fields_are_broadcast_from_slot_zero() {
        let mut v = vec![knobs(100, 7_000), knobs(200, 9_999), knobs(300, 1)];
        Scheduler::broadcast_global_fields(&mut v);
        for (i, k) in v.iter().enumerate() {
            assert_eq!(k.topology_tau_ns, 7_000, "slot {i} diverged on tau");
        }
    }

    #[test]
    fn per_cpu_fields_survive_the_broadcast() {
        // The whole point: slices may differ per CPU. A broadcast that
        // flattened them would silently restore the global-only behavior this
        // change exists to remove.
        let mut v = vec![knobs(100, 7_000), knobs(200, 0), knobs(300, 0)];
        Scheduler::broadcast_global_fields(&mut v);
        assert_eq!(v[0].slice_ns, 100);
        assert_eq!(v[1].slice_ns, 200);
        assert_eq!(v[2].slice_ns, 300);
    }

    #[test]
    fn uniform_input_stays_uniform() {
        // The acceptance criterion for the whole change: identical values in
        // every slot must be indistinguishable from the pre-per-CPU map.
        let mut v = vec![knobs(100, 7_000); 8];
        let before = v.clone();
        Scheduler::broadcast_global_fields(&mut v);
        for (a, b) in before.iter().zip(v.iter()) {
            assert_eq!(a.slice_ns, b.slice_ns);
            assert_eq!(a.topology_tau_ns, b.topology_tau_ns);
        }
    }

    #[test]
    fn empty_and_single_slot_are_no_ops() {
        let mut none: Vec<TuningKnobs> = Vec::new();
        Scheduler::broadcast_global_fields(&mut none);
        let mut one = vec![knobs(100, 7_000)];
        Scheduler::broadcast_global_fields(&mut one);
        assert_eq!(one[0].slice_ns, 100);
    }
}
