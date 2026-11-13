// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Will Clingan
// scx_panda LOADER
// OPEN, SIZE, LOAD, FILL, ATTACH, READ COUNTERS, READ THE EXIT. NOTHING HERE
// DECIDES ANYTHING ABOUT SCHEDULING.

use std::mem::MaybeUninit;

use anyhow::{Context, Result};
use libbpf_rs::MapCore;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::bpf_intf::{EWMA_HIST_BUCKETS, MAX_AFFINITY_CANDIDATES, MAX_CPUS, STEAL_REF_SLOTS};
use crate::bpf_skel::*;
use crate::topology::AffinityTables;

const SCX_EXIT_NONE: i32 = 0;
const SCX_ECODE_RST_MASK: u64 = 1 << 16;

// THE KERNEL'S EXIT DUMP, CARRIED IN THE EXIT INFO. THE PROGRAM'S
// exit_dump_len AND THE UEI BUFFER ARE SIZED TOGETHER.
pub const EXIT_DUMP_LEN: u32 = 262144;

// THE VERIFIER'S OWN COUNTS, ONE LINE PER PROGRAM, CAPTURED FROM libbpf's
// DEBUG PRINT WHEN --check ASKS FOR THEM. libbpf PRINTS EACH PROGRAM'S WHOLE
// LOAD LOG IN ONE CALL, HEADED BY THE PROGRAM'S NAME AND ENDED BY THE
// "processed N insns" SUMMARY THE STATS LOG LEVEL ADDS.
static VERIFIER_LINES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn capture_verifier_print(_level: libbpf_rs::PrintLevel, msg: String) {
    let mut prog = String::new();
    for line in msg.lines() {
        if let Some(rest) = line.strip_prefix("libbpf: prog '") {
            if let Some(end) = rest.find('\'') {
                prog = rest[..end].to_string();
            }
        }
        if line.starts_with("processed ") {
            if let Ok(mut v) = VERIFIER_LINES.lock() {
                v.push(format!("{prog}: {line}"));
            }
        }
    }
}

pub fn verifier_lines() -> Vec<String> {
    VERIFIER_LINES.lock().map(|v| v.clone()).unwrap_or_default()
}

// MATCHES struct panda_stats IN BPF (intf.h), FIELD FOR FIELD.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct PandaStats {
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
    pub nr_rescue: u64,
    pub nr_cross_domain: [u64; 6],
    pub nr_osc_park: u64,
    pub nr_spill_kick_preempt: u64,
    pub nr_steal: u64,
    pub nr_steal_lost: u64,
    pub nr_kick_declined: u64,
    pub nr_cut_reseat: u64,
    pub nr_steal_refused: [u64; STEAL_REF_SLOTS],
    pub nr_seat_expect_used: u64,
    pub nr_seat_expect_overrun: u64,
    pub ewma_hist: [u64; EWMA_HIST_BUCKETS],
    pub codel_target_live: u64,
}

// 20 SCALARS + 6 (nr_cross_domain) + 6 SCALARS + 16 (nr_steal_refused) +
// 2 SCALARS + 16 (ewma_hist) + 1 = 67 u64.
const _: () = assert!(std::mem::size_of::<PandaStats>() == 67 * 8);
const _: () = assert!(MAX_AFFINITY_CANDIDATES == MAX_CPUS >> 3);

pub struct Scheduler<'a> {
    skel: MainSkel<'a>,
    link: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    // OPEN THE OBJECT, WRITE RODATA, SIZE THE TOPOLOGY TABLES TO THIS BOX AND
    // LOAD. THE VERIFIER RUNS HERE. NOTHING IS ATTACHED YET.
    pub fn open_and_load(
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
        nr_cpus: u32,
        verifier_stats: bool,
    ) -> Result<Self> {
        // EVERY PER-CPU ARRAY IN THE PROGRAM, AND THE SEATS AND LANES init()
        // CREATES, STOP AT MAX_CPUS. A WIDER PART WOULD LOAD AND THEN SEAT TASKS
        // ON QUEUES THAT DO NOT EXIST, SO IT IS REFUSED HERE WITH THE REASON.
        if nr_cpus > MAX_CPUS {
            anyhow::bail!(
                "{} possible CPUs, and scx_panda's per-CPU tables hold {} (MAX_CPUS in src/bpf/intf.h): not loading",
                nr_cpus,
                MAX_CPUS
            );
        }
        if verifier_stats {
            libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Debug, capture_verifier_print)));
        }
        let builder = MainSkelBuilder::default();
        let mut open_skel = builder.open(open_object).context("open")?;

        // INJECT THE VERSION SUFFIX INTO THE OPS NAME FOR scx_loader
        {
            let ops = open_skel.struct_ops.panda_ops_mut();
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

        if verifier_stats {
            // BPF_LOG_STATS: THE VERIFIER APPENDS ITS INSTRUCTION AND STATE
            // COUNTS TO EACH PROGRAM'S LOG.
            for mut prog in open_skel.open_object_mut().progs_mut() {
                prog.set_log_level(4);
            }
        }

        {
            let rodata = open_skel
                .maps
                .rodata_data
                .as_mut()
                .context("rodata not mapped")?;
            rodata.nr_cpu_ids = nr_cpus as u64;
            rodata.uei_dump_len = EXIT_DUMP_LEN;
        }

        // THE sched_ext ENUM SHIMS, FROM THE RUNNING KERNEL'S BTF
        // VIA scx_utils.
        scx_utils::import_enums!(open_skel);

        // THE KERNEL'S HOTPLUG SEQUENCE, READ BEFORE THE TOPOLOGY IS. THE KERNEL
        // COMPARES IT AT ATTACH AND, WHEN A CPU WENT UP OR DOWN IN BETWEEN,
        // EXITS THE SCHEDULER WITH ITS RESTART CODE: TABLES BUILT AGAINST A SET
        // OF CPUs THAT HAS SINCE MOVED NEVER RUN, AND main()'s RESTART LOOP
        // DETECTS AGAIN. AN UNREADABLE SEQUENCE IS LEFT AT ZERO, WHICH THE
        // KERNEL DOES NOT COMPARE.
        if let Some(seq) = read_hotplug_seq() {
            open_skel.struct_ops.panda_ops_mut().hotplug_seq = seq;
        }

        // THE DYNAMIC ALLOCATION. THE TABLES ARE DECLARED AT MAX_CPUS AND
        // SIZED HERE TO THE CPUs THIS BOX HAS; THE BPF TREATS A LOOKUP PAST THE
        // END AS THE SENTINEL.
        let table = nr_cpus
            .checked_mul(MAX_AFFINITY_CANDIDATES)
            .context("affinity table size overflow")?;
        open_skel.maps.affinity_rank.set_max_entries(table)?;
        open_skel.maps.reff_value.set_max_entries(table)?;
        open_skel.maps.reff_frac.set_max_entries(table)?;
        open_skel.maps.domain_phi.set_max_entries(table)?;
        open_skel.maps.cache_domain.set_max_entries(nr_cpus)?;
        open_skel.maps.cpu_domain.set_max_entries(nr_cpus)?;
        // THE UEI DUMP BUFFER IS A RESIZABLE .data ARRAY; IT IS SIZED HERE TO
        // THE LENGTH THE PROGRAM's exit_dump_len AND uei_dump_len NAME.
        open_skel.maps.data_uei_dump.set_value_size(EXIT_DUMP_LEN)?;

        let skel = open_skel.load().context("load")?;
        Ok(Self { skel, link: None })
    }

    // THE KERNEL'S EXIT DUMP, EMPTY WHEN THE EXIT CARRIED NONE.
    pub fn read_exit_dump(&self) -> String {
        let key = 0u32.to_ne_bytes();
        match self
            .skel
            .maps
            .data_uei_dump
            .lookup(&key, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(bytes)) => cstr(&bytes),
            _ => String::new(),
        }
    }

    pub fn attach(&mut self) -> Result<()> {
        let link = self
            .skel
            .maps
            .panda_ops
            .attach_struct_ops()
            .context("attach")?;
        self.link = Some(link);
        Ok(())
    }

    pub fn read_stats_percpu(&self) -> Vec<PandaStats> {
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
        percpu_vals
            .iter()
            .filter(|v| v.len() >= std::mem::size_of::<PandaStats>())
            .map(|v| unsafe { std::ptr::read_unaligned(v.as_ptr() as *const PandaStats) })
            .collect()
    }

    // THE FOLD. codel_target_live TAKES A MAX ACROSS CPUs; EVERYTHING ELSE SUMS.
    pub fn fold_stats(percpu: &[PandaStats]) -> PandaStats {
        let mut t = PandaStats::default();
        for s in percpu {
            t.nr_dispatches += s.nr_dispatches;
            t.nr_idle_hits += s.nr_idle_hits;
            t.nr_shared += s.nr_shared;
            t.nr_preempt += s.nr_preempt;
            t.wake_lat_sum += s.wake_lat_sum;
            t.wake_lat_samples += s.wake_lat_samples;
            t.nr_keep_running += s.nr_keep_running;
            t.nr_hard_kicks += s.nr_hard_kicks;
            t.nr_soft_kicks += s.nr_soft_kicks;
            t.nr_enq_wakeup += s.nr_enq_wakeup;
            t.nr_enq_requeue += s.nr_enq_requeue;
            t.wake_lat_idle_sum += s.wake_lat_idle_sum;
            t.wake_lat_idle_cnt += s.wake_lat_idle_cnt;
            t.wake_lat_kick_sum += s.wake_lat_kick_sum;
            t.wake_lat_kick_cnt += s.wake_lat_kick_cnt;
            t.nr_l2_hit_batch += s.nr_l2_hit_batch;
            t.nr_l2_miss_batch += s.nr_l2_miss_batch;
            t.nr_l2_hit_interactive += s.nr_l2_hit_interactive;
            t.nr_l2_miss_interactive += s.nr_l2_miss_interactive;
            t.nr_rescue += s.nr_rescue;
            for i in 0..t.nr_cross_domain.len() {
                t.nr_cross_domain[i] += s.nr_cross_domain[i];
            }
            t.nr_osc_park += s.nr_osc_park;
            t.nr_spill_kick_preempt += s.nr_spill_kick_preempt;
            t.nr_steal += s.nr_steal;
            t.nr_steal_lost += s.nr_steal_lost;
            t.nr_kick_declined += s.nr_kick_declined;
            t.nr_cut_reseat += s.nr_cut_reseat;
            for i in 0..STEAL_REF_SLOTS {
                t.nr_steal_refused[i] += s.nr_steal_refused[i];
            }
            t.nr_seat_expect_used += s.nr_seat_expect_used;
            t.nr_seat_expect_overrun += s.nr_seat_expect_overrun;
            if s.codel_target_live > t.codel_target_live {
                t.codel_target_live = s.codel_target_live;
            }
            for i in 0..EWMA_HIST_BUCKETS {
                t.ewma_hist[i] += s.ewma_hist[i];
            }
        }
        t
    }

    pub fn read_stats(&self) -> PandaStats {
        Self::fold_stats(&self.read_stats_percpu())
    }

    // ONE ARRAY MAP, WHOLE, IN ONE CALL: values[k] TO KEY k. ONE ELEMENT A
    // SYSCALL WAS 512 SYSCALLS A CPU ACROSS THE FOUR TABLES, HALF A MILLION AT
    // 1,024 CPUs, AND ON HOTPLUG IT LEFT A WALK READING A ROW PART OLD AND PART
    // NEW FOR AS LONG AS THEY TOOK. THE KERNEL STILL COPIES ELEMENT BY ELEMENT,
    // SO A WALK CAN CROSS THE COPY; seat_ok() IS WHAT KEEPS A STALE ENTRY FROM
    // SEATING A TASK ON A CPU THAT WENT DOWN.
    fn write_table(map: &impl MapCore, values: &[u32]) -> Result<()> {
        let count = values.len() as u32;
        if count == 0 {
            return Ok(());
        }
        let keys: Vec<u8> = (0..count).flat_map(|k| k.to_ne_bytes()).collect();
        let vals: Vec<u8> = values.iter().flat_map(|v| v.to_ne_bytes()).collect();
        map.update_batch(
            &keys,
            &vals,
            count,
            libbpf_rs::MapFlags::ANY,
            libbpf_rs::MapFlags::ANY,
        )?;
        Ok(())
    }

    // cache_domain[cpu] = L2 GROUP.
    pub fn write_cache_domains(&self, l2_groups: &[u32]) -> Result<()> {
        Self::write_table(&self.skel.maps.cache_domain, l2_groups)
    }

    // cpu_domain[cpu] = EMERGENT DOMAIN.
    pub fn write_cpu_domains(&self, domains: &[u32]) -> Result<()> {
        Self::write_table(&self.skel.maps.cpu_domain, domains)
    }

    // THE FOUR TABLES PAIR 1:1 ON cpu * MAX_AFFINITY_CANDIDATES + slot. THE
    // RANK GOES FIRST: ITS SENTINEL IS WHERE EVERY WALK STOPS.
    pub fn write_affinity_tables(&self, t: &AffinityTables) -> Result<()> {
        Self::write_table(&self.skel.maps.affinity_rank, &t.rank)?;
        Self::write_table(&self.skel.maps.reff_value, &t.value)?;
        Self::write_table(&self.skel.maps.reff_frac, &t.frac)?;
        Self::write_table(&self.skel.maps.domain_phi, &t.phi)
    }

    // THE "GO" SIGNAL. WRITTEN LAST, AFTER EVERY TABLE, AND ITS GENERATION
    // AFTER ITS FIELDS: THE FIRST TICK THAT SEES A NEW GENERATION DERIVES
    // EVERYTHING topo FEEDS FROM FIELDS AND TABLES THAT ARE ALREADY WRITTEN.
    // THE MAP IS SHARED MEMORY THE PROGRAM READS WHILE THIS RUNS, SO THE FENCE
    // KEEPS THE GENERATION'S STORE BEHIND THE FIELDS'. A TOPOLOGY WHOSE tau DID
    // NOT MOVE STILL CARRIES A NEW GENERATION, AND ITS codel_eq_ns AND PEER
    // COUNT ARE APPLIED.
    pub fn write_topo(
        &mut self,
        tau_ns: u64,
        codel_eq_ns: u64,
        nr_domains: u32,
        affinity_domain_peers: u32,
    ) -> Result<()> {
        let data = self
            .skel
            .maps
            .data_data
            .as_mut()
            .context("data not mapped")?;
        data.topo.nr_domains = nr_domains;
        data.topo.affinity_domain_peers = affinity_domain_peers;
        data.topo.codel_eq_ns = codel_eq_ns;
        data.topo.tau_ns = tau_ns;
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        data.topo.generation = data.topo.generation.wrapping_add(1);
        Ok(())
    }

    // READ THE EXIT. RETURNS WHETHER THE KERNEL ASKED FOR A RESTART.
    pub fn read_exit_info(&self) -> bool {
        let Some(data) = self.skel.maps.data_data.as_ref() else {
            return false;
        };
        let kind = data.uei.kind;
        let exit_code = data.uei.exit_code;
        if kind != SCX_EXIT_NONE {
            let reason = cstr(&data.uei.reason);
            let msg = cstr(&data.uei.msg);
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
        self.skel
            .maps
            .data_data
            .as_ref()
            .map(|d| d.uei.kind != SCX_EXIT_NONE)
            .unwrap_or(true)
    }
}

// /sys/kernel/sched_ext/hotplug_seq: A COUNT THE KERNEL ADVANCES ON EVERY CPU
// ONLINE AND OFFLINE.
fn read_hotplug_seq() -> Option<u64> {
    std::fs::read_to_string("/sys/kernel/sched_ext/hotplug_seq")
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn cstr<T>(field: &[T]) -> String {
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(field.as_ptr() as *const u8, std::mem::size_of_val(field))
    };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
