// PANDEMONIUM SCHEDULER
// WRAPS THE BPF SKELETON: OPEN, CONFIGURE, LOAD, ATTACH, SHUTDOWN
// MONITORING AND ADAPTIVE CONTROL LIVE IN adaptive.rs

use std::mem::MaybeUninit;

use anyhow::Result;
use libbpf_rs::MapCore;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::bpf_skel::*;
use crate::tuning::TuningKnobs;
use pandemonium::event::EventLog;

// SCX EXIT CODES (FROM KERNEL)
const SCX_EXIT_NONE: i32 = 0;
const SCX_ECODE_RST_MASK: u64 = 1 << 16;

// SCX DSQ FLAGS (STABLE KERNEL ABI -- sched_ext/sched.h)
const SCX_DSQ_FLAG_BUILTIN:  u64 = 1u64 << 63;
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
    pub wake_lat_max: u64,
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
    pub nr_guard_clamps: u64,
    pub nr_procdb_hits: u64,
    pub nr_l2_hit_batch: u64,
    pub nr_l2_miss_batch: u64,
    pub nr_l2_hit_interactive: u64,
    pub nr_l2_miss_interactive: u64,
    pub nr_l2_hit_lat_crit: u64,
    pub nr_l2_miss_lat_crit: u64,
}

// COMPILE-TIME ABI SAFETY: MUST MATCH STRUCT LAYOUTS IN intf.h
const _: () = assert!(std::mem::size_of::<PandemoniumStats>() == 192);
const _: () = assert!(std::mem::size_of::<TuningKnobs>() == 56);

// TuningKnobs lives in tuning.rs (zero BPF dependencies, testable offline)

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
        adaptive: bool,
    ) -> Result<Self> {
        // OPEN
        let builder = MainSkelBuilder::default();
        let mut open_skel = builder.open(open_object)?;

        // CONFIGURE RODATA (BEFORE LOAD)
        let rodata = open_skel.maps.rodata_data.as_mut().unwrap();

        let possible = libbpf_rs::num_possible_cpus()? as u64;
        rodata.nr_cpu_ids = nr_cpus_override.unwrap_or(possible);
        rodata.ringbuf_active = adaptive;

        // POPULATE SCX ENUM VALUES
        rodata.__SCX_DSQ_FLAG_BUILTIN  = SCX_DSQ_FLAG_BUILTIN;
        rodata.__SCX_DSQ_FLAG_LOCAL_ON = SCX_DSQ_FLAG_LOCAL_ON;
        rodata.__SCX_DSQ_INVALID       = SCX_DSQ_FLAG_BUILTIN;
        rodata.__SCX_DSQ_GLOBAL        = SCX_DSQ_FLAG_BUILTIN | 1;
        rodata.__SCX_DSQ_LOCAL         = SCX_DSQ_FLAG_BUILTIN | SCX_DSQ_FLAG_LOCAL_ON;
        rodata.__SCX_DSQ_LOCAL_ON      = SCX_DSQ_FLAG_BUILTIN | SCX_DSQ_FLAG_LOCAL_ON | 1;
        rodata.__SCX_DSQ_LOCAL_CPU_MASK = 0xFFFFFFFF;

        // POPULATE SCX_KICK_* ENUM VALUES
        rodata.__SCX_KICK_IDLE    = 1;
        rodata.__SCX_KICK_PREEMPT = 2;
        rodata.__SCX_KICK_WAIT    = 4;

        // LOAD (VALIDATES BPF WITH KERNEL)
        let mut skel = open_skel.load()?;

        // ATTACH STRUCT_OPS
        let link = skel.maps.pandemonium_ops.attach_struct_ops()?;

        // PIN MAPS FOR USERSPACE ACCESS
        let pin_dir = "/sys/fs/bpf/pandemonium";
        std::fs::create_dir_all(pin_dir).ok();

        let rb_pin = "/sys/fs/bpf/pandemonium/wake_lat_rb";
        std::fs::remove_file(rb_pin).ok();
        skel.maps.wake_lat_rb.pin(rb_pin)?;

        std::fs::remove_file(KNOBS_PIN).ok();
        skel.maps.tuning_knobs_map.pin(KNOBS_PIN)?;

        let cache_pin = "/sys/fs/bpf/pandemonium/cache_domain";
        std::fs::remove_file(cache_pin).ok();
        skel.maps.cache_domain.pin(cache_pin)?;

        let observe_pin = "/sys/fs/bpf/pandemonium/task_class_observe";
        std::fs::remove_file(observe_pin).ok();
        skel.maps.task_class_observe.pin(observe_pin)?;

        let init_pin = "/sys/fs/bpf/pandemonium/task_class_init";
        std::fs::remove_file(init_pin).ok();
        skel.maps.task_class_init.pin(init_pin)?;

        let compositor_pin = "/sys/fs/bpf/pandemonium/compositor_map";
        std::fs::remove_file(compositor_pin).ok();
        skel.maps.compositor_map.pin(compositor_pin)?;

        Ok(Self {
            skel,
            _link: link,
            log: EventLog::new(),
        })
    }

    // SUM PER-CPU STATS INTO A SINGLE TOTAL
    pub fn read_stats(&self) -> PandemoniumStats {
        let key = 0u32.to_ne_bytes();
        let mut total = PandemoniumStats::default();

        let percpu_vals = match self.skel.maps.stats_map.lookup_percpu(&key, libbpf_rs::MapFlags::ANY) {
            Ok(Some(v)) => v,
            _ => return total,
        };

        for cpu_val in &percpu_vals {
            if cpu_val.len() >= std::mem::size_of::<PandemoniumStats>() {
                let stats: PandemoniumStats = unsafe {
                    std::ptr::read_unaligned(cpu_val.as_ptr() as *const PandemoniumStats)
                };
                total.nr_dispatches += stats.nr_dispatches;
                total.nr_idle_hits += stats.nr_idle_hits;
                total.nr_shared += stats.nr_shared;
                total.nr_preempt += stats.nr_preempt;
                total.wake_lat_sum += stats.wake_lat_sum;
                if stats.wake_lat_max > total.wake_lat_max {
                    total.wake_lat_max = stats.wake_lat_max;
                }
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
                total.nr_guard_clamps += stats.nr_guard_clamps;
                total.nr_procdb_hits += stats.nr_procdb_hits;
                total.nr_l2_hit_batch += stats.nr_l2_hit_batch;
                total.nr_l2_miss_batch += stats.nr_l2_miss_batch;
                total.nr_l2_hit_interactive += stats.nr_l2_hit_interactive;
                total.nr_l2_miss_interactive += stats.nr_l2_miss_interactive;
                total.nr_l2_hit_lat_crit += stats.nr_l2_hit_lat_crit;
                total.nr_l2_miss_lat_crit += stats.nr_l2_miss_lat_crit;
            }
        }

        total
    }

    // WRITE TUNING KNOBS TO BPF MAP -- CALLED BY MONITOR THREAD
    pub fn write_tuning_knobs(&self, knobs: &TuningKnobs) -> Result<()> {
        let key = 0u32.to_ne_bytes();
        let value = unsafe {
            std::slice::from_raw_parts(
                knobs as *const TuningKnobs as *const u8,
                std::mem::size_of::<TuningKnobs>(),
            )
        };
        self.skel.maps.tuning_knobs_map.update(&key, value, libbpf_rs::MapFlags::ANY)?;
        Ok(())
    }

    // READ CURRENT TUNING KNOBS FROM BPF MAP
    pub fn read_tuning_knobs(&self) -> TuningKnobs {
        let key = 0u32.to_ne_bytes();
        match self.skel.maps.tuning_knobs_map.lookup(&key, libbpf_rs::MapFlags::ANY) {
            Ok(Some(v)) if v.len() >= std::mem::size_of::<TuningKnobs>() => unsafe {
                std::ptr::read_unaligned(v.as_ptr() as *const TuningKnobs)
            },
            _ => TuningKnobs::default(),
        }
    }

    // BUILD RING BUFFER FOR WAKE LATENCY SAMPLES
    // CALLER PROVIDES CALLBACK. RING BUFFER OWNS THE FD INTERNALLY --
    // SAFE TO MOVE TO ANOTHER THREAD.
    pub fn build_wake_lat_ring_buffer<F: FnMut(&[u8]) -> i32 + 'static>(
        &self,
        callback: F,
    ) -> Result<libbpf_rs::RingBuffer<'static>> {
        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder.add(&self.skel.maps.wake_lat_rb, callback)?;
        builder.build().map_err(Into::into)
    }

    // OPEN AN INDEPENDENT HANDLE TO THE PINNED TUNING KNOBS MAP
    // RETURNS AN OWNED MapHandle THAT CAN BE SENT TO ANOTHER THREAD.
    // CALL AFTER init() HAS PINNED THE MAP.
    pub fn knobs_map_handle() -> Result<libbpf_rs::MapHandle> {
        libbpf_rs::MapHandle::from_pinned_path(KNOBS_PIN).map_err(Into::into)
    }

    // POPULATE CACHE DOMAIN MAP FROM TOPOLOGY DATA AT STARTUP
    pub fn write_cache_domain(&self, cpu: u32, l2_group: u32) -> Result<()> {
        let key = cpu.to_ne_bytes();
        let val = l2_group.to_ne_bytes();
        self.skel.maps.cache_domain.update(&key, &val, libbpf_rs::MapFlags::ANY)?;
        Ok(())
    }

    // POPULATE COMPOSITOR MAP ENTRY
    pub fn write_compositor(&self, name: &str) -> Result<()> {
        let mut key = [0u8; 16];
        let bytes = name.as_bytes();
        let len = bytes.len().min(15);
        key[..len].copy_from_slice(&bytes[..len]);
        let val = [1u8];
        self.skel.maps.compositor_map.update(&key, &val, libbpf_rs::MapFlags::ANY)?;
        Ok(())
    }

    // READ UEI EXIT INFO. RETURNS (should_restart).
    pub fn read_exit_info(&self) -> bool {
        let data = self.skel.maps.data_data.as_ref().unwrap();
        let kind = data.uei.kind;
        let exit_code = data.uei.exit_code;

        if kind != SCX_EXIT_NONE {
            let reason_bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(data.uei.reason.as_ptr() as *const u8, 128)
            };
            let msg_bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(data.uei.msg.as_ptr() as *const u8, 1024)
            };

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
        let _ = self.skel.maps.wake_lat_rb.unpin("/sys/fs/bpf/pandemonium/wake_lat_rb");
        let _ = self.skel.maps.tuning_knobs_map.unpin(KNOBS_PIN);
        let _ = self.skel.maps.cache_domain.unpin("/sys/fs/bpf/pandemonium/cache_domain");
        let _ = self.skel.maps.task_class_observe.unpin("/sys/fs/bpf/pandemonium/task_class_observe");
        let _ = self.skel.maps.task_class_init.unpin("/sys/fs/bpf/pandemonium/task_class_init");
        let _ = self.skel.maps.compositor_map.unpin("/sys/fs/bpf/pandemonium/compositor_map");
        let _ = std::fs::remove_dir("/sys/fs/bpf/pandemonium");
    }
}
