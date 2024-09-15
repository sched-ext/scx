// Copyright (c) Andrea Righi <andrea.righi@linux.dev>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::mem::MaybeUninit;

use crate::bpf_intf;
use crate::bpf_intf::*;
use crate::bpf_skel::*;

use std::ffi::c_int;
use std::ffi::c_ulong;
use std::fs::File;
use std::io::Read;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;

use plain::Plain;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;

use libc::{pthread_self, pthread_setschedparam, sched_param};

#[cfg(target_env = "musl")]
use libc::timespec;

use scx_utils::compat;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;

use scx_rustland_core::ALLOCATOR;

// Defined in UAPI
const SCHED_EXT: i32 = 7;

// Allow to dispatch the task on any CPU.
//
// The task will be dispatched to the global shared DSQ and it will run on the first CPU available.
#[allow(dead_code)]
pub const RL_CPU_ANY: i32 = bpf_intf::RL_CPU_ANY as i32;

/// High-level Rust abstraction to interact with a generic sched-ext BPF component.
///
/// Overview
/// ========
///
/// The main BPF interface is provided by the BpfScheduler() struct. When this object is
/// initialized it will take care of registering and initializing the BPF component.
///
/// The scheduler then can use BpfScheduler() instance to receive tasks (in the form of QueuedTask
/// objects) and dispatch tasks (in the form of DispatchedTask objects), using respectively the
/// methods dequeue_task() and dispatch_task().
///
/// BPF counters and statistics can be accessed using the methods nr_*_mut(), in particular
/// nr_queued_mut() and nr_scheduled_mut() can be updated to notify the BPF component if the
/// user-space scheduler has some pending work to do or not.
///
/// Finally the methods exited() and shutdown_and_report() can be used respectively to test
/// whether the BPF component exited, and to shutdown and report the exit message.
/// whether the BPF component exited, and to shutdown and report exit message.

// Task queued for scheduling from the BPF component (see bpf_intf::queued_task_ctx).
#[derive(Debug, PartialEq, Eq, PartialOrd, Clone)]
pub struct QueuedTask {
    pub pid: i32,              // pid that uniquely identifies a task
    pub cpu: i32,              // CPU where the task is running
    pub flags: u64,            // task enqueue flags
    pub sum_exec_runtime: u64, // Total cpu time
    pub weight: u64,           // Task static priority
    cpumask_cnt: u64,          // cpumask generation counter (private)
}

// Task queued for dispatching to the BPF component (see bpf_intf::dispatched_task_ctx).
#[derive(Debug, PartialEq, Eq, PartialOrd, Clone)]
pub struct DispatchedTask {
    pub pid: i32,      // pid that uniquely identifies a task
    pub cpu: i32,      // target CPU selected by the scheduler
    pub flags: u64,    // special dispatch flags
    pub slice_ns: u64, // time slice assigned to the task (0 = default)
    pub vtime: u64,    // task deadline / vruntime
    cpumask_cnt: u64,  // cpumask generation counter (private)
}

impl DispatchedTask {
    // Create a DispatchedTask from a QueuedTask.
    //
    // A dispatched task should be always originated from a QueuedTask (there is no reason to
    // dispatch a task if it wasn't queued to the scheduler earlier).
    pub fn new(task: &QueuedTask) -> Self {
        DispatchedTask {
            pid: task.pid,
            cpu: task.cpu,
            flags: task.flags,
            cpumask_cnt: task.cpumask_cnt,
            slice_ns: 0, // use default time slice
            vtime: 0,
        }
    }
}

// Helpers used to submit tasks to the BPF user ring buffer.
unsafe impl Plain for bpf_intf::dispatched_task_ctx {}

impl AsMut<bpf_intf::dispatched_task_ctx> for bpf_intf::dispatched_task_ctx {
    fn as_mut(&mut self) -> &mut bpf_intf::dispatched_task_ctx {
        self
    }
}

// Message received from the dispatcher (see bpf_intf::queued_task_ctx for details).
//
// NOTE: eventually libbpf-rs will provide a better abstraction for this.
struct EnqueuedMessage {
    inner: bpf_intf::queued_task_ctx,
}

impl EnqueuedMessage {
    fn from_bytes(bytes: &[u8]) -> Self {
        let queued_task_struct = unsafe { *(bytes.as_ptr() as *const bpf_intf::queued_task_ctx) };
        EnqueuedMessage {
            inner: queued_task_struct,
        }
    }

    fn to_queued_task(&self) -> QueuedTask {
        QueuedTask {
            pid: self.inner.pid,
            cpu: self.inner.cpu,
            flags: self.inner.flags,
            sum_exec_runtime: self.inner.sum_exec_runtime,
            weight: self.inner.weight,
            cpumask_cnt: self.inner.cpumask_cnt,
        }
    }
}

pub struct BpfScheduler<'cb> {
    pub skel: BpfSkel<'cb>,                // Low-level BPF connector
    shutdown: Arc<AtomicBool>,             // Determine scheduler shutdown
    queued: libbpf_rs::RingBuffer<'cb>,    // Ring buffer of queued tasks
    dispatched: libbpf_rs::UserRingBuffer, // User Ring buffer of dispatched tasks
    cpu_hotplug_cnt: u64,                  // CPU hotplug generation counter
    struct_ops: Option<libbpf_rs::Link>,   // Low-level BPF methods
}

// Buffer to store a task read from the ring buffer.
//
// NOTE: make the buffer aligned to 64-bits to prevent misaligned dereferences when accessing the
// buffer using a pointer.
const BUFSIZE: usize = std::mem::size_of::<QueuedTask>();

#[repr(align(8))]
struct AlignedBuffer([u8; BUFSIZE]);

static mut BUF: AlignedBuffer = AlignedBuffer([0; BUFSIZE]);

// Special negative error code for libbpf to stop after consuming just one item from a BPF
// ring buffer.
const LIBBPF_STOP: i32 = -255;

fn is_smt_active() -> std::io::Result<bool> {
    let mut file = File::open("/sys/devices/system/cpu/smt/active")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let smt_active: i32 = contents.trim().parse().unwrap_or(0);

    Ok(smt_active == 1)
}

impl<'cb> BpfScheduler<'cb> {
    pub fn init(
        open_object: &'cb mut MaybeUninit<OpenObject>,
        exit_dump_len: u32,
        partial: bool,
        debug: bool,
    ) -> Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        ctrlc::set_handler(move || {
            shutdown_clone.store(true, Ordering::Relaxed);
        })
        .context("Error setting Ctrl-C handler")?;

        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(debug);
        let mut skel = scx_ops_open!(skel_builder, open_object, rustland)?;

        // Lock all the memory to prevent page faults that could trigger potential deadlocks during
        // scheduling.
        ALLOCATOR.lock_memory();

        // Copy one item from the ring buffer.
        //
        // # Safety
        //
        // Each invocation of the callback will trigger the copy of exactly one QueuedTask item to
        // BUF. The caller must be synchronize to ensure that multiple invocations of the callback
        // are not happening at the same time, but this is implicitly guaranteed by the fact that
        // the caller is a single-thread process (for now).
        //
        // Use of a `str` whose contents are not valid UTF-8 is undefined behavior.
        fn callback(data: &[u8]) -> i32 {
            unsafe {
                // SAFETY: copying from the BPF ring buffer to BUF is safe, since the size of BUF
                // is exactly the size of QueuedTask and the callback operates in chunks of
                // QueuedTask items. It also copies exactly one QueuedTask at a time, this is
                // guaranteed by the error code returned by this callback (see below). From a
                // thread-safety perspective this is also correct, assuming the caller is a
                // single-thread process (as it is for now).
                BUF.0.copy_from_slice(data);
            }

            // Return an unsupported error to stop early and consume only one item.
            //
            // NOTE: this is quite a hack. I wish libbpf would honor stopping after the first item
            // is consumed, upon returning a non-zero positive value here, but it doesn't seem to
            // be the case:
            //
            // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/lib/bpf/ringbuf.c?h=v6.8-rc5#n260
            //
            // Maybe we should fix this to stop processing items from the ring buffer also when a
            // value > 0 is returned.
            //
            LIBBPF_STOP
        }

        // Check host topology to determine if we need to enable SMT capabilities.
        skel.maps.rodata_data.smt_enabled = is_smt_active()?;

        // Set scheduler options (defined in the BPF part).
        if partial {
            skel.struct_ops.rustland_mut().flags |= *compat::SCX_OPS_SWITCH_PARTIAL;
        }
        skel.struct_ops.rustland_mut().exit_dump_len = exit_dump_len;

        skel.maps.bss_data.usersched_pid = std::process::id();
        skel.maps.rodata_data.debug = debug;

        // Attach BPF scheduler.
        let mut skel = scx_ops_load!(skel, rustland, uei)?;

        // Initialize cache domains.
        let topo = Topology::new().unwrap();
        Self::init_l2_cache_domains(&mut skel, &topo)?;
        Self::init_l3_cache_domains(&mut skel, &topo)?;

        let struct_ops = Some(scx_ops_attach!(skel, rustland)?);

        // Build the ring buffer of queued tasks.
        let maps = &skel.maps;
        let queued_ring_buffer = &maps.queued;
        let mut rbb = libbpf_rs::RingBufferBuilder::new();
        rbb.add(queued_ring_buffer, callback)
            .expect("failed to add ringbuf callback");
        let queued = rbb.build().expect("failed to build ringbuf");

        // Build the user ring buffer of dispatched tasks.
        let dispatched = libbpf_rs::UserRingBuffer::new(&maps.dispatched)
            .expect("failed to create user ringbuf");

        // Make sure to use the SCHED_EXT class at least for the scheduler itself.
        match Self::use_sched_ext() {
            0 => Ok(Self {
                skel,
                shutdown,
                queued,
                dispatched,
                cpu_hotplug_cnt: 0,
                struct_ops,
            }),
            err => Err(anyhow::Error::msg(format!(
                "sched_setscheduler error: {}",
                err
            ))),
        }
    }

    fn enable_sibling_cpu(
        skel: &mut BpfSkel<'_>,
        lvl: usize,
        cpu: usize,
        sibling_cpu: usize,
    ) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_sibling_cpu;
        let mut args = domain_arg {
            lvl_id: lvl as c_int,
            cpu_id: cpu as c_int,
            sibling_cpu_id: sibling_cpu as c_int,
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
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }

        Ok(())
    }

    fn init_cache_domains(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
        cache_lvl: usize,
        enable_sibling_cpu_fn: &dyn Fn(&mut BpfSkel<'_>, usize, usize, usize) -> Result<(), u32>,
    ) -> Result<(), std::io::Error> {
        // Determine the list of CPU IDs associated to each cache node.
        let mut cache_id_map: HashMap<usize, Vec<usize>> = HashMap::new();
        for core in topo.cores().into_iter() {
            for (cpu_id, cpu) in core.cpus() {
                let cache_id = match cache_lvl {
                    2 => cpu.l2_id(),
                    3 => cpu.l3_id(),
                    _ => panic!("invalid cache level {}", cache_lvl),
                };
                cache_id_map
                    .entry(cache_id)
                    .or_insert_with(Vec::new)
                    .push(*cpu_id);
            }
        }

        // Update the BPF cpumasks for the cache domains.
        for (_cache_id, cpus) in cache_id_map {
            for cpu in &cpus {
                for sibling_cpu in &cpus {
                    match enable_sibling_cpu_fn(skel, cache_lvl, *cpu, *sibling_cpu) {
                        Ok(()) => {}
                        Err(_) => {}
                    }
                }
            }
        }

        Ok(())
    }

    fn init_l2_cache_domains(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
    ) -> Result<(), std::io::Error> {
        Self::init_cache_domains(skel, topo, 2, &|skel, lvl, cpu, sibling_cpu| {
            Self::enable_sibling_cpu(skel, lvl, cpu, sibling_cpu)
        })
    }

    fn init_l3_cache_domains(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
    ) -> Result<(), std::io::Error> {
        Self::init_cache_domains(skel, topo, 3, &|skel, lvl, cpu, sibling_cpu| {
            Self::enable_sibling_cpu(skel, lvl, cpu, sibling_cpu)
        })
    }

    fn refresh_cache_domains(&mut self) {
        // Check if we need to refresh the CPU cache information.
        if self.cpu_hotplug_cnt == self.skel.maps.bss_data.cpu_hotplug_cnt {
            return;
        }

        // Re-initialize cache domains.
        let topo = Topology::new().unwrap();
        Self::init_l2_cache_domains(&mut self.skel, &topo).unwrap();
        Self::init_l3_cache_domains(&mut self.skel, &topo).unwrap();

        // Update CPU hotplug generation counter.
        self.cpu_hotplug_cnt = self.skel.maps.bss_data.cpu_hotplug_cnt;
    }

    // Notify the BPF component that the user-space scheduler has completed its scheduling cycle,
    // updating the amount tasks that are still peding.
    //
    // NOTE: do not set allow(dead_code) for this method, any scheduler must use this method at
    // some point, otherwise the BPF component will keep waking-up the user-space scheduler in a
    // busy loop, causing unnecessary high CPU consumption.
    pub fn notify_complete(&mut self, nr_pending: u64) {
        self.refresh_cache_domains();
        self.skel.maps.bss_data.nr_scheduled = nr_pending;
        std::thread::yield_now();
    }

    // Counter of the online CPUs.
    #[allow(dead_code)]
    pub fn nr_online_cpus_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.nr_online_cpus
    }

    // Counter of currently running tasks.
    #[allow(dead_code)]
    pub fn nr_running_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.nr_running
    }

    // Counter of queued tasks.
    #[allow(dead_code)]
    pub fn nr_queued_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.nr_queued
    }

    // Counter of scheduled tasks.
    #[allow(dead_code)]
    pub fn nr_scheduled_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.nr_scheduled
    }

    // Counter of user dispatch events.
    #[allow(dead_code)]
    pub fn nr_user_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.nr_user_dispatches
    }

    // Counter of user kernel events.
    #[allow(dead_code)]
    pub fn nr_kernel_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.nr_kernel_dispatches
    }

    // Counter of cancel dispatch events.
    #[allow(dead_code)]
    pub fn nr_cancel_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.nr_cancel_dispatches
    }

    // Counter of dispatches bounced to the shared DSQ.
    #[allow(dead_code)]
    pub fn nr_bounce_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.nr_bounce_dispatches
    }

    // Counter of failed dispatch events.
    #[allow(dead_code)]
    pub fn nr_failed_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.nr_failed_dispatches
    }

    // Counter of scheduler congestion events.
    #[allow(dead_code)]
    pub fn nr_sched_congested_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.nr_sched_congested
    }

    // Set scheduling class for the scheduler itself to SCHED_EXT
    fn use_sched_ext() -> i32 {
        #[cfg(target_env = "gnu")]
        let param: sched_param = sched_param { sched_priority: 0 };
        #[cfg(target_env = "musl")]
        let param: sched_param = sched_param {
            sched_priority: 0,
            sched_ss_low_priority: 0,
            sched_ss_repl_period: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            sched_ss_init_budget: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            sched_ss_max_repl: 0,
        };

        unsafe { pthread_setschedparam(pthread_self(), SCHED_EXT, &param as *const sched_param) }
    }

    // Pick an idle CPU for the target PID.
    pub fn select_cpu(&mut self, pid: i32, cpu: i32, flags: u64) -> i32 {
        let prog = &mut self.skel.progs.rs_select_cpu;
        let mut args = task_cpu_arg {
            pid: pid as c_int,
            cpu: cpu as c_int,
            flags: flags as c_ulong,
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
        let out = prog.test_run(input).unwrap();

        out.return_value as i32
    }

    // Receive a task to be scheduled from the BPF dispatcher.
    pub fn dequeue_task(&mut self) -> Result<Option<QueuedTask>, i32> {
        match self.queued.consume_raw() {
            0 => {
                self.skel.maps.bss_data.nr_queued = 0;
                Ok(None)
            }
            LIBBPF_STOP => {
                // A valid task is received, convert data to a proper task struct.
                let task = unsafe { EnqueuedMessage::from_bytes(&BUF.0).to_queued_task() };
                self.skel.maps.bss_data.nr_queued -= 1;

                Ok(Some(task))
            }
            res if res < 0 => Err(res),
            res => panic!(
                "Unexpected return value from libbpf-rs::consume_raw(): {}",
                res
            ),
        }
    }

    // Send a task to the dispatcher.
    pub fn dispatch_task(&mut self, task: &DispatchedTask) -> Result<(), libbpf_rs::Error> {
        // Reserve a slot in the user ring buffer.
        let mut urb_sample = self
            .dispatched
            .reserve(std::mem::size_of::<bpf_intf::dispatched_task_ctx>())?;
        let bytes = urb_sample.as_mut();
        let dispatched_task = plain::from_mut_bytes::<bpf_intf::dispatched_task_ctx>(bytes)
            .expect("failed to convert bytes");

        // Convert the dispatched task into the low-level dispatched task context.
        let bpf_intf::dispatched_task_ctx {
            pid,
            cpu,
            flags,
            slice_ns,
            vtime,
            cpumask_cnt,
            ..
        } = &mut dispatched_task.as_mut();

        *pid = task.pid;
        *cpu = task.cpu;
        *flags = task.flags;
        *slice_ns = task.slice_ns;
        *vtime = task.vtime;
        *cpumask_cnt = task.cpumask_cnt;

        // Store the task in the user ring buffer.
        //
        // NOTE: submit() only updates the reserved slot in the user ring buffer, so it is not
        // expected to fail.
        self.dispatched
            .submit(urb_sample)
            .expect("failed to submit task");

        Ok(())
    }

    // Read exit code from the BPF part.
    pub fn exited(&mut self) -> bool {
        self.shutdown.load(Ordering::Relaxed) || uei_exited!(&self.skel, uei)
    }

    // Called on exit to shutdown and report exit message from the BPF part.
    pub fn shutdown_and_report(&mut self) -> Result<UserExitInfo> {
        self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

// Disconnect the low-level BPF scheduler.
impl<'a> Drop for BpfScheduler<'a> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
        ALLOCATOR.unlock_memory();
    }
}
