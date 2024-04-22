// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::bpf_intf;
use crate::bpf_skel::*;

use anyhow::Context;
use anyhow::Result;

use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;

use libc::{sched_param, sched_setscheduler};

use scx_utils::compat;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::uei_exited;
use scx_utils::uei_report;

use scx_rustland_core::ALLOCATOR;

// Defined in UAPI
const SCHED_EXT: i32 = 7;

// Allow to dispatch the task on any CPU.
//
// The task will be dispatched to the global shared DSQ and it will run on the first CPU available.
#[allow(dead_code)]
pub const RL_CPU_ANY: i32 = bpf_intf::RL_CPU_ANY as i32;

// Allow to preempt the target CPU when dispatching the task.
#[allow(dead_code)]
pub const RL_PREEMPT_CPU: i32 = bpf_intf::RL_PREEMPT_CPU as i32;

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
/// The CPU ownership map can be accessed using the method get_cpu_pid(), this also allows to keep
/// track of the idle and busy CPUs, with the corresponding PIDs associated to them.
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
    pub cpu: i32,              // CPU where the task is running (-1 = exiting)
    pub sum_exec_runtime: u64, // Total cpu time
    pub nvcsw: u64,            // Voluntary context switches
    pub weight: u64,           // Task static priority
    cpumask_cnt: u64,          // cpumask generation counter (private)
}

// Task queued for dispatching to the BPF component (see bpf_intf::dispatched_task_ctx).
#[derive(Debug, PartialEq, Eq, PartialOrd, Clone)]
pub struct DispatchedTask {
    pid: i32,         // pid that uniquely identifies a task
    cpu: i32,         // target CPU selected by the scheduler
    slice_ns: u64,    // time slice assigned to the task (0 = default)
    cpumask_cnt: u64, // cpumask generation counter (private)
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
            cpumask_cnt: task.cpumask_cnt,
            slice_ns: 0, // use default time slice
        }
    }

    // Assign a specific CPU to a task.
    #[allow(dead_code)]
    pub fn set_cpu(&mut self, cpu: i32) {
        self.cpu = cpu;
    }

    // Assign a specific dispatch flag to a task.
    #[allow(dead_code)]
    pub fn set_flag(&mut self, flag: i32) {
        self.cpu |= flag;
    }

    // Assign a specific time slice to a task.
    #[allow(dead_code)]
    pub fn set_slice_ns(&mut self, slice_ns: u64) {
        self.slice_ns = slice_ns;
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
            cpumask_cnt: self.inner.cpumask_cnt,
            sum_exec_runtime: self.inner.sum_exec_runtime,
            nvcsw: self.inner.nvcsw,
            weight: self.inner.weight,
        }
    }
}

// Message sent to the dispatcher (see bpf_intf::dispatched_task_ctx for details).
//
// NOTE: eventually libbpf-rs will provide a better abstraction for this.
struct DispatchedMessage {
    inner: bpf_intf::dispatched_task_ctx,
}

impl DispatchedMessage {
    fn from_dispatched_task(task: &DispatchedTask) -> Self {
        let dispatched_task_struct = bpf_intf::dispatched_task_ctx {
            pid: task.pid,
            cpu: task.cpu,
            cpumask_cnt: task.cpumask_cnt,
            slice_ns: task.slice_ns,
        };
        DispatchedMessage {
            inner: dispatched_task_struct,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        let size = std::mem::size_of::<bpf_intf::dispatched_task_ctx>();
        let ptr = &self.inner as *const _ as *const u8;

        unsafe { std::slice::from_raw_parts(ptr, size) }
    }
}

pub struct BpfScheduler<'cb> {
    pub skel: BpfSkel<'cb>,              // Low-level BPF connector
    queued: libbpf_rs::RingBuffer<'cb>,  // Ring buffer of queued tasks
    struct_ops: Option<libbpf_rs::Link>, // Low-level BPF methods
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

impl<'cb> BpfScheduler<'cb> {
    pub fn init(
        slice_us: u64,
        nr_cpus_online: i32,
        partial: bool,
	exit_dump_len: u32,
        full_user: bool,
        debug: bool,
    ) -> Result<Self> {
        // Open the BPF prog first for verification.
        let skel_builder = BpfSkelBuilder::default();
        init_libbpf_logging(None);
        let mut skel = skel_builder.open().context("Failed to open BPF program")?;

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

        // Initialize online CPUs counter.
        //
        // NOTE: we should probably refresh this counter during the normal execution to support cpu
        // hotplugging, but for now let's keep it simple and set this only at initialization).
        skel.rodata_mut().num_possible_cpus = nr_cpus_online;

        // Set scheduler options (defined in the BPF part).
        if partial {
            skel.struct_ops.rustland_mut().flags |= *compat::SCX_OPS_SWITCH_PARTIAL;
        }
	skel.struct_ops.rustland_mut().exit_dump_len = exit_dump_len;

        skel.bss_mut().usersched_pid = std::process::id();
        skel.rodata_mut().slice_ns = slice_us * 1000;
        skel.rodata_mut().switch_partial = partial;
        skel.rodata_mut().debug = debug;
        skel.rodata_mut().full_user = full_user;

        // Attach BPF scheduler.
        let mut skel = scx_ops_load!(skel, rustland, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, rustland)?);

        // Build the ring buffer of queued tasks.
        let binding = skel.maps();
        let queued_ring_buffer = binding.queued();
        let mut rbb = libbpf_rs::RingBufferBuilder::new();
        rbb.add(queued_ring_buffer, callback)
            .expect("failed to add ringbuf callback");
        let queued = rbb.build().expect("failed to build ringbuf");

        // Make sure to use the SCHED_EXT class at least for the scheduler itself.
        match Self::use_sched_ext() {
            0 => Ok(Self {
                skel,
                queued,
                struct_ops,
            }),
            err => Err(anyhow::Error::msg(format!(
                "sched_setscheduler error: {}",
                err
            ))),
        }
    }

    // Update the amount of tasks that have been queued to the user-space scheduler and dispatched.
    //
    // This method is used to notify the BPF component if the user-space scheduler has still some
    // pending actions to complete (based on the counter of queued and scheduled tasks).
    //
    // NOTE: do not set allow(dead_code) for this method, any scheduler must use this method at
    // some point, otherwise the BPF component will keep waking-up the user-space scheduler in a
    // busy loop, causing unnecessary high CPU consumption.
    pub fn update_tasks(&mut self, nr_queued: Option<u64>, nr_scheduled: Option<u64>) {
        if let Some(queued) = nr_queued {
            self.skel.bss_mut().nr_queued = queued;
        }
        if let Some(scheduled) = nr_scheduled {
            self.skel.bss_mut().nr_scheduled = scheduled;
        }
    }

    // Override the default scheduler time slice (in us).
    #[allow(dead_code)]
    pub fn set_effective_slice_us(&mut self, slice_us: u64) {
        self.skel.bss_mut().effective_slice_ns = slice_us * 1000;
    }

    // Get current value of time slice (slice_ns).
    #[allow(dead_code)]
    pub fn get_effective_slice_us(&mut self) -> u64 {
        let slice_ns = self.skel.bss().effective_slice_ns;

        if slice_ns > 0 {
            slice_ns / 1000
        } else {
            self.skel.rodata().slice_ns / 1000
        }
    }

    // Counter of queued tasks.
    #[allow(dead_code)]
    pub fn nr_queued_mut(&mut self) -> &mut u64 {
        &mut self.skel.bss_mut().nr_queued
    }

    // Counter of scheduled tasks.
    #[allow(dead_code)]
    pub fn nr_scheduled_mut(&mut self) -> &mut u64 {
        &mut self.skel.bss_mut().nr_scheduled
    }

    // Counter of user dispatch events.
    #[allow(dead_code)]
    pub fn nr_user_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.bss_mut().nr_user_dispatches
    }

    // Counter of user kernel events.
    #[allow(dead_code)]
    pub fn nr_kernel_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.bss_mut().nr_kernel_dispatches
    }

    // Counter of cancel dispatch events.
    #[allow(dead_code)]
    pub fn nr_cancel_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.bss_mut().nr_cancel_dispatches
    }

    // Counter of dispatches bounced to the shared DSQ.
    #[allow(dead_code)]
    pub fn nr_bounce_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.bss_mut().nr_bounce_dispatches
    }

    // Counter of failed dispatch events.
    #[allow(dead_code)]
    pub fn nr_failed_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.bss_mut().nr_failed_dispatches
    }

    // Counter of scheduler congestion events.
    #[allow(dead_code)]
    pub fn nr_sched_congested_mut(&mut self) -> &mut u64 {
        &mut self.skel.bss_mut().nr_sched_congested
    }

    // Set scheduling class for the scheduler itself to SCHED_EXT
    fn use_sched_ext() -> i32 {
        let pid = std::process::id();
        let param: sched_param = sched_param { sched_priority: 0 };
        let res =
            unsafe { sched_setscheduler(pid as i32, SCHED_EXT, &param as *const sched_param) };
        res
    }

    // Get the pid running on a certain CPU, if no tasks are running return 0.
    #[allow(dead_code)]
    pub fn get_cpu_pid(&self, cpu: i32) -> u32 {
        let cpu_map_ptr = self.skel.bss().cpu_map.as_ptr();

        unsafe { *cpu_map_ptr.offset(cpu as isize) }
    }

    // Receive a task to be scheduled from the BPF dispatcher.
    //
    // NOTE: if task.cpu is negative the task is exiting and it does not require to be scheduled.
    pub fn dequeue_task(&mut self) -> Result<Option<QueuedTask>, i32> {
        match self.queued.consume_raw() {
            0 => Ok(None),
            LIBBPF_STOP => {
                // A valid task is received, convert data to a proper task struct.
                let task = unsafe { EnqueuedMessage::from_bytes(&BUF.0).to_queued_task() };
                Ok(Some(task))
            }
            res if res < 0 => Err(res),
            res => panic!("Unexpected return value from libbpf-rs::consume_raw(): {}", res),
        }
    }

    // Send a task to the dispatcher.
    pub fn dispatch_task(&mut self, task: &DispatchedTask) -> Result<(), libbpf_rs::Error> {
        let maps = self.skel.maps();
        let dispatched = maps.dispatched();
        let msg = DispatchedMessage::from_dispatched_task(&task);

        dispatched.update(&[], msg.as_bytes(), libbpf_rs::MapFlags::ANY)
    }

    // Read exit code from the BPF part.
    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    // Called on exit to shutdown and report exit message from the BPF part.
    pub fn shutdown_and_report(&mut self) -> Result<()> {
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
