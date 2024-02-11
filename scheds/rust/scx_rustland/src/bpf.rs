// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::bpf_intf;
use crate::bpf_skel::*;

use anyhow::Context;
use anyhow::Result;

use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::Skel as _;
use libbpf_rs::skel::SkelBuilder as _;

use libc::{sched_param, sched_setscheduler};

mod alloc;
use alloc::*;

use scx_utils::uei_exited;
use scx_utils::uei_report;

// Defined in UAPI
const SCHED_EXT: i32 = 7;

// Do not assign any specific CPU to the task.
//
// The task will be dispatched to the global shared DSQ and it will run on the first CPU available.
#[allow(dead_code)]
pub const NO_CPU: i32 = -1;

/// scx_rustland: provide high-level abstractions to interact with the BPF component.
///
/// Overview
/// ========
///
/// The main BPF interface is provided by the BpfScheduler() struct. When this object is
/// initialized it will take care of registering and initializing the BPF component.
///
/// The scheduler then can use BpfScheduler() instance to receive tasks (in the form of QueuedTask
/// object) and dispatch tasks (in the form of DispatchedTask objects), using respectively the
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
/// whether the BPF component exited, and to shutdown and report exit message.
///
/// Example
/// =======
///
/// Following you can find bare minimum template that can be used to implement a simple FIFO
/// scheduler using the BPF abstraction:
///
/// mod bpf_skel;
/// pub use bpf_skel::*;
/// mod bpf;
/// pub mod bpf_intf;
/// use bpf::*;
///
/// use std::thread;
///
/// use std::sync::atomic::AtomicBool;
/// use std::sync::atomic::Ordering;
/// use std::sync::Arc;
///
/// use anyhow::Result;
///
/// struct Scheduler<'a> {
///     bpf: BpfScheduler<'a>,
/// }
///
/// impl<'a> Scheduler<'a> {
///     fn init() -> Result<Self> {
///         let bpf = BpfScheduler::init(20000, false, false)?;
///         Ok(Self { bpf })
///     }
///
///     fn dispatch_tasks(&mut self) {
///         loop {
///             match self.bpf.dequeue_task() {
///                 Ok(Some(task)) => {
///                     if task.cpu >= 0  {
///                         let _ = self.bpf.dispatch_task(
///                             &DispatchedTask {
///                                 pid: task.pid,
///                                 cpu: task.cpu,
///                                 payload: 0,
///                             }
///                         );
///                     }
///                 }
///                 Ok(None) => {
///                     *self.bpf.nr_queued_mut() = 0;
///                     *self.bpf.nr_scheduled_mut() = 0;
///                     break;
///                 }
///                 Err(_) => {
///                     break;
///                 }
///             }
///         }
///     }
///
///     fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
///         while !shutdown.load(Ordering::Relaxed) && !self.bpf.exited() {
///             self.dispatch_tasks();
///             thread::yield_now();
///         }
///
///         Ok(())
///     }
/// }
///
/// fn main() -> Result<()> {
///     let mut sched = Scheduler::init()?;
///     let shutdown = Arc::new(AtomicBool::new(false));
///     let shutdown_clone = shutdown.clone();
///     ctrlc::set_handler(move || {
///         shutdown_clone.store(true, Ordering::Relaxed);
///     })?;
///
///     sched.run(shutdown)
/// }
///

// Task queued for scheduling from the BPF component (see bpf_intf::queued_task_ctx).
#[derive(Debug)]
pub struct QueuedTask {
    pub pid: i32,              // pid that uniquely identifies a task
    pub cpu: i32,              // CPU where the task is running (-1 = exiting)
    pub cpumask_cnt: u64,      // cpumask generation counter
    pub sum_exec_runtime: u64, // Total cpu time
    pub nvcsw: u64,            // Voluntary context switches
    pub weight: u64,           // Task static priority
}

// Task queued for dispatching to the BPF component (see bpf_intf::dispatched_task_ctx).
#[derive(Debug)]
pub struct DispatchedTask {
    pub pid: i32,              // pid that uniquely identifies a task
    pub cpu: i32,              // target CPU selected by the scheduler
    pub cpumask_cnt: u64,      // cpumask generation counter
    pub payload: u64,          // task payload (used for debugging)
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
            payload: task.payload,
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

pub struct BpfScheduler<'a> {
    pub skel: BpfSkel<'a>,               // Low-level BPF connector
    struct_ops: Option<libbpf_rs::Link>, // Low-level BPF methods
}

impl<'a> BpfScheduler<'a> {
    pub fn init(slice_us: u64, nr_cpus_online: i32, partial: bool, debug: bool) -> Result<Self> {
        // Open the BPF prog first for verification.
        let skel_builder = BpfSkelBuilder::default();
        let mut skel = skel_builder.open().context("Failed to open BPF program")?;

        // Lock all the memory to prevent page faults that could trigger potential deadlocks during
        // scheduling.
        ALLOCATOR.lock_memory();

        // Initialize online CPUs counter.
        //
        // NOTE: we should probably refresh this counter during the normal execution to support cpu
        // hotplugging, but for now let's keep it simple and set this only at initialization).
        skel.rodata_mut().num_possible_cpus = nr_cpus_online;

        // Set scheduler options (defined in the BPF part).
        skel.bss_mut().usersched_pid = std::process::id();
        skel.rodata_mut().slice_ns = slice_us * 1000;
        skel.rodata_mut().switch_partial = partial;
        skel.rodata_mut().debug = debug;

        // Attach BPF scheduler.
        let mut skel = skel.load().context("Failed to load BPF program")?;
        skel.attach().context("Failed to attach BPF program")?;
        let struct_ops = Some(
            skel.maps_mut()
                .rustland()
                .attach_struct_ops()
                .context("Failed to attach struct ops")?,
        );

        // Make sure to use the SCHED_EXT class at least for the scheduler itself.
        match Self::use_sched_ext() {
            0 => Ok(Self { skel, struct_ops }),
            err => Err(anyhow::Error::msg(format!(
                "sched_setscheduler error: {}",
                err
            ))),
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
    pub fn nr_queued_mut(&mut self) -> &mut u64 {
        &mut self.skel.bss_mut().nr_queued
    }

    // Counter of scheduled tasks.
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
        let maps = self.skel.maps();
        let cpu_map = maps.cpu_map();

        let key = cpu.to_ne_bytes();
        let value = cpu_map.lookup(&key, libbpf_rs::MapFlags::ANY).unwrap();
        let pid = value.map_or(0u32, |vec| {
            let mut array: [u8; 4] = Default::default();
            array.copy_from_slice(&vec[..std::cmp::min(4, vec.len())]);
            u32::from_le_bytes(array)
        });

        pid
    }

    // Receive a task to be scheduled from the BPF dispatcher.
    //
    // NOTE: if task.cpu is negative the task is exiting and it does not require to be scheduled.
    pub fn dequeue_task(&mut self) -> Result<Option<QueuedTask>, libbpf_rs::Error> {
        let maps = self.skel.maps();
        let queued = maps.queued();

        match queued.lookup_and_delete(&[]) {
            Ok(Some(msg)) => {
                let task = EnqueuedMessage::from_bytes(msg.as_slice()).to_queued_task();
                Ok(Some(task))
            }
            Ok(None) => Ok(None),
            Err(err) => Err(err),
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
        uei_exited!(&self.skel.bss().uei)
    }

    // Called on exit to shutdown and report exit message from the BPF part.
    pub fn shutdown_and_report(&mut self) -> Result<()> {
        self.struct_ops.take();
        uei_report!(self.skel.bss().uei)
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
