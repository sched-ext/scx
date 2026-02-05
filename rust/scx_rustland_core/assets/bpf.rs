// Copyright (c) Andrea Righi <andrea.righi@linux.dev>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::mem::MaybeUninit;

use crate::bpf_intf;
use crate::bpf_intf::*;
use crate::bpf_skel::*;

use std::ffi::c_int;
use std::ffi::c_ulong;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Once;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

use plain::Plain;
use procfs::process::all_processes;

use libbpf_rs::libbpf_sys::bpf_object_open_opts;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;

use libc::{c_char, pthread_self, pthread_setschedparam, sched_param};

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
const TASK_COMM_LEN: usize = 16;

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

// Task queued for scheduling from the BPF component (see bpf_intf::queued_task_ctx).
#[derive(Debug, PartialEq, Eq, PartialOrd, Clone)]
pub struct QueuedTask {
    pub pid: i32,             // pid that uniquely identifies a task
    pub cpu: i32,             // CPU previously used by the task
    pub nr_cpus_allowed: u64, // Number of CPUs that the task can use
    pub flags: u64,           // task's enqueue flags
    pub start_ts: u64,        // Timestamp since last time the task ran on a CPU (in ns)
    pub stop_ts: u64,         // Timestamp since last time the task released a CPU (in ns)
    pub exec_runtime: u64,    // Total cpu time since last sleep (in ns)
    pub weight: u64,          // Task priority in the range [1..10000] (default is 100)
    pub vtime: u64,           // Current task vruntime / deadline (set by the scheduler)
    pub enq_cnt: u64,
    pub comm: [c_char; TASK_COMM_LEN], // Task's executable name
}

impl QueuedTask {
    /// Convert the task's comm field (C char array) into a Rust String.
    #[allow(dead_code)]
    pub fn comm_str(&self) -> String {
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(self.comm.as_ptr() as *const u8, self.comm.len()) };

        // Find the first NUL byte, or take the whole array.
        let nul_pos = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());

        // Convert to String (handle invalid UTF-8 gracefully).
        String::from_utf8_lossy(&bytes[..nul_pos]).into_owned()
    }
}

// Task queued for dispatching to the BPF component (see bpf_intf::dispatched_task_ctx).
#[derive(Debug, PartialEq, Eq, PartialOrd, Clone)]
pub struct DispatchedTask {
    pub pid: i32,      // pid that uniquely identifies a task
    pub cpu: i32, // target CPU selected by the scheduler (RL_CPU_ANY = dispatch on the first CPU available)
    pub flags: u64, // task's enqueue flags
    pub slice_ns: u64, // time slice in nanoseconds assigned to the task (0 = use default time slice)
    pub vtime: u64, // this value can be used to send the task's vruntime or deadline directly to the underlying BPF dispatcher
    pub enq_cnt: u64,
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
            slice_ns: 0, // use default time slice
            vtime: 0,
            enq_cnt: task.enq_cnt,
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
            nr_cpus_allowed: self.inner.nr_cpus_allowed,
            flags: self.inner.flags,
            start_ts: self.inner.start_ts,
            stop_ts: self.inner.stop_ts,
            exec_runtime: self.inner.exec_runtime,
            weight: self.inner.weight,
            vtime: self.inner.vtime,
            enq_cnt: self.inner.enq_cnt,
            comm: self.inner.comm,
        }
    }
}

pub struct BpfScheduler<'cb> {
    pub skel: BpfSkel<'cb>,                // Low-level BPF connector
    shutdown: Arc<AtomicBool>,             // Determine scheduler shutdown
    queued: libbpf_rs::RingBuffer<'cb>,    // Ring buffer of queued tasks
    dispatched: libbpf_rs::UserRingBuffer, // User Ring buffer of dispatched tasks
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

static SET_HANDLER: Once = Once::new();

fn set_ctrlc_handler(shutdown: Arc<AtomicBool>) -> Result<(), anyhow::Error> {
    SET_HANDLER.call_once(|| {
        let shutdown_clone = shutdown.clone();
        ctrlc::set_handler(move || {
            shutdown_clone.store(true, Ordering::Relaxed);
        })
        .expect("Error setting Ctrl-C handler");
    });
    Ok(())
}

impl<'cb> BpfScheduler<'cb> {
    pub fn init(
        open_object: &'cb mut MaybeUninit<OpenObject>,
        open_opts: Option<bpf_object_open_opts>,
        exit_dump_len: u32,
        partial: bool,
        debug: bool,
        builtin_idle: bool,
        slice_ns: u64,
        name: &str,
    ) -> Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        set_ctrlc_handler(shutdown.clone()).context("Error setting Ctrl-C handler")?;

        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(debug);
        let mut skel = scx_ops_open!(skel_builder, open_object, rustland, open_opts)?;

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
            #[allow(static_mut_refs)]
            unsafe {
                // SAFETY: copying from the BPF ring buffer to BUF is safe, since the size of BUF
                // is exactly the size of QueuedTask and the callback operates in chunks of
                // QueuedTask items. It also copies exactly one QueuedTask at a time, this is
                // guaranteed by the error code returned by this callback (see below). From a
                // thread-safety perspective this is also correct, assuming the caller is a
                // single-thread process (as it is for now).
                BUF.0.copy_from_slice(data);
            }

            // Return 0 to indicate successful completion of the copy.
            0
        }

        // Check host topology to determine if we need to enable SMT capabilities.
        let topo = Topology::new().unwrap();
        skel.maps.rodata_data.as_mut().unwrap().smt_enabled = topo.smt_enabled;

        // Enable scheduler flags.
        skel.struct_ops.rustland_mut().flags =
            *compat::SCX_OPS_ENQ_LAST | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;
        if partial {
            skel.struct_ops.rustland_mut().flags |= *compat::SCX_OPS_SWITCH_PARTIAL;
        }
        skel.struct_ops.rustland_mut().exit_dump_len = exit_dump_len;
        skel.maps.rodata_data.as_mut().unwrap().usersched_pid = std::process::id();
        skel.maps.rodata_data.as_mut().unwrap().khugepaged_pid = Self::khugepaged_pid();
        skel.maps.rodata_data.as_mut().unwrap().builtin_idle = builtin_idle;
        skel.maps.rodata_data.as_mut().unwrap().slice_ns = slice_ns;
        skel.maps.rodata_data.as_mut().unwrap().debug = debug;
        let _ = Self::set_scx_ops_name(&mut skel.struct_ops.rustland_mut().name, name);

        // Attach BPF scheduler.
        let mut skel = scx_ops_load!(skel, rustland, uei)?;

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

        // Lock all the memory to prevent page faults that could trigger potential deadlocks during
        // scheduling.
        ALLOCATOR.lock_memory();
        ALLOCATOR.disable_mmap().expect("Failed to disable mmap");

        // Make sure to use the SCHED_EXT class at least for the scheduler itself.
        if partial {
            let err = Self::use_sched_ext();
            if err < 0 {
                return Err(anyhow::Error::msg(format!(
                    "sched_setscheduler error: {err}"
                )));
            }
        }

        Ok(Self {
            skel,
            shutdown,
            queued,
            dispatched,
            struct_ops,
        })
    }

    // Set the name of the scx ops.
    fn set_scx_ops_name(name_field: &mut [i8], src: &str) -> Result<()> {
        if !src.is_ascii() {
            bail!("name must be an ASCII string");
        }

        let bytes = src.as_bytes();
        let n = bytes.len().min(name_field.len().saturating_sub(1));

        name_field.fill(0);
        for i in 0..n {
            name_field[i] = bytes[i] as i8;
        }

        let version_suffix = ::scx_utils::build_id::ops_version_suffix(env!("CARGO_PKG_VERSION"));
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

        Ok(())
    }

    // Return the PID of khugepaged, if present, otherwise return 0.
    fn khugepaged_pid() -> u32 {
        let procs = match all_processes() {
            Ok(p) => p,
            Err(_) => return 0,
        };

        for proc in procs {
            let proc = match proc {
                Ok(p) => p,
                Err(_) => continue,
            };

            if let Ok(stat) = proc.stat() {
                if proc.exe().is_err() && stat.comm == "khugepaged" {
                    return proc.pid() as u32;
                }
            }
        }

        0
    }

    // Notify the BPF component that the user-space scheduler has completed its scheduling cycle,
    // updating the amount tasks that are still pending.
    //
    // NOTE: do not set allow(dead_code) for this method, any scheduler must use this method at
    // some point, otherwise the BPF component will keep waking-up the user-space scheduler in a
    // busy loop, causing unnecessary high CPU consumption.
    pub fn notify_complete(&mut self, nr_pending: u64) {
        self.skel.maps.bss_data.as_mut().unwrap().nr_scheduled = nr_pending;
        std::thread::yield_now();
    }

    // Counter of the online CPUs.
    #[allow(dead_code)]
    pub fn nr_online_cpus_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.as_mut().unwrap().nr_online_cpus
    }

    // Counter of currently running tasks.
    #[allow(dead_code)]
    pub fn nr_running_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.as_mut().unwrap().nr_running
    }

    // Counter of queued tasks.
    #[allow(dead_code)]
    pub fn nr_queued_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.as_mut().unwrap().nr_queued
    }

    // Counter of scheduled tasks.
    #[allow(dead_code)]
    pub fn nr_scheduled_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.as_mut().unwrap().nr_scheduled
    }

    // Counter of user dispatch events.
    #[allow(dead_code)]
    pub fn nr_user_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.as_mut().unwrap().nr_user_dispatches
    }

    // Counter of user kernel events.
    #[allow(dead_code)]
    pub fn nr_kernel_dispatches_mut(&mut self) -> &mut u64 {
        &mut self
            .skel
            .maps
            .bss_data
            .as_mut()
            .unwrap()
            .nr_kernel_dispatches
    }

    // Counter of cancel dispatch events.
    #[allow(dead_code)]
    pub fn nr_cancel_dispatches_mut(&mut self) -> &mut u64 {
        &mut self
            .skel
            .maps
            .bss_data
            .as_mut()
            .unwrap()
            .nr_cancel_dispatches
    }

    // Counter of dispatches bounced to the shared DSQ.
    #[allow(dead_code)]
    pub fn nr_bounce_dispatches_mut(&mut self) -> &mut u64 {
        &mut self
            .skel
            .maps
            .bss_data
            .as_mut()
            .unwrap()
            .nr_bounce_dispatches
    }

    // Counter of failed dispatch events.
    #[allow(dead_code)]
    pub fn nr_failed_dispatches_mut(&mut self) -> &mut u64 {
        &mut self
            .skel
            .maps
            .bss_data
            .as_mut()
            .unwrap()
            .nr_failed_dispatches
    }

    // Counter of scheduler congestion events.
    #[allow(dead_code)]
    pub fn nr_sched_congested_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.as_mut().unwrap().nr_sched_congested
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
    #[allow(dead_code)]
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
    #[allow(static_mut_refs)]
    pub fn dequeue_task(&mut self) -> Result<Option<QueuedTask>, i32> {
        let bss_data = self.skel.maps.bss_data.as_mut().unwrap();
        
        // Try to consume the first task from the ring buffer.
        match self.queued.consume_raw_n(1) {
            0 => {
                // Ring buffer is empty.
                bss_data.nr_queued = 0;
                Ok(None)
            }
            1 => {
                // A valid task is received, convert data to a proper task struct.
                let task = unsafe { EnqueuedMessage::from_bytes(&BUF.0).to_queued_task() };
                bss_data.nr_queued = bss_data.nr_queued.saturating_sub(1);

                Ok(Some(task))
            }
            res if res < 0 => Err(res),
            res => panic!("Unexpected return value from libbpf-rs::consume_raw(): {res}"),
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
            enq_cnt,
            ..
        } = &mut dispatched_task.as_mut();

        *pid = task.pid;
        *cpu = task.cpu;
        *flags = task.flags;
        *slice_ns = task.slice_ns;
        *vtime = task.vtime;
        *enq_cnt = task.enq_cnt;

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
        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

// Disconnect the low-level BPF scheduler.
impl Drop for BpfScheduler<'_> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
        ALLOCATOR.unlock_memory();
    }
}
