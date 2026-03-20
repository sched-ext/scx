// Copyright (c) Andrea Righi <andrea.righi@linux.dev>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::mem::MaybeUninit;
use std::rc::Rc;
use std::thread;
use std::time::{Duration, Instant};

use crate::bpf_intf;
use crate::bpf_intf::*;
use crate::bpf_skel::*;
use crate::BpfProfile;

use std::ffi::c_int;
use std::ffi::c_ulong;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use log::warn;

use plain::Plain;

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
const MAX_TOPO_CPUS: usize = bpf_intf::MAX_CPUS as usize;
const MAX_LLCS: usize = 64;
const MAX_NODES: usize = 64;

// Allow to dispatch the task on any CPU.
//
// The task will be dispatched to the global shared DSQ and it will run on the first CPU available.
#[allow(dead_code)]
pub const RL_CPU_ANY: i32 = bpf_intf::RL_CPU_ANY as i32;
const ROOT_OPS_PATH: &str = "/sys/kernel/sched_ext/root/ops";
const DETACH_WAIT_TIMEOUT: Duration = Duration::from_millis(500);
const DETACH_WAIT_POLL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone)]
struct TopologyExport {
    smt_enabled: bool,
    nr_llcs: u32,
    nr_nodes: u32,
    cpu_llc_idx_map: [u16; MAX_TOPO_CPUS],
    cpu_node_idx_map: [u16; MAX_TOPO_CPUS],
    llc_node_idx_map: [u16; MAX_LLCS],
}

impl Default for TopologyExport {
    fn default() -> Self {
        Self {
            smt_enabled: false,
            nr_llcs: 1,
            nr_nodes: 1,
            cpu_llc_idx_map: [0; MAX_TOPO_CPUS],
            cpu_node_idx_map: [0; MAX_TOPO_CPUS],
            llc_node_idx_map: [0; MAX_LLCS],
        }
    }
}

impl TopologyExport {
    fn detect() -> Self {
        let mut export = Self::default();

        match Topology::new() {
            Ok(topo) => {
                export.smt_enabled = topo.smt_enabled;

                if topo.all_llcs.is_empty() {
                    warn!("topology probe returned no LLC domains; falling back to a single logical LLC");
                    return export;
                }

                if topo.all_llcs.len() > MAX_LLCS {
                    warn!(
                        "host exposes {} LLC domains but Cognis supports at most {MAX_LLCS}; falling back to a single shared LLC domain",
                        topo.all_llcs.len()
                    );
                    return export;
                }

                if topo.nodes.len() > MAX_NODES {
                    warn!(
                        "host exposes {} NUMA domains but Cognis supports at most {MAX_NODES}; falling back to a single logical node",
                        topo.nodes.len()
                    );
                    return export;
                }

                let mut node_remap = BTreeMap::<usize, u16>::new();
                let mut llc_remap = BTreeMap::<usize, u16>::new();
                let mut next_node = 0u16;
                let mut next_llc = 0u16;

                for (&cpu_id, cpu) in &topo.all_cpus {
                    if cpu_id >= MAX_TOPO_CPUS {
                        warn!(
                            "ignoring CPU {} while exporting topology to BPF (max supported CPUs: {MAX_TOPO_CPUS})",
                            cpu_id
                        );
                        continue;
                    }

                    let node_idx = if let Some(&idx) = node_remap.get(&cpu.node_id) {
                        idx
                    } else {
                        let idx = next_node;
                        node_remap.insert(cpu.node_id, idx);
                        next_node = next_node.saturating_add(1);
                        idx
                    };

                    let llc_idx = if let Some(&idx) = llc_remap.get(&cpu.llc_id) {
                        idx
                    } else {
                        let idx = next_llc;
                        llc_remap.insert(cpu.llc_id, idx);
                        next_llc = next_llc.saturating_add(1);
                        idx
                    };

                    export.cpu_node_idx_map[cpu_id] = node_idx;
                    export.cpu_llc_idx_map[cpu_id] = llc_idx;
                    export.llc_node_idx_map[llc_idx as usize] = node_idx;
                }

                export.nr_nodes = u32::from(next_node).max(1);
                export.nr_llcs = u32::from(next_llc).max(1);
            }
            Err(err) => {
                warn!(
                    "topology probe failed while initializing BPF state: {err}; falling back to a single logical LLC and disabling SMT-specific heuristics"
                );
            }
        }

        export
    }
}

/// High-level Rust abstraction to interact with a generic sched-ext BPF component.
///
/// Overview
/// ========
///
/// The main BPF interface is provided by the `BpfScheduler` struct. When this object is
/// initialized it registers the BPF component, wires profile knobs into rodata,
/// and keeps the legacy userspace queue/dispatch rings available for the
/// narrow compatibility path.
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
    /// Borrow the task's comm field as UTF-8 without allocating.
    #[allow(dead_code)]
    pub fn comm_str(&self) -> &str {
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(self.comm.as_ptr() as *const u8, self.comm.len()) };

        // Find the first NUL byte, or take the whole array.
        let nul_pos = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());

        std::str::from_utf8(&bytes[..nul_pos]).unwrap_or("?")
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

fn current_root_ops_name() -> Option<String> {
    let content = fs::read_to_string(ROOT_OPS_PATH).ok()?;
    let name = content.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

fn decode_queued_task(data: &[u8]) -> Result<QueuedTask, i32> {
    if data.len() != std::mem::size_of::<bpf_intf::queued_task_ctx>() {
        return Err(-libc::EINVAL);
    }

    let inner = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const bpf_intf::queued_task_ctx) };
    Ok(QueuedTask {
        pid: inner.pid,
        cpu: inner.cpu,
        nr_cpus_allowed: inner.nr_cpus_allowed,
        flags: inner.flags,
        start_ts: inner.start_ts,
        stop_ts: inner.stop_ts,
        exec_runtime: inner.exec_runtime,
        weight: inner.weight,
        vtime: inner.vtime,
        enq_cnt: inner.enq_cnt,
        comm: inner.comm,
    })
}

fn decode_exited_pid(data: &[u8]) -> Result<i32, i32> {
    if data.len() != std::mem::size_of::<u32>() {
        return Err(-libc::EINVAL);
    }

    let pid = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const u32) };
    Ok(pid as i32)
}

pub struct BpfScheduler<'cb> {
    pub skel: BpfSkel<'cb>,                // Low-level BPF connector
    shutdown: Arc<AtomicBool>,             // Determine scheduler shutdown
    queued: libbpf_rs::RingBuffer<'cb>,    // Ring buffer of queued tasks
    task_exits: libbpf_rs::RingBuffer<'cb>, // Ring buffer of exiting task pids
    dispatched: libbpf_rs::UserRingBuffer, // User Ring buffer of dispatched tasks
    queued_slot: Rc<RefCell<Option<QueuedTask>>>,
    exited_pid_slot: Rc<RefCell<Option<i32>>>,
    struct_ops: Option<libbpf_rs::Link>,   // Low-level BPF methods
}

impl<'cb> BpfScheduler<'cb> {
    /// Initialise the BPF scheduler.
    ///
    /// `shutdown` must be the **process-level** `Arc<AtomicBool>` whose ctrlc
    /// handler was registered once in `main()`.  Sharing the same Arc across
    /// every restart iteration ensures that a SIGTERM received at any point —
    /// including the restart backoff window between two `run()` calls — is
    /// always observed by `bpf.exited()`, preventing the scheduler from
    /// ignoring a `systemctl stop` / `sudo kill` request.
    pub fn init(
        shutdown: Arc<AtomicBool>,
        open_object: &'cb mut MaybeUninit<OpenObject>,
        open_opts: Option<bpf_object_open_opts>,
        exit_dump_len: u32,
        partial: bool,
        debug: bool,
        builtin_idle: bool,
        profile: &BpfProfile,
        name: &str,
    ) -> Result<Self> {

        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(debug);
        let mut skel = scx_ops_open!(skel_builder, open_object, cognis, open_opts)?;

        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("missing rodata_data map in BPF skeleton")?;

        let topo = TopologyExport::detect();
        rodata.smt_enabled = topo.smt_enabled;
        rodata.nr_llcs = topo.nr_llcs;
        rodata.nr_nodes = topo.nr_nodes;
        rodata.cpu_llc_idx_map.copy_from_slice(&topo.cpu_llc_idx_map);
        rodata.cpu_node_idx_map.copy_from_slice(&topo.cpu_node_idx_map);
        rodata.llc_node_idx_map.copy_from_slice(&topo.llc_node_idx_map);

        // Enable scheduler flags.
        skel.struct_ops.cognis_mut().flags =
            *compat::SCX_OPS_ENQ_LAST | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;
        if partial {
            skel.struct_ops.cognis_mut().flags |= *compat::SCX_OPS_SWITCH_PARTIAL;
        }
        skel.struct_ops.cognis_mut().exit_dump_len = exit_dump_len;
        rodata.usersched_pid = std::process::id();
        rodata.builtin_idle = builtin_idle;
        rodata.slice_ns = profile.slice_ns;
        rodata.slice_min_ns = profile.slice_min_ns;
        rodata.slice_lag_ns = profile.slice_lag_ns;
        rodata.no_wake_sync = profile.no_wake_sync;
        rodata.sticky_tasks = profile.sticky_tasks;
        rodata.server_mode = profile.is_server();
        rodata.debug = debug;
        let _ = Self::set_scx_ops_name(&mut skel.struct_ops.cognis_mut().name, name);

        // Attach BPF scheduler.
        let mut skel = scx_ops_load!(skel, cognis, uei)?;
        let _ = skel
            .maps
            .bss_data
            .as_ref()
            .context("missing bss_data map in BPF skeleton")?;

        let struct_ops = Some(scx_ops_attach!(skel, cognis)?);

        let queued_slot = Rc::new(RefCell::new(None));
        let exit_slot = Rc::new(RefCell::new(None));

        // Build the ring buffer of queued tasks.
        let maps = &skel.maps;
        let queued_ring_buffer = &maps.queued;
        let mut rbb = libbpf_rs::RingBufferBuilder::new();
        {
            let queued_slot_cb = queued_slot.clone();
            rbb.add(queued_ring_buffer, move |data| match decode_queued_task(data) {
                Ok(task) => {
                    *queued_slot_cb.borrow_mut() = Some(task);
                    0
                }
                Err(err) => {
                    warn!("dropping malformed queued task message from BPF ringbuf: len={}", data.len());
                    err
                }
            })
            .context("failed to add ringbuf callback")?;
        }
        let queued = rbb.build().context("failed to build ringbuf")?;

        let exit_ring_buffer = &maps.task_exits;
        let mut ebb = libbpf_rs::RingBufferBuilder::new();
        {
            let exit_slot_cb = exit_slot.clone();
            ebb.add(exit_ring_buffer, move |data| match decode_exited_pid(data) {
                Ok(pid) => {
                    *exit_slot_cb.borrow_mut() = Some(pid);
                    0
                }
                Err(err) => {
                    warn!("dropping malformed task_exits message from BPF ringbuf: len={}", data.len());
                    err
                }
            })
            .context("failed to add task_exits ringbuf callback")?;
        }
        let task_exits = ebb
            .build()
            .context("failed to build task_exits ringbuf")?;

        // Build the user ring buffer of dispatched tasks.
        let dispatched = libbpf_rs::UserRingBuffer::new(&maps.dispatched)
            .context("failed to create user ringbuf")?;

        // Lock all the memory to prevent page faults that could trigger potential deadlocks during
        // scheduling.
        //
        // NOTE: `disable_mmap()` is intentionally NOT called here.  That method installs a seccomp
        // BPF filter that blocks every mmap(2) syscall with EPERM, and seccomp filters are
        // inherited across exec(2) — they cannot be removed once loaded.  After a sched_ext
        // watchdog crash, the scheduler re-execs itself for a clean in-process restart.  With the
        // seccomp filter active, the new process image's dynamic linker cannot mmap shared
        // libraries (libseccomp.so.2 and others), making every restart attempt permanently fatal
        // with "cannot create shared object descriptor: Operation not permitted".
        //
        // The 64 MB preallocated arena (`HEAP_SIZE = 64 MiB`) combined with
        // mlockall(MCL_CURRENT | MCL_FUTURE) already guarantees page-fault-free allocation on the
        // hot scheduling path.  The seccomp guard is a redundant, restart-breaking safety net that
        // provides no additional correctness benefit for a correctly sized arena.
        ALLOCATOR.lock_memory();

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
            task_exits,
            dispatched,
            queued_slot,
            exited_pid_slot: exit_slot,
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

    // Notify the BPF component that the user-space scheduler has completed its scheduling cycle,
    // updating the amount tasks that are still pending.
    //
    // NOTE: do not set allow(dead_code) for this method, any scheduler must use this method at
    // some point, otherwise the BPF component will keep waking-up the user-space scheduler in a
    // busy loop, causing unnecessary high CPU consumption.
    pub fn notify_complete(&mut self, nr_pending: u64) {
        self.skel.maps.bss_data.as_mut().unwrap().nr_scheduled = nr_pending;
        if nr_pending > 0 {
            std::thread::yield_now();
        }
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

    // Counter of BPF routes that stayed on a CPU-local DSQ.
    #[allow(dead_code)]
    pub fn nr_local_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.as_mut().unwrap().nr_local_dispatches
    }

    // Counter of BPF routes that spilled into an LLC DSQ.
    #[allow(dead_code)]
    pub fn nr_llc_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.as_mut().unwrap().nr_llc_dispatches
    }

    // Counter of BPF routes that spilled into a node DSQ.
    #[allow(dead_code)]
    pub fn nr_node_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.as_mut().unwrap().nr_node_dispatches
    }

    // Counter of BPF routes that spilled into the global shared DSQ.
    #[allow(dead_code)]
    pub fn nr_shared_dispatches_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.as_mut().unwrap().nr_shared_dispatches
    }

    // Counter of remote LLC steals performed after local queues drained.
    #[allow(dead_code)]
    pub fn nr_xllc_steals_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.as_mut().unwrap().nr_xllc_steals
    }

    // Counter of remote node steals performed after local tiers drained.
    #[allow(dead_code)]
    pub fn nr_xnode_steals_mut(&mut self) -> &mut u64 {
        &mut self.skel.maps.bss_data.as_mut().unwrap().nr_xnode_steals
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
        match prog.test_run(input) {
            Ok(out) => out.return_value as i32,
            Err(err) => {
                warn!("select_cpu BPF test_run failed for pid {pid}: {err}");
                RL_CPU_ANY
            }
        }
    }

    // Receive a task to be scheduled from the BPF dispatcher.
    pub fn dequeue_task(&mut self) -> Result<Option<QueuedTask>, i32> {
        let Some(bss_data) = self.skel.maps.bss_data.as_mut() else {
            return Err(-libc::EIO);
        };
        self.queued_slot.borrow_mut().take();
        
        // Try to consume the first task from the ring buffer.
        match self.queued.consume_raw_n(1) {
            0 => {
                // Ring buffer is empty.
                bss_data.nr_queued = 0;
                Ok(None)
            }
            1 => {
                let Some(task) = self.queued_slot.borrow_mut().take() else {
                    warn!("queued ring buffer reported data without delivering a decoded task");
                    return Err(-libc::EIO);
                };
                bss_data.nr_queued = bss_data.nr_queued.saturating_sub(1);

                Ok(Some(task))
            }
            res if res < 0 => Err(res),
            res => {
                warn!("unexpected queued ring buffer consume result: {res}");
                Err(-libc::EPROTO)
            }
        }
    }

    // Receive one exiting pid published by ops.disable.
    pub fn dequeue_exited_pid(&mut self) -> Result<Option<i32>, i32> {
        self.exited_pid_slot.borrow_mut().take();
        match self.task_exits.consume_raw_n(1) {
            0 => Ok(None),
            1 => {
                let Some(pid) = self.exited_pid_slot.borrow_mut().take() else {
                    warn!("task_exits ring buffer reported data without delivering a decoded pid");
                    return Err(-libc::EIO);
                };
                Ok(Some(pid))
            }
            res if res < 0 => Err(res),
            res => {
                warn!("unexpected task_exits ring buffer consume result: {res}");
                Err(-libc::EPROTO)
            }
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
            .map_err(|_| libbpf_rs::Error::from_raw_os_error(libc::EINVAL))?;

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
        self.dispatched.submit(urb_sample)?;

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

    pub fn wait_for_detach(&self) -> Option<String> {
        let started = Instant::now();
        loop {
            match current_root_ops_name() {
                Some(name) if name.starts_with("cognis_") => {
                    if started.elapsed() >= DETACH_WAIT_TIMEOUT {
                        return Some(name);
                    }
                    thread::sleep(DETACH_WAIT_POLL);
                }
                _ => return None,
            }
        }
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
