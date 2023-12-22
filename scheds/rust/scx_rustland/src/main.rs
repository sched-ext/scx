// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

use std::thread;

use std::collections::BTreeSet;
use std::collections::HashMap;

use std::ffi::CStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::Skel as _;
use libbpf_rs::skel::SkelBuilder as _;
use log::info;
use log::warn;

use libc::{sched_param, sched_setscheduler};

const SCHEDULER_NAME: &'static str = "RustLand";

// Defined in UAPI
const SCHED_EXT: i32 = 7;

/// scx_rustland: simple user-space scheduler written in Rust
///
/// The main goal of this scheduler is be an "easy to read" template that can be used to quickly
/// test more complex scheduling policies. For this reason this scheduler is mostly focused on
/// simplicity and code readability.
///
/// The scheduler is made of a BPF component (dispatcher) that implements the low level sched-ext
/// functionalities and a user-space counterpart (scheduler), written in Rust, that implements the
/// actual scheduling policy.
///
/// The default scheduling policy implemented in the user-space scheduler is a based on virtual
/// runtime (vruntime):
///
/// - each task receives the same time slice of execution (slice_ns)
///
/// - the actual execution time, adjusted based on the task's static priority (weight), determines
///   the vruntime
///
/// - tasks are then dispatched from the lowest to the highest vruntime
///
/// All the tasks are stored in a BTreeSet (TaskTree), using vruntime as the ordering key.
/// Once the order of execution is determined all tasks are sent back to the BPF counterpart to be
/// dispatched. To keep track of the accumulated cputime and vruntime the scheduler maintain a
/// HashMap (TaskInfoMap) indexed by pid.
///
/// The BPF dispatcher is completely agnostic of the particular scheduling policy implemented in
/// user-space. For this reason developers that are willing to use this scheduler to experiment
/// scheduling policies should be able to simply modify the Rust component, without having to deal
/// with any internal kernel / BPF details.
///
#[derive(Debug, Parser)]
struct Opts {
    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "20000")]
    slice_us: u64,

    /// If specified, only tasks which have their scheduling policy set to
    /// SCHED_EXT using sched_setscheduler(2) are switched. Otherwise, all
    /// tasks are switched.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    partial: bool,

    /// If specified, all the BPF scheduling events will be reported in
    /// debugfs (e.g., /sys/kernel/debug/tracing/trace_pipe).
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,
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

    fn as_queued_task_ctx(&self) -> bpf_intf::queued_task_ctx {
        self.inner
    }
}

// Message sent to the dispatcher (see bpf_intf::dispatched_task_ctx for details).
//
// NOTE: eventually libbpf-rs will provide a better abstraction for this.
struct DispatchedMessage {
    inner: bpf_intf::dispatched_task_ctx,
}

impl DispatchedMessage {
    fn from_task(task: &Task) -> Self {
        let dispatched_task_struct = bpf_intf::dispatched_task_ctx {
            pid: task.pid,
            cpu: task.cpu,
            payload: task.vruntime,
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

// Basic item stored in the task information map.
#[derive(Debug)]
struct TaskInfo {
    sum_exec_runtime: u64, // total cpu time used by the task
    vruntime: u64,         // total vruntime of the task
}

// Task information map: store total execution time and vruntime of each task in the system.
//
// TaskInfo objects are stored in the HashMap and they are indexed by pid.
//
// TODO: provide some hooks for .disable() in the BPF part to clean up entries once the task exits
// (or provide a garbage collector to free up the items that are not needed anymore).
struct TaskInfoMap {
    tasks: HashMap<i32, TaskInfo>,
}

// TaskInfoMap implementation: provide methods to get items and update items by pid.
impl TaskInfoMap {
    fn new() -> Self {
        TaskInfoMap {
            tasks: HashMap::new(),
        }
    }

    // Get an item (as mutable) from the HashMap (by pid)
    fn get_mut(&mut self, pid: i32) -> Option<&mut TaskInfo> {
        self.tasks.get_mut(&pid)
    }

    // Add or update an item in the HashMap (by pid), if the pid is already present the item will
    // be replaced (updated)
    fn insert(&mut self, pid: i32, task: TaskInfo) {
        self.tasks.insert(pid, task);
    }
}

// Basic task item stored in the task pool.
#[derive(Debug, PartialEq, Eq, PartialOrd)]
struct Task {
    pid: i32,      // pid that uniquely identifies a task
    cpu: i32,      // CPU where the task is running
    vruntime: u64, // total vruntime (that determines the order how tasks are dispatched)
}

// Make sure tasks are ordered by vruntime, if multiple tasks have the same vruntime order by pid.
impl Ord for Task {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.vruntime
            .cmp(&other.vruntime)
            .then_with(|| self.pid.cmp(&other.pid))
    }
}

// Task pool where all the tasks that needs to run are stored before dispatching
// (ordered by vruntime using a BTreeSet).
struct TaskTree {
    tasks: BTreeSet<Task>,
}

// Task pool methods (push / pop).
impl TaskTree {
    fn new() -> Self {
        TaskTree {
            tasks: BTreeSet::new(),
        }
    }

    // Add an item to the pool (item will be placed in the tree depending on its vruntime, items
    // with the same vruntime will be sorted by pid).
    fn push(&mut self, pid: i32, cpu: i32, vruntime: u64) {
        let task = Task { pid, cpu, vruntime };
        self.tasks.insert(task);
    }

    // Pop the first item from the BTreeSet (item with the smallest vruntime).
    fn pop(&mut self) -> Option<Task> {
        self.tasks.pop_first()
    }
}

// Main scheduler object
struct Scheduler<'a> {
    skel: BpfSkel<'a>,     // BPF connector
    task_pool: TaskTree,   // tasks ordered by vruntime
    task_map: TaskInfoMap, // map pids to the corresponding task information
    min_vruntime: u64,     // Keep track of the minimum vruntime across all tasks
    nr_cpus_online: u64,   // Amount of the available CPUs in the system
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts) -> Result<Self> {
        // Open the BPF prog first for verification.
        let skel_builder = BpfSkelBuilder::default();
        let mut skel = skel_builder.open().context("Failed to open BPF program")?;
        let pid = std::process::id();

        // Scheduler task pool to sort tasks by vruntime.
        let task_pool = TaskTree::new();

        // Scheduler task map to store tasks information.
        let task_map = TaskInfoMap::new();

        // Initialize global minimum vruntime.
        let min_vruntime: u64 = 0;

        // Initialize online CPUs counter.
        //
        // We should probably refresh this counter during the normal execution to support cpu
        // hotplugging, but for now let's keep it simple and set this only at initialization).
        let nr_cpus_online = libbpf_rs::num_possible_cpus().unwrap() as u64;

        // Set scheduler options (defined in the BPF part).
        skel.bss_mut().usersched_pid = pid;
        skel.rodata_mut().slice_ns = opts.slice_us * 1000;
        skel.rodata_mut().switch_partial = opts.partial;
        skel.rodata_mut().debug = opts.debug;

        // Attach BPF scheduler.
        let mut skel = skel.load().context("Failed to load BPF program")?;
        skel.attach().context("Failed to attach BPF program")?;
        let struct_ops = Some(
            skel.maps_mut()
                .rustland()
                .attach_struct_ops()
                .context("Failed to attach struct ops")?,
        );
        info!("{} scheduler attached", SCHEDULER_NAME);

        // Return scheduler object.
        Ok(Self {
            skel,
            task_pool,
            task_map,
            min_vruntime,
            nr_cpus_online,
            struct_ops,
        })
    }

    // Read exit code from the BPF part.
    fn read_bpf_exit_kind(&mut self) -> i32 {
        unsafe { std::ptr::read_volatile(&self.skel.bss().exit_kind as *const _) }
    }

    // Called on exit to get exit code and exit message from the BPF part.
    fn report_bpf_exit_kind(&mut self) -> Result<()> {
        let cstr = unsafe { CStr::from_ptr(self.skel.bss().exit_msg.as_ptr() as *const _) };
        let msg = cstr
            .to_str()
            .context("Failed to convert exit msg to string")
            .unwrap();
        if !msg.is_empty() {
            warn!("EXIT: {}", msg);
        }
        match self.read_bpf_exit_kind() {
            0 => Ok(()),
            err => bail!("BPF error code: {}", err),
        }
    }

    // Get the pid running on a certain CPU, if no tasks are running return 0
    fn get_cpu_pid(&self, cpu: u32) -> u32 {
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

    // Check if there's at least a CPU that can accept tasks.
    fn is_dispatcher_needed(&self) -> bool {
        for cpu in 0..self.nr_cpus_online {
            let pid = self.get_cpu_pid(cpu as u32);
            if pid == 0 {
                return true;
            }
        }
        return false;
    }

    // Search for an idle CPU in the system.
    //
    // First check the previously used CPU, that is always the best choice (to mitigate migration
    // overhead), otherwise check all the others in order.
    //
    // If all the CPUs are busy return the previouly used CPU.
    fn select_task_cpu(&self, prev_cpu: i32) -> i32 {
        if self.get_cpu_pid(prev_cpu as u32) != 0 {
            for cpu in 0..self.nr_cpus_online {
                let pid = self.get_cpu_pid(cpu as u32);
                if pid == 0 {
                    return cpu as i32;
                }
            }
        }

        prev_cpu
    }

    // Update task's vruntime based on the information collected from the kernel part.
    fn update_enqueued(
        task_info: &mut TaskInfo,
        sum_exec_runtime: u64,
        weight: u64,
        min_vruntime: u64,
    ) {
        // Add cputime delta normalized by weight to the vruntime (if delta > 0).
        if sum_exec_runtime > task_info.sum_exec_runtime {
            let delta = (sum_exec_runtime - task_info.sum_exec_runtime) / weight;
            task_info.vruntime += delta;
        }
        // Make sure vruntime is moving forward (> current minimum).
        if min_vruntime > task_info.vruntime {
            task_info.vruntime = min_vruntime;
        }
        // Update total task cputime.
        task_info.sum_exec_runtime = sum_exec_runtime;
    }

    // Drain all the tasks from the queued list, update their vruntime (Self::update_enqueued()),
    // then push them all to the task pool (doing so will sort them by their vruntime).
    fn drain_queued_tasks(&mut self) {
        let maps = self.skel.maps();
        let queued = maps.queued();

        loop {
            match queued.lookup_and_delete(&[]) {
                Ok(Some(msg)) => {
                    // Schedule the task and update task information.
                    let task = EnqueuedMessage::from_bytes(msg.as_slice()).as_queued_task_ctx();
                    if let Some(task_info) = self.task_map.get_mut(task.pid) {
                        Self::update_enqueued(
                            task_info,
                            task.sum_exec_runtime,
                            task.weight,
                            self.min_vruntime,
                        );
                        self.task_pool.push(task.pid, task.cpu, task_info.vruntime);
                    } else {
                        let task_info = TaskInfo {
                            sum_exec_runtime: task.sum_exec_runtime,
                            vruntime: self.min_vruntime,
                        };
                        let cpu = self.select_task_cpu(task.cpu);
                        self.task_map.insert(task.pid, task_info);
                        self.task_pool.push(task.pid, cpu, self.min_vruntime);
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    warn!("Error: {}", err);
                    break;
                }
            }
        }
    }

    // Dispatch tasks from the task pool in order (sending them to the BPF dispatcher).
    fn dispatch_tasks(&mut self) {
        let maps = self.skel.maps();
        let dispatched = maps.dispatched();

        loop {
            match self.task_pool.pop() {
                Some(task) => {
                    // Update global minimum vruntime.
                    self.min_vruntime = task.vruntime;

                    // Send task to the dispatcher.
                    let msg = DispatchedMessage::from_task(&task);
                    match dispatched.update(&[], msg.as_bytes(), libbpf_rs::MapFlags::ANY) {
                        Ok(_) => {}
                        Err(_) => {
                            /*
                             * Re-add the task to the dispatched list in case of failure and stop
                             * dispatching.
                             */
                            self.task_pool.push(task.pid, task.cpu, task.vruntime);
                            break;
                        }
                    }
                }
                None => break,
            }
        }
    }

    // Main scheduling function (called in a loop to periodically drain tasks from the queued list
    // and dispatch them to the BPF part via the dispatched list).
    fn schedule(&mut self) {
        self.drain_queued_tasks();
        // Instead of immediately dispatching all the tasks check if there is at least an idle CPU.
        // This logic can be improved, because in this way we are going to add more scheduling
        // overhead when the system is already overloaded (no idle CPUs).
        //
        // Probably a better solution could be to have a reasonable batch size (i.e., as a function
        // of the CPUs and slice duration) and dispatch up to a maximum of BATCH_SIZE tasks each
        // time.
        if self.is_dispatcher_needed() {
            self.dispatch_tasks();
        }

        // Yield to avoid using too much CPU from the scheduler itself.
        thread::yield_now();
    }

    // Print internal scheduler statistics (fetched from the BPF part)
    fn print_stats(&mut self) {
        let nr_enqueues = self.skel.bss().nr_enqueues as u64;
        let nr_user_dispatches = self.skel.bss().nr_user_dispatches as u64;
        let nr_kernel_dispatches = self.skel.bss().nr_kernel_dispatches as u64;
        let nr_sched_congested = self.skel.bss().nr_sched_congested as u64;

        info!(
            "min_vtime={} nr_enqueues={} nr_user_dispatched={} nr_kernel_dispatches={} nr_sched_congested={}",
            self.min_vruntime, nr_enqueues, nr_user_dispatches, nr_kernel_dispatches, nr_sched_congested
        );
        for cpu in 0..self.nr_cpus_online {
            let pid = self.get_cpu_pid(cpu as u32);
            info!("cpu={} pid={}", cpu, pid);
        }

        log::logger().flush();
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        let mut prev_ts = SystemTime::now();

        while !shutdown.load(Ordering::Relaxed) && self.read_bpf_exit_kind() == 0 {
            let curr_ts = SystemTime::now();
            let elapsed = curr_ts
                .duration_since(prev_ts)
                .unwrap_or_else(|_| Duration::from_secs(0));

            self.schedule();

            // Print scheduler statistics every second.
            if elapsed > Duration::from_secs(1) {
                self.print_stats();
                prev_ts = curr_ts;
            }
        }
        self.report_bpf_exit_kind()
    }
}

impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
        info!("Unregister {} scheduler", SCHEDULER_NAME);
    }
}

// Set scheduling class for the scheduler itself to SCHED_EXT
fn use_sched_ext() -> i32 {
    let pid = std::process::id();
    let param: sched_param = sched_param { sched_priority: 0 };
    let res = unsafe { sched_setscheduler(pid as i32, SCHED_EXT, &param as *const sched_param) };
    res
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    let loglevel = simplelog::LevelFilter::Info;

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    // Make sure to use the SCHED_EXT class at least for the scheduler itself.
    let res = use_sched_ext();
    if res != 0 {
        bail!("Failed to all sched_setscheduler: {}", res);
    }

    let mut sched = Scheduler::init(&opts)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    // Start the scheduler.
    sched.run(shutdown)
}
