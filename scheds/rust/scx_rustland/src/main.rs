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

use std::fs::metadata;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

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

    // Get an item (as mutable) from the HashMap (by pid).
    fn get_mut(&mut self, pid: i32) -> Option<&mut TaskInfo> {
        self.tasks.get_mut(&pid)
    }

    // Add or update an item in the HashMap (by pid), if the pid is already present the item will
    // be replaced (updated).
    fn insert(&mut self, pid: i32, task: TaskInfo) {
        self.tasks.insert(pid, task);
    }

    // Return the amount of tasks stored in the TaskInfoMap.
    fn len(&self) -> usize {
        self.tasks.len()
    }

    // Clean up old entries (pids that don't exist anymore).
    fn gc(&mut self) {
        fn is_pid_running(pid: i32) -> bool {
            let path = format!("/proc/{}", pid);
            metadata(path).is_ok()
        }
        let pids: Vec<i32> = self.tasks.keys().cloned().collect();
        for pid in pids {
            if !is_pid_running(pid) {
                self.tasks.remove(&pid);
            }
        }
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
    nr_cpus_online: i32,   // Amount of the available CPUs in the system
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
        let nr_cpus_online = libbpf_rs::num_possible_cpus().unwrap() as i32;

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
    fn get_cpu_pid(&self, cpu: i32) -> u32 {
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

    // Return the array of idle CPU ids.
    fn get_idle_cpus(&self) -> Vec<i32> {
        let mut idle_cpus = Vec::new();

        for cpu in 0..self.nr_cpus_online {
            let pid = self.get_cpu_pid(cpu);
            if pid == 0 {
                idle_cpus.push(cpu);
            }
        }

        idle_cpus
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
                        self.task_map.insert(task.pid, task_info);
                        self.task_pool.push(task.pid, task.cpu, self.min_vruntime);
                    }
                }
                Ok(None) => {
                    // Reset nr_queued and update nr_scheduled, to notify the dispatcher that
                    // queued tasks are drained, but there is still some work left to do in the
                    // scheduler.
                    self.skel.bss_mut().nr_queued = 0;
                    self.skel.bss_mut().nr_scheduled = self.task_pool.tasks.len() as u64;
                    break;
                }
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
        let mut idle_cpus = self.get_idle_cpus();

        // Dispatch only a batch of tasks equal to the amount of idle CPUs in the system.
        //
        // This allows to have more tasks sitting in the task pool, reducing the pressure on the
        // dispatcher queues and giving a chance to higher priority tasks to come in and get
        // dispatched earlier, mitigating potential priority inversion issues.
        while !idle_cpus.is_empty() {
            match self.task_pool.pop() {
                Some(mut task) => {
                    // Update global minimum vruntime.
                    self.min_vruntime = task.vruntime;

                    // Select a CPU to dispatch the task.
                    //
                    // Use the previously used CPU if idle, that is always the best choice (to
                    // mitigate migration overhead), otherwise pick the next idle CPU available.
                    if let Some(pos) = idle_cpus.iter().position(|&x| x == task.cpu) {
                        // The CPU assigned to the task is in idle_cpus, keep the assignment and
                        // remove the CPU from idle_cpus.
                        idle_cpus.remove(pos);
                    } else {
                        // The CPU assigned to the task is not in idle_cpus, pop the first CPU from
                        // idle_cpus and assign it to the task.
                        task.cpu = idle_cpus.pop().unwrap();
                    }

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
        // Reset nr_scheduled to notify the dispatcher that all the tasks received by the scheduler
        // has been dispatched, so there is no reason to re-activate the scheduler, unless more
        // tasks are queued.
        self.skel.bss_mut().nr_scheduled = self.task_pool.tasks.len() as u64;
    }

    // Main scheduling function (called in a loop to periodically drain tasks from the queued list
    // and dispatch them to the BPF part via the dispatched list).
    fn schedule(&mut self) {
        self.drain_queued_tasks();
        self.dispatch_tasks();

        // Yield to avoid using too much CPU from the scheduler itself.
        thread::yield_now();
    }

    // Get the current CPU where the scheduler is running.
    fn get_current_cpu() -> io::Result<i32> {
        // Open /proc/self/stat file
        let path = Path::new("/proc/self/stat");
        let mut file = File::open(path)?;

        // Read the content of the file into a String
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        // Split the content into fields using whitespace as the delimiter
        let fields: Vec<&str> = content.split_whitespace().collect();

        // Parse the 39th field as an i32 and return it.
        if let Some(field) = fields.get(38) {
            if let Ok(value) = field.parse::<i32>() {
                Ok(value)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unable to parse current CPU information as i32",
                ))
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unable to get current CPU information",
            ))
        }
    }

    // Print internal scheduler statistics (fetched from the BPF part).
    fn print_stats(&mut self) {
        // Show minimum vruntime (this should be constantly incrementing).
        info!("vruntime={} tasks={}", self.min_vruntime, self.task_map.len());

        // Show general statistics.
        let nr_user_dispatches = self.skel.bss().nr_user_dispatches as u64;
        let nr_kernel_dispatches = self.skel.bss().nr_kernel_dispatches as u64;
        let nr_sched_congested = self.skel.bss().nr_sched_congested as u64;
        info!(
            "  nr_user_dispatched={} nr_kernel_dispatches={} nr_sched_congested={}",
            nr_user_dispatches, nr_kernel_dispatches, nr_sched_congested
        );

        // Show tasks that are waiting to be dispatched.
        let nr_queued = self.skel.bss().nr_queued as u64;
        let nr_scheduled = self.skel.bss().nr_scheduled as u64;
        let nr_waiting = nr_queued + nr_scheduled;
        info!(
            "  nr_waiting={} [nr_queued={} + nr_scheduled={}]",
            nr_waiting, nr_queued, nr_scheduled
        );

        // Show tasks that are currently running.
        let sched_cpu = match Self::get_current_cpu() {
            Ok(cpu_info) => cpu_info,
            Err(_) => -1,
        };
        info!("Running tasks:");
        for cpu in 0..self.nr_cpus_online {
            let pid = if cpu == sched_cpu {
                "[self]".to_string()
            } else {
                self.get_cpu_pid(cpu).to_string()
            };
            info!("  cpu={} pid={}", cpu, pid);
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
                // Free up unused scheduler resources.
                self.task_map.gc();
                // Print scheduler statistics.
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
