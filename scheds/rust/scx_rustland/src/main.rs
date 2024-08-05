// Copyright (c) Andrea Righi <andrea.righi@linux.dev>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

mod bpf;
use bpf::*;

use scx_utils::Topology;
use scx_utils::TopologyMap;
use scx_utils::UserExitInfo;

use std::thread;

use std::collections::BTreeSet;
use std::collections::HashMap;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::SystemTime;

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use log::info;
use log::warn;

const SCHEDULER_NAME: &'static str = "RustLand";

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

/// scx_rustland: user-space scheduler written in Rust
///
/// scx_rustland is designed to prioritize interactive workloads over background CPU-intensive
/// workloads. For this reason the typical use case of this scheduler involves low-latency
/// interactive applications, such as gaming, video conferencing and live streaming.
///
/// scx_rustland is also designed to be an "easy to read" template that can be used by any
/// developer to quickly experiment more complex scheduling policies fully implemented in Rust.
///
/// The scheduler is made of a BPF component (scx_rustland_core) that implements the low level
/// sched-ext functionalities and a user-space counterpart (scheduler), written in Rust, that
/// implements the actual scheduling policy.
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
/// === Troubleshooting ===
///
/// - Reduce the time slice (option `-s`) if you experience audio issues (i.e., cracking audio or
///   audio packet loss).
///
#[derive(Debug, Parser)]
struct Opts {
    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "5000")]
    slice_us: u64,

    /// Scheduling minimum slice duration in microseconds.
    #[clap(short = 'S', long, default_value = "500")]
    slice_us_min: u64,

    /// If specified, all the scheduling events and actions will be processed in user-space,
    /// disabling any form of in-kernel optimization.
    ///
    /// This mode will likely make the system less responsive, but more predictable in terms of
    /// performance.
    #[clap(short = 'u', long, action = clap::ArgAction::SetTrue)]
    full_user: bool,

    /// When low-power mode is enabled, the scheduler behaves in a more non-work conserving way:
    /// the CPUs operate at reduced capacity, which slows down CPU-bound tasks, enhancing the
    /// prioritization of interactive workloads.  In summary, enabling low-power mode will limit
    /// the performance of CPU-intensive tasks, reducing power consumption, while maintaining
    /// effective prioritization of interactive tasks.
    #[clap(short = 'l', long, action = clap::ArgAction::SetTrue)]
    low_power: bool,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// If specified, all the BPF scheduling events will be reported in
    /// debugfs (e.g., /sys/kernel/debug/tracing/trace_pipe).
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

// Time constants.
const NSEC_PER_USEC: u64 = 1_000;
const NSEC_PER_SEC: u64 = 1_000_000_000;

#[derive(Debug, Clone)]
struct TaskStat {
    pid: i32,
    comm: String,
    nvcsw: u64,
}

fn parse_proc_pid_stat(pid: i32) -> std::io::Result<TaskStat> {
    let path = format!("/proc/{}/status", pid);
    let content = std::fs::read_to_string(&path)?;

    let mut comm = String::new();
    let mut nvcsw = 0;

    for line in content.lines() {
        if line.starts_with("Name:") {
            comm = line.split_whitespace().nth(1).unwrap_or("").to_string();
        } else if line.starts_with("voluntary_ctxt_switches:") {
            nvcsw = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
        }
    }

    Ok(TaskStat {
        pid,
        comm,
        nvcsw,
    })
}

fn get_all_pids() -> std::io::Result<Vec<i32>> {
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        if let Ok(entry) = entry {
            let file_name = entry.file_name();
            if let Ok(pid) = file_name.to_string_lossy().parse::<i32>() {
                pids.push(pid);
            }
        }
    }
    Ok(pids)
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
// Entries are removed when the corresponding task exits.
//
// This information is fetched from the BPF section (through the .exit_task() callback) and
// received by the user-space scheduler via self.bpf.dequeue_task(): a task with a negative .cpu
// value represents an exiting task, so in this case we can free the corresponding entry in
// TaskInfoMap (see also Scheduler::drain_queued_tasks()).
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
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Clone)]
struct Task {
    qtask: QueuedTask,    // queued task
    vruntime: u64,        // total vruntime (that determines the order how tasks are dispatched)
    timestamp: u64,       // task enqueue timestamp
    is_interactive: bool, // task is interactive
}

// Sort tasks by their interactive status first (interactive tasks are always scheduled before
// regular tasks), then sort them by their vruntime, then by their timestamp and lastly by their
// pid.
impl Ord for Task {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.is_interactive.cmp(&self.is_interactive)
            .then_with(|| self.vruntime.cmp(&other.vruntime))
            .then_with(|| self.timestamp.cmp(&other.timestamp))
            .then_with(|| self.qtask.pid.cmp(&other.qtask.pid))
    }
}

// Task pool where all the tasks that needs to run are stored before dispatching
// (ordered by vruntime using a BTreeSet).
struct TaskTree {
    tasks: BTreeSet<Task>,
    task_map: HashMap<i32, Task>, // Map from pid to task
}

// Task pool methods (push / pop).
impl TaskTree {
    fn new() -> Self {
        TaskTree {
            tasks: BTreeSet::new(),
            task_map: HashMap::new(),
        }
    }

    // Add an item to the pool (item will be placed in the tree depending on its vruntime, items
    // with the same vruntime will be sorted by pid).
    fn push(&mut self, task: Task) {
        // Check if task already exists.
        if let Some(prev_task) = self.task_map.get(&task.qtask.pid) {
            self.tasks.remove(prev_task);
        }

        // Insert/update task.
        self.tasks.insert(task.clone());
        self.task_map.insert(task.qtask.pid, task);
    }

    // Pop the first item from the BTreeSet (item with the smallest vruntime).
    fn pop(&mut self) -> Option<Task> {
        if let Some(task) = self.tasks.pop_first() {
            self.task_map.remove(&task.qtask.pid);
            Some(task)
        } else {
            None
        }
    }
}

// Main scheduler object
struct Scheduler<'a> {
    bpf: BpfScheduler<'a>, // BPF connector
    topo_map: TopologyMap, // Host topology
    task_pool: TaskTree,   // tasks ordered by vruntime
    task_map: TaskInfoMap, // map pids to the corresponding task information
    proc_stats: HashMap<i32, u64>, // Task statistics from procfs
    interactive_pids: Vec<i32>, // List of interactive tasks
    min_vruntime: u64,     // Keep track of the minimum vruntime across all tasks
    init_page_faults: u64, // Initial page faults counter
    slice_ns: u64,         // Default time slice (in ns)
    slice_ns_min: u64,     // Minimum time slice (in ns)
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts) -> Result<Self> {
        // Initialize core mapping topology.
        let topo = Topology::new().expect("Failed to build host topology");
        let topo_map = TopologyMap::new(&topo).expect("Failed to generate topology map");

        // Low-level BPF connector.
        let bpf = BpfScheduler::init(
            opts.exit_dump_len,
            opts.slice_us,
            opts.full_user,
            opts.low_power,
            opts.verbose,
            opts.debug,
        )?;
        info!("{} scheduler attached", SCHEDULER_NAME);

        // Return scheduler object.
        Ok(Self {
            bpf,
            topo_map,
            task_pool: TaskTree::new(),
            task_map: TaskInfoMap::new(),
            proc_stats: HashMap::new(),
            interactive_pids: Vec::new(),
            min_vruntime: 0,
            init_page_faults: 0,
            slice_ns: opts.slice_us * NSEC_PER_USEC,
            slice_ns_min: opts.slice_us_min * NSEC_PER_USEC,
        })
    }

    // Return current timestamp in ns.
    fn now() -> u64 {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        ts.as_nanos() as u64
    }

    // Update task's vruntime based on the information collected from the kernel and return to the
    // caller the evaluated task's vruntime.
    //
    // This method implements the main task ordering logic of the scheduler.
    fn update_enqueued(&mut self, task: &QueuedTask) -> u64 {
        // Determine if a task is new or old, based on their current runtime and previous runtime
        // counters.
        fn is_new_task(curr_runtime: u64, prev_runtime: u64) -> bool {
            curr_runtime < prev_runtime || prev_runtime == 0
        }

        // Get task information if the task is already stored in the task map,
        // otherwise create a new entry for it.
        let task_info = self
            .task_map
            .tasks
            .entry(task.pid)
            .or_insert_with_key(|&_pid| TaskInfo {
                sum_exec_runtime: 0,
                vruntime: self.min_vruntime,
            });

        // Evaluate used task time slice.
        let slice = if is_new_task(task.sum_exec_runtime, task_info.sum_exec_runtime) {
            task.sum_exec_runtime
        } else {
            task.sum_exec_runtime - task_info.sum_exec_runtime
        }.min(self.slice_ns);

        // Update task's vruntime re-aligning it to min_vruntime, to avoid
        // over-prioritizing tasks with a mostly sleepy behavior.
        if task_info.vruntime < self.min_vruntime {
            task_info.vruntime = self.min_vruntime;
        }
        task_info.vruntime += slice * 100 / task.weight;

        // Update total task cputime.
        task_info.sum_exec_runtime = task.sum_exec_runtime;

        // Return the task vruntime.
        task_info.vruntime
    }

    // Drain all the tasks from the queued list, update their vruntime (Self::update_enqueued()),
    // then push them all to the task pool (doing so will sort them by their vruntime).
    fn drain_queued_tasks(&mut self) {
        loop {
            match self.bpf.dequeue_task() {
                Ok(Some(task)) => {
                    // Check for exiting tasks (cpu < 0) and remove their corresponding entries in
                    // the task map (if present).
                    if task.cpu < 0 {
                        self.task_map.tasks.remove(&task.pid);
                        continue;
                    }

                    // Update task information and determine vruntime.
                    let vruntime = self.update_enqueued(&task);
                    let timestamp = Self::now();
                    let is_interactive = self.interactive_pids.contains(&task.pid);

                    // Insert task in the task pool (ordered by vruntime).
                    self.task_pool.push(Task {
                        qtask: task,
                        vruntime,
                        timestamp,
                        is_interactive,
                    });
                }
                Ok(None) => {
                    // Reset nr_queued and update nr_scheduled, to notify the dispatcher that
                    // queued tasks are drained, but there is still some work left to do in the
                    // scheduler.
                    self.bpf
                        .update_tasks(Some(0), Some(self.task_pool.tasks.len() as u64));
                    break;
                }
                Err(err) => {
                    warn!("Error: {}", err);
                    break;
                }
            }
        }
    }

    // Return the total amount of tasks that are waiting to be scheduled.
    fn nr_tasks_waiting(&mut self) -> u64 {
        let nr_queued = *self.bpf.nr_queued_mut();
        let nr_scheduled = *self.bpf.nr_scheduled_mut();

        nr_queued + nr_scheduled
    }

    // Dispatch the first task from the task pool (sending them to the BPF dispatcher).
    fn dispatch_task(&mut self) {
        match self.task_pool.pop() {
            Some(task) => {
                // Update global minimum vruntime.
                if self.min_vruntime < task.vruntime {
                    self.min_vruntime = task.vruntime;
                }

                // Scale time slice based on the amount of tasks that are waiting in the
                // scheduler's queue and the previously unused time slice budget, but make sure
                // to assign at least slice_us_min.
                let slice_ns = (self.slice_ns / (self.nr_tasks_waiting() + 1)).max(self.slice_ns_min);

                // Create a new task to dispatch.
                let mut dispatched_task = DispatchedTask::new(&task.qtask);

                // Assign the time slice to the task.
                dispatched_task.set_slice_ns(slice_ns);

                // Dispatch task on the first CPU available if it is classified as
                // interactive, non-interactive tasks will continue to run on the same CPU.
                if task.is_interactive {
                    dispatched_task.set_flag(RL_CPU_ANY);
                }

                // Send task to the BPF dispatcher.
                match self.bpf.dispatch_task(&dispatched_task) {
                    Ok(_) => {}
                    Err(_) => {
                        /*
                         * Re-add the task to the dispatched list in case of failure and stop
                         * dispatching.
                         */
                        self.task_pool.push(task);
                    }
                }
            }
            None => {}
        }

        // Update nr_scheduled to notify the dispatcher that all the tasks received by the
        // scheduler has been dispatched, so there is no reason to re-activate the scheduler,
        // unless more tasks are queued.
        self.bpf
            .update_tasks(None, Some(self.task_pool.tasks.len() as u64));
    }

    // Main scheduling function (called in a loop to periodically drain tasks from the queued list
    // and dispatch them to the BPF part via the dispatched list).
    fn schedule(&mut self) {
        self.drain_queued_tasks();
        self.dispatch_task();

        // Yield to avoid using too much CPU from the scheduler itself.
        thread::yield_now();
    }

    // Get total page faults from /proc/self/stat.
    fn get_page_faults() -> Result<u64, io::Error> {
        let path = format!("/proc/self/stat");
        let mut file = File::open(path)?;

        // Read the contents of the file into a string.
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        // Parse the relevant fields and calculate the total page faults.
        let fields: Vec<&str> = content.split_whitespace().collect();
        if fields.len() >= 12 {
            let minflt: u64 = fields[9].parse().unwrap_or(0);
            let majflt: u64 = fields[11].parse().unwrap_or(0);
            Ok(minflt + majflt)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid format in /proc/[PID]/stat",
            ))
        }
    }

    // Print critical user-space scheduler statistics.
    fn print_faults(&mut self) {
        // Get counters of scheduling failures.
        let nr_failed_dispatches = *self.bpf.nr_failed_dispatches_mut();
        let nr_sched_congested = *self.bpf.nr_sched_congested_mut();

        // Get the total amount of page faults of the user-space scheduler.
        //
        // NOTE:this value must remain set to 0, if the user-space scheduler is faulting we may
        // experience deadlock conditions in the scheduler.
        let page_faults = match Self::get_page_faults() {
            Ok(page_faults) => page_faults,
            Err(_) => 0,
        };
        if self.init_page_faults == 0 {
            self.init_page_faults = page_faults;
        }
        let nr_page_faults = page_faults - self.init_page_faults;

        // Report overall scheduler status at the end.
        let status = if nr_page_faults + nr_failed_dispatches + nr_sched_congested > 0 {
            "WARNING"
        } else {
            "OK"
        };
        info!(
            "  nr_failed_dispatches={} nr_sched_congested={} nr_page_faults={} [{}]",
            nr_failed_dispatches, nr_sched_congested, nr_page_faults, status
        );
    }

    // Print internal scheduler statistics (fetched from the BPF part).
    fn print_stats(&mut self) {
        // Show online CPUs, minimum vruntime and time slice.
        info!(
            "cpus={} min_vruntime={} slice={}us",
            *self.bpf.nr_online_cpus_mut(),
            self.min_vruntime,
            self.slice_ns / NSEC_PER_USEC,
        );

        // Show the total amount of tasks currently monitored by the scheduler.
        info!("  tasks={}", self.task_map.tasks.len());

        // Show general statistics.
        let nr_user_dispatches = *self.bpf.nr_user_dispatches_mut();
        let nr_kernel_dispatches = *self.bpf.nr_kernel_dispatches_mut();
        info!(
            "  nr_user_dispatches={} nr_kernel_dispatches={}",
            nr_user_dispatches, nr_kernel_dispatches,
        );
        let nr_cancel_dispatches = *self.bpf.nr_cancel_dispatches_mut();
        let nr_bounce_dispatches = *self.bpf.nr_bounce_dispatches_mut();
        info!(
            "  nr_cancel_dispatches={} nr_bounce_dispatches={}",
            nr_cancel_dispatches, nr_bounce_dispatches,
        );

        // Show tasks that are running or waiting to be dispatched.
        let nr_running = *self.bpf.nr_running_mut();
        let nr_queued = *self.bpf.nr_queued_mut();
        let nr_scheduled = *self.bpf.nr_scheduled_mut();
        let nr_waiting = nr_queued + nr_scheduled;
        info!(
            "  nr_running={} nr_waiting={} [nr_queued={} + nr_scheduled={}]",
            nr_running, nr_waiting, nr_queued, nr_scheduled
        );

        // Show total page faults of the user-space scheduler.
        self.print_faults();

        log::logger().flush();
    }

    fn sync_interactive_tasks(&mut self, stats: &[TaskStat]) {
        self.interactive_pids.clear();

        info!("{:<8} {:>10} {} <-- interactive tasks", "[pid]", "[nvcsw]", "[comm]");
        for i in 0..stats.len() {
            let stat = &stats[i];

            // At least 10 context switches per sec are required to consider the
            // task as interactive.
            if stat.nvcsw < 10 {
                break;
            }
            self.interactive_pids.push(stat.pid);
            info!(
                "{:<8} {:>10} {}",
                stat.pid, stat.nvcsw, stat.comm
            );
        }

        log::logger().flush();
    }

    fn update_interactive_stats(&mut self) -> std::io::Result<Vec<TaskStat>> {
        let mut new_stats = Vec::new();

        for pid in get_all_pids()? {
            if let Ok(stat) = parse_proc_pid_stat(pid) {
                // Retrieve the previous nvcsw value, or 0 if not present.
                let prev_nvcsw = self.proc_stats.get(&stat.pid).copied().unwrap_or_default();

                // Update the proc_stats entry with the new nvcsw.
                self.proc_stats.insert(stat.pid, stat.nvcsw);

                // Skip the first time that we see the task or if the task has no voluntary context
                // switches at all.
                if prev_nvcsw > 0 {
                    // Add the task entry with the delta nvcsw.
                    let delta_nvcsw = stat.nvcsw.saturating_sub(prev_nvcsw);
                    new_stats.push(TaskStat {
                        pid: stat.pid,
                        comm: stat.comm,
                        nvcsw: delta_nvcsw,
                    });
                }
            }
        }

        // Sort by delta of nvcsw in descending order to ensure we always classify the tasks with
        // greater nvcsw as interactive.
        new_stats.sort_by(|a, b| b.nvcsw.cmp(&a.nvcsw));

        Ok(new_stats)
    }

    fn refresh_interactive_tasks(&mut self) -> std::io::Result<()> {
        let current_stats = match self.update_interactive_stats() {
            Ok(stats) => stats,
            Err(e) => {
                warn!("Failed to update stats: {}", e);
                return Err(e);
            }
        };
        self.sync_interactive_tasks(&current_stats);

        Ok(())
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let mut prev_ts = Self::now();

        while !shutdown.load(Ordering::Relaxed) && !self.bpf.exited() {
            // Call the main scheduler body.
            self.schedule();

            let now = Self::now();
            if now - prev_ts > NSEC_PER_SEC {
                self.print_stats();
                self.refresh_interactive_tasks().unwrap();

                prev_ts = now;
            }
        }
        // Dump scheduler statistics before exiting
        self.print_stats();

        self.bpf.shutdown_and_report()
    }
}

// Unregister the scheduler.
impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        info!("Unregister {} scheduler", SCHEDULER_NAME);
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} version {} - scx_rustland_core {}",
            SCHEDULER_NAME,
            VERSION,
            scx_rustland_core::VERSION
        );
        return Ok(());
    }

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

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    loop {
        let mut sched = Scheduler::init(&opts)?;
        // Start the scheduler.
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
