// Copyright (c) Andrea Righi <andrea.righi@linux.dev>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

#[rustfmt::skip]
mod bpf;
use bpf::*;

mod stats;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::io::{self};
use std::mem::MaybeUninit;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::OpenObject;
use log::info;
use log::warn;
use scx_stats::prelude::*;
use scx_utils::UserExitInfo;
use stats::Metrics;

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
/// The scheduler is based on scx_rustland_core, which implements the low level sched-ext
/// functionalities.
///
/// The scheduling policy implemented in user-space is a based on a deadline, evaluated as
/// following:
///
///       deadline = vruntime + exec_runtime
///
/// Where, vruntime reflects the task's total runtime scaled by weight (ensuring fairness), while
/// exec_runtime accounts the CPU time used since the last sleep (capturing responsiveness). Tasks
/// are then dispatched from the lowest to the highest deadline.
///
/// This approach favors latency-sensitive tasks: those that frequently sleep will accumulate less
/// exec_runtime, resulting in earlier deadlines. In contrast, CPU-intensive tasks that don’t sleep
/// accumulate a larger exec_runtime and thus get scheduled later.
///
/// All the tasks are stored in a BTreeSet (TaskTree), using the deadline as the ordering key.
/// Once the order of execution is determined all tasks are sent back to the BPF counterpart
/// (scx_rustland_core) to be dispatched. To keep track of the accumulated execution time and
/// vruntime, the scheduler maintains a HashMap (TaskInfoMap), indexed by pid.
///
/// The BPF dispatcher is completely agnostic of the particular scheduling policy implemented in
/// user-space. For this reason developers that are willing to use this scheduler to experiment
/// scheduling policies should be able to simply modify the Rust component, without having to deal
/// with any internal kernel / BPF details.
///
/// === Troubleshooting ===
///
/// - Reduce the time slice (option `-s`) if you experience lag or cracking audio.
///
#[derive(Debug, Parser)]
struct Opts {
    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "20000")]
    slice_us: u64,

    /// Scheduling minimum slice duration in microseconds.
    #[clap(short = 'S', long, default_value = "1000")]
    slice_us_min: u64,

    /// If specified, only tasks which have their scheduling policy set to SCHED_EXT using
    /// sched_setscheduler(2) are switched. Otherwise, all tasks are switched.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    partial: bool,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Enable verbose output, including libbpf details. Moreover, BPF scheduling events will be
    /// reported in tracefs (e.g., /sys/kernel/tracing/trace_pipe).
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

// Time constants.
const NSEC_PER_USEC: u64 = 1_000;

// Basic item stored in the task information map.
#[derive(Debug)]
struct TaskInfo {
    vruntime: u64, // total vruntime of the task
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
    qtask: QueuedTask, // queued task
    deadline: u64,     // task deadline (that determines the order how tasks are dispatched)
    timestamp: u64,    // task enqueue timestamp
}

// Sort tasks by their interactive status first (interactive tasks are always scheduled before
// regular tasks), then sort them by their vruntime, then by their timestamp and lastly by their
// pid.
impl Ord for Task {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deadline
            .cmp(&other.deadline)
            .then_with(|| self.timestamp.cmp(&other.timestamp))
            .then_with(|| self.qtask.pid.cmp(&other.qtask.pid))
    }
}

// Task pool where all the tasks that needs to run are stored before dispatching (ordered by their
// shortest deadline using a BTreeSet).
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

    // Add an item to the pool (item will be placed in the tree depending on its deadline, items
    // with the same deadline will be sorted by pid).
    fn push(&mut self, task: Task) {
        // Check if task already exists.
        if let Some(prev_task) = self.task_map.get(&task.qtask.pid) {
            self.tasks.remove(prev_task);
        }

        // Insert/update task.
        self.tasks.insert(task.clone());
        self.task_map.insert(task.qtask.pid, task);
    }

    // Pop the first item from the BTreeSet (item with the shortest deadline).
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
    bpf: BpfScheduler<'a>,                  // BPF connector
    stats_server: StatsServer<(), Metrics>, // statistics
    task_pool: TaskTree,                    // tasks ordered by deadline
    task_map: TaskInfoMap,                  // map pids to the corresponding task information
    min_vruntime: u64,                      // Keep track of the minimum vruntime across all tasks
    init_page_faults: u64,                  // Initial page faults counter
    slice_ns: u64,                          // Default time slice (in ns)
    slice_ns_min: u64,                      // Minimum time slice (in ns)
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        // Low-level BPF connector.
        let bpf = BpfScheduler::init(
            open_object,
            opts.exit_dump_len,
            opts.partial,
            opts.verbose,
            true, // Enable built-in idle CPU selection policy
        )?;

        info!("{} scheduler attached", SCHEDULER_NAME);

        // Return scheduler object.
        Ok(Self {
            bpf,
            stats_server,
            task_pool: TaskTree::new(),
            task_map: TaskInfoMap::new(),
            min_vruntime: 0,
            init_page_faults: 0,
            slice_ns: opts.slice_us * NSEC_PER_USEC,
            slice_ns_min: opts.slice_us_min * NSEC_PER_USEC,
        })
    }

    fn get_metrics(&mut self) -> Metrics {
        let page_faults = match Self::get_page_faults() {
            Ok(page_faults) => page_faults,
            Err(_) => 0,
        };
        if self.init_page_faults == 0 {
            self.init_page_faults = page_faults;
        }
        let nr_page_faults = page_faults - self.init_page_faults;

        Metrics {
            nr_running: *self.bpf.nr_running_mut(),
            nr_cpus: *self.bpf.nr_online_cpus_mut(),
            nr_queued: *self.bpf.nr_queued_mut(),
            nr_scheduled: *self.bpf.nr_scheduled_mut(),
            nr_page_faults,
            nr_user_dispatches: *self.bpf.nr_user_dispatches_mut(),
            nr_kernel_dispatches: *self.bpf.nr_kernel_dispatches_mut(),
            nr_cancel_dispatches: *self.bpf.nr_cancel_dispatches_mut(),
            nr_bounce_dispatches: *self.bpf.nr_bounce_dispatches_mut(),
            nr_failed_dispatches: *self.bpf.nr_failed_dispatches_mut(),
            nr_sched_congested: *self.bpf.nr_sched_congested_mut(),
        }
    }

    // Return current timestamp in ns.
    fn now() -> u64 {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        ts.as_nanos() as u64
    }

    // Update task's vruntime based on the information collected from the kernel and return to the
    // caller the evaluated task's deadline.
    //
    // This method implements the main task ordering logic of the scheduler.
    fn update_enqueued(&mut self, task: &QueuedTask) -> u64 {
        // Get task information if the task is already stored in the task map,
        // otherwise create a new entry for it.
        let task_info = self
            .task_map
            .tasks
            .entry(task.pid)
            .or_insert_with_key(|&_pid| TaskInfo {
                vruntime: self.min_vruntime,
            });

        // Update global minimum vruntime based on the previous task's vruntime.
        if self.min_vruntime < task.vtime {
            self.min_vruntime = task.vtime;
        }

        // Estimate the used time slice based on total runtime since the last sleep.
        //
        // Cap the value to slice_ns, since exec_runtime accumulates across multiple enqueue
        // events, but what matters here is the time used in the most recent slice, so:
        //  - if the task didn't sleep, it's the full slice_ns,
        //  - if it did sleep, it's exec_runtime.
        //
        // Note that there may be some inaccuracies here, as a task can exceed its assigned time
        // slice due to factors like holding locks or becoming non-deschedulable. These
        // inaccuracies are tolerated to ensure smoother vruntime progression and prevent excessive
        // gaps between tasks' vruntimes.
        let slice = task.exec_runtime.min(self.slice_ns);

        // Update task's vruntime re-aligning it to min_vruntime (never allow a task to accumulate
        // a budget of more than a time slice to prevent starvation).
        let min_vruntime = self.min_vruntime.saturating_sub(self.slice_ns);
        if task_info.vruntime < min_vruntime {
            task_info.vruntime = min_vruntime;
        }
        let vslice = slice * 100 / task.weight;
        task_info.vruntime += vslice;

        // Return the task's deadline.
        task_info.vruntime + task.exec_runtime.min(self.slice_ns * 100)
    }

    // Drain all the tasks from the queued list, update their vruntime (Self::update_enqueued()),
    // then push them all to the task pool (doing so will sort them by their vruntime).
    fn drain_queued_tasks(&mut self) {
        loop {
            match self.bpf.dequeue_task() {
                Ok(Some(task)) => {
                    // Update task information and determine vruntime.
                    let deadline = self.update_enqueued(&task);
                    let timestamp = Self::now();

                    // Insert task in the task pool (ordered by vruntime).
                    self.task_pool.push(Task {
                        qtask: task,
                        deadline,
                        timestamp,
                    });
                }
                Ok(None) => {
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
    fn dispatch_tasks(&mut self) {
        match self.task_pool.pop() {
            Some(task) => {
                // Scale time slice based on the amount of tasks that are waiting in the
                // scheduler's queue and the previously unused time slice budget, but make sure
                // to assign at least slice_us_min.
                let nr_waiting = self.nr_tasks_waiting() + 1;
                let slice_ns = (self.slice_ns / nr_waiting).max(self.slice_ns_min);

                // Create a new task to dispatch.
                let mut dispatched_task = DispatchedTask::new(&task.qtask);

                // Assign the time slice to the task and propagate the vruntime.
                dispatched_task.slice_ns = slice_ns;

                // Propagate the evaluated task's deadline to the scx_rustland_core backend.
                dispatched_task.vtime = task.deadline;

                // Try to pick an idle CPU for the task.
                let cpu = self
                    .bpf
                    .select_cpu(task.qtask.pid, task.qtask.cpu, task.qtask.flags);
                dispatched_task.cpu = if cpu >= 0 { cpu } else { task.qtask.cpu };

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
    }

    // Main scheduling function (called in a loop to periodically drain tasks from the queued list
    // and dispatch them to the BPF part via the dispatched list).
    fn schedule(&mut self) {
        self.drain_queued_tasks();
        self.dispatch_tasks();

        // Notify the dispatcher if there are still pending tasks to be processed,
        self.bpf.notify_complete(self.task_pool.tasks.len() as u64);
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

    fn run(&mut self) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !self.bpf.exited() {
            // Call the main scheduler body.
            self.schedule();

            // Handle monitor requests asynchronously.
            match req_ch.try_recv() {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(_) => {}
            }
        }

        self.bpf.shutdown_and_report()
    }
}

// Unregister the scheduler.
impl Drop for Scheduler<'_> {
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

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
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

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let jh = std::thread::spawn(move || stats::monitor(Duration::from_secs_f64(intv)).unwrap());
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run()?.should_restart() {
            break;
        }
    }

    Ok(())
}
