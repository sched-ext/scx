// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

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
/// - Adjust the time slice boost parameter (option `-b`) to enhance the responsiveness of
///   low-latency applications (i.e., online gaming, live streaming, video conferencing etc.).
///
/// - Reduce the time slice boost parameter (option `-b`) if you notice poor performance in your
///   CPU-intensive applications or if you experience any stall during your typical workload.
///
/// - Reduce the time slice (option `-s`) if you experience audio issues (i.e., cracking audio or
///   audio packet loss).
///
#[derive(Debug, Parser)]
struct Opts {
    /// Scheduling slice duration in microseconds (default is 5ms).
    #[clap(short = 's', long, default_value = "5000")]
    slice_us: u64,

    /// Time slice boost: increasing this value enhances performance of interactive applications
    /// (gaming, multimedia, GUIs, etc.), but may lead to decreased responsiveness of other tasks
    /// in the system.
    ///
    /// WARNING: setting a large value can make the scheduler quite unpredictable and you may
    /// experience temporary system stalls (before hitting the sched-ext watchdog timeout).
    ///
    /// Default time slice boost is 100, which means interactive tasks will get a 100x priority
    /// boost to run respect to non-interactive tasks.
    ///
    /// Use "0" to disable time slice boost and fallback to the standard vruntime-based scheduling.
    #[clap(short = 'b', long, default_value = "100")]
    slice_boost: u64,

    /// If specified, disable task preemption.
    ///
    /// Disabling task preemption can help to improve the throughput of CPU-intensive tasks, while
    /// still providing a good level of system responsiveness.
    ///
    /// Preemption is enabled by default to provide a higher level of responsiveness to the
    /// interactive tasks.
    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    no_preemption: bool,

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

    /// By default the scheduler automatically transitions to FIFO mode when the system is
    /// underutilized. This allows to reduce unnecessary scheduling overhead and boost performance
    /// when the system is not running at full capacity.
    ///
    /// Be aware that FIFO mode can lead to less predictable performance. Therefore, use this
    /// option if performance predictability is important, such as when running real-time audio
    /// applications or during live streaming. Conversely, avoid using this option when you care
    /// about maximizing performance, such as gaming.
    ///
    /// Set this option to disable this automatic transition.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    disable_fifo: bool,

    /// If specified, only tasks which have their scheduling policy set to
    /// SCHED_EXT using sched_setscheduler(2) are switched. Otherwise, all
    /// tasks are switched.
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    partial: bool,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// If specified, all the BPF scheduling events will be reported in
    /// debugfs (e.g., /sys/kernel/debug/tracing/trace_pipe).
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

// Time constants.
const NSEC_PER_USEC: u64 = 1_000;
const NSEC_PER_MSEC: u64 = 1_000_000;
const NSEC_PER_SEC: u64 = 1_000_000_000;

// Basic item stored in the task information map.
#[derive(Debug)]
struct TaskInfo {
    sum_exec_runtime: u64, // total cpu time used by the task
    vruntime: u64,         // total vruntime of the task
    avg_nvcsw: u64,        // average of voluntary context switches
    nvcsw: u64,            // total amount of voluntary context switches
    nvcsw_ts: u64,         // timestamp of the previous nvcsw update
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
    is_interactive: bool, // task can preempt other tasks
}

// Make sure tasks are ordered by vruntime, if multiple tasks have the same vruntime order by pid.
impl Ord for Task {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.vruntime
            .cmp(&other.vruntime)
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
    min_vruntime: u64,     // Keep track of the minimum vruntime across all tasks
    max_vruntime: u64,     // Keep track of the maximum vruntime across all tasks
    slice_ns: u64,         // Default time slice (in ns)
    slice_boost: u64,      // Slice booster
    init_page_faults: u64, // Initial page faults counter
    no_preemption: bool,   // Disable task preemption
    full_user: bool,       // Run all tasks through the user-space scheduler
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts) -> Result<Self> {
        // Initialize core mapping topology.
        let topo = Topology::new().expect("Failed to build host topology");
        let topo_map = TopologyMap::new(topo).expect("Failed to generate topology map");

        // Save the default time slice (in ns) in the scheduler class.
        let slice_ns = opts.slice_us * NSEC_PER_USEC;

        // Slice booster (0 = disabled).
        let slice_boost = opts.slice_boost;

        // Disable task preemption.
        let no_preemption = opts.no_preemption;

        // Run all tasks through the user-space scheduler.
        let full_user = opts.full_user;

        // Scheduler task pool to sort tasks by vruntime.
        let task_pool = TaskTree::new();

        // Scheduler task map to store tasks information.
        let task_map = TaskInfoMap::new();

        // Initialize global minimum and maximum vruntime.
        let min_vruntime: u64 = 0;
        let max_vruntime: u64 = 0;

        // Initialize initial page fault counter.
        let init_page_faults: u64 = 0;

        // Low-level BPF connector.
        let nr_cpus = topo_map.nr_cpus_possible();
        let bpf = BpfScheduler::init(
            opts.slice_us,
            nr_cpus as i32,
            opts.partial,
            opts.exit_dump_len,
            opts.full_user,
            opts.low_power,
            !opts.disable_fifo,
            opts.debug,
        )?;
        info!("{} scheduler attached - {} CPUs", SCHEDULER_NAME, nr_cpus);

        // Return scheduler object.
        Ok(Self {
            bpf,
            topo_map,
            task_pool,
            task_map,
            min_vruntime,
            max_vruntime,
            slice_ns,
            slice_boost,
            init_page_faults,
            no_preemption,
            full_user,
        })
    }

    // Return the amount of idle cores.
    //
    // On SMT systems consider only one CPU for each fully idle core, to avoid disrupting
    // performnance too much by running multiple tasks in the same core.
    fn nr_idle_cpus(&mut self) -> usize {
        let mut idle_cpu_count = 0;

        // Count the number of cores where all the CPUs are idle.
        for core in self.topo_map.iter() {
            let mut all_idle = true;
            for cpu_id in core {
                if self.bpf.get_cpu_pid(*cpu_id as i32) != 0 {
                    all_idle = false;
                    break;
                }
            }

            if all_idle {
                idle_cpu_count += 1;
            }
        }

        idle_cpu_count
    }

    // Return current timestamp in ns.
    fn now() -> u64 {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        ts.as_nanos() as u64
    }

    // Update task's vruntime based on the information collected from the kernel and return to the
    // caller the evaluated weighted time slice along with a flag indicating whether the task is
    // interactive or not (interactive tasks are allowed to preempt other tasks).
    //
    // This method implements the main task ordering logic of the scheduler.
    fn update_enqueued(&mut self, task: &QueuedTask) -> (u64, bool) {
        // Determine if a task is new or old, based on their current runtime and previous runtime
        // counters.
        //
        // NOTE: make sure to handle the case where the current sum_exec_runtime is less then the
        // previous sum_exec_runtime. This can happen, for example, when a new task is created via
        // execve() (or its variants): the kernel will initialize a new task_struct, resetting
        // sum_exec_runtime, while keeping the same PID.
        //
        // Consequently, the existing task_info slot is reused, containing the total run-time of
        // the previous task (likely exceeding the current sum_exec_runtime). In such cases, simply
        // use sum_exec_runtime as the time slice of the new task.
        fn is_new_task(curr_runtime: u64, prev_runtime: u64) -> bool {
            curr_runtime < prev_runtime || prev_runtime == 0
        }

        // Cache the current timestamp.
        let now = Self::now();

        // Get task information if the task is already stored in the task map,
        // otherwise create a new entry for it.
        let task_info = self
            .task_map
            .tasks
            .entry(task.pid)
            .or_insert_with_key(|&_pid| TaskInfo {
                sum_exec_runtime: 0,
                vruntime: self.min_vruntime,
                nvcsw: task.nvcsw,
                nvcsw_ts: now,
                avg_nvcsw: 0,
            });

        // Evaluate last time slot used by the task.
        let mut slice = if is_new_task(task.sum_exec_runtime, task_info.sum_exec_runtime) {
            task.sum_exec_runtime
        } else {
            task.sum_exec_runtime - task_info.sum_exec_runtime
        };

        // Determine if a task is interactive, based on the moving average of voluntary context
        // switches over time.
        //
        // NOTE: we should make this threshold a tunable, but for now let's assume that a moving
        // average of 10 voluntary context switch per second is enough to classify the task as
        // interactive.
        let is_interactive = task_info.avg_nvcsw >= 10;

        // Apply the slice boost to interactive tasks.
        //
        // NOTE: some tasks may have a very high weight, that can potentially disrupt our slice
        // boost optimizations, therefore always limit the task priority to a max of 1000.
        let weight = if is_interactive {
            task.weight.min(1000) * self.slice_boost.max(1)
        } else {
            task.weight.min(1000)
        };

        // Scale the time slice by the task's priority (weight).
        slice = slice * 100 / weight;

        // Make sure that the updated vruntime is in the range:
        //
        //   (min_vruntime, min_vruntime + slice_ns]
        //
        // In this way we ensure that global vruntime is always progressing during each scheduler
        // run, preventing excessive starvation of the other tasks sitting in the self.task_pool
        // tree.
        //
        // Moreover, limiting the accounted time slice to slice_ns, allows to prevent starving the
        // current task for too long in the scheduler task pool.
        task_info.vruntime = self.min_vruntime + slice.clamp(1, self.slice_ns);

        // Update maximum vruntime.
        self.max_vruntime = self.max_vruntime.max(task_info.vruntime);

        // Update total task cputime.
        task_info.sum_exec_runtime = task.sum_exec_runtime;

        // Refresh voluntay context switches average, counter and timestamp every second.
        if now - task_info.nvcsw_ts > NSEC_PER_SEC {
            let delta_nvcsw = task.nvcsw - task_info.nvcsw;
            let delta_t = (now - task_info.nvcsw_ts).max(1);
            let avg_nvcsw = delta_nvcsw * NSEC_PER_SEC / delta_t;

            task_info.avg_nvcsw = (task_info.avg_nvcsw + avg_nvcsw) / 2;
            task_info.nvcsw = task.nvcsw;
            task_info.nvcsw_ts = now;
        }

        // Return the task vruntime and a flag indicating if the task is interactive.
        (task_info.vruntime, is_interactive)
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

                    // Update task information and determine vruntime and interactiveness.
                    let (vruntime, is_interactive) = self.update_enqueued(&task);

                    // Insert task in the task pool (ordered by vruntime).
                    self.task_pool.push(Task {
                        qtask: task,
                        vruntime,
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

    // Return the target time slice, proportionally adjusted based on the total amount of tasks
    // waiting to be scheduled (more tasks waiting => shorter time slice).
    // Dispatch tasks from the task pool in order (sending them to the BPF dispatcher).
    fn dispatch_tasks(&mut self) {
        // Dispatch only a batch of tasks equal to the amount of idle CPUs in the system.
        //
        // This allows to have more tasks sitting in the task pool, reducing the pressure on the
        // dispatcher queues and giving a chance to higher priority tasks to come in and get
        // dispatched earlier, mitigating potential priority inversion issues.
        let delta_slice = self.max_vruntime - self.min_vruntime;
        let nr_tasks = if delta_slice <= self.slice_ns {
            self.nr_idle_cpus().max(1)
        } else {
            // Scheduler is getting congested, flush all tasks that are waiting to be scheduled to
            // mitigate excessive starvation.
            usize::MAX
        };
        for _ in 0..nr_tasks {
            match self.task_pool.pop() {
                Some(task) => {
                    // Determine the task's virtual time slice.
                    //
                    // The goal is to evaluate the optimal time slice, considering the vruntime as
                    // a deadline for the task to complete its work before releasing the CPU.
                    //
                    // This is accomplished by calculating the difference between the task's
                    // vruntime and the global current vruntime and use this value as the task time
                    // slice.
                    //
                    // In this way, tasks that "promise" to release the CPU quickly (based on
                    // their previous work pattern) get a much higher priority (due to
                    // vruntime-based scheduling and the additional priority boost for being
                    // classified as interactive), but they are also given a shorter time slice
                    // to complete their work and fulfill their promise of rapidity.
                    //
                    // At the same time tasks that are more CPU-intensive get de-prioritized, but
                    // they will also tend to have a longer time slice available, reducing in this
                    // way the amount of context switches that can negatively affect their
                    // performance.
                    //
                    // In conclusion, latency-sensitive tasks get a high priority and a short time
                    // slice (and they can preempt other tasks), CPU-intensive tasks get low
                    // priority and a long time slice.
                    //
                    // Moreover, ensure that the time slice is never less than 0.25 ms to prevent
                    // excessive penalty from assigning time slices that are too short and reduce
                    // context switch overhead.
                    let slice_ns =
                        (task.vruntime - self.min_vruntime).clamp(NSEC_PER_MSEC / 4, self.slice_ns);

                    // Update global minimum vruntime.
                    self.min_vruntime = task.vruntime;

                    // Create a new task to dispatch.
                    let mut dispatched_task = DispatchedTask::new(&task.qtask);

                    dispatched_task.set_slice_ns(slice_ns);

                    if task.is_interactive {
                        // Dispatch interactive tasks on the first CPU available.
                        dispatched_task.set_flag(RL_CPU_ANY);

                        // Interactive tasks can preempt other tasks.
                        if !self.no_preemption {
                            dispatched_task.set_flag(RL_PREEMPT_CPU);
                        }
                    }

                    // In full-user mode we skip the built-in idle selection logic, so simply
                    // dispatch all the tasks on the first CPU available.
                    if self.full_user {
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
                            break;
                        }
                    }
                }
                None => break,
            }
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
        self.dispatch_tasks();

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
        // Show minimum vruntime (this should be constantly incrementing).
        let delta = self.max_vruntime - self.min_vruntime;
        info!(
            "min_vruntime={} max_vruntime={} delta={}us slice={}us",
            self.min_vruntime,
            self.max_vruntime,
            delta / NSEC_PER_USEC,
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

        // Show tasks that are currently running on each core and CPU.
        let sched_cpu = match Self::get_current_cpu() {
            Ok(cpu_info) => cpu_info,
            Err(_) => -1,
        };
        info!("Running tasks:");
        for (core_id, core) in self.topo_map.iter().enumerate() {
            for cpu_id in core {
                let pid = if *cpu_id as i32 == sched_cpu {
                    "[self]".to_string()
                } else {
                    self.bpf.get_cpu_pid(*cpu_id as i32).to_string()
                };
                info!("  core {:2} cpu {:2} pid={}", core_id, cpu_id, pid);
            }
        }

        log::logger().flush();
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let mut prev_ts = Self::now();

        while !shutdown.load(Ordering::Relaxed) && !self.bpf.exited() {
            // Call the main scheduler body.
            self.schedule();

            // Print scheduler statistics every second.
            let curr_ts = Self::now();
            if curr_ts - prev_ts > NSEC_PER_SEC {
                self.print_stats();

                prev_ts = curr_ts;
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
