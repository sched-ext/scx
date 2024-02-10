// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

mod bpf;
use bpf::*;

mod topology;
use topology::*;

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
/// === Troubleshooting ===
///
/// - Disable HyperThreading / SMT if you notice poor performance (add "nosmt" to the kernel boot
///   parameters): this scheduler is not NUMA-aware and it implements a simple policy of handling
///   SMT cores.
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
    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "20000")]
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

// Time constants.
const USEC_PER_NSEC: u64 = 1_000;
const NSEC_PER_USEC: u64 = 1_000;
const MSEC_PER_SEC: u64 = 1_000;
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
    pid: i32,         // pid that uniquely identifies a task
    cpu: i32,         // CPU where the task is running
    cpumask_cnt: u64, // cpumask generation counter
    vruntime: u64,    // total vruntime (that determines the order how tasks are dispatched)
}

// Make sure tasks are ordered by vruntime, if multiple tasks have the same vruntime order by pid.
impl Ord for Task {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.vruntime
            .cmp(&other.vruntime)
            .then_with(|| self.pid.cmp(&other.pid))
    }
}

// Convert Task to DispatchedTask used by the dispatcher.
impl Task {
    pub fn to_dispatched_task(&self) -> DispatchedTask {
        DispatchedTask {
            pid: self.pid,
            cpu: self.cpu,
            cpumask_cnt: self.cpumask_cnt,
            payload: self.vruntime,
        }
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
        if let Some(prev_task) = self.task_map.get(&task.pid) {
            self.tasks.remove(prev_task);
        }

        // Insert/update task.
        self.tasks.insert(task.clone());
        self.task_map.insert(task.pid, task);
    }

    // Pop the first item from the BTreeSet (item with the smallest vruntime).
    fn pop(&mut self) -> Option<Task> {
        if let Some(task) = self.tasks.pop_first() {
            self.task_map.remove(&task.pid);
            Some(task)
        } else {
            None
        }
    }
}

// Main scheduler object
struct Scheduler<'a> {
    bpf: BpfScheduler<'a>, // BPF connector
    cores: CoreMapping,    // Map of core ids -> CPU ids
    task_pool: TaskTree,   // tasks ordered by vruntime
    task_map: TaskInfoMap, // map pids to the corresponding task information
    min_vruntime: u64,     // Keep track of the minimum vruntime across all tasks
    slice_ns: u64,         // Default time slice (in ns)
    slice_boost: u64,      // Slice booster
    eff_slice_boost: u64,  // Effective slice booster
    init_page_faults: u64, // Initial page faults counter
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts) -> Result<Self> {
        // Initialize core mapping topology.
        let cores = CoreMapping::new();

        // Save the default time slice (in ns) in the scheduler class.
        let slice_ns = opts.slice_us * NSEC_PER_USEC;

        // Slice booster (0 = disabled).
        let slice_boost = opts.slice_boost;
        let eff_slice_boost = slice_boost;

        // Scheduler task pool to sort tasks by vruntime.
        let task_pool = TaskTree::new();

        // Scheduler task map to store tasks information.
        let task_map = TaskInfoMap::new();

        // Initialize global minimum vruntime.
        let min_vruntime: u64 = 0;

        // Initialize initial page fault counter.
        let init_page_faults: u64 = 0;

        // Low-level BPF connector.
        let bpf = BpfScheduler::init(
            opts.slice_us,
            cores.nr_cpus_online,
            opts.partial,
            opts.debug,
        )?;
        info!("{} scheduler attached", SCHEDULER_NAME);

        // Return scheduler object.
        Ok(Self {
            bpf,
            cores,
            task_pool,
            task_map,
            min_vruntime,
            slice_ns,
            slice_boost,
            eff_slice_boost,
            init_page_faults,
        })
    }

    // Returns the list of idle CPUs.
    //
    // On SMT systems consider only one CPU for each fully idle core, to avoid disrupting
    // performnance too much by running multiple tasks in the same core.
    fn get_idle_cpus(&self) -> Vec<i32> {
        let cores = &self.cores.map;
        let num_cpus = self.cores.nr_cpus_online;

        // Cache the results of self.bpf.get_cpu_pid() for all CPUs.
        let cpu_pid_map: Vec<u32> = (0..num_cpus)
            .map(|cpu_id| self.bpf.get_cpu_pid(cpu_id))
            .collect();

        // Generate the list of idle CPU IDs by selecting the first item from each list of CPU IDs
        // associated to the idle cores. The remaining sibling CPUs will be used as spare/emergency
        // CPUs by the BPF dispatcher.
        //
        // This prevents overloading cores on SMT systems, improving the overall system
        // responsiveness and it also improves scheduler stability: using the remaining sibling
        // CPUs as spare CPUs ensures that the BPF dispatcher will always have some available CPUs
        // that can be used in emergency conditions.
        let idle_cores: Vec<i32> = cores
            .iter()
            .filter_map(|(&core_id, core_cpus)| {
                if core_cpus
                    .iter()
                    .all(|&cpu_id| cpu_pid_map[cpu_id as usize] == 0)
                {
                    Some(core_id)
                } else {
                    None
                }
            })
            .collect();

        idle_cores.iter().map(|&core| cores[&core][0]).collect()
    }

    // Return current timestamp in ns.
    fn now() -> u64 {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        ts.as_nanos() as u64
    }

    // Update task's vruntime based on the information collected from the kernel and return the
    // evaluated weighted time slice to the caller.
    //
    // This method implements the main task ordering logic of the scheduler.
    fn update_enqueued(&mut self, task: &QueuedTask) -> u64 {
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

        // Get the current effective time slice.
        let slice_ns = self.bpf.get_effective_slice_us() * MSEC_PER_SEC;

        // Update dynamic slice boost.
        //
        // The slice boost is dynamically adjusted as a function of the amount of CPUs
        // in the system and the amount of tasks currently waiting to be dispatched.
        //
        // As the amount of waiting tasks in the task_pool increases we should reduce
        // the slice boost to enforce the scheduler to apply a pure vruntime-based
        // policy.
        //
        // This allows to survive stress tests that are spawning a massive amount of
        // tasks.
        self.eff_slice_boost = (self.slice_boost * self.cores.nr_cpus_online as u64
            / self.task_pool.tasks.len().max(1) as u64)
            .max(1);

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

        // Apply the slice boost to interactive tasks.
        //
        // Determine if a task is interactive, based on the moving average of voluntary context
        // switches over time.
        //
        // NOTE: we should make this threshold a tunable, but for now let's assume that a moving
        // average of 10 voluntary context switch per second is enough to classify the task as
        // interactive.
        let weight = if task_info.avg_nvcsw >= 10 {
            task.weight * self.slice_boost.max(1)
        } else {
            task.weight
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
        task_info.vruntime = self.min_vruntime + slice.clamp(1, slice_ns);

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

                    // Update task information.
                    let vruntime = self.update_enqueued(&task);

                    // Insert task in the task pool (ordered by vruntime).
                    self.task_pool.push(Task {
                        pid: task.pid,
                        cpu: task.cpu,
                        cpumask_cnt: task.cpumask_cnt,
                        vruntime,
                    });
                }
                Ok(None) => {
                    // Reset nr_queued and update nr_scheduled, to notify the dispatcher that
                    // queued tasks are drained, but there is still some work left to do in the
                    // scheduler.
                    *self.bpf.nr_queued_mut() = 0;
                    *self.bpf.nr_scheduled_mut() = self.task_pool.tasks.len() as u64;
                    break;
                }
                Err(err) => {
                    warn!("Error: {}", err);
                    break;
                }
            }
        }
    }

    // Dynamically adjust the time slice based on the amount of waiting tasks.
    fn scale_slice_ns(&mut self) {
        let nr_scheduled = self.task_pool.tasks.len() as u64;
        let slice_us_max = self.slice_ns / MSEC_PER_SEC;

        // Scale time slice as a function of nr_scheduled, but never scale below 250 us.
        let scaling = ((nr_scheduled + 1) / 2).max(1);
        let slice_us = (slice_us_max / scaling).max(USEC_PER_NSEC / 4);

        // Apply new scaling.
        self.bpf.set_effective_slice_us(slice_us);
    }

    // Dispatch tasks from the task pool in order (sending them to the BPF dispatcher).
    fn dispatch_tasks(&mut self) {
        // Dispatch only a batch of tasks equal to the amount of idle CPUs in the system.
        //
        // This allows to have more tasks sitting in the task pool, reducing the pressure on the
        // dispatcher queues and giving a chance to higher priority tasks to come in and get
        // dispatched earlier, mitigating potential priority inversion issues.
        let idle_cpus = self.get_idle_cpus();
        for _ in &idle_cpus {
            match self.task_pool.pop() {
                Some(mut task) => {
                    // Update global minimum vruntime.
                    self.min_vruntime = task.vruntime;

                    // If the CPU assigned to the task is not idle anymore, dispatch to the first
                    // CPU that becomes available.
                    if !idle_cpus.contains(&task.cpu) {
                        task.cpu = NO_CPU;
                    }

                    // Send task to the BPF dispatcher.
                    match self.bpf.dispatch_task(&task.to_dispatched_task()) {
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
        // Reset nr_scheduled to notify the dispatcher that all the tasks received by the scheduler
        // has been dispatched, so there is no reason to re-activate the scheduler, unless more
        // tasks are queued.
        self.bpf.skel.bss_mut().nr_scheduled = self.task_pool.tasks.len() as u64;
    }

    // Main scheduling function (called in a loop to periodically drain tasks from the queued list
    // and dispatch them to the BPF part via the dispatched list).
    fn schedule(&mut self) {
        self.drain_queued_tasks();
        self.dispatch_tasks();

        // Adjust the dynamic time slice immediately after dispatching the tasks.
        self.scale_slice_ns();

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
        info!("vruntime={}", self.min_vruntime);

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

        // Show tasks that are waiting to be dispatched.
        let nr_queued = *self.bpf.nr_queued_mut();
        let nr_scheduled = *self.bpf.nr_scheduled_mut();
        let nr_waiting = nr_queued + nr_scheduled;
        info!(
            "  nr_waiting={} [nr_queued={} + nr_scheduled={}]",
            nr_waiting, nr_queued, nr_scheduled
        );

        // Show total page faults of the user-space scheduler.
        self.print_faults();

        // Show current used time slice.
        info!("time slice = {} us", self.bpf.get_effective_slice_us());

        // Show current slice boost.
        info!("slice boost = {}", self.eff_slice_boost);

        // Show tasks that are currently running on each core and CPU.
        let sched_cpu = match Self::get_current_cpu() {
            Ok(cpu_info) => cpu_info,
            Err(_) => -1,
        };
        info!("Running tasks:");
        let mut core_ids: Vec<i32> = self.cores.map.keys().copied().collect();
        core_ids.sort();
        for core_id in core_ids {
            let mut cpu_ids: Vec<i32> = self.cores.map.get(&core_id).unwrap().clone();
            cpu_ids.sort();
            for cpu_id in cpu_ids {
                let pid = if cpu_id == sched_cpu {
                    "[self]".to_string()
                } else {
                    self.bpf.get_cpu_pid(cpu_id).to_string()
                };
                info!("  core {:2} cpu {:2} pid={}", core_id, cpu_id, pid);
            }
        }

        log::logger().flush();
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
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
