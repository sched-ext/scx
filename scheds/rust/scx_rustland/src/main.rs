// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

mod bpf;
use bpf::*;

use std::thread;

use std::collections::BTreeSet;
use std::collections::HashMap;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

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
}

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

// Convert Task to DispatchedTask used by the dispatcher.
impl Task {
    pub fn to_dispatched_task(&self) -> DispatchedTask {
        DispatchedTask {
            pid: self.pid,
            cpu: self.cpu,
            payload: self.vruntime,
        }
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
    fn push(&mut self, task: Task) {
        self.tasks.insert(task);
    }

    // Pop the first item from the BTreeSet (item with the smallest vruntime).
    fn pop(&mut self) -> Option<Task> {
        self.tasks.pop_first()
    }
}

// Main scheduler object
struct Scheduler<'a> {
    bpf: BpfScheduler<'a>, // BPF connector
    task_pool: TaskTree,   // tasks ordered by vruntime
    task_map: TaskInfoMap, // map pids to the corresponding task information
    min_vruntime: u64,     // Keep track of the minimum vruntime across all tasks
    slice_ns: u64,         // Default time slice (in ns)
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts) -> Result<Self> {
        // Low-level BPF connector.
        let bpf = BpfScheduler::init(opts.slice_us, opts.partial, opts.debug)?;
        info!("{} scheduler attached", SCHEDULER_NAME);

        // Save the default time slice (in ns) in the scheduler class.
        let slice_ns = opts.slice_us * 1000;

        // Scheduler task pool to sort tasks by vruntime.
        let task_pool = TaskTree::new();

        // Scheduler task map to store tasks information.
        let task_map = TaskInfoMap::new();

        // Initialize global minimum vruntime.
        let min_vruntime: u64 = 0;

        // Return scheduler object.
        Ok(Self {
            bpf,
            task_pool,
            task_map,
            min_vruntime,
            slice_ns,
        })
    }

    // Return the array of idle CPU ids.
    fn get_idle_cpus(&self) -> Vec<i32> {
        let mut idle_cpus = Vec::new();

        for cpu in 0..self.bpf.get_nr_cpus() {
            let pid = self.bpf.get_cpu_pid(cpu);
            if pid == 0 {
                idle_cpus.push(cpu);
            }
        }

        idle_cpus
    }

    // Update task's vruntime based on the information collected from the kernel and return the
    // evaluated weighted time slice to the caller.
    //
    // This method implements the main task ordering logic of the scheduler.
    fn update_enqueued(
        task_info: &mut TaskInfo,
        sum_exec_runtime: u64,
        weight: u64,
        min_vruntime: u64,
        slice_ns: u64,
    ) {
        // Evaluate last time slot used by the task, scaled by its priority (weight).
        //
        // NOTE: make sure to handle the case where the current sum_exec_runtime is less then the
        // previous sum_exec_runtime. This can happen, for example, when a new task is created via
        // execve() (or its variants): the kernel will initialize a new task_struct, resetting
        // sum_exec_runtime, while keeping the same PID.
        //
        // Consequently, the existing task_info slot is reused, containing the total run-time of
        // the previous task (likely exceeding the current sum_exec_runtime). In such cases, simply
        // use sum_exec_runtime as the time slice of the new task.
        let slice = if sum_exec_runtime > task_info.sum_exec_runtime {
            sum_exec_runtime - task_info.sum_exec_runtime
        } else {
            sum_exec_runtime
        } * 100
            / weight;

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
        task_info.vruntime = min_vruntime + slice.clamp(1, slice_ns);

        // Update total task cputime.
        task_info.sum_exec_runtime = sum_exec_runtime;
    }

    // Drain all the tasks from the queued list, update their vruntime (Self::update_enqueued()),
    // then push them all to the task pool (doing so will sort them by their vruntime).
    fn drain_queued_tasks(&mut self) {
        let slice_ns = self.bpf.get_effective_slice_us() * 1000;
        loop {
            match self.bpf.dequeue_task() {
                Ok(Some(task)) => {
                    // Check for exiting tasks (cpu < 0) and remove their corresponding entries in
                    // the task map (if present).
                    if task.cpu < 0 {
                        self.task_map.tasks.remove(&task.pid);
                        continue;
                    }

                    // Get task information if the task is already stored in the task map,
                    // otherwise create a new entry for it.
                    let task_info =
                        self.task_map
                            .tasks
                            .entry(task.pid)
                            .or_insert_with_key(|&_pid| TaskInfo {
                                sum_exec_runtime: 0,
                                vruntime: self.min_vruntime,
                            });

                    // Update task information.
                    Self::update_enqueued(
                        task_info,
                        task.sum_exec_runtime,
                        task.weight,
                        self.min_vruntime,
                        slice_ns,
                    );

                    // Insert task in the task pool (ordered by vruntime).
                    self.task_pool.push(Task {
                        pid: task.pid,
                        cpu: task.cpu,
                        vruntime: task_info.vruntime,
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
        let nr_queued = *self.bpf.nr_queued_mut();
        let nr_scheduled = *self.bpf.nr_scheduled_mut();
        let nr_waiting = nr_queued + nr_scheduled;
        let nr_cpus = self.bpf.get_nr_cpus() as u64;

        // Scale time slice, but never scale below 1 ms.
        let scaling = nr_waiting / nr_cpus + 1;
        let slice_us = (self.slice_ns / scaling / 1000).max(1000);

        // Apply new scaling.
        self.bpf.set_effective_slice_us(slice_us);
    }

    // Dispatch tasks from the task pool in order (sending them to the BPF dispatcher).
    fn dispatch_tasks(&mut self) {
        let mut idle_cpus = self.get_idle_cpus();

        // Adjust the dynamic time slice immediately before dispatching the tasks.
        self.scale_slice_ns();

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
        info!(
            "vruntime={} tasks={}",
            self.min_vruntime,
            self.task_map.tasks.len()
        );

        // Show general statistics.
        let nr_user_dispatches = *self.bpf.nr_user_dispatches_mut();
        let nr_kernel_dispatches = *self.bpf.nr_kernel_dispatches_mut();
        info!(
            "  nr_user_dispatches={} nr_kernel_dispatches={}",
            nr_user_dispatches, nr_kernel_dispatches
        );

        // Show failure statistics.
        let nr_failed_dispatches = *self.bpf.nr_failed_dispatches_mut();
        let nr_sched_congested = *self.bpf.nr_sched_congested_mut();
        info!(
            "  nr_failed_dispatches={} nr_sched_congested={}",
            nr_failed_dispatches, nr_sched_congested
        );

        // Show tasks that are waiting to be dispatched.
        let nr_queued = *self.bpf.nr_queued_mut();
        let nr_scheduled = *self.bpf.nr_scheduled_mut();
        let nr_waiting = nr_queued + nr_scheduled;
        info!(
            "  nr_waiting={} [nr_queued={} + nr_scheduled={}]",
            nr_waiting, nr_queued, nr_scheduled
        );

        // Show current used time slice.
        info!("time slice = {} us", self.bpf.get_effective_slice_us());

        // Show tasks that are currently running.
        let sched_cpu = match Self::get_current_cpu() {
            Ok(cpu_info) => cpu_info,
            Err(_) => -1,
        };
        info!("Running tasks:");
        for cpu in 0..self.bpf.get_nr_cpus() {
            let pid = if cpu == sched_cpu {
                "[self]".to_string()
            } else {
                self.bpf.get_cpu_pid(cpu).to_string()
            };
            info!("  cpu={} pid={}", cpu, pid);
        }

        log::logger().flush();
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        let mut prev_ts = SystemTime::now();

        while !shutdown.load(Ordering::Relaxed) && self.bpf.read_bpf_exit_kind() == 0 {
            let curr_ts = SystemTime::now();
            let elapsed = curr_ts
                .duration_since(prev_ts)
                .unwrap_or_else(|_| Duration::from_secs(0));

            // Call the main scheduler body.
            self.schedule();

            // Print scheduler statistics every second.
            if elapsed > Duration::from_secs(1) {
                // Print scheduler statistics.
                self.print_stats();

                prev_ts = curr_ts;
            }
        }

        // Report exit code and message from the BPF part.
        let (exit_code, msg) = self.bpf.report_bpf_exit_kind();
        match exit_code {
            0 => {
                if !msg.is_empty() {
                    info!("EXIT: {}", msg);
                }
                Ok(())
            }
            err => {
                if !msg.is_empty() {
                    warn!("FAIL: {} (err={})", msg, err);
                }
                Err(anyhow::Error::msg(err))
            }
        }
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
