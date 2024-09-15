// Copyright (c) Andrea Righi <andrea.righi@linux.dev>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! # FIFO Linux kernel scheduler that runs in user-space
//!
//! ## Overview
//!
//! This is a fully functional FIFO scheduler for the Linux kernel that operates in user-space and
//! it is 100% implemented in Rust.
//!
//! The scheduler is designed to serve as a simple template for developers looking to implement
//! more advanced scheduling policies.
//!
//! It is based on `scx_rustland_core`, a framework that is specifically designed to simplify the
//! creation of user-space schedulers, leveraging the Linux kernel's `sched_ext` feature (a
//! technology that allows to implement schedulers in BPF).
//!
//! The `scx_rustland_core` crate offers an abstraction layer over `sched_ext`, enabling developers
//! to write schedulers in Rust without needing to interact directly with low-level kernel or BPF
//! internal details.
//!
//! ## scx_rustland_core API
//!
//! ### struct `BpfScheduler`
//!
//! The `BpfScheduler` struct is the core interface for interacting with `sched_ext` via BPF.
//!
//! - **Initialization**:
//!   - `BpfScheduler::init()` registers the scheduler and initializes the BPF component.
//!
//! - **Task Management**:
//!   - `dequeue_task()`: Consume a task that wants to run, returns a QueuedTask object
//!   - `select_cpu(pid: i32, prev_cpu: i32, flags: u64)`: Select an idle CPU for a task
//!   - `dispatch_task(task: &DispatchedTask)`: Dispatch a task
//!
//! - **Completion Notification**:
//!   - `notify_complete(nr_pending: u64)` Give control to the BPF component and report the number
//!      of tasks that are still pending (this function can sleep)
//!
//! Each task received from dequeue_task() contains the following:
//!
//! struct QueuedTask {
//!     pub pid: i32,              // pid that uniquely identifies a task
//!     pub cpu: i32,              // CPU previously used by the task
//!     pub flags: u64,            // task's enqueue flags
//!     pub sum_exec_runtime: u64, // Total cpu time in nanoseconds
//!     pub weight: u64,           // Task priority in the range [1..10000] (default is 100)
//! }
//!
//! Each task dispatched using dispatch_task() contains the following:
//!
//! struct DispatchedTask {
//!     pub pid: i32,      // pid that uniquely identifies a task
//!     pub cpu: i32,      // target CPU selected by the scheduler
//!                        // (RL_CPU_ANY = dispatch on the first CPU available)
//!     pub flags: u64,    // task's enqueue flags
//!     pub slice_ns: u64, // time slice in nanoseconds assigned to the task
//!                        // (0 = use default time slice)
//!     pub vtime: u64,    // this value can be used to send the task's vruntime or deadline
//!                        // directly to the underlying BPF dispatcher
//! }
//!
//! Other internal statistics that can be used to implement better scheduling policies:
//!
//!  let n: u64 = *self.bpf.nr_online_cpus_mut();       // amount of online CPUs
//!  let n: u64 = *self.bpf.nr_running_mut();           // amount of currently running tasks
//!  let n: u64 = *self.bpf.nr_queued_mut();            // amount of tasks queued to be scheduled
//!  let n: u64 = *self.bpf.nr_scheduled_mut();         // amount of tasks managed by the user-space scheduler
//!  let n: u64 = *self.bpf.nr_user_dispatches_mut();   // amount of user-space dispatches
//!  let n: u64 = *self.bpf.nr_kernel_dispatches_mut(); // amount of kernel dispatches
//!  let n: u64 = *self.bpf.nr_cancel_dispatches_mut(); // amount of cancelled dispatches
//!  let n: u64 = *self.bpf.nr_bounce_dispatches_mut(); // amount of bounced dispatches
//!  let n: u64 = *self.bpf.nr_failed_dispatches_mut(); // amount of failed dispatches
//!  let n: u64 = *self.bpf.nr_sched_congested_mut();   // amount of scheduler congestion events

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

#[rustfmt::skip]
mod bpf;
use std::mem::MaybeUninit;
use std::time::SystemTime;

use anyhow::Result;
use bpf::*;
use libbpf_rs::OpenObject;
use scx_utils::UserExitInfo;

// Maximum time slice (in nanoseconds) that a task can use before it is re-enqueued.
const SLICE_NS: u64 = 5_000_000;

struct Scheduler<'a> {
    bpf: BpfScheduler<'a>, // Connector to the sched_ext BPF backend
}

impl<'a> Scheduler<'a> {
    fn init(open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let bpf = BpfScheduler::init(
            open_object,
            0,     // exit_dump_len (buffer size of exit info, 0 = default)
            false, // partial (false = include all tasks)
            false, // debug (false = debug mode off)
        )?;
        Ok(Self { bpf })
    }

    fn dispatch_tasks(&mut self) {
        // Get the amount of tasks that are waiting to be scheduled.
        let nr_waiting = *self.bpf.nr_queued_mut();

        // Start consuming and dispatching tasks, until all the CPUs are busy or there are no more
        // tasks to be dispatched.
        while let Ok(Some(task)) = self.bpf.dequeue_task() {
            // Create a new task to be dispatched from the received enqueued task.
            let mut dispatched_task = DispatchedTask::new(&task);

            // Decide where the task needs to run (pick a target CPU).
            //
            // A call to select_cpu() will return the most suitable idle CPU for the task,
            // prioritizing its previously used CPU (task.cpu).
            //
            // If we can't find any idle CPU, keep the task running on the same CPU.
            let cpu = self.bpf.select_cpu(task.pid, task.cpu, task.flags);
            dispatched_task.cpu = if cpu < 0 { task.cpu } else { RL_CPU_ANY };

            // Determine the task's time slice: assign value inversely proportional to the number
            // of tasks waiting to be scheduled.
            dispatched_task.slice_ns = SLICE_NS / (nr_waiting + 1);

            // Dispatch the task.
            self.bpf.dispatch_task(&dispatched_task).unwrap();

            // Stop dispatching if all the CPUs are busy (select_cpu() couldn't find an idle CPU).
            if cpu < 0 {
                break;
            }
        }

        // Notify the BPF component that tasks have been dispatched.
        //
        // This function will put the scheduler to sleep, until another task needs to run.
        self.bpf.notify_complete(0);
    }

    fn print_stats(&mut self) {
        // Internal scx_rustland_core statistics.
        let nr_user_dispatches = *self.bpf.nr_user_dispatches_mut();
        let nr_kernel_dispatches = *self.bpf.nr_kernel_dispatches_mut();
        let nr_cancel_dispatches = *self.bpf.nr_cancel_dispatches_mut();
        let nr_bounce_dispatches = *self.bpf.nr_bounce_dispatches_mut();
        let nr_failed_dispatches = *self.bpf.nr_failed_dispatches_mut();
        let nr_sched_congested = *self.bpf.nr_sched_congested_mut();

        println!(
            "user={} kernel={} cancel={} bounce={} fail={} cong={}",
            nr_user_dispatches,
            nr_kernel_dispatches,
            nr_cancel_dispatches,
            nr_bounce_dispatches,
            nr_failed_dispatches,
            nr_sched_congested,
        );
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn run(&mut self) -> Result<UserExitInfo> {
        let mut prev_ts = Self::now();

        while !self.bpf.exited() {
            self.dispatch_tasks();

            let curr_ts = Self::now();
            if curr_ts > prev_ts {
                self.print_stats();
                prev_ts = curr_ts;
            }
        }
        self.bpf.shutdown_and_report()
    }
}

fn print_warning() {
    let warning = r#"
**************************************************************************

WARNING: The purpose of scx_rlfifo is to provide a simple scheduler
implementation based on scx_rustland_core, and it is not intended for
use in production environments. If you want to run a scheduler that makes
decisions in user space, it is recommended to use *scx_rustland* instead.

Please do not open GitHub issues in the event of poor performance, or
scheduler eviction due to a runnable task timeout. However, if running this
scheduler results in a system crash or the entire system becoming unresponsive,
please open a GitHub issue.

**************************************************************************"#;

    println!("{}", warning);
}

fn main() -> Result<()> {
    print_warning();

    // Initialize and load the FIFO scheduler.
    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&mut open_object)?;
        if !sched.run()?.should_restart() {
            break;
        }
    }

    Ok(())
}
