// Copyright (c) Andrea Righi <andrea.righi@linux.dev>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

mod bpf;
use bpf::*;

use scx_utils::UserExitInfo;

use libbpf_rs::OpenObject;

use std::collections::VecDeque;
use std::mem::MaybeUninit;
use std::time::SystemTime;

use anyhow::Result;

const SLICE_US: u64 = 5000;

struct Scheduler<'a> {
    bpf: BpfScheduler<'a>,
    task_queue: VecDeque<QueuedTask>,
}

impl<'a> Scheduler<'a> {
    fn init(open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let bpf = BpfScheduler::init(
            open_object,
            0,     // exit_dump_len (buffer size of exit info, 0 = default)
            false, // partial (false = include all tasks)
            false, // debug (false = debug mode off)
        )?;
        Ok(Self {
            bpf,
            task_queue: VecDeque::new(),
        })
    }

    fn consume_all_tasks(&mut self) {
        // Consume all tasks that are ready to run.
        //
        // Each task contains the following details:
        //
        // pub struct QueuedTask {
        //     pub pid: i32,              // pid that uniquely identifies a task
        //     pub cpu: i32,              // CPU where the task is running
        //     pub sum_exec_runtime: u64, // Total cpu time
        //     pub weight: u64,           // Task static priority
        // }
        //
        // Although the FIFO scheduler doesn't use these fields, they can provide valuable data for
        // implementing more sophisticated scheduling policies.
        while let Ok(Some(task)) = self.bpf.dequeue_task() {
            self.task_queue.push_back(task);
        }
    }

    fn dispatch_next_task(&mut self) {
        if let Some(task) = self.task_queue.pop_front() {
            // Create a new task to be dispatched, derived from the received enqueued task.
            //
            // pub struct DispatchedTask {
            //     pub pid: i32,      // pid that uniquely identifies a task
            //     pub cpu: i32,      // target CPU selected by the scheduler
            //     pub flags: u64,    // special dispatch flags
            //     pub slice_ns: u64, // time slice assigned to the task (0 = default)
            // }
            //
            // The dispatched task's information are pre-populated from the QueuedTask and they can
            // be modified before dispatching it via self.bpf.dispatch_task().
            let mut dispatched_task = DispatchedTask::new(&task);

            // Decide where the task needs to run (target CPU).
            //
            // A call to select_cpu() will return the most suitable idle CPU for the task,
            // considering its previously used CPU.
            let cpu = self.bpf.select_cpu(task.pid, task.cpu, task.flags);
            if cpu >= 0 {
                dispatched_task.cpu = cpu;
            } else {
                dispatched_task.flags |= RL_CPU_ANY;
            }

            // Decide for how long the task needs to run (time slice); if not specified
            // SCX_SLICE_DFL will be used by default.
            dispatched_task.slice_ns = SLICE_US;

            // Dispatch the task on the target CPU.
            self.bpf.dispatch_task(&dispatched_task).unwrap();

            // Notify the BPF component of the number of pending tasks and immediately give a
            // chance to run to the dispatched task.
            self.bpf.notify_complete(self.task_queue.len() as u64);
        }
    }

    fn dispatch_tasks(&mut self) {
        loop {
            // Consume all tasks before dispatching any.
            self.consume_all_tasks();

            // Dispatch one task from the queue.
            self.dispatch_next_task();

            // If no task is ready to run (or in case of error), stop dispatching tasks and notify
            // the BPF component that all tasks have been scheduled / dispatched, with no remaining
            // pending tasks.
            if self.task_queue.is_empty() {
                self.bpf.notify_complete(0);
                break;
            }
        }
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
