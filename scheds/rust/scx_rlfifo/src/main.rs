// Copyright (c) Andrea Righi <andrea.righi@canonical.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

mod bpf;
use bpf::*;

use scx_utils::Topology;
use scx_utils::UserExitInfo;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use std::time::SystemTime;

use anyhow::Result;

struct Scheduler<'a> {
    bpf: BpfScheduler<'a>,
}

impl<'a> Scheduler<'a> {
    fn init() -> Result<Self> {
        let topo = Topology::new().expect("Failed to build host topology");
        let bpf = BpfScheduler::init(
            5000,                           // slice_ns (default task time slice)
            topo.nr_cpus_possible() as i32, // nr_cpus (max CPUs available in the system)
            false,                          // partial (include all tasks if disabled)
            0,                              // exit_dump_len (buffer size of exit info)
            false,                          // full_user (schedule all tasks in user-space)
            false,                          // low_power (low power mode)
            true,                           // fifo_sched (enable BPF FIFO scheduling)
            false,                          // debug (debug mode)
        )?;
        Ok(Self { bpf })
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn dispatch_tasks(&mut self) {
        loop {
            // Get queued taks and dispatch them in order (FIFO).
            match self.bpf.dequeue_task() {
                Ok(Some(task)) => {
                    // task.cpu < 0 is used to to notify an exiting task, in this
                    // case we can simply ignore the task.
                    if task.cpu >= 0 {
                        let dispatched_task = DispatchedTask::new(&task);
                        let _ = self.bpf.dispatch_task(&dispatched_task);

                        // Give the task a chance to run and prevent overflowing the dispatch queue.
                        std::thread::yield_now();
                    }
                }
                Ok(None) => {
                    // Notify the BPF component that all tasks have been scheduled and dispatched.
                    self.bpf.update_tasks(Some(0), Some(0));
                    break;
                }
                Err(_) => {
                    break;
                }
            }
        }
        // All queued tasks have been dipatched, yield to reduce scheduler's CPU consumption.
        std::thread::yield_now();
    }

    fn print_stats(&mut self) {
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

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let mut prev_ts = Self::now();

        while !shutdown.load(Ordering::Relaxed) && !self.bpf.exited() {
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

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    loop {
        let mut sched = Scheduler::init()?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
