# Framework to implement `sched_ext` schedulers running in user-space

`scx_rustland_core` is a Rust framework designed to facilitate the
implementation of user-space schedulers based on the Linux kernel `sched_ext`
feature.

`sched_ext` allows to dynamic load and execute custom schedulers in the kernel,
leveraging BPF to manage scheduling policies.

This crate provides an abstraction layer for `sched_ext`, enabling developers
to write schedulers in Rust without dealing with low-level kernel or BPF
details.

## Features

- **Generic BPF Abstraction**: Interact with BPF components using a high-level Rust API.
- **Task Scheduling**: Enqueue and dispatch tasks using provided methods.
- **CPU Selection**: Select idle CPUs for task execution with a preference for reusing previous CPUs.
- **Time slice**: Assign a specific time slice on a per-task basis.
- **Performance Reporting**: Access internal scheduling statistics.

## API

### `BpfScheduler`

The `BpfScheduler` struct is the core interface for interacting with the BPF
component.

- **Initialization**:
  - `BpfScheduler::init` registers and initializes the BPF component.

- **Task Management**:
  - `dequeue_task()`: Retrieve tasks that need to be scheduled.
  - `dispatch_task(task: &DispatchedTask)`: Dispatch tasks to specific CPUs.
  - `select_cpu(pid: i32, prev_cpu: i32, flags: u64)`: Select an idle CPU for a task.

- **Completion Notification**:
  - `notify_complete(nr_pending: u64)` reports the number of pending tasks to the BPF component.

## Getting Started

 - **Installation**:
   - Add `scx_rustland_core` to your `Cargo.toml` dependencies.
```
[dependencies]
scx_rustland_core = "0.1"
```
 - **Implementation**:
   - Create your scheduler by implementing the provided API.

 - **Execution**:
   - Compile and run your scheduler. Ensure that your kernel supports `sched_ext` and is configured to load your BPF programs.


## Example

Following you can find a simple example of a fully working FIFO scheduler,
implemented using the `scx_rustland_core` framework:
```
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

use std::mem::MaybeUninit;
use std::collections::VecDeque;

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
        Ok(Self { bpf, task_queue: VecDeque::new() })
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
        //     pub nvcsw: u64,            // Total amount of voluntary context switches
        //     pub slice: u64,            // Remaining time slice budget
        //     pub vtime: u64,            // Current task vruntime / deadline (set by the scheduler)
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
            let cpu = self.bpf.select_cpu(task.pid, task.cpu, 0);
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

    fn run(&mut self) -> Result<UserExitInfo> {
        while !self.bpf.exited() {
            self.dispatch_tasks();
        }
        self.bpf.shutdown_and_report()
    }
}

fn main() -> Result<()> {
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
```

## License

This software is licensed under the GNU General Public License version 2. See
the LICENSE file for details.

## Contributing

Contributions are welcome! Please submit issues or pull requests via GitHub.
