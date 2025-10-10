# Framework to implement `sched_ext` schedulers running in user-space

`scx_rustland_core` is a `Rust` framework designed to facilitate the
implementation of user-space schedulers based on the Linux kernel
`sched_ext` feature.

`sched_ext` allows to dynamic load and execute custom schedulers in the
kernel, leveraging BPF to manage scheduling policies.

This crate provides an abstraction layer for `sched_ext`, enabling
developers to write schedulers in `Rust` without dealing with low-level
kernel or BPF details.

## Features

- **Generic BPF Abstraction**: Interact with BPF components using a
  high-level `Rust` API.
- **Task Scheduling**: Enqueue and dispatch tasks using provided methods.
- **CPU Selection**: Select idle CPUs for task execution with a preference
  for reusing previous CPUs.
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
  - `notify_complete(nr_pending: u64)` reports the number of pending tasks
    to the BPF component.

## Getting Started

- **Installation**:
  - Add `scx_rustland_core` to your `Cargo.toml` dependencies.

- **Implementation**:
  - Create your scheduler by implementing the provided API.

- **Execution**:
  - Compile and run your scheduler. Ensure that your kernel supports
    `sched_ext` and is configured to load your BPF programs.

### struct `BpfScheduler`

The `BpfScheduler` struct is the core interface for interacting with
`sched_ext` via BPF.

- **Initialization**:
  - `BpfScheduler::init()` registers the scheduler and initializes the BPF
    component.

- **Task Management**:
  - `dequeue_task()`: Consume a task that wants to run, returns a
    QueuedTask object
  - `select_cpu(pid: i32, prev_cpu: i32, flags: u64)`: Select an idle CPU
    for a task
  - `dispatch_task(task: &DispatchedTask)`: Dispatch a task

- **Completion Notification**:
  - `notify_complete(nr_pending: u64)`: Give control to the BPF component
    and report the number of tasks that are still pending (this function
    can sleep)

Each task received from `.dequeue_task()` contains the following:

```rust
struct QueuedTask {
    pub pid: i32,              // pid that uniquely identifies a task
    pub cpu: i32,              // CPU previously used by the task
    pub nr_cpus_allowed: u64,  // Number of CPUs that the task can use
    pub flags: u64,            // task's enqueue flags
    pub start_ts: u64,         // Timestamp since last time the task ran on a CPU (in ns)
    pub stop_ts: u64,          // Timestamp since last time the task released a CPU (in ns)
    pub exec_runtime: u64,     // Total cpu time since last sleep (in ns)
    pub weight: u64,           // Task priority in the range [1..10000] (default is 100)
    pub vtime: u64,            // Current task vruntime / deadline (set by the scheduler)
    pub comm: [c_char; TASK_COMM_LEN], // Task's executable name
}
```

Each task dispatched using `.dispatch_task()` contains the following:

```rust
struct DispatchedTask {
    pub pid: i32,      // pid that uniquely identifies a task
    pub cpu: i32,      // target CPU selected by the scheduler
                       // (RL_CPU_ANY = dispatch on the first CPU available)
    pub flags: u64,    // task's enqueue flags
    pub slice_ns: u64, // time slice in nanoseconds assigned to the task
                       // (0 = use default time slice)
    pub vtime: u64,    // this value can be used to send the task's vruntime or deadline
                       // directly to the underlying BPF dispatcher
}
```

Other internal statistics that can be used to implement better scheduling policies:

```rust
let n: u64 = *self.bpf.nr_online_cpus_mut();       // amount of online CPUs
let n: u64 = *self.bpf.nr_running_mut();           // amount of currently running tasks
let n: u64 = *self.bpf.nr_queued_mut();            // amount of tasks queued to be scheduled
let n: u64 = *self.bpf.nr_scheduled_mut();         // amount of tasks managed by the user-space scheduler
let n: u64 = *self.bpf.nr_user_dispatches_mut();   // amount of user-space dispatches
let n: u64 = *self.bpf.nr_kernel_dispatches_mut(); // amount of kernel dispatches
let n: u64 = *self.bpf.nr_cancel_dispatches_mut(); // amount of cancelled dispatches
let n: u64 = *self.bpf.nr_bounce_dispatches_mut(); // amount of bounced dispatches
let n: u64 = *self.bpf.nr_failed_dispatches_mut(); // amount of failed dispatches
let n: u64 = *self.bpf.nr_sched_congested_mut();   // amount of scheduler congestion events
```

## Example

Check out
[scx_rlfifo](https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_rlfifo)
for a basic implementation of a working Round-Robin scheduler.

## License

This software is licensed under the GNU General Public License version 2. See
the LICENSE file for details.

## Contributing

Contributions are welcome! Please submit issues or pull requests via GitHub.
