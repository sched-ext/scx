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

You can find a simple example of a fully working FIFO scheduler implemented
using the `scx_rustland_core` framework here:
[scx_rlfifo](https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_rlfifo).

## License

This software is licensed under the GNU General Public License version 2. See
the LICENSE file for details.

## Contributing

Contributions are welcome! Please submit issues or pull requests via GitHub.
