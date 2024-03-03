# Framework to implement sched_ext schedulers running in user-space

[sched_ext](https://github.com/sched-ext/scx) is a Linux kernel feature
which enables implementing kernel thread schedulers in BPF and dynamically
loading them.

This crate provides a generic layer that can be used to implement sched-ext
schedulers that run in user-space.

It provides a generic BPF abstraction that is completely agnostic of the
particular scheduling policy implemented in user-space.

Developers can use such abstraction to implement schedulers using pure Rust
code, without having to deal with any internal kernel / BPF internal details.

## API

The main BPF interface is provided by the `BpfScheduler` struct. When this
object is initialized it will take care of registering and initializing the BPF
component.

The scheduler then can use `BpfScheduler` instance to receive tasks (in the
form of `QueuedTask` objects) and dispatch tasks (in the form of DispatchedTask
objects), using respectively the methods `dequeue_task()` and `dispatch_task()`.

Example usage (FIFO scheduler):
```
struct Scheduler<'a> {
    bpf: BpfScheduler<'a>,
}

impl<'a> Scheduler<'a> {
    fn init() -> Result<Self> {
        let topo = Topology::new().expect("Failed to build host topology");
        let bpf = BpfScheduler::init(5000, topo.nr_cpus() as i32, false, false, false)?;
        Ok(Self { bpf })
    }

    fn schedule(&mut self) {
        match self.bpf.dequeue_task() {
            Ok(Some(task)) => {
                // task.cpu < 0 is used to to notify an exiting task, in this
                // case we can simply ignore it.
                if task.cpu >= 0 {
                    let _ = self.bpf.dispatch_task(&DispatchedTask {
                        pid: task.pid,
                        cpu: task.cpu,
                        cpumask_cnt: task.cpumask_cnt,
                        slice_ns: 0,
                    });
                }
            }
            Ok(None) => {
                // Notify the BPF component that all tasks have been dispatched.
                self.bpf.update_tasks(Some(0), Some(0))?

                break;
            }
            Err(_) => {
                break;
            }
        }
    }
```

Moreover, a CPU ownership map (that keeps track of which PID runs on which CPU)
can be accessed using the method `get_cpu_pid()`. This also allows to keep
track of the idle and busy CPUs, with the corresponding PIDs associated to
them.

BPF counters and statistics can be accessed using the methods `nr_*_mut()`, in
particular `nr_queued_mut()` and `nr_scheduled_mut()` can be updated to notify
the BPF component if the user-space scheduler has still some pending work to do
or not.

Lastly, the methods `exited()` and `shutdown_and_report()` can be used
respectively to test whether the BPF component exited, and to shutdown and
report the exit message.
