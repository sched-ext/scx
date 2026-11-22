# scx_mlfq

## What

scx_mlfq is a knob-free multilevel feedback queue scheduler on sched_ext. Tasks drop through eight levels while they run without sleeping, each allowing twice the runtime of the one above, and return to the top when they wake up. Each LLC owns one kernel virtual deadline DSQ for shared tasks and each CPU owns one for pinned tasks, plus one fallback FIFO DSQ. Wakeups inherit scores between wakers and workers with log scale runtime compression, and lower levels cost more virtual time. Placement claims idle cores atomically (largest L3 for urgent tasks > core group > LLC > node) with direct local dispatch on won idle CPUs and in place slice continuation. Slices are bounded and track a ten millisecond window with boost for long frame runs, and wakeups preempt deep tasks of other processes or cut a peer's slice. Active cores run at maximum frequency and idle cores decay to half on a timer.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.

## Credits

scx_mlfq is made possible by the support we received from the sched_ext community. Credit goes to the developers and contributors whose work inspired it and who helped with its development.
