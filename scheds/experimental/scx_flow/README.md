# scx_flow

## What

scx_flow is a knob-free latency score scheduler on sched_ext. Each LLC owns one kernel virtual deadline DSQ for shared tasks and each CPU owns one for pinned tasks, plus one fallback FIFO DSQ. Wakeups inherit scores between wakers and workers with log scale runtime compression, and long bursts cost more virtual time. Placement claims idle cores atomically (largest L3 for urgent tasks > core group > LLC > node) with direct local dispatch on won idle CPUs and in place slice continuation. Slices stay bounded and track a ten millisecond window with boost for long frame runs, and urgent tasks shorten a peer's slice with no interrupt. Active cores run at maximum frequency and idle cores decay to half on a timer.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
