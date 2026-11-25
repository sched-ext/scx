# scx_flow

## What

scx_flow is a knob-free latency score scheduler on sched_ext. Each LLC owns one kernel virtual deadline DSQ for shared tasks and each CPU owns one for pinned tasks, plus one fallback FIFO DSQ. Wakeups inherit scores between wakers and workers with log scale runtime compression, and long bursts cost more virtual time. Placement claims idle cores atomically (largest L3 for urgent tasks > core group > LLC > node) with direct local dispatch on won idle CPUs and in place slice continuation. Slices are bounded and track a ten millisecond window with boost for long frame runs, and urgent tasks shorten a peer's slice without an IPI. Active cores run at maximum frequency and idle cores decay to half on a timer.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

> [!TIP]
> 1. Start scx_flow with `--helicoprion` to try the helicoprion mode. This mode is for research into whether it benefits users more than running without it. User feedback may be shared with other developers to help improve other schedulers and, where possible, the [helicoprion](https://github.com/Seafoam-Labs/helicoprion) benchmark itself.
> 2. Start scx_flow with `--performance` for the highest frame rates and the lowest input latency, at the cost of more power. An urgent task gets its CPU at once, more game threads may push background work aside, LLC pairs share double helix queues, and busy CPUs only poll while idle. It cannot be combined with `--helicoprion`.

## Limitations

- Hotplug reloads it.

## Credits

scx_flow is made possible by the support we received from the sched_ext community. Credit goes to the developers and contributors whose work inspired it and who helped with its development.
