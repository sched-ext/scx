# scx_flow

## What

scx_flow orders tasks by deadline. Each per-CPU queue holds tasks in
deadline order with equal deadlines in insertion order, plus one fallback
queue in FIFO order. Running tasks pay for burnt time. Virtual deadline adds
a burst scaled slice step to the floored time. Steady tasks price by the kept
max run length with short tasks keeping the burst path with a floor slice and long tasks in one slice quanta.
Unknown tasks keep the burst path. An insert miss keeps the newcomer in
fallback in FIFO order with no evict. Stopping plus tick keep the burst
and run state with guarded preempt and no reclaim. Dispatch drains local first,
then same LLC, then same node, then remote. Wakeups wake idle targets, plus a
guarded preempt on a much earlier Virtual deadline. Queues hold without bound.
Slice is fixed at 1ms, and hotplug needs restart.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
