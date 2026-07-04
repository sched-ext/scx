# scx_lunar

## Introduction

Scx_lunar is a multipurpose scheduler which was originally invented with the goal to make frametimes in games as smooth as possible with acceptable latency.
But then it grew a little and changed to a desktop usage focused scheduler.

## Explanation

The scheduler does only use FIFO queues and works without preemption. 

It has 6 tiers. Which are: 

1. SOFT ( KTHREADs with PRIO 100) 
2. LC which have a positive vlag and <= average runtime of 50us
3. INTERACTIVE which have a positive vlag and with <= average runtime of 200us
4. NORMAL which have a positive vlag and with <= average runtime of 1ms
5. Batch everything else but which does not exceed the avg runtime per cpu by more than a factor of 4
6. GREEDY everthing which has a 4x or more avg cpu time per run than the avg cpu time of a task on the cpu core.

Tasks and its children will also be thrown into greedy when they are spamming new tasks.

Each tier except SOFT queue has a max continous time gate. Where when there are too many tasks of for example LC and there is a task waiting in INTERACTIVE than after a defined time, one task  of a lower prio task is forced.

TIER soft is always executed first.

Each tier also has different slice times per task. 
Which are:

1. SOFT -> 200us
2. LC -> 200us
3. INTERACTIVE -> 500us
4. NORMAL -> 1000us
5. BATCH -> 2000us
6. GREEDY -> 2000us

## MODES

This scheduler also has 2 modes.

`--mode dsq_per_llc`

Where the above explained are available for each LLC. So more than one core pull from the same DSQs.

and:

`--mode dsq_per_cpu`

Where the above explained are available for each cpu core. So each core has its own queues.

## Stealing

Each cores first tries to steal its own queued tasks, then the same llc and then from other llcs.

## Testing

There where 2 design goals for this scheduler.

1. That music keeps playing normally when executing the cachyos benchmarker https://github.com/CachyOS/cachyos-benchmarker
2. To keep frametimes as smooth as possible with as little frametime spikes as possible. 

As far as i have tested. Both modes do accomplish these tasks very well.
