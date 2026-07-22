
# scx_lunar

## Introduction

Scx_lunar is a multipurpose scheduler which was originally invented with the goal to make frametimes in games as smooth as possible.
But then it grew a little and changed to a desktop usage focused scheduler which focuses on IO bound and kthreads with prio 100.

Which makes the scheduler one of the best when it comes to responsiveness.

This scheduler uses only FIFO queues and no preemption.

## Explanation

The scheduler does only use FIFO queues and works without preemption. 

It has 5 tiers. Which are: 

1. LC which have a positive vlag and <= average runtime of 200us
2. INTERACTIVE which have a positive vlag and with <= average runtime of 500us
3. NORMAL which have a positive vlag and with <= average runtime of 2ms
4. BATCH which have a positive vlag and with <= average runtime of 8ms
5. GREEDY everything else with more average runtime than 8ms or negative vlag

All new tasks get thrown into greedy.

Each tier also has different slice times per task. 
Which are:

1. LC -> 200us
2. INTERACTIVE -> 500us
3. NORMAL -> 500us
4. BATCH -> 500us
5. GREEDY -> 500us

One of the big things of this scheduler is that in LC and Interactive it gives it exactly the slice which the average runtime is. So this makes the execution very smooth.

## MODES

This scheduler also has 2 modes.

`--mode dsqs_per_llc` 


Where the above explained are available for each LLC. So more than one core pull from the same DSQs.

and:

`--mode dsqs_per_cpu`

DEFAULT MODE!
Where the above explained dsqs are available for each cpu core. So each core has its own queues.
This mode is used automatically when starting without start parameters.

## Dispatch

For mode `dsqs_per_cpu`
Each core first tries to run its own queued tasks, then from another core from the same llc and then from core of other llcs.
From which core the core startes stealing is randomized for better load distribution.

for mode `dsqs_per_llc`
Each core tries to first to run from the dsqs of the llc from the core. Then it tries to steal from other llcs.

## Testing

There where 2 design goals for this scheduler.

1. That music keeps playing normally when executing the cachyos benchmarker https://github.com/CachyOS/cachyos-benchmarker
2. To keep frametimes as smooth as possible with as little frametime spikes as possible. 

As far as i have tested. Both modes do accomplish these tasks very well.

The only problem is i couldn't test the functionality with different llcs as i don't have such an cpu by hand.
The next thing is, that i mostly developed this scheduler with SMT disabled. As i found that SMT off works the best for this ryzen 5800x3d. But you can test both. Your mileage may vary.
