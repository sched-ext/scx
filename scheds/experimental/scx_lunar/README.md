
# Lunar

## Introduction

Scx_lunar is a multipurpose scheduler which was originally invented with the goal to make frametimes in games as smooth as possible
But then it grew a little and changed to a desktop usage focused scheduler which focuses on IO bound threads.

Which makes the scheduler one of the best when it comes to responsiveness.

This scheduler uses only FIFO queues.

## Explanation

The scheduler works with accounting of duty.

Duty goes from 0 to 1023.

The higher the duty number the more the task hogs cpu power.
The lower the more it is sleeping or dependent on io.

The duty is calculated from a window of the last 100ms

It is calculated like this.

duty = sleep_time * 1024 /(run_time + sleep_time + 1)

The Tier are calculated as Percent of the 1024 max duty value.

It has 5 tiers. Which are: 

1. LC with duty <= 5%
2. INTERACTIVE with duty <= 20%
3. NORMAL with duty <= 40%
4. BATCH with duty <= 90%
5. GREEDY with duty <= 100%

All new tasks get thrown into greedy. And start with duty of 1023.
There is also a min. sample rate of the duty value to be eligible for promotion into higher tiers. 

Each tier also has a slice time of 500us.

When a lower tier task is running at the moment a higher tier gets enqueued then the current task gets kicked and preempted.

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
