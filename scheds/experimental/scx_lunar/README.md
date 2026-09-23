
# Lunar

## Introduction

Scx_lunar is a multipurpose scheduler which was originally invented with the goal to make frametimes in games as smooth as possible

This scheduler uses only FIFO queues.

## Explanation

The scheduler works with accounting of duty and crit score.

Duty goes from 0 to 1023.

The higher the duty number the more the task hogs cpu power.
The lower the more it is sleeping or dependent on io.

The duty is calculated from a window of the last 100ms

It is calculated like this.

duty = sleep_time * 1024 /(run_time + sleep_time + 1)

The Tier are calculated as Percent of the 1024 max duty value.

crit score goes from 0 to 32.

It is based on the waker and wakee frequency of a task.

it is calculated from 
log2(1s/ wakee interval) + log2(1s/ waker interval)

It has 5 tiers. Which are: 

1. LC with duty <= 5% and crit score of >= 5
2. INTERACTIVE with duty <= 10% and crit score of >= 3
3. NORMAL with duty <= 80% and crit score of >= 1
5. GREEDY with duty > 80% or crit score under 1

All new tasks get thrown into greedy. And start with duty of 512.
There is also a min. sample rate of the duty value to be eligible for promotion into higher tiers. 

Each tier also has a slice time of 1ms.

At the moment the scheduler does not use preemption.

## Dispatch

Each core first tries to run its own queued tasks, then from another core from the same llc and then from core of other llcs.
From which core the core startes stealing is randomized for better load distribution.

## Testing

There where 2 design goals for this scheduler.

1. That music keeps playing normally when executing the cachyos benchmarker https://github.com/CachyOS/cachyos-benchmarker
2. To keep frametimes as smooth as possible with as little frametime spikes as possible. 

As far as i have tested. Both modes do accomplish these tasks very well.

The only problem is i couldn't test the functionality with different llcs as i don't have such an cpu by hand.
The next thing is, that i mostly developed this scheduler with SMT disabled. As i found that SMT off works the best for this ryzen 5800x3d. But you can test both. Your mileage may vary.
