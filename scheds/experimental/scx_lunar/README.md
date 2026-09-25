
# Lunar

## Introduction

Scx_lunar is a multipurpose scheduler which was originally invented with the goal to make frametimes in games as smooth as possible

This scheduler uses only FIFO queues.

## Explanation

The scheduler works with accounting of duty and crit score.

Duty goes from 0 to 1023.

The higher the duty number the more the task hogs cpu power.
The lower the more it is sleeping or dependent on io.

Run time and sleep time are accumulated and both halved together once their sum
exceeds 200ms, so the duty roughly reflects the last 100-200ms.

It is calculated like this.

duty = run_time * 1024 / (run_time + sleep_time + 1)

The Tier are calculated as Percent of the 1024 max duty value.

crit score goes from 0 to 32.

It is based on the waker and wakee frequency of a task.

it is calculated from
log2(1s / wakee interval) + log2(1s / waker interval)

It has 3 tiers. Which are:

1. LC with duty <= 5% and crit score of >= 5
2. INTERACTIVE with duty <= 10% and crit score of >= 3
3. NORMAL with duty <= 80% and crit score of >=1
4. Greedy with everything else

There is no hysteresis on the crit score. There is a hysteresis of 1% on the duty.

All new tasks start in greedy.
There is also a min. sample rate of the duty value to be eligible for promotion into higher tiers.

Every task has a slice time of 1ms.

Nice values and scheduling policies are intentionally ignored. Every task is
treated equally and only its behavior (duty and crit score) decides its tier.

## Preemption

A waking LC task preempts a running task of a lower tier. The preempted task goes
back to the head of its queue with the rest of its slice.

## Placement and balancing

Each core has its own queue per tier.

When a task wakes up and an idle core is found, it runs there directly.
Otherwise the task goes to the queue of the core with the least work ahead of it:

- an idle core is always preferred
- LC and INTERACTIVE tasks check all cores of the same llc, so they don't wait
  behind a task of their own tier while another core runs lower tier work
- NORMAL and GREEDY tasks compare their core with 2 random cores of the same llc
  and move at most once every 10ms, which evens out long queues between busy cores

## Dispatch

Each core first runs its own LC tasks, then a starved tier if there is one, then
its own INTERACTIVE, NORMAL and GREEDY tasks. After that it steals from another
core of the same llc and then from cores of other llcs.
From which core the core starts stealing is randomized for better load distribution.

## Testing

There where 2 design goals for this scheduler.

1. That music keeps playing normally when executing the cachyos benchmarker https://github.com/CachyOS/cachyos-benchmarker
2. To keep frametimes as smooth as possible with as little frametime spikes as possible. 

As far as i have tested. Both modes do accomplish these tasks very well.

The only problem is i couldn't test the functionality with different llcs as i don't have such an cpu by hand.
The next thing is, that i mostly developed this scheduler with SMT disabled. As i found that SMT off works the best for this ryzen 5800x3d. But you can test both. Your mileage may vary.
