# sched_ext case study on a production workload

This is a case study of using [sched_ext](http://lkml.kernel.org/r/20230711011412.100319-1-tj@kernel.org) to quickly develop and iterate a scheduler for a latency sensitive workload.

This is one of the biggest workloads in our fleet. How much work a machine does is regulated by the response P99 latency and the usual CPU utilization swings around 40%. With so much CPU time unused, it looked like there's plenty of room for scheduling optimizations.

There are several avenues that I wanted to explore:

1. Work conservation - Are we idling CPUs when there's work to be done?
2. Idle CPU selection - A task is waking up and looking for a CPU to run on. Which CPU should we pick?
3. Soft-affinity - While there is only one main workload, there are also a lot of other things running in the system for system maintenance and monitoring. Would confining miscellaneous workloads to a subset of CPUs be beneficial?
4. Custom policies for different threads - The workload is already setting nice values for important threads. Maybe applying more aggressive strategy for them would help?

## Work-conservation and idle CPU selection

It's easy to implement work-conservation in sched_ext, especially on single socket machines. As `dsq`'s can be shared across multiple CPUs, I can simply let all CPUs share one `dsq`. Any CPU which becomes available will execute any thread which is ready to run making the scheduling behavior fully conserving. A similar behavior can be achieved in the default CFS (or EEVDF) kernel scheduler with [David Vernet](https://github.com/Decave)'s [shared runqueue patchset](https://lore.kernel.org/lkml/20230710200342.358255-1-void@manifault.com/). In fact, a variant of that patchset was already deployed in production showing ~1% bandwidth gain and [`scx_simple`](https://github.com/sched-ext/sched_ext/blob/sched_ext/tools/sched_ext/scx_simple.bpf.c) without idle CPU selection improvements closely matched its performance.

Past experiences have indicated that, for many workloads, L1/2 locality didn't mean that much across scheduling boundaries. The suspicion is that the temporal locality decays too quickly while running something else, so what may remain in the cache usually isn't significant enough to make a big difference. This means that it usually isn't beneficial to wait for a thread's previous CPU if there are idle CPUs, which partly explains the gains from work-conservation. If L2 locality doesn't matter either, there is no reason to prefer hyper-thread pair over fully idle core (both siblings).

In other words, given the choice between temporal locality and more hardware (full CPU with its own L1/2 cache), picking more hardware is likely to lead to better performance, albeit at a higher power cost.

[`scx_simple`](https://github.com/sched-ext/sched_ext/blob/sched_ext/tools/sched_ext/scx_simple.bpf.c) uses sched_ext's default idle CPU selection implementation - [`scx_select_cpu_dfl()`](https://github.com/sched-ext/sched_ext/blob/sched_ext-v5/kernel/sched/ext.c#L1990) which already always prefers fully idle cores. Testing on an ~1000 machine cluster and comparing against control clusters was showing ~3.5% gain.

<p align="center"><img width="80%" src="https://github.com/sched-ext/sched_ext/blob/case-studies/scx_layered/scx_simple-exp.png?raw=true"></p>

The solid lines are from the test set. Dotted, control. Both upper and lower line groups capture basically the same signal from different points. Before the red vertical line, the systems are running the default CFS scheduler. At the red marker, I copied the `scx_simple` binary to the machines and simply ran it.

I had my suspicion but wanted to verify that the idle core selection actually is the main contributor, so I copied `scx_select_cpu_dfl()` and BPF'ied it to make a custom [`simple_select_cpu()`](https://github.com/sched-ext/sched_ext/blob/case-studies/scx_layered/modified-scx_simple.bpf.c#L63) implementation. This is the exact same logic just in BPF.

Now that I have something I can quickly modify and deploy, I started playing with it.

<p align="center"><img width="80%" src="https://github.com/sched-ext/sched_ext/blob/case-studies/scx_layered/scx_simple-identify.png?raw=true"></p>

1. **scx_off**: I stopped `scx_simple` waited to verify that the perf gain disappeared.
2. **T-DUP - broken**: I copied out the modified binary with custom `select_cpu()` and started it. While performance improved a little bit, it was still mostly parity with the control sets. After a while, I realized that I forgot to clear `enq_local` flag which made all threads to be enqueued locally.
3. **T-DUP**: After fixing that, I redeployed and verified that perf gain is consistent as with the standard `scx_simple`, waited for periodic service restart to pass.
4. **T-NO_CORE**: and then deployed a new version which has the idle core prioritization [commented out](https://github.com/sched-ext/sched_ext/blob/case-studies/scx_layered/modified-scx_simple.bpf.c#L101). This lost most of the perf gain indicating that this likely was the main contributor.
5. **scx off**: I stopped `scx_simple` so that the systems switch back to CFS.

I didn't wait long enough to gather high confidence data. However, in the span of only several hours, I could deploy three different versions of the scheduler, one of them buggy, and verify that the main contributor is better CPU selection without disturbing the workload in any significant way. This really is a night and day difference in how quickly scheduler implementation can be iterated.

Note that upstream fair scheduler recently received a similar behavior change in [`b1bfeab9b002 ("sched/fair: Consider the idle state of the whole core for load balance")`](https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/commit/?id=b1bfeab9b00283f521d2100afb9f5af84ccdae13).

## Soft-affinity and custom policies

It was great that something as simple as `scx_simple` could show such substantial gains. However, testing soft-affinity and custom policies would require something more complex. [`scx_layered`](https://github.com/sched-ext/sched_ext/tree/sched_ext-v5/tools/sched_ext/scx_layered) is a hybrid scheduler with hot paths implemented in BPF and high-level decisions made in rust userspace.

`scx_layered` organizes threads in the system into multiple fully configurable layers. Each layer has matches and policy. The matches determine which threads belong the layer and the policy determines how the threads are scheduled.

For example, in our fleet, the top-level cgroup `system.slice` contains applications that aren't service critical. We want them to run reasonably well but whether they run a bit quicker or not doesn't matter. We can match them with

```json
"matches": [
	[
		{ "CgroupPrefix": "system.slice/" }
	]
]
```

and then prevent them from running over all CPUs.

```json
"kind": {
	"Confined": {
        "cpus_range": [ 0, 16 ],
        "util_range": [ 0.8, 0.9 ]
    }
}
```

The above says the the layer can occupy upto 16 CPUs and the number of CPUs allocated will be dynamically adjusted to keep the average per-CPU utilization between 80% and 90%. This allows confining these low priority workloads to as few CPUs as possible for running them reasonably so that they don't walk around all over the system polluting caches and causing scheduling latencies.

Note that we don't want to set a low fixed number limit. They are low priority but still need to run and depending on what's happening on the system, some managerial workloads may consume quite a bit of CPU cycles.

If you want to learn more about `scx_layered` and its configuration. Please read the [help message](https://github.com/sched-ext/sched_ext/blob/case-studies/scx_layered/scx_layered-help.txt) and take a look at an [example configuration file](https://github.com/sched-ext/sched_ext/blob/case-studies/scx_layered/scx_layered-example-config.json).

The following is from one afternoon that I spent iterating on `scx_layered` implementation and different configurations.

<p align="center"><img width="100%" src="https://github.com/sched-ext/sched_ext/blob/case-studies/scx_layered/scx_layered-exp.png?raw=true"></p>

This is the same ~1000 machine test set and I'm trying out different configurations and adding new features on the fly. You can see that the first, third and fourth trials didn't work too well while the second and last did pretty good. The final configuration I settled on was pretty similar to the example configuration above.

What limited the iteration speed was how quickly I could read signals from the workload and how fast I could decide what to do next. The deployment of new scheduler implementation and configuration was not a factor at all.

This is the exact opposite of what this would be like without sched_ext. Setting up this test cluster and stabilizing to match the controls took multiple weeks. Rebooting the machines to deploy a new kernel and getting reliable signals would take at least several days in the bets of circumstances. If you make a mistake, as we all do, and deploy a kernel which crashes and causes production issues, that may easily extend to weeks.

Speaking of bugs and crashes, I did make a mistake and the scheduler I was testing above was faulty. It had a bug in per-thread data structure management and would fail after PID wraps which takes a few days in these machines. Not knowing the bug and happy with the performance gain it was showing, I left it running.

<p align="center"><img width="60%" src="https://github.com/sched-ext/sched_ext/blob/case-studies/scx_layered/scx_layered-bug.png?raw=true"></p>

Two days later, I checked the graph and noticed that the performance gain went away in the morning (the rightmost CFS red line). I investigated and it turned out all the `scx_layered` schedulers failed in a pretty short time frame. Deploying a scheduler with a latent bug would usually mean disaster. Here, all that happened was that the machines seamlessly switched back to CFS and the performance gain went away. No machines crashed. No drama.

We are currently in the process of setting up a larger scale testing to obtain more reliable result but the results up until now is indicating combined >5% gain in bandwidth compared to CFS with shared queue, which is a staggering amount.
## Conclusion

This experience has clearly confirmed the benefits of sched_ext. There is no way we could have experimented with scheduler change this significant with production workload. It would have taken too long, too much coordination and pain, and even if we could experiment and obtain the same results, the path to deployment would be too uncertain and arduous.

With sched_ext, I spent a couple weeks writing `scx_layered`, another week testing it on the production workload while continuously tinkering. Also, because it's so safe, we can easily expand the testing to wider scale and deploy as-is.

I didn't spend too much effort optimizing the configuration and the configuration I applied isn't very specific to the workload. The goal behind `scx_layered` is to allow application teams to easily apply their domain specific knowledge and experience to improve scheduling behaviors. With `scx_layered` and other efforts, we're planning to work closely with application teams.

It's worth noting that all the optimization ideas I found are generic and widely applicable. Figuring out the right way to structure the interface would take efforts but we now know with certainty that these are valid strategies. With the ability to quickly experiment and iterate, we'll continue to find and identify effective strategies, and keep publishing the findings along with code. As we learn more and gain more experiences, I believe that we'll be able to build a scheduler or a set of them that can incorporate most of the identified strategies generically and consistently.
