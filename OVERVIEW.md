# Overview

[`sched_ext`](https://github.com/sched-ext/scx) is a Linux kernel feature which
enables implementing and dynamically loading safe kernel thread schedulers in
BPF.

The benefits of such a framework are multifaceted, with there being three main
axes where `sched_ext` is specifically designed to provide significant value:

1. Ease of experimentation and exploration: Enabling rapid iteration of new
   scheduling policies.

2. Customization: Building application-specific schedulers which implement
   policies that are not applicable to general-purpose schedulers.

3. Rapid scheduler deployments: Non-disruptive swap outs of scheduling
   policies in production environments.

We'll begin by doing a deeper dive into the motivation of `sched_ext` in the
following [Motivation](#motivation) section. Following that, we'll provide some
deatils on the overall architecture of `sched_ext` in the [How](#how) section
below.

# Motivation<a name="motivation"></a>

## 1. Ease of experimentation and exploration

### Why is exploration important?

Scheduling is a challenging problem space. Small changes in scheduling behavior
can have a significant impact on various components of a system, with the
corresponding effects varying widely across different platforms, architectures,
and workloads.

While complexities have always existed in scheduling, they have increased
dramatically over the past 10-15 years. In the mid-late 2000s, cores were
typically homogeneous and further apart from each other, with the criteria for
scheduling being roughly the same across the entire die.

Systems in the modern age are by comparison much more complex. Modern CPU
designs, where the total power budget of all CPU cores often far exceeds the
power budget of the socket, with dynamic frequency scaling, and with or without
chiplets, have significantly expanded the scheduling problem space.  Cache
hierarchies have become less uniform, with Core Complex (CCX) designs such as
recent AMD processors having multiple shared L3 caches within a single socket.
Such topologies resemble NUMA sans persistent NUMA node stickiness.

Use-cases have become increasingly complex and diverse as well. Applications
such as mobile and VR have strict latency requirements to avoid missing
deadlines that impact user experience. Stacking workloads in servers is
constantly pushing the demands on the scheduler in terms of workload isolation
and resource distribution.

Experimentation and exploration are important for any non-trivial problem
space. However, given the recent hardware and software developments, we believe
that experimentation and exploration are not just important, but _critical_ in
the scheduling problem space.

Indeed, other approaches in industry are already being explored. AMD has
proposed an experimental [patch
set](https://lore.kernel.org/lkml/20220910105326.1797-1-kprateek.nayak@amd.com/)
which enables userspace to provide hints to the scheduler via "Userspace
Hinting". The approach adds a prctl() API which allows callers to set a
numerical "hint" value on a struct task_struct. This hint is then optionally
read by the scheduler to adjust the cost calculus for various scheduling
decisions.

Huawei have also [expressed
interest](https://lore.kernel.org/bpf/dedc7b72-9da4-91d0-d81d-75360c177188@huawei.com/)
in enabling some form of programmable scheduling. While we're unaware of any
patch sets which have been sent to the upstream list for this proposal, it
similarly illustrates the need for more flexibility in the scheduler.

Additionally, Google has developed
[ghOSt](https://dl.acm.org/doi/pdf/10.1145/3477132.3483542) with the goal of
enabling custom, userspace driven scheduling policies. Prior
[presentations](https://lpc.events/event/16/contributions/1365/) at LPC have
discussed ghOSt and how BPF can be used to accelerate scheduling.

### Why can't we just explore directly with CFS?

Experimenting with CFS directly or implementing a new sched_class from scratch
is of course possible, but is often difficult and time consuming. Newcomers to
the scheduler often require years to understand the codebase and become
productive contributors. Even for seasoned kernel engineers, experimenting with
and upstreaming features can take a very long time. The iteration process
itself is also time consuming, as testing scheduler changes on real hardware
requires reinstalling the kernel and rebooting the host.

Core scheduling is an example of a feature that took a significant amount of
time and effort to integrate into the kernel. Part of the difficulty with core
scheduling was the inherent mismatch in abstraction between the desire to
perform core-wide scheduling, and the per-cpu design of the kernel scheduler.
This caused issues, for example ensuring proper fairness between the
independent runqueues of SMT siblings.

The high barrier to entry for working on the scheduler is an impediment to
academia as well. Master's/PhD candidates who are interested in improving the
scheduler will spend years ramping-up, only to complete their degrees just as
they're finally ready to make significant changes. A lower entrance barrier
would allow researchers to more quickly ramp up, test out hypotheses, and
iterate on novel ideas. Research methodology is also severely hampered by the
high barrier of entry to make modifications; for example, the
[Shenango](https://www.usenix.org/system/files/nsdi19-ousterhout.pdf) and
Shinjuku scheduling policies used sched affinity to replicate the desired
policy semantics, due to the difficulty of incorporating these policies into
the kernel directly.

The iterative process itself also imposes a significant cost to working on the
scheduler. Testing changes requires developers to recompile and reinstall the
kernel, reboot their machines, rewarm their workloads, and then finally rerun
their benchmarks. Though some of this overhead could potentially be mitigated
by enabling schedulers to be implemented as kernel modules, a machine crash or
subtle system state corruption is always only one innocuous mistake away.
These problems are exacerbated when testing production workloads in a
datacenter environment as well, where multiple hosts may be involved in an
experiment; requiring a significantly longer ramp up time. Warming up memcache
instances in the Meta production environment takes hours, for example.

### How does `sched_ext` help with exploration?

`sched_ext` attempts to address all of the problems described above. In this
section, we'll describe the benefits to experimentation and exploration that
are afforded by `sched_ext`, provide real-world examples of those benefits, and
discuss some of the trade-offs and considerations in our design choices.

One of our main goals was to lower the barrier to entry for experimenting
with the scheduler. `sched_ext` provides ergonomic callbacks and helpers to
ease common operations such as managing idle CPUs, scheduling tasks on
arbitrary CPUs, handling preemptions from other scheduling classes, and
more. While `sched_ext` does require some ramp-up, the complexity is
self-contained, and the learning curve gradual. Developers can ramp up by
first implementing simple policies such as global weighted vtime scheduling
in only tens of lines of code, and then continue to learn the APIs and
building blocks available with `sched_ext` as they build more featureful and
complex schedulers.

Another critical advantage provided by `sched_ext` is the use of BPF. BPF
provides strong safety guarantees by statically analyzing programs at load
time to ensure that they cannot corrupt or crash the system. `sched_ext`
guarantees system integrity no matter what BPF scheduler is loaded, and
provides mechanisms to safely disable the current BPF scheduler and migrate
tasks back to a trusted scheduler. For example, we also implement in-kernel
safety mechanisms to guarantee that a misbehaving scheduler cannot
indefinitely starve tasks. BPF also enables `sched_ext` to significantly improve
iteration speed for running experiments. Loading and unloading a BPF scheduler
is simply a matter of running and terminating a `sched_ext` binary.

BPF also provides programs with a rich set of APIs, such as maps, kfuncs, and
BPF helpers. In addition to providing useful building blocks to programs that
run entirely in kernel space (such as many of our example schedulers), these
APIs also allow programs to leverage user space in making scheduling decisions.
Specifically, the Atropos sample scheduler has a relatively simple weighted
vtime or FIFO scheduling layer in BPF, paired with a load balancing component
in userspace written in Rust. As described in more detail below, we also built
a more general user-space scheduling framework called "rhone" by leveraging
various BPF features.

On the other hand, BPF does have shortcomings, as can be plainly seen from the
complexity in some of the example schedulers. `scx_pair.bpf.c` illustrates this
point well. To start, it requires a good amount of code to emulate
cgroup-local-storage. In the kernel proper, this would simply be a matter of
adding another pointer to the struct cgroup, but in BPF, it requires a complex
juggling of data amongst multiple different maps, a good amount of boilerplate
code, and some unwieldy `bpf_loop()`'s and atomics. The code is also littered
with explicit and often unnecessary sanity checks to appease the verifier.

That being said, BPF is being rapidly improved. For example, Yonghong Song
recently upstreamed a
[patch set](https://lore.kernel.org/bpf/20221026042835.672317-1-yhs@fb.com/) to
add a cgroup local storage map type, allowing `scx_pair.bpf.c` to be simplified.
There are plans to address other issues as well, such as providing
statically-verified locking, and avoiding the need for unnecessary sanity
checks. Addressing these shortcomings is a high priority for BPF, and as
progress continues to be made, we expect most deficiencies to be addressed in
the not-too-distant future.

Yet another exploration advantage of `sched_ext` is helping widening the scope
of experiments. For example, `sched_ext` makes it easy to defer CPU assignment
until a task starts executing, allowing schedulers to share scheduling queues
at any granularity (hyper-twin, CCX and so on). Additionally, higher level
frameworks can be built on top to further widen the scope. For example, the
aforementioned [rhone](https://github.com/Byte-Lab/rhone) library allows
implementing scheduling policies in user-space by encapsulating the complexity
around communicating scheduling decisions with the kernel. This allows taking
advantage of a richer programming environment in user-space, enabling
experimenting with, for instance, more complex mathematical models.

`sched_ext` also allows developers to leverage machine learning. At Meta, we
experimented with using machine learning to predict whether a running task
would soon yield its CPU. These predictions can be used to aid the scheduler in
deciding whether to keep a runnable task on its current CPU rather than
migrating it to an idle CPU, with the hope of avoiding unnecessary cache
misses. Using a tiny neural net model with only one hidden layer of size 16,
and a decaying count of 64 syscalls as a feature, we were able to achieve a 15%
throughput improvement on an Nginx benchmark, with an 87% inference accuracy.

## 2. Customization

This section discusses how `sched_ext` can enable users to run workloads on
application-specific schedulers.

### Why deploy custom schedulers rather than improving CFS?

Implementing application-specific schedulers and improving CFS are not
conflicting goals. Scheduling features explored with `sched_ext` which yield
beneficial results, and which are sufficiently generalizable, can and should
be integrated into CFS. However, CFS is fundamentally designed to be a general
purpose scheduler, and thus is not conducive to being extended with some
highly targeted application or hardware specific changes.

Targeted, bespoke scheduling has many potential use cases. For example, VM
scheduling can make certain optimizations that are infeasible in CFS due to
the constrained problem space (scheduling a static number of long-running
VCPUs versus an arbitrary number of threads). Additionally, certain
applications might want to make targeted policy decisions based on hints
directly from the application (for example, a service that knows the different
deadlines of incoming RPCs).

Google has also experimented with some promising, novel scheduling policies.
One example is "central" scheduling, wherein a single CPU makes all scheduling
decisions for the entire system. This allows most cores on the system to be
fully dedicated to running workloads, and can have significant performance
improvements for certain use cases. For example, central scheduling with VCPUs
can avoid expensive vmexits and cache flushes, by instead delegating the
responsibility of preemption checks from the tick to a single CPU. See
`scx_central.bpf.c` for a simple example of a central scheduling policy built in
`sched_ext`.

Some workloads also have non-generalizable constraints which enable
optimizations in a scheduling policy which would otherwise not be feasible.
For example,VM workloads at Google typically have a low overcommit ratio
compared to the number of physical CPUs. This allows the scheduler to support
bounded tail latencies, as well as longer blocks of uninterrupted time.

Yet another interesting use case is the `scx_flatcg` scheduler, which provides a
flattened hierarchical vtree for cgroups. This scheduler does not account for
thundering herd problems among cgroups, and therefore may not be suitable for
inclusion in CFS. However, in a simple benchmark using
[wrk](https://github.com/wg/wrk) on apache serving a CGI script calculating
sha1sum of a small file, it outperformed CFS by ~3% with CPU controller
disabled and by ~10% with two apache instances competing with 2:1 weight ratio
nested four level deep.

Certain industries require specific scheduling behaviors that do not apply
broadly. For example, ARINC 653 defines scheduling behavior that is widely used
by avionic software, and some out-of-tree implementations
(https://ieeexplore.ieee.org/document/7005306) have been built. While the
upstream community may decide to merge one such implementation in the future,
it would also be entirely reasonable to not do so given the narrowness of
use-case, and non-generalizable, strict requirements. Such cases can be well
served by `sched_ext` in all stages of the software development lifecycle --
development, testing, deployment and maintenance.

There are also classes of policy exploration, such as machine learning, or
responding in real-time to application hints, that are significantly harder
(and not necessarily appropriate) to integrate within the kernel itself.

### Won't this increase fragmentation?

We acknowledge that to some degree, `sched_ext` does run the risk of increasing
the fragmentation of scheduler implementations. As a result of exploration,
however, we believe that enabling the larger ecosystem to innovate will
ultimately accelerate the overall development and performance of Linux.

BPF programs are required to be GPLv2, which is enforced by the verifier on
program loads. With regards to API stability, just as with other semi-internal
interfaces such as BPF kfuncs, we won't be providing any API stability
guarantees to BPF schedulers. While we intend to make an effort to provide
compatibility when possible, we will not provide any explicit, strong
guarantees as the kernel typically does with e.g. UAPI headers. For users who
decide to keep their schedulers out-of-tree,the licensing and maintenance
overheads will be fundamentally the same as for carrying out-of-tree patches.

With regards to the schedulers included in this patch set, and any other
schedulers we implement in the future, both Meta and Google will open-source
all of the schedulers we implement which have any relevance to the broader
upstream community. We expect that some of these, such as the simple example
schedulers and `scx_rusty` scheduler, will be upstreamed as part of the kernel
tree. Distros will be able to package and release these schedulers with the
kernel, allowing users to utilize these schedulers out-of-the-box without
requiring any additional work or dependencies such as clang or building the
scheduler programs themselves. Other schedulers and scheduling frameworks such
as rhone may be open-sourced through separate per-project repos.

## 3. Rapid scheduler deployments

Rolling out kernel upgrades is a slow and iterative process. At a large scale
it can take months to roll a new kernel out to a fleet of servers. While this
latency is expected and inevitable for normal kernel upgrades, it can become
highly problematic when kernel changes are required to fix bugs.
[Livepatch](https://www.kernel.org/doc/html/latest/livepatch/livepatch.html) is
available to quickly roll out critical security fixes to large fleets, but the
scope of changes that can be applied with livepatching is fairly limited, and
would likely not be usable for patching scheduling policies. With `sched_ext`,
new scheduling policies can be rapidly rolled out to production environments.

As an example, one of the variants of the [L1 Terminal Fault
(L1TF)](https://www.intel.com/content/www/us/en/architecture-and-technology/l1tf.html)
vulnerability allows a VCPU running a VM to read arbitrary host kernel memory
for pages in L1 data cache. The solution was to implement core scheduling,
which ensures that tasks running as hypertwins have the same "cookie".

While core scheduling works well, it took a long time to finalize and land
upstream. This long rollout period was painful, and required organizations to
make difficult choices amongst a bad set of options. Some companies such as
Google chose to implement and use their own custom L1TF-safe scheduler, others
chose to run without hyper-threading enabled, and yet others left
hyper-threading enabled and crossed their fingers.

Once core scheduling was upstream, organizations had to upgrade the kernels on
their entire fleets. As downtime is not an option for many, these upgrades had
to be gradually rolled out, which can take a very long time for large fleets.

An example of an `sched_ext` scheduler that illustrates core scheduling semantics
is `scx_pair.bpf.c`, which co-schedules pairs of tasks from the same cgroup, and
is resilient to L1TF vulnerabilities. While this example scheduler is certainly
not suitable for production in its current form, a similar scheduler that is
more performant and featureful could be written and deployed if necessary.

Rapid scheduling deployments can similarly be useful to quickly roll-out new
scheduling features without requiring kernel upgrades. At Google, for example,
it was observed that some low-priority workloads were causing degraded
performance for higher-priority workloads due to consuming a disproportionate
share of memory bandwidth. While a temporary mitigation was to use sched
affinity to limit the footprint of this low-priority workload to a small subset
of CPUs, a preferable solution would be to implement a more featureful
task-priority mechanism which automatically throttles lower-priority tasks
which are causing memory contention for the rest of the system. Implementing
this in CFS and rolling it out to the fleet could take a very long time.

`sched_ext` would directly address these gaps. If another hardware bug or
resource contention issue comes in that requires scheduler support to mitigate,
`sched_ext` can be used to experiment with and test different policies. Once a
scheduler is available, it can quickly be rolled out to as many hosts as
necessary, and function as a stop-gap solution until a longer-term mitigation
is upstreamed.

# How

`sched_ext` is a new sched_class which allows scheduling policies to be
implemented in BPF programs.

`sched_ext` leverages BPF's struct_ops feature to define a structure which
exports function callbacks and flags to BPF programs that wish to implement
scheduling policies. The struct_ops structure exported by `sched_ext` is struct
`sched_ext_ops`, and is conceptually similar to struct sched_class. The role of
`sched_ext` is to map the complex `sched_class` callbacks to the more simple and
ergonomic struct `sched_ext_ops` callbacks.

Unlike some other BPF program types which have ABI requirements due to
exporting UAPIs, `struct_ops` has no ABI requirements whatsoever. This provides
us with the flexibility to change the APIs provided to schedulers as necessary.
BPF `struct_ops` is also already being used successfully in other subsystems,
such as in support of TCP congestion control.

The only `struct_ops` field that is required to be specified by a scheduler is
the `name` field. Otherwise, `sched_ext` will provide sane default behavior, such
as automatically choosing an idle CPU on the task wakeup path if `.select_cpu()`
is missing.

### Dispatch queues

To match the impedance between the scheduler core and the BPF scheduler,
`sched_ext` uses DSQs (dispatch queues) which can operate as both a FIFO and a
priority queue. By default, there is one global FIFO (`SCX_DSQ_GLOBAL`),
and one local dsq per CPU (`SCX_DSQ_LOCAL`). The BPF scheduler can manage
an arbitrary number of dsq's using `scx_bpf_create_dsq()` and
`scx_bpf_destroy_dsq()`.

A CPU always executes a task from its local DSQ. A task is "dispatched" to a
DSQ. A non-local DSQ is "consumed" to transfer a task to the consuming CPU's
local DSQ.

When a CPU is looking for the next task to run, if the local DSQ is not
empty, the first task is picked. Otherwise, the CPU tries to consume the
global DSQ. If that doesn't yield a runnable task either, `ops.dispatch()`
is invoked.

### Scheduling cycle

The following briefly shows how a waking task is scheduled and executed.

1. When a task is waking up, `ops.select_cpu()` is the first operation
   invoked. This serves two purposes. First, CPU selection optimization
   hint. Second, waking up the selected CPU if idle.

   The CPU selected by `ops.select_cpu()` is an optimization hint and not
   binding. The actual decision is made at the last step of scheduling.
   However, there is a small performance gain if the CPU
   `ops.select_cpu()` returns matches the CPU the task eventually runs on.

   A side-effect of selecting a CPU is waking it up from idle. While a BPF
   scheduler can wake up any cpu using the `scx_bpf_kick_cpu()` helper,
   using `ops.select_cpu()` judiciously can be simpler and more efficient.

   A task can be immediately dispatched to a DSQ from `ops.select_cpu()` by
   calling `scx_bpf_dispatch()`. If the task is dispatched to
   `SCX_DSQ_LOCAL` from `ops.select_cpu()`, it will be dispatched to the
   local DSQ of whichever CPU is returned from `ops.select_cpu()`.
   Additionally, dispatching directly from `ops.select_cpu()` will cause the
   `ops.enqueue()` callback to be skipped.

   Note that the scheduler core will ignore an invalid CPU selection, for
   example, if it's outside the allowed cpumask of the task.

2. Once the target CPU is selected, `ops.enqueue()` is invoked (unless the
   task was dispatched directly from `ops.select_cpu()`). `ops.enqueue()`
   can make one of the following decisions:

   * Immediately dispatch the task to either the global or local DSQ by
     calling `scx_bpf_dispatch()` with `SCX_DSQ_GLOBAL` or
     `SCX_DSQ_LOCAL`, respectively.

   * Immediately dispatch the task to a custom DSQ by calling
     `scx_bpf_dispatch()` with a DSQ ID which is smaller than $2^{63}$.

   * Queue the task on the BPF side.

3. When a CPU is ready to schedule, it first looks at its local DSQ. If
   empty, it then looks at the global DSQ. If there still isn't a task to
   run, `ops.dispatch()` is invoked which can use the following two
   functions to populate the local DSQ.

   * `scx_bpf_dispatch()` dispatches a task to a DSQ. Any target DSQ can
     be used - `SCX_DSQ_LOCAL`, `SCX_DSQ_LOCAL_ON | cpu`,
     `SCX_DSQ_GLOBAL` or a custom DSQ. While `scx_bpf_dispatch()`
     currently can't be called with BPF locks held, this is being worked on
     and will be supported. `scx_bpf_dispatch()` schedules dispatching
     rather than performing them immediately. There can be up to
     `ops.dispatch_max_batch` pending tasks.

   * `scx_bpf_consume()` tranfers a task from the specified non-local DSQ
     to the dispatching DSQ. This function cannot be called with any BPF
     locks held. `scx_bpf_consume()` flushes the pending dispatched tasks
     before trying to consume the specified DSQ.

4. After `ops.dispatch()` returns, if there are tasks in the local DSQ,
   the CPU runs the first one. If empty, the following steps are taken:

   * Try to consume the global DSQ. If successful, run the task.

   * If `ops.dispatch()` has dispatched any tasks, retry #3.

   * If the previous task is an `SCX` task and still runnable, keep executing it (see `SCX_OPS_ENQ_LAST`).

   * Go idle.

Note that the BPF scheduler can always choose to dispatch tasks immediately in
`ops.select_cpu()` or `ops.enqueue()`. If only the built-in DSQs are used,
there is no need to implement `ops.dispatch()` as a task is never queued on
the BPF scheduler and both the local and global DSQs are consumed
automatically.

`scx_bpf_dispatch()` queues the task on the FIFO of the target DSQ. Use
`scx_bpf_dispatch_vtime()` for the priority queue. Internal DSQs such as
`SCX_DSQ_LOCAL` and `SCX_DSQ_GLOBAL` do not support priority-queue
dispatching, and must be dispatched to with `scx_bpf_dispatch()`.

### Verifying callback behavior

`sched_ext` always verifies that any value returned from a callback is valid, and
will issue an error and unload the scheduler if it is not. For example, if
`.select_cpu()` returns an invalid CPU, or if an attempt is made to invoke the
`scx_bpf_dispatch()` with invalid enqueue flags. Furthermore, if a task remains
runnable for too long without being scheduled, `sched_ext` will detect it and
error-out the scheduler.

# Closing Thoughts

Both Meta and Google have experimented quite a lot with schedulers in the last
several years. Google has benchmarked various workloads using user space
scheduling, and have achieved performance wins by trading off generality for
application specific needs. At Meta, we are actively experimenting with
multiple production workloads and seeing significant performance gains, and are
in the process of deploying `sched_ext` schedulers on production workloads at
scale. We expect to leverage it extensively to run various experiments and
develop customized schedulers for a number of critical workloads.

# Written By

- David Vernet <dvernet@meta.com>
- Josh Don <joshdon@google.com>
- Tejun Heo <tj@kernel.org>
- Barret Rhoden <brho@google.com>

# Supported By

- Paul Turner <pjt@google.com>
- Neel Natu <neelnatu@google.com>
- Patrick Bellasi <derkling@google.com>
- Hao Luo <haoluo@google.com>
- Dimitrios Skarlatos <dskarlat@cs.cmu.edu>
