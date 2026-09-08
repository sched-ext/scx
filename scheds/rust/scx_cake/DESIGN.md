# scx_cake — model of operation

This describes the selected pool-direct nightly build. Experiment
results, decisions, and open issues live in [STATE.md](./STATE.md).

## Queue ownership and admission

Cake creates one virtual-time DSQ per CPU and one wake DSQ per LLC. Kernel
local DSQs receive direct admissions. Hosts with present CPU IDs beyond the
64-bit placement mask collapse wake pools to one domain; the loader reports
this fallback. CPU-ID span and online capacity are distinct quantities.

Kernel idle masks provide candidate CPUs. An atomic idle claim establishes
idle admission; a snapshot, queue count, or peek does not reserve a CPU or
task. Only a successful DSQ move establishes that dispatch consumed work.
Affinity remains a hard constraint. IRQ, cache, seat, and platform-rank
information express preferences and cannot guarantee an uninterrupted run.

## Placement

select_cpu considers an inferred serial handoff, a stage task's seat,
cache-warm home admission, and a claimed idle choice. Serial handoff requires
an idle count of at least 75% of the CPU-ID span, eligible empty queues, and
an occupant estimated to be yielding. Sparse IDs/offline headroom can therefore
suppress this path; the later online-capacity correction is not in this build.

Cold choices prefer whole idle cores, unheld seats, cleaner IRQ targets, and
platform rank. Home admission and seat retakes also inspect SMT interference.
Noisy CPUs remain usable when cleaner eligible capacity is unavailable.
Failed placement leaves enqueue responsible for routing the task.

Seats associate a task with a logical CPU using serialized ownership changes.
Task storage retains placement history; it is not a reservation of both SMT
threads. Stage classification uses mean burst duration of at least 64 us,
without a negative-nice shortcut. Diagnostic/probe paths are optional.

## Enqueue and dispatch

Kthread wakes use idle local admission where possible; unbound wakes without
an idle target can enter a wake pool. Pinned work remains constrained to its
allowed CPU. Starved unpinned wakes normally enter their LLC wake pool;
self-enqueue races use the owner queue. A wake behind a served peer may claim
an idle CPU directly before falling back to the pool. Forced reenqueue also
uses the pool. Other continuations use their owner queue.

Notifications seek eligible capacity and may preempt a suitable occupant.
Affinity-compatible idle CPUs can receive forwarded kicks when the current
CPU cannot consume the pool head. A held seat with no owner work can decline
service and kick an idle, unheld, affinity-compatible CPU on its LLC; wall
escalation prevents this decline for an overdue pool head.

Dispatch first checks a remote offer, then orders its owner queue and local
wake pool by virtual time and pool service age. It attempts both before
stealing from owner queues and checking foreign wake pools. A previous task
can receive a renewed slice when the search finds no consumable work.

Queue marks and remote offers remain advisory protocol state in this retained
version. Deferred-publication models exposed dual-CCD gaps in those protocols;
the pool-truth and remote-service replacements are parked experiments, not
part of this candidate. See STATE.md for their evidence and limitations.
The 24 ms pool escalation is a policy threshold, not a universal wait bound.

## Service accounting

Starvation classification compares lifetime mean wait with lifetime mean run
using fixed 16-bit time quantization and 64-bit products. Large lifetime
counters can overflow those products; the later arithmetic repair is not in
this build. This does not measure the current wake's delay in isolation.

For runtime r, task age a, and switch-count denominator n, the slice is
the minimum of 2 * floor(r / n), floor(a / (2 * n)), and 1.5 ms, then
floored by the startup handoff estimate. The implementation shares one divide.
This is an execution budget, not a guarantee of exact preemption timing.

Stopping charges executed runtime using reciprocal task weights. Wake keys
and the shared frontier order service; peer capping limits frontier advance
from low-weight occupants. There is no frame-clock sampling loop.

## Loader and topology

Startup discovers possible/present/online CPUs, SMT siblings, dense LLC IDs,
and complete platform capacity/preferred-core hints. Rank hints are ordinal,
not measured speed ratios. Missing, equal, or unsupported hints retain valid
fallback placement. Maximum frequency is reporting information.

The loader monitors IRQ handler-time shares with a 1–16 second polling
interval. Four manually attached IRQ/softirq tracepoints maintain live depth;
exit attaches before entry, with paired failure handling. Tick look-ahead is
an additional advisory signal when the startup probe succeeds.

After privileged setup, the loader drops its calling thread's capabilities
and restores process inspection. Requested topology restarts re-execute the
loader. Debug/probe telemetry is distinct from release performance evidence.
