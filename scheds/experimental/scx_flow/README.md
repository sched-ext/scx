# scx_flow

scx_flow is our own EDF scheduler for Linux, written
in Rust with a BPF core, that runs inside
[`sched_ext`](https://github.com/sched-ext/scx/tree/main).
It keeps one ordered queue per-CPU with a fixed slice at
1ms plus two groups for light waits and hog burn, strict
exactly when ready is zero and best effort when ready
is one.
It is deliberately knob-free. It uses per-CPU ordered
EDF plus vruntime fairness plus the fixed slice.

## Overview

### Order and deadlines

Tasks wait in per-CPU ordered queues, plus one park queue
per group for tasks with no allowed CPU. Earliest deadline
runs first with arrival order for ties. The deadline adds
clamped virtual time and a scaled estimate at live weight
from nice. Exiting tasks run at once on the task CPU
via LOCAL_ON with no order wait. The task CPU wins
over the enqueuer, so an exit enqueued elsewhere still
runs where the task lives. Single insert with an idle
kick only plus no coalesce. Falls back when the task
CPU is not allowed.

### Fixed slice

The slice is fixed at 1ms with no knob. Fresh tasks join
with the slice, so the start stays neutral. Estimates hold
the last burst clamped at 1ns to 1 second.

### Fairness

Sleeper lag is capped at a weight scaled cap in 125us to
8ms, so a waking task gains at most the cap of advantage.
Virtual time moves forward with scaled runtime while work
stays queued and resets to waking time on idle. Blocked
tasks complete at once. Runnable tasks requeue ordered
with a refreshed estimate.

### Groups

Two groups split physical cores with siblings kept in one
group and cache local shares where the hardware allows.
All singleton cores use halves exactly, so dense full
keeps prior state. Online ranks seed by id with offline
light inert, skewed forces ready one, snapshot covers
online only. Strict when ready is zero, best effort when
ready is one.

### Placement

Strict order is waker CPU when idle in group,
free core in group, any idle in group, prior,
current, then least queued in group, then first
allowed, and the task mask always wins. Least picks
lowest queued depth with lowest id on ties.
Perf widens each miss to any allowed, see governor
mode. An idle core cannot
stack, so locality is free. Every other case keeps
current behavior. Pinned tasks stay local. Empty masks
park in order in the task group. Frequency cards stay
display only and never shape placement. Pinned subsets
stay in mask. Groups seed by online rank with write by
id. See `src/bpf/select_cpu.bpf.c` plus
`src/bpf/enqueue.bpf.c`.

### Dispatch

Strict order is local queue, group park, then steals
from idle peers with mask checks. An idle thief with
no moved plus no own left may rescue a lone queued
task past unmovable park leftovers while busy thieves
keep depth 2. Perf leaves dispatch on halves, see
governor mode. Isolation follows placement plus park
choice with peer best effort across groups. Dispatch
uses halves while placement uses the live table seeded
by online rank.

### Kicks

Idle targets with at most 2 queued are kicked with a mask
check. Busy targets need latched delay arm 16 stand 8
in 32us units plus deserved woken deadline before
frontier plus quarter granule weight aware with 64us
floor plus 32us slack plus same group strict plus mask
plus atomic rate claim with one kick per slice
alone, bounded extra on overlap. Perf bypasses group,
see governor mode. Frontier is
the service floor, so beating it by granule
plus slack proves earliness with no occupant
state. Short heavy granule is stricter, tempering
the deadline lead, net easiness is deadline math.
Quarter bounds theft near 25% of a slice, floor
at 64us covers switch cost plus slack at 32us
bounded at half floor with no storm. Uses
woken weight only.
Total plus five reasons cover all fail-closed busy
no-kicks in branch order armed plus deserved plus group
plus mask plus rate. One coalesced count covers q2 idle
skips in 50us at 200B. Second queued to idle in 50us
skips when not pinned with no slide, single queued
always kicks, deep stays quiet, pinned never skips.
Delay persists across idle, delay shows stale
when idle. A missed wakeup is rescued on the next
insert while deep queues stay quiet. Exiting uses
a separate idle kick on the task CPU with no depth
plus no coalesce plus no preempt. Park sends
no kick and the next dispatch pass collects it.
Disarmed stays idle only. See `src/bpf/intf.h`
plus `src/bpf/main.bpf.c` plus
`src/bpf/enqueue.bpf.c` plus `src/flow_select.rs`.

### Governor mode

Strict keeps group isolation with mask win.
Perf widens placement to any allowed on miss
with same tier order plus least over any.
Perf bypasses the kick group gate with no recount,
so group skips stay flat in perf. Unanimous
performance over online CPUs sets perf one,
else strict zero. Polls online only on the 1s tick
with BSS write on transition only. Dashboard shows
strict plus perf in the mode cell with governor tip.
Dispatch stays on halves with no perf widen.
No CLI knob changes this. See `src/bpf/intf.h` plus
`src/bpf/select_cpu.bpf.c` plus `src/bpf/enqueue.bpf.c`
plus `src/topology.rs` plus `src/snapshot.rs` plus
`ui/index.html`.

### Cpu perf

Running maps the stored EMA to 0 to 1024
uniform both groups with no tier. Stopping
decays by elapsed with 24ms half-life then
climbs on the burst toward the 1ms budget
with 12x in FP8, so boost follows load with
fast attack plus slow decay. Blocked with
empty queues maps the decayed EMA, long sleep
with no burst still maps to zero via 64
period decay. Init plus no state holds max
1024. See `src/bpf/intf.h` plus
`src/bpf/lifecycle.bpf.c` plus
`src/bpf/main.bpf.c`.

Weight follows nice from minus 20 to 19 with center 1024
and no knob. The slice stays fixed at 1ms. The version is
in `Cargo.toml`.

## Typical Use Cases

- Latency-sensitive applications. Short deadlines run first,
  so wakeups and frame work rarely wait behind long work.
- General desktop use. The session stays responsive
  while long bursts serve with a fixed slice without blocking
  short arrivals.
- Mixed batch workloads. Long jobs keep throughput
  with ordered queues while short arrivals keep draining
  first.

## Production Ready?

Yes.

## Configuration

The scheduler is knob-free. No command-line option changes
scheduling behavior. Reporting only is `--stats`,
`--monitor` and `--no-webui`.

## Web UI

The dashboard serves loopback port `50005` with a unix
socket fallback at `/tmp/scx_flow.sock` and no
authentication, since loopback is the trust boundary.
It shows group depths, move rates, preempt rates,
per-CPU nice plus weight plus delay dots, and a button
to download the full snapshot as JSON.
`--no-webui` disables it.

## Code map

- Slice math and queue rules: `src/bpf/intf.h`
- Maps, helpers, ops table: `src/bpf/main.bpf.c`
- Placement: `src/bpf/select_cpu.bpf.c`
- Inserts: `src/bpf/enqueue.bpf.c`
- Drains: `src/bpf/dispatch.bpf.c`
- Lifecycle plus classifier: `src/bpf/lifecycle.bpf.c`
- Rust mirrors: `src/flow_slice.rs`, `src/flow_edf.rs`,
  `src/flow_select.rs`, `src/flow_group.rs`,
  `src/flow_preempt.rs`
- Facade: `src/flow.rs`
- Tests: `src/flow_tests_edf.rs`,
  `src/flow_tests_group.rs`, `src/flow_tests_preempt.rs`
- Constant validation: `src/config.rs`
- Generated bindings plus skeleton: `src/bpf_intf.rs`,
  `src/bpf_skel.rs`
- Snapshot plus topology: `src/snapshot.rs`,
  `src/topology.rs`
- Stats plus dashboard payload: `src/stats.rs`,
  `src/webui.rs`, `ui/index.html`

## Measuring Wakeup Latency

Pin measurement threads to dedicated CPUs, use the
monotonic clock and the performance governor, and move
device IRQs off the measured CPUs. The harness probe
wakes each 10ms and records wake delay as a light
baseline with no realtime use.

## Limitations

- Groups are strict when ready is zero and best effort
  when ready is one. Dispatch uses halves while placement
  uses the live table seeded by online rank with offline
  light inert. Peer steal is mask only.
- Topology plus online set is snapshotted at attach, so
  a CPU hotplug needs a restart. Snapshot covers online
  only with per CPU count matching online count.
- Unknown frequency stays unknown with no effect on
  placement. Frequency cards are display only.
- Single-thread and single-CPU hosts run the same path
  with no peer scan.
- Needs a kernel with sched_ext enabled.
