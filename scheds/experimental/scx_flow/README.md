# scx_flow

scx_flow is our own slot scheduler for Linux, written
in Rust with a BPF core, that runs inside
[`sched_ext`](https://github.com/sched-ext/scx/tree/main).
It keeps two FIFO queues per CPU, one per group,
with one overflow tail per group and a fixed slice at
1ms. Two groups split light waits and hog burn, strict
exactly when ready is zero and best effort when ready
is one.
It is deliberately knob-free. It uses deadline mapped
FIFO queues, vruntime fairness, and the fixed slice.

## Overview

### Order and deadlines

Tasks wait in per CPU FIFO queues picked by deadline,
with one overflow tail per group for past horizon
deadlines. Pinned tasks rest in the group overflow
tail with no per CPU use, so every owner dispatch
visits them in the window. A probe maps the deadline
to a near slot near 64us or pins past the horizon to
the tail, so arrival order holds inside each queue. The deadline adds
clamped virtual time and a scaled estimate at live
weight from nice. Exiting tasks run at once on the
task CPU via LOCAL_ON with no order wait. The task
CPU wins over the enqueuer, so an exit enqueued
elsewhere still runs where the task lives. Single
insert with an idle kick only and no coalesce. Falls
back when the task CPU is not allowed.

### Fixed slice

The slice is fixed at 1ms with no knob. Fresh tasks join
with the slice, so the start stays neutral. Estimates hold
the last burst clamped at 1ns to 1 second.

### Fairness

Sleeper lag is capped at a weight scaled cap in 125us to
8ms, so a waking task gains at most the cap of advantage.
Virtual time moves forward with scaled runtime while work
stays queued and resets to waking time on idle. Blocked
tasks complete at once. Runnable tasks requeue FIFO
into the per CPU queue with a refreshed estimate. Burst
allowance reads windowed depths over own per CPU,
other per CPU, and both overflows with four reads, so
quiet keeps 4ms and flood still floors at 1ms with no
full scan.

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
current, then first allowed in group, then first
allowed, and the task mask always wins. First
allowed keeps lowest per CPU queued depth with
lowest id on ties. Perf widens each miss to any
allowed, see governor mode. An idle core cannot
stack, so locality is free. Every other case keeps
current behavior. Pinned tasks stay local. Empty masks
rest in the task group overflow tail in arrival order.
Placement scans up to nr CPUs outside the queue store
constant claim. Frequency cards stay display only
and never shape placement. Pinned subsets stay in
mask. Groups seed by online rank with write by id. See
`src/bpf/select_cpu.bpf.c` and `src/bpf/enqueue.bpf.c`.

### Dispatch

Strict order is own per CPU own group at 31, own group
overflow at 4, own CPU other group at 4, other group
overflow at 4, then one peer steal with a single move
toward 32. All trips skip empty with one read, so idle
pays no empty scan. Each drain caps the walk at budget
plus 8, so miss walks stay bounded. Start reads the
masked cursor plus one with wrap once per dispatch, so
passes spread. The scan reads bound same group peers
from start with wrap plus live check and keeps the first
donor at need, which is 1 when idle with no moves and no
window work, else 2. Self visit stays allowed with no
extra branch, so hosts keep cover. Same group scans first
and keeps cache apart in strict with no cross scan. Perf
only cross second scans bound other group peers from start
plus 8 on same group miss with same need, keep first,
one shared drain. Fold counts all peer moves in
steal_moves with post hoc LSB compare in steal_xmoves with
unconditional adds. Single move keeps tail smooth with local trips
owning the window. Cursor steps by 8 with a bounded swap
in 4 tries that keeps rate plus stand and drops on race. Single CPU
hosts skip the pass. Pinned tasks rest in overflow, so
trips visit them each pass. Own at 31 leaves budget open
for overflow plus steal. A capped drain with work left
counts one defer with no kick. Sweep kicks at 256 run on
zero-move window only. Moves with window ride the next
dispatch with no kick. All trips share one drain with
mask wins and move to local, so order stays FIFO.
Placement, dispatch, and pressure read the live table.
See `src/bpf/dispatch.bpf.c`, `src/bpf/intf.h`, and
`src/flow_slot.rs`.

### Kicks

Idle targets are always kicked with a mask check
regardless of queue depth, so no idle CPU with
queued work sleeps unkicked. Busy targets use
a bound preempt gate with no armed check and
total plus reason counts at 296B. The chain is
pinned, then empty at most one queued, then
deserved or hog, then same with perf bypass,
then mask, then rate last as a single CAS.
Pinned and deep count total only with no reason
write. Deserved needs woken deadline past frontier
plus granule plus 32us slack or occupant hog
regardless of waker class with no time cap, still
bounded by empty plus same plus mask plus rate. Same
keeps group with perf forced true
and no recount, so group skips stay flat in perf.
Mask keeps allowed, defensive, expect ~0. Rate keeps one win per slice,
win sends PREEMPT with kicks live since 4.2.41,
miss counts total plus rate. Deserved, group, mask,
and rate stay live since 4.2.41 with armed retired
frozen for compat. Occupant group rides a u8 tail
at 64B with LIGHT fallback, written in running,
cleared with pid. One coalesced count covers q2 idle
skips in 50us at 296B. Second queued to idle in 50us
skips when not pinned with no slide, single queued
always kicks, deep always kicks, pinned never skips.
Delay persists across idle, shows stale
when idle. A missed wakeup is rescued on the next
insert with no strand. Exiting uses
an idle kick on the task CPU with no depth,
no coalesce, and no preempt. Fallback overflow with
no live CPU sends no kick and the next drain
pass collects it. Pinned overflow from a live
owner keeps the idle kick with no coalesce.
Storm stays reverted with deep quiet, no extra
kick. See `src/bpf/intf.h`,
`src/bpf/main.bpf.c`, `src/bpf/enqueue.bpf.c`, and
`src/flow_select.rs`.

### Governor mode

Strict keeps group isolation with mask win.
Perf widens placement to any allowed on miss
with same tier order and least over per CPU plus
group overflow.
Perf bypasses the kick group gate with no recount,
so group skips stay flat in perf. Unanimous
performance over online CPUs sets perf one,
else strict zero. Polls online only on the 1s tick
with BSS write on transition only. Dashboard shows
strict and perf in the mode cell with governor tip.
Dispatch reads live groups with no perf widen.
No CLI knob changes this. See `src/bpf/intf.h`,
`src/bpf/select_cpu.bpf.c`, and `src/bpf/enqueue.bpf.c`.
See `src/topology.rs`, `src/snapshot.rs`, and `ui/index.html`.

### CPU perf

Running maps the stored EMA to 0 to 1024
uniform both groups with no tier. Stopping
decays by elapsed with 24ms half-life then
climbs on the burst toward the 1ms budget
with 12x in FP8, so boost follows load with
fast attack and slow decay. Blocked with
empty queues maps the decayed EMA, long sleep
with no burst still maps to zero via 64
period decay. Init and no state hold max
1024. See `src/bpf/intf.h`,
`src/bpf/lifecycle.bpf.c`, and `src/bpf/main.bpf.c`.

Weight follows nice from minus 20 to 19 with center 1024
and no knob. The slice stays fixed at 1ms. The version is
in `Cargo.toml`.

### Energy probe

Package energy comes from RAPL counters with per-CPU active time from BPF
state. The probe alternates strict and baseline arms and reports collecting,
waiting, and unavailable states until enough accepted pairs exist for a
headline. Daily, yearly, and since attach savings appear in kWh on the
dashboard with a live trace. Details live in `src/rapl.rs`,
`src/snapshot.rs`, and `src/stats.rs`. See `src/webui.rs`,
`ui/index.html`, and `src/bpf/intf.h` for the full path.

## Typical Use Cases

- Latency-sensitive applications. Near deadlines land in per CPU queues with
  capped trip drains, so wakeups and frame work rarely wait behind
  long work at one head.
- General desktop use. The session stays responsive
  while long bursts serve with a fixed slice without blocking
  short arrivals.
- Mixed batch workloads. Long jobs keep throughput
  with FIFO queues while short arrivals keep draining
  through trips plus steal.

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
It shows group depths, move rates, preempt rates, slot moves with defer and
safety net kicks,
per-CPU nice, weight, and delay dots, and a button
to download the full snapshot as JSON.
`--no-webui` disables it.

## Code map

- Slice math and queue rules: `src/bpf/intf.h`
- Maps, helpers, ops table: `src/bpf/main.bpf.c`
- Placement: `src/bpf/select_cpu.bpf.c`
- Inserts: `src/bpf/enqueue.bpf.c`
- Drains: `src/bpf/dispatch.bpf.c`
- Lifecycle and classifier: `src/bpf/lifecycle.bpf.c`
- Rust mirrors: `src/flow_slice.rs`, `src/flow_edf.rs`,
  `src/flow_select.rs`, `src/flow_group.rs`,
  `src/flow_preempt.rs`, `src/flow_slot.rs`
- Facade: `src/flow.rs`
- Tests: `src/flow_tests_edf.rs`,
  `src/flow_tests_group.rs`, `src/flow_tests_preempt.rs`,
  `src/flow_tests_slot.rs`
- Constant validation: `src/config.rs`
- Generated bindings and skeleton: `src/bpf_intf.rs`,
  `src/bpf_skel.rs`
- Snapshot and topology: `src/snapshot.rs`,
  `src/topology.rs`
- Stats and dashboard payload: `src/stats.rs`,
  `src/webui.rs`, `ui/index.html`

## Measuring Wakeup Latency

Pin measurement threads to dedicated CPUs, use the
monotonic clock and the performance governor, and move
device IRQs off the measured CPUs. The harness probe
wakes each 10ms and records wake delay as a light
baseline with no realtime use. To bench the bound gate,
run a shallow light flood against a hog occupant and
read preempt_kicks plus deserved, group, mask, and rate
skips over the poll interval with the same pin and clock
method, so shallow deserved wakes show kicks with deep
quiet and hog occupants show kicks past deserved.

## Limitations

- Groups are strict when ready is zero and best effort
  when ready is one. Placement, dispatch, and pressure read the live table
  seeded by online rank with offline light inert. Same group steal scans
  first and keeps cache apart in strict, perf only cross second scans
  other group peers on same group miss with one shared drain, steal_moves
  counts all peer moves and steal_xmoves counts the cross subset.
- Topology with online set is snapshotted at attach, so
  a CPU hotplug needs a restart. Offline queues drain via overflow plus
  steal on the next pass, while the stale table window lasts until restart
  with offline light inert. Snapshot covers online
  only with per CPU count matching online count.
- Queue ids changed in 4.2.38, so upgrading from 4.2.37
  needs a scheduler restart with no live transition.
- CPU state grew 56B to 64B and preempt counters unfroze
  in 4.2.41, so upgrading from 4.2.40 needs a scheduler
  restart with no live transition.
- Unknown frequency stays unknown with no effect on
  placement. Frequency cards are display only.
- Single-thread and single-CPU hosts run the same path
  with no peer scan.
- Light load probe delay rose +163 to +223 percent in
  relative terms in the 4.2.37 gate while absolute delay
  stayed sub-ms, so the gap reads as a slot path tradeoff
  with no hot miss. Per CPU dispatch is not yet measured
  in the same gate. See `src/bpf/dispatch.bpf.c` and
  `src/flow_slot.rs`.
- Needs a kernel with sched_ext enabled.
