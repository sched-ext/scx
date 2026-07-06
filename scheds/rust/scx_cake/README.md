# scx_cake 1.2.0

[![License: GPL-2.0](https://img.shields.io/badge/license-GPL--2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/GPL-2.0)
[![Kernel: 7.1+](https://img.shields.io/badge/kernel-7.1%2B-green.svg?style=flat-square)](https://kernel.org)
[![sched_ext](https://img.shields.io/badge/sched_ext-BPF-orange.svg?style=flat-square)](https://github.com/sched-ext/scx)

`scx_cake` is a **pluggable CPU scheduler** for Linux — it replaces the
kernel's default logic for deciding *which program runs on which CPU core,
and when*. Its primary focus is **gaming**: consistent frame times, low
input lag, and taming the worst-case stutters, while remaining a competent
general-purpose scheduler. It borrows its philosophy from CAKE, the network
queue manager that fixed "bufferbloat" on home routers: keep the queues
short, give latency-critical work a fast path *by construction*, and share
what's left fairly.

It runs via `sched_ext`, the Linux facility for loading schedulers as
sandboxed BPF programs: **if the scheduler misbehaves, the kernel's watchdog
evicts it and your system falls back to the default scheduler within
seconds** — a crashed experiment costs a hiccup, not a hang or a reboot.

> [!IMPORTANT]
> **Honest status for gamers:** this 1.2.0 rewrite currently proves itself
> on system benchmarks (results below), where it beats or matches both the
> previous scx_cake and the kernel default on nearly everything. Its live
> game A/B validation (frame-time capture during real gameplay) is **still
> pending** — the gaming results you may have seen belong to the previous
> 1.1.x line. If you want the game-validated version today, run your
> distro's packaged scx_cake; if you want the faster benchmark-validated
> engine and don't mind experimental, build this one.

> [!IMPORTANT]
> **AI assistance disclosure.** Code mutation in this project is done with
> AI assistance, stated openly because users deserve to know how the
> software they run is built. The discipline that makes this workable: **no
> change lands on trust** — every change is committed singly and must prove
> itself through an interleaved, noise-gated benchmark A/B (and, for
> defaults, live game A/Bs) before it stays. Changes that fail are reverted
> with their falsification documented in the decision log.

## Requirements

- **Linux kernel 7.1+** with `sched_ext` enabled (`CONFIG_SCHED_EXT=y`;
  check with `zgrep SCHED_EXT /proc/config.gz`). Gaming-oriented distro
  kernels (CachyOS et al.) qualify; cake also uses the lockless
  `scx_bpf_dsq_peek` kfunc from this kernel generation.
- To build: a Rust toolchain + clang ≥ 17 (the standard
  [scx](https://github.com/sched-ext/scx) build environment).
- Distro packages (`scx-scheds`) currently ship the 1.1.x line; this
  rewrite is build-from-source for now.

## Running it

```sh
# build (from the scx repo root)
cargo build --release -p scx_cake

# run in a terminal (Ctrl+C stops it and restores the default scheduler)
sudo ./target/release/scx_cake

# or manage it like any scx scheduler:
scxctl start -s scx_cake        # and: scxctl stop / scxctl get
# on boot: set default_sched = "scx_cake" in /etc/scx_loader.toml,
# then: systemctl enable --now scx_loader
```

**Verify it's active:** `cat /sys/kernel/sched_ext/root/ops` → prints
`cake_…` while cake is scheduling. If the watchdog ever evicts it, that
file disappears, the default scheduler resumes silently, and the exit
reason lands in `dmesg` (grep for `sched_ext`).

**Stop / undo:** Ctrl+C the terminal process, or `scxctl stop`, or stop the
`scx_loader` service. There is nothing else to clean up — the default
scheduler takes over instantly.

There are no build-time or runtime tuning flags. That is the point:

**no flags · one algorithm · no division · no cold paths · no rescue buckets**

## How it works — in plain terms

A CPU scheduler answers one question thousands of times per second: *this
task just became runnable — where should it run, and does anything need to
get out of the way?*

Most of the time there's a free CPU core and the answer is easy (cake hands
the task straight to it, preferring cores whose caches still hold that
task's data). The interesting case is when **every core is busy**. Cake's
core rule for that case:

- A task that just **woke up** (e.g. a game thread that was waiting for
  input, a worker handed a message) goes into one **shared waiting line**
  that every core checks — so the *first* core to free up anywhere picks it
  up. Wakers are latency-sensitive; they should never wait behind one
  specific busy core.
- A task that simply **used up its turn** goes back into **its own core's
  line** — its data is still hot in that core's cache, and it loses nothing
  by waiting where it is.

Everything else in the design is a measured refinement of that rule's edge
cases: when a woken task is better off staying on its old core (its cache
warmth outweighs the shared line's speed), when a sleeping partner should
take over its waker's core directly (two tasks ping-ponging a message run
fastest sharing one core), when a task deserves to interrupt the current
one immediately (only if the current task just started — never mid-way
through real work), and how cores under heavy overload shed queued work to
each other without tearing communicating pairs apart. Fairness comes from a
per-task "virtual time" clock — tasks that have consumed less CPU run
first, weighted by nice level.

If you want the mechanism-level version of that paragraph — every rule,
every threshold, and the benchmark receipt for why each exists —
[`DESIGN.md`](./DESIGN.md) is the full document, and the BPF source itself
is half comments explaining the why.

## The design in one page (for the technically curious)

Vocabulary (five terms carry everything):
- **DSQ** — *dispatch queue*, sched_ext's task queue primitive. Cake makes
  one per CPU, plus one global **wake queue** and one global **overflow
  queue**.
- **vtime** — each task's *virtual runtime*: CPU time consumed, weighted by
  priority. Lower vtime = has had less than its share = runs sooner.
- **frontier** — the highest vtime any task has reached; "the present
  moment" of the fairness clock.
- **sleeper vs peer** — a task whose vtime sits well *behind* the frontier
  just slept a while (it earned credit); a task *at* the frontier has been
  running all along. Cake constantly uses this one-comparison distinction:
  sleepers get fast service, peers can wait a turn.
- **slice** — a task's turn length: 3 ms (measured optimum of 1/2/3/4 ms),
  1.5× when someone is waiting behind it.

Life of a wake under load: the kernel asks cake for a CPU
(`select_cpu`) — if the default idle-search finds a free core, direct
dispatch, done. Otherwise cake checks two special shapes: a *synchronous
handoff* ("I'm waking you and going to sleep") lands on the waker's own
CPU, and a *sleeper* wake whose waker's queues are empty converges there
too — that's how message-passing pairs collapse onto one warm core and stay
there. Failing those, `enqueue` routes it: to its **own previous CPU** if
that CPU is free-ish, the wake is shallow, or the global queue is already
backlogged (backlog = the whole machine is saturated, and scattering more
wakes would tear communicating pairs apart — this single gate recovered
2–4× oversubscribed workloads by 2–5×); otherwise to the **global wake
queue**, kicking the warmest idle CPU (the previous CPU's cache-sharing
sibling) to come collect it. A newly queued wake may **preempt** the task
currently running on its target CPU only if that task is *young* (started
< 100 µs ago — interrupting a just-started handoff partner is free;
flushing a mid-request worker destroys throughput) *and* the wakee is ahead
on fairness by a real margin. Expired tasks requeue on their own CPU —
unless that queue already holds two, in which case they spill to the
overflow queue that any draining CPU picks up (the load-balancing that
otherwise never happens when no core ever idles). Each CPU's `dispatch`
drains: own queue vs wake queue by earliest vtime (with hysteresis so the
global queue's lock isn't stampeded), then overflow, then a ring-scan steal
from neighbors, then "keep running what I have".

Fairness accounting costs almost nothing: the turn charge is the delta of
the kernel's own `sum_exec_runtime` (zero clock reads at context switch),
weighted by a reciprocal table (no division on the hot path), and new
tasks start exactly at the frontier.

## Benchmark results

**Test environment** (all numbers below): AMD Ryzen 7 9800X3D (8 cores /
16 threads, single CCD/LLC, 96 MB X3D cache), CachyOS kernel 7.1.x,
`amd-pstate-epp` performance governor. Methodology: interleaved A/B pairs
(cake ↔ EEVDF back-to-back in the same noise window), ≥2 reps per arm,
external CPU noise recorded per run and mismatched pairs discarded, ties
declared when result ranges overlap. Harness, corpus, and raw runs live in
the companion `scx_cake_bench_assets` repo; the complete
falsification-by-falsification log is
[`EEVDF_GATE_2026-07-04.md`](./EEVDF_GATE_2026-07-04.md).

**vs the packaged scx_cake 1.1.1: zero losses** — every benchmark wins or
ties (futex 2.8×, schbench-saturated +52%, fork/thread/ffmpeg/argon2 wins,
ties elsewhere).

**vs EEVDF (the kernel's default scheduler), 21-benchmark suite** —
schbench (request-latency), stress-ng families (locking, cache, memory),
perf-sched micro-benchmarks, and real workloads (x265 encode, ffmpeg
compile, blender, NAMD, xz/7zip, y-cruncher, kernel build):

| | count | detail |
|---|---|---|
| wins | 7 | schbench-saturated +31% · futex +25% · cpu-cache-mem +28% · cache +13–25% · fork +9–12% · perf-memcpy · xz |
| statistical ties | 12–13 | incl. schbench-mid, certified by a literal dead heat in interleaved pairs |
| losses | 2 | x265 −1.2 to −1.7% (excess cold pickups; every stateless fix measured and falsified) · perf-sched-pipe −11% (equals cake's own BPF callback execution time — the sched_ext framework's cost on a 1:1 microbench, decomposed to the nanosecond) |

**vs EEVDF under oversubscription** (2–4× more runnable threads than
CPUs — the regime where schedulers usually fall apart): futex 32-thread
**+28%** and 64-thread **+46%** (recovered from −64%/−92% the same day by
the backlog and overflow gates), cache-32t +3–7%, argon2 p32 +8.8% / p64
+1.6%. The schbench-saturated margin traded down from +50% to +31% to buy
those wins; re-tightening that gate is the open tuning task, alongside a
clean-window revalidation of cache/cpu-cache-mem at 1×.

Caveats, stated plainly: single machine, single topology (the global wake
queue is validated on one 16-CPU LLC — multi-CCD/multi-socket scaling is
untested); numbers are author-reported pending independent reproduction;
and the live game A/B for this rewrite is pending (see the status note at
the top).

## How it compares to other scx schedulers

`scx_lavd` (latency-criticality heuristics, per-task state),
`scx_bpfland`/`scx_rusty` (interactivity boosting, load balancing domains)
are mature, feature-rich schedulers. Cake's bet is different: **zero
per-task state, zero tunables, one algorithm small enough to audit in an
afternoon** — adaptivity comes from classifying the current scheduling
state (queue depths, wake shapes, fairness-clock positions), never from
tracked history. Whether that bet beats the heuristic approach on *your*
workload is exactly what the benchmark discipline above exists to answer.

## Learned laws (paid for in benchmarks)

- **Dispatch frequency IS the wake-service rate.** Stretching turn lengths
  under load delayed global-queue pickup: −25% cache, −16% futex.
- **Clock reads are only owed where mid-slice precision is consumed.**
  Switch boundaries are core-charged for free (`sum_exec_runtime`).
- **Ordering rules over shared queues need hysteresis.** Plain
  earliest-vtime stampeded every CPU onto the global queue's lock (−49%).
- **Migration count is not the throughput signal** — lock serialization is.
- **Route by system state, not by force.** At oversubscription, every added
  preempt/forced-migration lever measured worse (seven falsifications);
  the wins were two minimal routing gates. And the overflow channel must be
  its own queue — sharing the wake queue corrupted the signal it reads.

## Source tour

| file | contents |
|---|---|
| `src/bpf/cake.bpf.c` | the scheduler — 8 callbacks, ~870 lines, half comments explaining the why |
| `src/bpf/intf.h` | `SLICE_NS`, `MAX_CPUS`, `WAKE_DSQ`, `OVF_DSQ` — the only constants |
| `src/main.rs` | thin Rust loader (attach, exit reporting) |
| [`DESIGN.md`](./DESIGN.md) | the full design: every rule, every dose-responsed constant, invariants |
| [`EEVDF_GATE_2026-07-04.md`](./EEVDF_GATE_2026-07-04.md) | the complete benchmark campaign log — every keep and every falsification |
| `docs/` | historical decision logs from the pre-rewrite mutation campaigns |

## Contributing & reporting problems

Bug reports and stall/eviction reports are welcome via GitHub issues —
please include `dmesg | grep sched_ext` output and your CPU/kernel. Be
aware of the contribution bar: every behavioral change must survive the
interleaved noise-gated A/B discipline described above before it lands, so
a PR should come with (or expect) benchmark evidence, not just reasoning.

## License

GPL-2.0.
