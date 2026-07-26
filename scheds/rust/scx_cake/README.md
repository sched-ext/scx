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
> **Honest current status (2026-07-24).** This 1.2.0 development source builds
> and benchmarks: the current working head carries a build receipt, passes the
> readiness probe, and has been screened against native EEVDF across every
> registered workload through the exact-pair broker. What it does **not** have
> is a live-game gate. Game frame-time tails are this scheduler's stated hard
> constraint, and no game A/B has been run on the current mutation stack — so
> the benchmark numbers below are real, and the gaming claim in the paragraph
> above is *unproven for this checkout*. Treat it as a research candidate, not
> a drop-in daily driver.

> [!IMPORTANT]
> **AI assistance disclosure.** Code mutation in this project is done with
> AI assistance, stated openly because users deserve to know how the
> software they run is built. The required discipline is **no change lands on
> trust**: a candidate intended for retention must eventually clear
> interleaved, noise-gated benchmark A/B and, for defaults, live-game A/B.
> Historical A/Bs are research evidence rather than current promotion proof;
> this checkout has not yet cleared that protocol.

## Requirements

- **Linux kernel 7.1+** with `sched_ext` enabled (`CONFIG_SCHED_EXT=y`;
  check with `zgrep SCHED_EXT /proc/config.gz`). Gaming-oriented distro
  kernels (CachyOS et al.) qualify; cake also uses the lockless
  `scx_bpf_dsq_peek` kfunc from this kernel generation.
- Future receipt-producing builds require a Rust toolchain + clang ≥ 17 (the
  standard [scx](https://github.com/sched-ext/scx) build environment).
- Distro packages (`scx-scheds`) currently ship the 1.1.x line; this
  rewrite remains development source rather than a promotion-ready package.

## Development and execution

No maintained receipt-producing builder currently exists. Do not invoke Cargo
directly for score-bearing research: an unreceipted binary/BPF pair cannot be
attributed to this source or admitted by the strict runner. The owning-user
`./cakebench diagnostics doctor --json` command remains a read-only environment
check; it is not build, activation, or performance proof.

Do not activate a development binary directly or through a privilege wrapper.
This checkout's `cakebench` shim delegates to the maintained owning-user
benchmark project, which requires exact binary/BPF receipts, current-boot
runtime checks, and pre-provisioned capabilities. Missing access is a hard
failure; the project does not grant or repair privileges during a run.

Distribution service management is outside this development/benchmark
contract and must not be used as evidence that a dirty candidate was built,
validated, or benchmarked correctly.

**Verify it's active:** `cat /sys/kernel/sched_ext/root/ops` → prints
`cake_…` while cake is scheduling. If the watchdog ever evicts it, that
file disappears, the default scheduler resumes silently, and the exit
reason lands in `dmesg` (grep for `sched_ext`).

**Stop / undo:** the maintained runner must prove that sched_ext returned to
`disabled` after every arm. A run without that restoration receipt is invalid.

There are no runtime tuning flags, and nothing for a user to configure — the
binary takes `-v` and `-V` and nothing else. That is the point:

**no knobs · one algorithm · no division · no cold paths · no rescue buckets**

(`intf.h` does carry compile-time *research* switches for mutation campaigns.
They are all off or at their default value in the shipped build, and the
project's own rule is that experiments are A/B'd as two git commits rather
than by flipping a cflag — see invariant 1 in [`DESIGN.md`](./DESIGN.md).)

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
unless that queue already holds six, in which case they spill to the
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

**vs EEVDF — sealed exact-pair medians** (2026-07-17/18, 8 interleaved blocks
per workload, noise sealed per arm as a covariate):

| | detail |
|---|---|
| wins | futex +57.2% · schbench-saturated p99 +49.1% · ccm-cache +45.9% · stress-ng-cache +26.5% · perf-sched-pipe +22.7% (CI +21.1…+24.9) · blender-render +11.9% · mutex-handoff +10.3% · thread +7.5% · fork +5.5% · stress-ng-memcpy +4.5% |
| losses | ccm-memcpy −14.9% (attributed: zero-sum CPU-share reallocation, equal per-CPU-second efficiency both schedulers) · schbench-light p99 −1.42% quiet / −9.6% under heavy desktop load (attributed: the priced side of the futex/pipe/saturated wins — same behavior, seven falsifications) · futex-lock-pi −71.8%, recovered from −86.6% |

A 2-block screen of the later K+L+M+S1d stack (2026-07-20) reproduced the shape
and moved two entries materially: `futex-lock-pi` −1.2% (from −86.6%, once the
regime was controlled for) and `schbench-light` −2.24% (8-block trusted — about
0.8 pt of the stack's cost). Every registered workload has now been screened
against that stack; the only losses anywhere are `ccm-memcpy` and
`schbench-light`.

> **Read futex numbers as mode-tagged, not code-tagged.** On 2026-07-20 the
> same binary, boot, and noise regime measured 4.7M / 1.4M / 0.35M futex ops/s
> across sessions while native EEVDF stayed flat at 3.0M. The host variable
> behind that mode shift is still unidentified. Every historical futex delta in
> this project — including the +57.2% above — is conditional on which mode the
> host was in.

Caveats, stated plainly: single machine, single topology (the global wake
queue is validated on one 16-CPU single-CCD LLC — multi-CCD/multi-socket
scaling is untested); numbers are author-reported pending independent
reproduction; several older workloads (namd, kernel-defconfig, xz, prime,
x265, argon2, 7zip, y-cruncher, perf-memcpy) have **no current native
baseline** and are deliberately omitted above rather than quoted stale; and
the live game A/B is pending (see the status note at the top).

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
| `src/bpf/cake.bpf.c` | the scheduler — 8 callbacks in the release build, ~1.75k lines, roughly half comments explaining the why |
| `src/bpf/intf.h` | the constant surface: `SLICE_NS`, `MAX_CPUS`, `WAKE_DSQ`, `OVF_DSQ`, the policy divisors every threshold derives from, and the default-off compile-time research switches |
| `src/main.rs` | thin Rust loader (attach, exit reporting) |
| [`DESIGN.md`](./DESIGN.md) | the full design: every rule, every dose-responsed constant, invariants |
| [`EEVDF_GATE_2026-07-04.md`](./EEVDF_GATE_2026-07-04.md) | the complete benchmark campaign log — every keep and every falsification |
| [`docs/GAME_RENDER_PIPELINE_SCHED_EXT_INVESTIGATION_2026-07-23.md`](./docs/GAME_RENDER_PIPELINE_SCHED_EXT_INVESTIGATION_2026-07-23.md) | input-to-photon Wayland/KWin/DRM pipeline and the RT-preemption escape investigation (its IMMED candidate is superseded — see below) |
| [`docs/RT_PLACEMENT_LOGIC_2026-07-24.md`](./docs/RT_PLACEMENT_LOGIC_2026-07-24.md) | how Linux RT chooses cores, kernel-source verified — and the falsified hypothesis that cake's occupancy can steer it |
| [`docs/LEDGER_REPAIR_AND_REGIME_GATE_2026-07-24.md`](./docs/LEDGER_REPAIR_AND_REGIME_GATE_2026-07-24.md) | the experiment ledger was emitting zeros; gear Gate 1 result on the repaired corpus |
| `docs/` | historical decision logs from the pre-rewrite mutation campaigns |

## Contributing & reporting problems

Bug reports and stall/eviction reports are welcome via GitHub issues —
please include `dmesg | grep sched_ext` output and your CPU/kernel. Be
aware of the contribution bar: every behavioral change must survive the
interleaved noise-gated A/B discipline described above before it lands, so
a PR should come with (or expect) benchmark evidence, not just reasoning.

## License

GPL-2.0.
