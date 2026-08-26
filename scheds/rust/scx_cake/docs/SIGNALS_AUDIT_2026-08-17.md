# Kernel signal audit + PSI theory verdict — 2026-08-17

Two workflows (17 agents): exhaustive sweep of kernel-exposed filesystems for scheduling
signals, and an adversarial theory panel on using PSI (`/proc/pressure/*`, cgroup
`cpu.pressure`) in scx_cake. Full transcripts: workflow runs `wf_0a96a7e8-736` (sweep) and
`wf_50239df2-a48` (panel) under the session subagents dir.

## Verdict

**PSI is falsified as a cake input** — killed on three independent grounds:

1. **Redundancy**: every decision PSI would inform at 500 ms–1 s granularity is available
   per-event, exactly, at the decision point in BPF: `scx_bpf_cpu_curr` names the occupant a
   crowd wake waits behind; a two-step `pick_idle` (nonsink first, full-mask fallback) IS the
   slack-vs-saturation discriminant; crowd-membership on `curr` answers culprit-vs-victim per
   wake. A polled word can only be a stale summary of what the hot path already sees fresh.
2. **Contamination**: cake deliberately starves background work, so global PSI `some` is
   nonzero whenever any background load exists — it detects "background exists", not
   "scheduler failing". High global stall with a quiet game is cake WORKING.
3. **Host structure**: Steam titles run in `app-steam@<uuid>.service` shared with the Steam
   client and CEF webhelpers — there is no clean per-game scope. Verified: that scope had
   accrued 18.9 s of `full` stall with NO game running. Per-scope trigger writes also fail
   post-cap-drop (files are ritz:ritz 644; uid0 without CAP_DAC_OVERRIDE gets EACCES).

Plus the standing timescale truth: PSI's 500 ms minimum window is 3–5 orders of magnitude
slower than the µs decisions it would steer.

## The harvest — per-event constructs the kills named (all BTF-verified on this kernel)

| # | item | what it replaces | class |
|---|---|---|---|
| H1 | `scx_bpf_now` (cached rq clock) | `bpf_ktime_get_ns` at 6 hot sites (running, dispatch stamps, occupant_live, handoff_yields) | mechanical cheapening |
| H2 | cake-owned qmark bits | `scx_bpf_dsq_nr_queued` on custom DSQ ids = rhashtable lookup per call, 4 hot sites (L710, 822, 967, 979) | hot-path structural |
| H3 | two-step kick pick: nonsink mask first, full-mask fallback | the sink-blind ROUTE_GLOBAL kicks (wake_notify L849/856, enqueue L1120) — §G30's accepted residual, fixed per-event with no new signal | §G30 residual fix |
| H4 | one-pick fallback | double idle scan on nonsink miss (`select_cpu_and` then `select_cpu_dfl`, L756→762) | mechanical |
| H5 | `.update_idle` callback + idle counter | `cake_system_serial`'s get/put idle-cpumask + popcount per serial wake (L524–534) — event-driven, §R.25-aligned | structural, new callback |
| H6 | crowd-membership test on `scx_bpf_cpu_curr` occupant | the entire killed PSI culprit/victim comparator family | future construct |

## Signal sweep results (what the OS offers, measured)

Tier ruling: **file reads are never nanosecond-class** (~0.3 µs syscall floor). Tier 1 is
BPF-visible state only; the loader's legitimate role is digesting files into bss words —
cake's existing frame-clock/sink-flag pattern. A 1 s poll steers modes and classifications,
never wakes or frames.

Event-driven (kernel pushes, four files on the whole host): game-scope `cpu.pressure`
(trigger + POLLPRI — but see verdict), `cgroup.events` (POLLPRI + inotify; clean game
launch/exit signal, no polling), `/proc/pressure/cpu`, `/proc/pressure/irq`.

Cheap polled tier (p50): per-tid `schedstat` 0.3 µs (runtime ns, **run_delay ns**, pcount —
per-game-thread wake-wait, 25× cheaper than /proc/stat), `feedback_ctrs` APERF/MPERF 0.4 µs
(true busy/boost; `scaling_cur_freq` LIES on idle cores), scope `cpu.stat` 0.7 µs,
`sched_ext/root/events` 0.6 µs (cake's own SELECT_CPU_FALLBACK counter — self-diagnosis),
k10temp 1.8 µs, nvidia IRQ line delta 4.3 µs (fps proxy → GPU-bound regime bit).

Traps: `scaling_cur_freq` (stale on idle cores — the exact cores placement wants),
`/proc/schedstat` (18 µs, may exclude scx tasks while attached), `loadavg` (5 s EMA + D-state).

## Sweep keepers not yet used

- `cgroup.events` populated-flag: event-exact game session start/stop for profile attach.
- per-tid `schedstat` run_delay: cheapest possible per-thread wake-wait trend — a scoring
  and thread-classification input (never frame-steering).
- `sched_ext/root/events` deltas: placement-failure alarm on cake itself.
- `/dev/cpu_dma_latency`: PM QoS bound, read 4-byte u32; writing it would pin C-state exit
  latency (host currently runs cpuidle driver `none`, so moot here — relevant on other hosts).
