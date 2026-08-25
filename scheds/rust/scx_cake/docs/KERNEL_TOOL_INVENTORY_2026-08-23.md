# Kernel-level tool inventory for scx_cake diagnosis

2026-08-23. Companion to `bench/PROFILING.md` (which owns cake-bpfstats,
thread-profile, SMT residency). This file maps **diagnostic questions → kernel
tools**, with commands tuned to this host and this project's rules (never sudo;
identity-validity before numbers; noise as covariate). All listed tools verified
present 2026-08-23 unless marked ABSENT.

---

## Q1. What is the scheduler itself doing right now?

| tool | what it answers | command |
|---|---|---|
| `scxtop tui` | live per-CPU util, DSQ latencies, LLC misses, per-task runtime — the sched_ext-native view; runs identically under EEVDF/cake | `scxtop tui` while playing |
| `scxtop trace` | the same signals into a **perfetto** trace (open at ui.perfetto.dev); correlate DSQ latency against MangoHud frames on one timeline | `scxtop trace -o out.pb` |
| `bpftool prog show name <cb>` | per-callback run_time_ns / run_cnt (this is `cake-bpfstats`; keep `bpf_stats` OFF outside measurement) | `bpftool prog show` |
| `bpftool map dump` | cake's own state: run slots, qmask, frontier word, census — ground truth for "was the hint set", "did the claim fire" | `bpftool map dump name <map>` |
| `/proc/sys/kernel/bpf_stats_enabled` | toggle for the above (write 0 when done — it taxes every program run) | — |

## Q2. Where does wake-to-run latency come from?

The retained-trace pipeline (`cakebench wake-latency capture` +
`bench/wake_maxdecomp.py`, `wake_occupant.py`, `wake_migsplit.py`) stays the
primary. Add these for questions it cannot answer:

| tool | what it adds | command sketch |
|---|---|---|
| **bpftrace runqlat** | continuous runqueue-wait histogram per CPU/thread at ~zero cost — catches transient herds between captures | `bpftrace -e 'tracepoint:sched:sched_wakeup { @start[args->pid] = nsecs; } tracepoint:sched:sched_switch /@start[args->next_pid]/ { @usecs = hist((nsecs-@start[args->next_pid])/1000); delete(@start[args->next_pid]); }'` |
| **perf wakeup chains** (`--switch-events --call-graph dwarf`) | who woke whom, with stacks — resolves handoff PAIRS (mutex/serial shape) instead of single transitions | `perf record -e sched:sched_switch,sched:sched_wakeup -R -k 1 -a --call-graph dwarf -- sleep 20` then filter by tid |
| **bpftrace waker→wakee matrix** | which threads wake which (the many-to-many TaskGraph shape, open gap #7) | aggregate `sched_wakeup` by `[args->target_pid, pid]`, sort by count |
| `perf sched latency/map` | post-process any sched-event capture into per-task wait/slice/migration tables; cross-checks our own analyzers | `perf sched latency -i perf.data` |
| **osnoise / timerlat tracers** (tracefs) | IRQ + scheduler jitter floor with no RT setup (rtla ABSENT; drive raw tracers directly) | `cd /sys/kernel/tracing && echo osnoise > current_tracer && cat trace_pipe` |
| `sched_stat_blocked/runtime/wait` tracepoints | exact block reason + wait time distributions — separates "waiting for CPU" from "waiting on dependency" | enable alongside sched_switch |

## Q3. What is the machine doing underneath the scheduler?

| tool | what it answers | notes |
|---|---|---|
| `/proc/interrupts` diff over N s | which CPUs carry which IRQs — independent check on the sink mask (G33/G35) | `cat /proc/interrupts; sleep 10; cat ...` |
| irq + softirq tracepoints | handler durations/cadence (the §G33 share computation; also the analyzer in `runs/toggle_game_wake_20260822/irqjitter.py`) | `events/irq/irq_handler_{entry,exit}`, `events/softirq` |
| **cpuidle sysfs counters** | per-CPU per-state residency + exit-latency usage — the cheap local answer to §G51 (driver reports `none` here; this shows whether BIOS changed after a reboot) | snapshot loop over `/sys/devices/system/cpu/cpu*/cpuidle/state*/{usage,time}` |
| `/proc/pressure/*` (PSI) | system-wide stall pressure as an OBSERVER (PSI-as-input was falsified §G34; as a covariate it is still valid) | record avg10/avg60 per arm |
| `/proc/<tid>/schedstat`, `/status` | per-thread cumulative wait slices, voluntary/involuntary switches, last_cpu — already in thread_profile; cite directly when a single thread matters | zero-cost, safe mid-game |
| `/sys/kernel/debug/sched/features` + `base_slice_ns` | **EEVDF's own knobs** — read them to know what native is doing (preempt granularity, migration_cost); flipping them on the native arm isolates "EEVDF feature" vs "cake gap" | debugfs must be mounted |

## Q4. Microarchitecture per thread (why a frame was slow, not just that)

| tool | what it answers | command sketch |
|---|---|---|
| `perf stat -t <tid> -e cycles,instructions,LLC-load-misses,dTLB-load-misses,context-switches,cpu-migrations` | IPC + miss rates for ONE thread over a window (game IPC endpoint, per-thread) | interval mode `-I 5000` for trend rows |
| **AMD IBS** (`ibs_op//`, `ibs_fetch//`) | precise per-sample load latency + DTLB + L2/L3 hit levels on Zen — WHERE the GameThread stalls, cache-warm claims vindicated or refuted | `perf record -e ibs_op//pp -a -C <cpus> -- sleep 15` |
| `perf mem record -t <tid>` | sampled data-address heatmap of the hot thread — pairs with IBS for the same story in one step | needs IBS on AMD |
| `perf c2c` | false-sharing/HITM detection — the direct test for contention on cake's own shared lines (frontier.word, qmask, census words) | `perf c2c record -a -- sleep 15; perf c2c report` |
| `perf record -g dwarf` + flamegraph collapse | per-thread on-CPU profile → flamegraph for the maintainer's eye | any capture you already retain |

## Q5. Cross-correlating scheduler events WITH frames

The missing layer in most captures: scheduler truth and frame truth on one axis.

1. `scxtop trace` (perfetto) + import the MangoHud CSV → two tracks, one timeline
   (perfetto query language joins on ts).
2. Or annotate perf captures with frame marks:
   `sudo-less` route — run MangoHud with `output_folder` + `log_interval=1`
   (frame rows) while `perf record -e sched:sched_switch,...` runs; join offline
   on timestamp. `bench/wake_maxdecomp.py` already parses the perf side; the
   join is a small extension (frame_ts ± window → event counts).
3. `perf inject --sched-stat` merges stat_* events into switch records so each
   switch carries its preceding wait time — one less manual pass.

---

## Rules that bind all of these (from CLAUDE.md)

- Identity first: confirm ops-name prefix + binary sha256 before reading ANY number.
- Never sudo; a failing privileged step is a capability bug, not an instruction to elevate.
- Nothing heavy attaches during a live frame capture (observers ride BETWEEN slots).
- Interleaved A/B only for cross-run comparisons; regime is covariate #1.
- Every number names its evidence class (FRAME/WAKE/CENSUS/STATIC/SIM).

## Highest-value additions, ranked for the current campaign

1. **IBS / perf mem on the GameThread + kwin** — the domain audit found
   GameThread p99 72 µs and exec +15–42% unexplained; precise stall attribution
   says whether cake's placement is costing cache warmth (mechanism, not guess).
2. **waker→wakee matrix** — quantifies the many-to-many TaskGraph shape per
   game; turns open gap #7 into measured pair counts (input for a burst-classifier).
3. **`perf c2c` during play** — prices the shared-line RFO tax directly instead
   of inferring it from ns/call deltas.
4. **cpuidle sysfs snapshot loop** — free §G51 progress check every boot; the
   depth model stays dead until the driver appears.
5. **osnoise tracer** — a jitter-floor number both arms must respect; would
   have caught the mode-variance confounds (§G38.1 attribution) earlier.
