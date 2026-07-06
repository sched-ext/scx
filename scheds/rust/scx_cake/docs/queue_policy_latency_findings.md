# Queue Policy Latency Findings

## Purpose

This note captures the April 30, 2026 queue-policy A/B result that made
`llc-vtime` the historical default fallback queue path for game-latency work.
It is retained as context now that later stress-ng score work moved the release
benchmark tuple back to `local`.

The important finding is simple: the local-only fallback path preserved average
FPS, but badly hurt low-percentile FPS. Restoring a per-LLC vtime fallback queue
recovered the 0.1% and 1% lows while leaving average FPS essentially unchanged.

This is not a game-specific or TGID-specific rule. It is a scheduler-shape
finding about how runnable work is arbitrated after direct idle dispatch is no
longer possible.

## Test Context

Benchmark source files were MangoHud captures under `/home/ritz/Benchmarks`.
The tested game process was `PortalWars2Client-Win64-Shipping`, captured while
testing Splitgate 2.

System line from the latest capture:

```text
Steam Runtime 3 (sniper), AMD Ryzen 7 9800X3D 8-Core Processor, NVIDIA GeForce RTX 4090, kernel 7.0.2-2-cachyos, cpuscheduler powersave
```

The CSV files do not encode the active scheduler. Scheduler labels below come
from the test log and capture order in the development session.

## Results

Each row is the average of two summary CSVs.

| Run group | Captures | 0.1% low FPS | 1% low FPS | Average FPS | 97% FPS | GPU load | CPU load |
| :-- | :-- | --: | --: | --: | --: | --: | --: |
| `scx_cake` local-only reference | `11-19-26`, `11-20-37` | `177.095` | `212.200` | `428.050` | `963.913` | `89.60` | `27.70` |
| `scx_cake --queue-policy llc-vtime` | `12-04-10`, `12-04-43` | `251.476` | `273.602` | `427.350` | `653.484` | `89.75` | `24.40` |
| Installed Cake `1.1.0` reference | `09-50-39`, `09-51-12` | `248.229` | `271.850` | `412.300` | `689.188` | `90.15` | `22.55` |
| EEVDF reference | `09-31-23`, `09-31-57` | `251.344` | `278.237` | `428.750` | `637.706` | `90.00` | `22.30` |

The main local-only to `llc-vtime` delta:

| Metric | Local-only | `llc-vtime` | Delta |
| :-- | --: | --: | --: |
| 0.1% low FPS | `177.095` | `251.476` | `+74.381` / `+42.0%` |
| 1% low FPS | `212.200` | `273.602` | `+61.402` / `+28.9%` |
| Average FPS | `428.050` | `427.350` | `-0.700` / `-0.2%` |

`llc-vtime` also landed near the EEVDF reference:

| Metric | EEVDF | `llc-vtime` | Delta |
| :-- | --: | --: | --: |
| 0.1% low FPS | `251.344` | `251.476` | `+0.132` |
| 1% low FPS | `278.237` | `273.602` | `-4.635` |
| Average FPS | `428.750` | `427.350` | `-1.400` |

## Interpretation

The result points at queue arbitration, not raw hot-path overhead.

The local-only fallback path made `cake_select_cpu` pick a target CPU and then
kept busy fallback work on that CPU's local DSQ. That is cheap and cache-local,
but it can strand latency-sensitive frame-adjacent work behind the current owner
of one CPU. Other CPUs in the same cache domain cannot pull that local queue.
When a game has many short blocking workers, render-helper threads, driver
wakeups, and input-adjacent wake chains, that per-CPU head-of-line blocking can
show up as weak 0.1% and 1% lows even when average FPS remains strong.

The `llc-vtime` path keeps the same idle-first selection and direct local insert
fast path. The difference only appears when fallback work is busy:

1. If the target CPU still looks idle, `cake_insert_llc_vtime()` direct-inserts
   with `SCX_DSQ_LOCAL_ON`.
2. If the target CPU is busy, it inserts into `LLC_DSQ_BASE + llc_id`, ordered by
   `p->scx.dsq_vtime`.
3. `cake_dispatch()` pulls from the current CPU's LLC queue first, then tries
   other LLC queues only if needed.

On a single-LLC CPU such as the 9800X3D, this effectively restores one shared
virtual-time fallback arbiter for all busy fallback work while staying inside
the same cache domain. That better matches the service model that EEVDF is good
at: recently served work advances in virtual time, sleepers can re-enter without
being pinned behind one unlucky local owner, and any CPU that reaches dispatch
can pull the next eligible fallback task.

## Decision

`llc-vtime` was the default queue policy for this game-latency checkpoint. As of
the later benchmark-guided stress-ng work, release builds default to `local`
while retaining `llc-vtime` as a compile-time/runtime A/B mode.

`--queue-policy llc-vtime` remains useful for regression testing and for
checking whether a future change needs the shared fallback arbiter again.

## Follow-Up Checks

Useful future comparisons:

- repeat same-session A/B pairs with `sudo ./target/release/scx_cake` and
  `sudo ./target/release/scx_cake --queue-policy local`
- keep comparing against EEVDF when changing queueing or wakeup policy
- in debug dumps, watch `nr_shared_vtime_inserts`, `nr_local_dispatches`,
  `nr_stolen_dispatches`, wake wait tails, and busy wake counts
- on multi-LLC systems, check whether cross-LLC stealing helps tails or causes
  locality loss
