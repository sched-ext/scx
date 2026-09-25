# Audit: per-component cost vs EEVDF, with reduction paths

2026-08-23, maintainer-directed ("make each component less expensive than
EEVDF while still performing its role"). Source at `070e0af86`. Costs are
STATIC attribution (insns/spills from `fnspills.py`, object 2427 insns total)
plus the toggle campaign's measurements; per-frame anchors from the KovaaKs
menu frame A/B (premium ≈ 45 µs/frame tip, 80 stack, at 700 fps).

## The structural frame

sched_ext pays a BPF trampoline entry/exit per callback that EEVDF's native
calls never pay. Cake therefore cannot beat EEVDF on raw per-event entry
cost; it must win the total: **fewer events** (measured: −28% context
switches, softirqs halved, both games), **O(1) decisions** where EEVDF scans,
and **better placement** (measured: game IPC 1.55 vs 1.40 loaded). The
per-frame total is events × cost + cache effects — all three factors are
cake's to shape.

## Wake path (`cake_select_cpu`, 426 insns, 99.86% of game dispatches)

| component | role | cake cost (common case) | EEVDF analog | reduction path |
|---|---|---|---|---|
| serial-handoff block | co-locate true handoff pairs | 1 slot load + branch; rare: §G45 word (was mask walk), §G44 bit (was rhashtable) | WF_SYNC hint, ~free | AT FLOOR after §G44/§G45 |
| prev-CPU home claim | cache warmth beats idle-core rank | starved_turn 2 mults + irq 2 loads + **core_contended: cpu_curr deref chain** + atomic claim | select_idle_sibling prev check | **§G49**: sibling-busy via `scx_bpf_get_idle_smtmask` bit read, deletes the rq deref chain |
| nonsink gen check | live sink set | 1 load+cmp | — | at floor |
| ranked idle pick (`select_cpu_and`/dfl) | first placement | **full LLC scan kfunc, the largest term** | select_idle_sibling with SIS_UTIL throttle (gives up under load) | **§G48**: going-idle hint claim FIRST (extend §G43 to this site) — hit = zero scans; the menu regime is its design case |
| SYNC re-rank + qmark guard | §R.6 weld avoidance, ordering | SYNC wakes only | — | leave |
| escape + tick veto | §G35/§G36 cleanliness | claim-time only; 1 ktime read | — | leave; §G43-hit skips them |

## Enqueue (203 insns; 0.14% of game dispatches, 23.6% saturated)

| component | role | cake cost | EEVDF analog | reduction path |
|---|---|---|---|---|
| route classify | wakeups global / continuations local | starved_turn recompute (2 mults) | — | cheap; recompute is deliberate (§R.13) |
| kthread arm + §G47 | bounded kthread service; ISR successor stays | idle pick, or 3 loads on the §G47 hit | ttwu picks waker/prev | BUILT (§G47) |
| wake_vtime + cadence | sleeper clamp fairness | loads + shifts + ≤2 mults | place_entity + update_curr | already ≤ EEVDF |
| insert kfunc | queue admission | rbtree insert | enqueue_entity rbtree | parity, floor |
| wake_notify | someone must run it | §G43-hinted; else scans + occupant_live | wakeup_preempt local | hint hit rate is the lever (§G43/§G48) |

## Dispatch + accounting

| component | role | cake cost | EEVDF analog | verdict |
|---|---|---|---|---|
| dispatch_search | earliest eligible of {own, wake} | own peek + §G41 word + §G25 bitmask ring | rbtree leftmost + periodic load_balance softirq | cake inline steal vs EEVDF softirq: roughly parity; cake's marks already O(1)-gated |
| keep-prev slice | idle-avoidance regrant | 2 divides + ktime | — | candidate: serve from §G46 cache (registered untouched; needs a running-task entry) |
| running/stopping | vtime charge | 2 stores + 1 multiply-add (+§G46 publish) | update_curr + PELT decay + cgroup walk | **cake already cheaper** |
| no .tick | — | zero | entity_tick + PELT per tick | cake wins by absence |
| update_idle (§G45) | idle census | flip-gated atomics per transition | inline in idle path | measured lean-positive; keep |

## What EEVDF pays that cake never does

PELT per-entity decay chains, cgroup share recomputation, load-balance
softirq scans, NUMA-balancing hooks, tick-time entity accounting. This is
why cake's switch/softirq counts and accounting path are already below
native's, and why "below EEVDF per frame" is reachable despite the
trampoline floor.

## What cake pays that EEVDF never does

Trampoline entries (structural), kfunc call overhead, BPF-text L1i footprint
(E4a splits this from migration-cooling), and the placement insurance
premium. The premium is policy, not overhead — the reduction is
contention-pricing (engage spreading/sink rules on current evidence of
contention; §G47 is the first instance), never deletion.

## Registered from this audit

- **§G48** — hint-first main placement: the §G43 going-idle claim moves ahead
  of `select_cpu_and`, making the common idle-machine wake O(1). Targets the
  menu-regime fps gap directly; §G38 core preference preserved by the claim
  gates.
- **§G49** — core-contended via idle-smtmask bit instead of the sibling
  `cpu_curr` deref chain. Same §G38 semantics, cheaper read, one fewer
  pointer chase per home claim.

Both behind campaign toggles; screens per the standing ladder (wallclock →
game rotation → frames where MangoHud exists).
