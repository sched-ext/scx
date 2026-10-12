# burstkey: cosmos-style requeue key (2026-10-12)

| Verdict | Kernel | Evidence level | Patch | Data |
|---|---|---|---|---|
| ❌ rejected, reverted | 🐧 any sched_ext | game (KovaaK's, CPU-limited, quiet) | [burstkey.patch](burstkey.patch) | `scx_cake_bench/runs/cosmos_20261012/r2_*` |

## ❓ Question

Does cake gain cosmos's tail behaviour if a requeue that has not slept since its wake
queues behind fresh wakes by the runtime it burned since then (cosmos: deadline =
vtime + exec runtime since sleep, capped by `slice_lag` 20 ms)?

## 🔧 Patch

`ops.runnable` stamps `sum_exec_runtime` in task storage at each wake; the continuation
arm adds the weighted runtime since then (cap 20 ms) to the requeue key.
`--toggle burstkey=1`.

## 📊 Evidence (6 × 20 s per run, ext CPU 1.2–1.5 %)

| | avg FPS | p99 | 1 % low | 0.1 % low | stddev | worst frame |
|---|---|---|---|---|---|---|
| **cosmos vs cake `lazy`** | −0.9 % (0/9) | +2.2 % (0/9) | −1.5 % (0/9) | +2.0 % (6/9) | +11 % (1/9) | −5 % (6/9) |
| **burstkey vs off** | +0.1 % | −0.3 % | −0.6 % | −3.3 % | +2.9 % | +52 % (2/9) |

A first round was spoiled by 6–8 outside Blender processes (ext CPU 35–43 %); discarded.

## 🧩 Reading

In CPU-limited KovaaK's cake `lazy` beats cosmos on average, p99, 1 % lows and jitter;
cosmos is only marginally better at the extreme tail. Borrowing cosmos's key did not
help cake. Tail spikes seen elsewhere need their own capture (GPU-limited or loaded).
