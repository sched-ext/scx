# claimhome: lean `lazy`'s placement without the kernel patch (2026-10-12)

**Verdict: not shipped.** Placement reproduced; frame win not. Source reverted.
Kernel requirement: none.

## Question

Lean `lazy` (kernel patch 4, K3) beats `off`; `on` (K1/K2/K4) alone does not.
Probe census: under `lazy` a claimed CPU's core keeps its whole-idle bit until
that CPU runs, and 5.5–7 points more wakes go to their warm home CPU
(`home_warm` ~70 % vs ~64.6 %, replicated twice). Can cake get that alone?

## Patch

[claimhome.patch](claimhome.patch), `--toggle claimhome=1`: cake marks CPUs its
`taci` claims win in one word, clears the mark at `ops.running` or idle entry,
and `cake_core_word()` treats a core as whole when each thread is idle or so
marked (shift-pair SMT maps). A first version that only relaxed the home
core-busy test fired on 0.1 % of wakes and moved nothing.

## Evidence (KovaaK's menu, ≤5 min runs)

| Arms | Result |
|---|---|
| Placement, `off`+claimhome vs `off` vs `lazy` | home 71.7 % / 65.5 % / 70.7 %; warm-elsewhere 15.0 / 21.4 / 15.9 % |
| Frames, `off`+claimhome vs `off`, quiet | avg +0.45 % (9/9), p99 −1.0 %, 1 % low −1.6 % (0/9), p99.9 +2.2 % (0/9) |
| Frames, same, 16 hogs | avg +0.15 %, 1 % low +1.3 % (7/9), 0.1 % low +8.4 % (7/9) |
| Frames, `on`+claimhome vs `lazy`, quiet | avg −0.04 %, 1 % low −2.0 % (1/9), p99.9 −3.4 % |
| Cost (bpf_stats) | `select_cpu` 79 ns either way (lean claim: 68); `running` +0–6 ns |

Reading: `lazy`'s frame win needs both the cheaper claim (K1/K2) and the
home-friendly placement (K3); either alone is not a clear gain. `on`+claimhome
nearly matches `lazy`, slightly worse, consistent with claimhome's two atomics
per wake on a shared word. Data: `scx_cake_bench/runs/claimhome_20261012/`.
