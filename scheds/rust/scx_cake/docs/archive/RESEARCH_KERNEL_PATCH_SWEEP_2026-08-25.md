# Kernel-patch sweep: what would help scx_cake performance

2026-08-25. Baseline: host kernel 7.2.0-1-cachyos; local grounding tree
`~/Documents/Repo/linux` @ v7.2-11943-g2709dd5ae32f (`kernel/sched/ext/` layout:
arena.c, cid.c, idle.c, sub.c). Method: two research passes over lore.kernel.org,
tj's sched_ext tree branches, LWN-adjacent sources, cross-checked against the
local tree where load-bearing. Every item names its verification status.

## Ranked findings

| # | patch / series | status | mechanism | expected effect on cake | verification |
|---|---|---|---|---|---|
| 1 | Righi, "Make proxy execution compatible with sched_ext" v12 (17 patches), 2026-08-16, queued for **7.3** — lore.kernel.org/all/20260816173732.17162-1-arighi@nvidia.com | NOT in 7.2 (grep-verified locally); needs CONFIG_SCHED_PROXY_EXEC + Stultz "Sleeping Owner Handling" base | `SCX_OPS_ENQ_BLOCKED` + `SCX_ENQ_BLOCKED`: PI-blocked proxy donors arrive in `ops.enqueue()` where BPF picks placement; today they stay pinned behind the lock-owner occupant | Attacks the accepted −71.8% futex-lock-pi loss AND the Wayland/mutex-handoff game path; series selftest: mutex wait −20.4% same-CPU, −12.9% cross-CPU | thread + Tejun review reply read |
| 2 | K2 fused place kfunc (**ours**, §G54 registry) | not written | fuse placement ladder into one kernel-side op | ~10–15 ns/call toward the 65–70 ns floor; re-priced LOW after mailbox redesign deleted pull sites | n/a — design doc only |
| 3 | Heo, `scx_bpf_cid_override()` + `ops.set_cmask()` (arena cmask), branches scx-cid-v1..v4, in for-7.2/7.3 | cid.c IS in local 7.2; usage semantics unread | scheduler-directed CPU assignment without the separate pick/test-and-clear/kick sequence | could collapse the claim+kick dance in the wake path to one call; needs cover-letter read before pricing | file presence verified; mechanism INFERENCE — flag |
| 4 | amd-pstate preferred core (Meng Li v14, merged 6.6) + CPPC preferred-core online detection (Shenoy, backports 6.12/6.17) | merged long ago | highest_perf tiers → arch asym priorities | NOTHING NEW TO CHASE: ranking already reaches cake via §G52's loader read of `highest_perf`; no BPF kfunc API queued; intra-CCD ranking is a no-op on uniform-Zen SKUs | sources read |
| 5 | cpuidle `none` on this Zen host | **BIOS, not a patch**: x86 has NO native AMD idle driver in-tree (drivers/idle = intel_idle only); acpi_idle feeds off ACPI _CST tables, hidden when BIOS Global C-State Control is off | enable Global C-State Control + Power Supply Idle Control=Auto; drop any `idle=`/`cpuidle.off=1` cmdline | unblocks §G51 depth model without any kernel work | docs.kernel.org admin-guide/pm/cpuidle.html; drivers/idle listing verified |

## Negative results (swept, nothing found)

- **No patches reduce struct_ops trampoline entry cost** (2025-08→2026-08 window;
  bpf-next pulls 6.16–7.3 not exhaustively readable — flagged, but zero hits on
  every searched surface). Confirms the eighth-pass audit: the trampoline floor
  is structural and nobody upstream is working it.
- **Nothing touches DSQ peek/move_to_local/nr_queued cost** in the window.
- **No fused-placement discussion upstream**; closest existing thing is
  `scx_bpf_select_cpu_and()` itself (merged 6.15, already used).
- **No occupant-at-wake, sibling-busy-without-deref, or C-state-to-BPF kfuncs**
  proposed anywhere — K3 would also be novel.
- tj's cgroup sub-scheduler RFC (Sep 2025, 46 patches, still RFC-shaped):
  wrong architecture for cake (clean-slate refusal stands).

## Unread leads worth one pass each

1. Righi v12 cover letter + Tejun review thread in full — confirm the
   blocked-donor migration veto (`task_cpu != wake_cpu && is_blocked`) can't
   recreate the pinning we're escaping.
2. `cid.c`/cid.h in the local tree + branch `arena-args` follow-up.
3. tj-tree branches `scx-enq-immed{,-v2}`, `scx-ddsp-local-on{,-v2}`,
   `scx-pick_task`, `scx-remove-static_keys` — titles hint enqueue/dispatch-path
   changes; contents unchecked.

## Recommendation

Lane 1 (proxy-exec compat) is the only upstream patch with a measured,
cake-relevant win attached. It lands in 7.3 regardless of our involvement —
the actionable work is OURS: an `SCX_OPS_ENQ_BLOCKED` consumer design behind a
toggle, ready when CachyOS ships 7.3. Register as §G56; K2 stays parked pending
the miss-path hit-rate experiments; K3 stays parked (novelty ≠ value until the
80→65 ns gap matters).
