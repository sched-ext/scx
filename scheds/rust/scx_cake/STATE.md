# scx_cake — CURRENT STATE

> [!IMPORTANT]
> **Read this first, every session.** It holds only what is current: what is owed,
> then the latest rounds, newest first. Rules live in `CLAUDE.md`; behaviour in
> `DESIGN.md`.

**2026-09-26 — REVERTED to `9db04489e` (2026-09-22).** Everything after it (the
2026-09-23..25 nightlies and the uncommitted §G98 work) was reverted; it is kept on branch
`keep/pre-revert-2026-09-26` and in `git stash` ("pre-revert 2026-09-26 …"). Maintainer's
note: Claude Opus 5.5 is of questionable quality for this project; avoid it.

What the reverted rounds showed (full entries: `git stash show -p stash@{0} --
scheds/rust/scx_cake/STATE.md`; data: `scx_cake_bench/runs/wow_*_2026092[56]/`):
- §G97 (interrupt-CPU placement, 09-23) cost WoW about 1.3–1.6 % fps and 5–6 % on p99
  and 1 % low. NVIDIA IRQ 97 lands on CPU 12 in bursts of back-to-back handlers; §G97
  queued the GPU-completion threads (vkd3d_fence, one WoW.exe thread) on CPU 12 for the
  whole burst: wake-to-run p99 about 106 µs against under 1 µs.
- Without §G97, the 09-25 tree with §G98 still trailed 09-22 in the tail over two
  back-to-back pairs: max frame about 45 % longer, frame-time stddev 5–14 % higher,
  0.1 % low 1–4 % lower; average fps within 0.25 %.
- schedstat `run_delay` (thread-health) misses IRQ time between a wakeup and its switch
  (`rq_clock_skip_update`); use tracepoint timing for this class of delay.
- No cake build needs sudo: copy it to `target/cake_receipt_builds/<name>/scx_cake`, run
  `sudo -n /usr/local/libexec/scx-bench-setcap <absolute path>`, start it as the user.
- 09-22 still carries the frontier change behind the 09-25 Unreal Editor `runnable task
  stall`; the §G98 fix for it is in the stash.

The code is `9db04489e`. The entries from 2026-09-22 on and the Owed list below record
the reverted work as history.

**Archive:** `docs/archive/STATE_ARCHIVE.md` holds every settled entry word for word,
newest first: the rounds up to 2026-09-19, the August campaign, the scoreboard (last
sealed 2026-08-23; re-baseline before citing), the ledger and the `§` registry. Search
it with grep; do not read it whole. Older history: `git log -p -- scheds/rust/scx_cake/STATE.md`.

**Offload rule:** once nothing in an entry is owed, move it whole and unchanged to the
top of the archive, in the same session. An item that is still owed moves up to "Owed"
first.

Branch: `RitzDaCat/scx_cake-nightly`. Last upstream merge: PR #3786 (`c410fcbd7`,
2026-09-06). Squash and backup-branch history: the archive's first section. Hashes
from `12803f341` to `f397452b5` are pre-squash commits, kept only on the local branch
`keep/pre-squash-2026-09-25`; the branch carries them as the six commits after
`9db04489e`.

---

## Owed

Items below were owed by the reverted 2026-09-23..26 work; re-check each against
`9db04489e` before acting on it.

- **2026-09-25 (night), §G98, the startup rows and the §G97 removal (uncommitted):** the
  maintainer's go to commit; the game frame A/B (`cakebench game ab`) for the set; the
  independent-review fixes still open (entry below); `cargo test -p scx_cake --
  --ignored verifier_load_topologies` with BPF capabilities (multi-LLC, >64 CPUs, sparse
  ids); an HZ 250/300 host run of the stall scenarios.
- **2026-09-25:** an 8-slot `cakebench cost ee0dbabc7 f9b4d3281 --slots 4` run for
  the four commits of that day (the 2-slot run had one slot in a load burst), on a
  quiet host.
- **2026-09-23 (night):** the "Open" list in that entry below.
- **Carried from the 2026-09-19 entries, now in the archive (not rechecked since):**

> **Unresolved, carried:** in each of the last two rotations one new-arm slot
> dipped at the 0.1 % low (a handful of 0.9–0.97 ms frames whose whole appsim
> chain ran long); old arms show the same frame class (s6_old max 0.90 ms,
> s4_old 0.84 in `rot3`), seven of eight slots per rotation are identical,
> and the 4-slot run of 2026-09-19 dipped on both arms. Not called null: the
> next rotation (or an A/A on `8248fe6c3`) decides whether the new arms carry
> it. Net over the round vs the pushed nightly `e355a60f2`: dispatch 42.7 →
> 32.2 ns/run, total cake BPF 29.4 → 30.1 ms/s (the interlock's +2.8 minus
> these −2.4), frames flat within the carried question.

> Deferred from the layout lens, with a census owed first: lock-free seat
> slot (`pid|seq<<32`, −4 helper calls per stage pair, but a HOLD/RELEASE
> race can lose a reservation: not placement-neutral); stopping precomputing
> stage/starved/subhandoff into the groove to trade four remote-dirty task
> lines for one storage lookup (needs `perf c2c` on those loads).

> Owed: maintainer's push decision; the §G93 trace on a WoW dungeon (gates
> cpu_release's evacuation, unchanged by this round); testers' probe=1 logs
> from a 5800X / 14900K / 7950X3D / Threadripper for §G96; the game-scene
> histograms before any actuation of the floor or the stage boundary (§G37
> Phase A' sweep: `--handoff-ns 800/1464/3000`); the grant timer behind
> `grant_lt_tick`.

> Owed, in order: probe=1 slot in both games (V19's cut rule: fired=0 in
> both games AND one saturated harness slot, with a recorded design reason);
> V18 seat pricing once the sudoers `prog profile` rule carries
> `llc_misses`; V11 race table; the seamlessness council's findings (below,
> when in); then the §G93 trace (`rt_displace_capture.sh 30`) and the
> irq_leave scene-matched bisect from the 09-18 list below.

---

## RESUME HERE

**2026-09-26 — §G97 REMOVED (ISR-WAKE PLACEMENT).** Uncommitted, on top of §G98 and the
startup rows (release binary `dde4a804`). §G97 (`3c56bafb2`; its entry is now in the
archive) put a non-stage task woken inside a hardirq on the idle waking CPU, IMMED. Here
NVIDIA IRQ 97 always lands on CPU 12 and fires in bursts of back-to-back handlers
(handler p50 21 µs, next entry 0.3–0.4 µs after each exit, bursts about 80 µs), so the
placed task waited out the burst: in 10 s, 6,491 of 8,841 CPU-12 placements waited over
20 µs (p50 93 µs). The two WoW threads that report GPU completion (vkd3d_fence and an
unnamed WoW.exe thread) went from p99 0.6–0.8 µs to 106–107 µs, woke about 30 % less
often, and GPU busy fell 97.6 → 96.2 %; every other render thread was unchanged. Removed:
`cake_isr_wake_cpu`, its call in `cake_select_cpu`, `CAKE_SITE_ISR_WAKE` and its loader
name, the DESIGN.md paragraph.

WoW at one GPU-bound spot (4K 240 Hz, about 690 fps), one 25 s pass per arm, 20 s
filtered traces. Two sessions: the §G97 passes ran 12–15 min before D, when 09-22 measured
688.0 fps (first and last §G97 passes 0.25 % apart); by the D session the scene ran 1.3 %
faster. Through 09-22 as the common arm, §G97 cost about 1.6 % fps and 6 % p99 and 1 % low:

| build | avg fps | p99 ms | 1 % low | fence p99 µs | tid 11129 p99 µs |
|---|---|---|---|---|---|
| §G98 + §G97 (`1562987c`, two passes) | 676.3 / 678.0 | 1.90 / 1.89 | 527 / 530 | 107.2 | 105.9 |
| 09-22 `9db04489e` (same session as D) | 697.2 | 1.75 | 570 | 0.82 | 0.58 |
| D: §G98 without §G97 (`dde4a804`) | 696.9 | 1.74 | 573 | 0.86 | 0.57 |

§G98 is not involved: the 09-24 nightly, without §G98, showed the same loss (676.7 fps,
p99 1.89 ms). Checks: fmt; clippy debug and release, 0 scx_cake warnings; `cargo test -p
scx_cake` 35 pass; attached twice, the loaded `cake_select_cpu` has no
`cake_isr_wake_cpu`. Data: `scx_cake_bench/runs/wow_versions_20260925/`,
`runs/wow_mech_20260926/`, `runs/wow_dtest_20260926/`; earlier diagnostics in
`runs/wow_live_g98_20260925/` and `runs/wow_quick_ab_20260925/`.

Measurement notes: schedstat `run_delay` misses IRQ time between a wakeup and its switch
(`rq_clock_skip_update`, kernel `core.c:2310` and `:7150`), so thread-health cannot see
this delay; tracepoint timing can. The OSLTT gain credited to §G97 was measured against
the shipped cake 1.2.1, not against its parent: before any interrupt-CPU placement
returns, measure OSLTT against `9db04489e`, and make it burst-aware or uncommitted
(shared queue plus kick).

**2026-09-25 (late night) — STARTUP ROWS: HOST VALUES ONLY.** Uncommitted, loader only,
BPF unchanged. Maintainer's rule: startup shows that cake runs and the host's values;
derived policy goes behind `-v`. The `Vtime cap` row (raw ns, policy with one host input)
is now `Tick         1 ms (HZ 1000)` (`not measured; precise clock used` without a
tick); `-v` adds `   vtime   lead cap = one 4 ms run at the task's weight (65.5 µs –
102.4 ms)`; the `-v` `age` row after Running is gone (the Tick row states the clock).
Proof: fmt; clippy debug and release, 0 scx_cake warnings; `cargo test -p scx_cake` 35
pass (2 new, `rodata::tests`); an unprivileged debug run printed both rows, then stopped
at BPF load (EPERM).

**2026-09-25 (night) — §G98 BOUNDED VTIME LEAD: RATE-BAND FRONTIER.** Uncommitted in
the working tree. Release object vs the measured arm Q2 (`aa9a6b6a0`, scratch; binary
`target/cake_receipt_builds/cost_aa9a6b6a0c8d/scx_cake`): objdiff differs only in
`cake_frontier_step` (an exact early return, review fix) and the probe record's size.
Data and tools: `scx_cake_bench/runs/g98_20260925/`.

Incident: the maintainer's run of the 09-25 nightly (`67295ff5`, Unreal Editor + 12
python3) was ejected: `runnable task stall` (BackgroundWorker, nice 5, 6.436 s). The
stuck workers sat 90.3–92.6 s of vtime ahead of the frontier on per-CPU DSQs. Cause:
`d97e93c3b` (2026-09-06, in every nightly since 09-07) capped F at other CPUs' live
occupant vtime; nothing capped v − F, so a low-weight task running on free CPUs banked
lead at 3.057 − r_F per ns; per-CPU queues have no wall-clock net (§G42's open half).
Not caused by the release/debug split (`ee0dbabc7`): every probe-gated block only
observes (read-only audit).

Rule (council round 2: five lenses, synthesis, critic; no rescue, no polling):
- Ceiling at the charge: `v ≤ F_run + cake_vtime_cap(idx)`; the cap is the charge of one
  longest run (`cake_vcap_unit_ns`, loader rodata from the tick), within
  [`FRONTIER_GRAIN_NS`, `CAKE_VTIME_CAP_MAX_NS` = one nice-19 grant, 102.4 ms].
  SCHED_IDLE shares the nice-19 cap.
- F advances in ops.running within the band [dt >> `RATE_FLOOR_SHIFT`, dt] since its
  last store, stored by CAS with a stamp; the common path (within a grain, floor owes
  under a grain) is two compares, the step is a cold `__noinline`.
- The candidate sweep reads `CAKE_NEIGHBOUR_PROBE_DEPTH` loader-listed peers
  (`cpu_frontier_peer`, topology-aware; unit test over 15 layouts), not every CPU.
- Bound by construction: wait ≤ (`CAKE_FLOOR_WINDOW_NS` << `RATE_FLOOR_SHIFT`) + drain.
- Policy, no measurement: `CAKE_KEY_BUDGET_NS` = half the watchdog (key window vs drain,
  tick, skew, RT hold; the kernel ejects at runnable_at + timeout); `RATE_FLOOR_SHIFT`
  = the largest k with window << k within the budget (static asserts: 4).
- § entries (policy, no measurement): §G98a `CAKE_KEY_BUDGET_NS` = WATCHDOG/2;
  §G98b `CAKE_VTIME_CAP_MAX_NS` = one nice-19 grant (the most lead any weight holds;
  SCHED_IDLE shares it, so its effective weight rises to nice 19's); §G98c
  `FRONTIER_GRAIN_NS` (65 µs, underived since 09-19) gains two roles: the cap floor and,
  << `RATE_FLOOR_SHIFT`, the 1.05 ms floor-store threshold.
- Independent review (non-author, read-only): rule, bound, CAS and peer list correct on
  AMD 1/2/4-CCD +C numbering, 3950X, 7980X, Strix Point, Raptor/Meteor/Arrow Lake, 1-2
  CPUs, sparse ids; fixes applied (early return, dead probe field, comm helper, comments).
  Open: the verifier has not loaded the multi-LLC, >64-CPU and sparse rows (Owed).
- Rejected: C (F = wall clock): three lens models showed game threads lose their wake
  head start under saturation (FIFO order). P (ceiling only): its bound depends on F's
  rate (stalled below).

Results, 2026-09-25, 16-CPU 9800X3D, HZ 1000 (arms HEAD+probe `7bc248a69`, P `483dbda17`,
Q `c811a90f7`, Q2 `aa9a6b6a0`; EEVDF = no scheduler):

| test | EEVDF | HEAD | P | Q / Q2 |
|---|---|---|---|---|
| stall repro, idle host, largest lead | — | 68,735.79 ms | 38.22 ms | 33.60 ms |
| SCHED_IDLE vs 10 pinned per CPU | 9.05 s gap | ejected (6.590 s) | 1.05 s | 1.09 / 1.07 s |
| nice 19 vs 60 pinned per CPU | 11.4 s gap | ejected (6.572 s) | ejected (6.205 s) | 1.81 / 1.80 s |
| nice 19 waking among 64 spinners | 0.60 s | 1.49 s | 0.18 s | 0.28 / 0.31 s |
| nice 5 share vs 4 nice-0 (pure 7.5 %) | 7.50 % | 12.50 / 8.18 % | 13.50 % | 9.53 % (Q) |

Game-facing (metric order: games owed; appsim; wall clocks):
- appsim `cakebench cost` HEAD vs Q2 (`runs/cost/20260925T193741_appsim`, busy 42.9–46.3 %):
  p99 0.6280/0.6274 vs 0.6292/0.6324 ms; 0.1 % low 1366/1360 vs 1357/1318 fps; the Q2
  slots ran 1–3 points busier. ns/run: running 33.1/37.4 vs 32.6/34.0, stopping 18.5/19.3
  vs 20.3/20.9 (the ceiling, +1.4..2.4 ns), dispatch 40.1/40.6 vs 41.2/42.8.
- HEAD/P/Q at matched busy (`20260925T191251_appsim`): total 26.75 / 26.89 / 26.76–27.38
  ms/s, p99 0.620 / 0.619 / 0.619 ms. Q before the fast path: running +3.97 ns under
  Blender (39.56 → 43.53); render 45.10 → 45.24 s (`runs/cost` blender, 2 slots).
- OSLTT input wake (USB fetch → evdev echo, µs, mean/p50/p90/p99): HEAD 41.5/41/51/57.8
  vs Q2 39.6/36/47/52.8 (2 × 100); HEAD 50.6/48/59/92.7 vs Q 50.9/49/59/103.4 (4 × 100,
  p99 inside each arm's round range). USB-to-photon (ms, mean/p99, 3 × 60): EEVDF
  7.623/11.149, HEAD 7.566/10.572, Q 7.704/11.075.


**2026-09-25 — DEDUP, CLAIM AND DISPATCH SHAVES, THE COST TOOL.** Same placement and
scheduling; each commit carries its object proof.

| commit | what | proof |
|---|---|---|
| `f2807609b` | helpers for four repeated idioms: `cake_noisy_word`, `cake_seat_cores`, `cake_seat_idx`, `cake_seat_drop` | objdiff IDENTICAL |
| `87b16b4f8` | `cake_rank_tier` reads the tier count once per call | 8 insns per tier scanned, was 10; four pickers −1..−4 insns |
| `f0dfb4ed7` | `cake_claim_warm` passes `preferred` as the first try's cold set | warm path 45 → 31 BPF slots, 2 fills fewer; a 200,000-case model of both forms matched |
| `f9b4d3281` | the both-empty dispatch test runs in `cake_dispatch`'s frame | empty path 85 → 81 slots and one call fewer; +117 static insns |

Tried and left out: a helper for dispatch's two move-and-serve blocks
(`cake_dispatch_search` 536 → 555 insns, fills 37 → 42); one `home_ok` bool in
`cake_select_cpu` (−3 static insns, hot path unchanged).

Measured: `cakebench cost ee0dbabc7 f9b4d3281 --slots 2`
(`scx_cake_bench/runs/cost/20260925T102205`), all four slots valid. Slot 2 (tip) ran in
an outside load burst (busy 56.6 %, enqueue 48.8k/s against ~5k/s). The matched slots
(3 tip / 4 base, busy 33.8 / 33.9 %): dispatch 36.8 / 35.8, select 91.9 / 94.4, running
30.0 / 30.8 ns/run. Not decided; the 8-slot run is owed.

A second run, `--slots 4` (`runs/cost/20260925T114740_appsim`), stopped in slot 7. The
host was switched off by hand at about 11:53 (the maintainer confirms; not a hang) with
the base arm (`c5afc313`) attached; slot 6's output was lost. Slots 1–5 are valid, and both arms show raised rates:

- enqueue: tip slots 3 and 5 at 14.2k and 195.5k/s against 4.5–7.3k/s; slot 5 also ran
  346.0k running/s against 159.3–168.7k/s;
- dispatch: base slot 1 and tip slots 2 and 5 at 761.7k, 1,465.9k and 425.6k/s against
  158.0–170.1k/s.

Tip slot 2 ran at base enqueue rates (6.2k/s). A read-only review found no behaviour
change in the four commits, so the cause is likely outside load; not decided. The cost
tool records no `noise_class` or `external_cpu_avg_pct`.

`bpftool prog profile` on the loaded build (older than HEAD), per run: select 626
cycles / 1,285 insns, dispatch 703 / 1,566, running 374 / 818, update_idle 347 / 832,
irq_enter 508 / 596, irq_leave 946 / 600. This is the "next" step the 09-18 irq_leave
entry names: the same instruction count and 438 more cycles; the cause stays open.

Tooling: `cakebench cost <A> <B> [--slots N]` (`scx_cake_bench/bench/scx_cake_cost.py`)
builds arms in one parked worktree (`scx_cake_bench/_scratch/worktrees/cost`; a cold
build takes 13 s), grants capabilities, runs a mirrored appsim rotation with bpf_stats,
checks each slot's identity against the loader's `Build SHA256` line and prints one
table. Found on the way: `target/` was wiped at 09:38, a session's `mkdir -p` then
recreated `target/cake_receipt_builds` at mode 755, and the receipt builder refuses any
root that is not 700; `cost` creates the root at 700.

**2026-09-24 — INSTRUCTION ROUND, 13 commits (`8b22c6cd4` … `ee0dbabc7`).** Recorded
2026-09-25 from the commit messages and the saved runs.

| commit | what | result |
|---|---|---|
| `8b22c6cd4` | dispatch: test `pend_spin` before clearing it | objdiff: `cake_dispatch_search` only |
| `7a3bd8d26` | dispatch: inline `cake_wake_serve_stamp` | `cake_dispatch_search` 529 → 545 |
| `0bd25ebd5` | ring walk over marked CPUs only | reverted in `a58cca2ff`: dispatch 29.63 against 28.24 before it |
| `7660314f1` | pool move before the count | reverted in `6282a7ea1`: dispatch 29.63 → 44.06 ns/run |
| `1c21cd199` | probe: the CPU id for `cake_tried` read under the toggle | one insn in each of two functions |
| `13811c96e` | `cake_claim_warm`: prev's seat bit before its seat pid | warm path two loads fewer |
| `3273cc4c9` | `cake_select_cpu`: handler depth tested before the ISR-wake call | warm path 118 → 106 insns, one call fewer |
| `181c3e628` | enqueue: the expiry preempt tests the grant first | pooled wake about 148 → 132 insns |
| `45b72dd96` | `cake_select_undecided`: no idle CPU in scope returns prev first | no-idle path 188 → 125 insns |
| `5c53951eb` | seat: the holder back on its own seat skips storage and the lock | running 165 → 176, stopping 215 → 237 live insns |
| `ee0dbabc7` | release compiles the probe out; debug runs it; `--toggle` removed | `cake_select_cpu` 473 → 384 live insns, no spills |

Data: `scx_cake_bench/runs/opt_bisect_dispatch_20260924` (the two reverts);
`runs/noprobe_rot_20260924`, the toggle build (A, `dd2b92ec`) against a probe-out
prototype (B, `64fee63d`), 4 slots per arm, busy 31.7 / 31.8 %: select 88.2 → 84.1,
dispatch 28.2 → 30.3, running 27.6 → 25.7, stopping 14.1 → 14.1, enqueue 186.0 → 176.9
ns/run.

**2026-09-23 (night) — OPEN-ITEM FIXES (two reviewers each, read-only).**

| commit | what | proof |
|---|---|---|
| `8fd3cc6cf` | black box: `__sync_fetch_and_add` reserves the slot. clang 22 lowered the relaxed `__atomic_fetch_add` to a non-fetching add, so every record went to slot 1 and slots 0, 2, 3 printed zeros (since `77251dd02`) | objdiff: `cake_probe_run` only |
| `2f4bc9a6c` | loader: exit reports after detach. The `-v` events row read `cake_events` before `ops.exit` filled it (8 of 8 saved rows `0 0 0`) | link close → `bpf_scx_unreg` → disable flush waits for `ops.exit`; maps stay mapped |
| `c7a7057c3` | deleted the stale review and topology harnesses | — |
| `3210c8e80` | census `taci_pool` / `taciw_pool`: the pool kicks' claims apart from `taci_notify` | 106 stat-index immediates in 37 functions remapped; `cake_stats` 139 → 141 entries |
| `97e8898a3` | `cake_claim_free` / `cake_offer_remote` add `cake_deep_word()` to the noisy set, as `cake_claim_warm` / `cake_pick_idle_clean` do (§G96 extension, inert here) | these two only; claim_free 180 → 190 insns, spill/fill 4/3 → 3/3; offer_remote 234 → 247, 5/4 → 4/3 |
| next commit | the static assert compares the TACI / TACIW block lengths; two comments | object identical |

Attach checks, 2026-09-23 night, host busy with unrelated work (40.7–80.4 % busy):
- `cakebench try` HEAD `57cd21c70`: verifier accepted, 0 stalls, native restored.
- probe=1 `-v`, one appsim run: black-box records in slots 0–3, none zero; events row
  `select_fallback 317380 keep_last 90 enq_skip_exiting 1166` (was always `0 0 0`).
- bpfstats, appsim helldivers2-mission-fitted 45 s, ABBA then BAAB 60 s apart, base
  `3154a112e` (`e8db9764`) vs tip `57cd21c70` (`e50d6e50`); data
  `scx_cake_bench/runs/openfix_rot_20260923/`. Raw means favour the tip (dispatch −47 %),
  but the base slots drew the busy bursts (mean busy 65.5 vs 50.3 %); dispatch ns/run
  tracks busy (5.10 ns per point, R² 0.77). Busy-adjusted, every callback is level
  (dispatch −1.5 ± 40.5, cpu_release −4.6 ± 12.2 ns); at matched busy dispatch is
  110.8 / 107.3 and 79.2 / 77.5 ns. Kept. On one LLC `cake_offer_remote` is not reached.
- `select_fallback` is not a cake fault: it equals `probe_fired` (317,683) within 0.1 %.
  The neighbour preempt inserts LOCAL_ON to a CPU other than the one select_cpu returned
  (place.bpf.h:485-493); the kernel counts any enqueue off `selected_cpu` as a fallback
  (ext.c:2183-2185). 3.9 % of wakes pay a deferred remote move.

Open:
- `cake_prefer_irq_clean` merges the deep word into the IRQ-hot set: when every candidate
  is deep, the fallback is the whole set and IRQ-hot avoidance is lost, in all four
  pickers. A tiered preference (clean, then not IRQ-hot, then all) is a design choice;
  unmeasured, needs a cpuidle host.
- On a cpuidle host each pool kick now reads `cake_deep_idle_word`, written on every
  deep-idle entry and exit: a likely shared-line miss. Capture owed with §G96.
- No offline policy assertion remains. The deleted harnesses covered `cake_cross_llc`
  wide pairs, the `cake_offer_remote` slot and kick, frontier spans, seat retirement
  races, select_cpu parity with probe on and off, retake exclusions, dispatch_search seat
  cases, `cake_slice_from_service` and the `cake_stage` bound. Elsewhere: the SMT fold
  formula (`layout.rs`, a Rust copy), liveness under affinity churn (CI stress-ng),
  verifier load shapes (`verifier_load_topologies`, `#[ignore]`, manual with BPF caps).
  Rewrite `cake_slice_from_service` and `cake_cross_llc` first, when either changes.
- Stale docs, not from these commits: README.md toggles g85–g89 and llcsplit;
  docs/TOOLING.md "build a PROBE commit" and `--toggle llcsplit=1`.

**2026-09-23 (later) — READABILITY REFACTOR (no scheduling-policy change).** The BPF
source is one translation unit in 12 files, the loader 12 files; every no-change commit
is proven with `bench/objdiff.py` (instructions per function and data layout against the
parent). Base `2a27111df`, tip `0aae3f409`.

| commit | what | proof |
|---|---|---|
| `c45dea62d` | named probe constants, dead `intf.h` constants gone, stale comments | object identical |
| `17cc22855` | 20 helpers for repeated idioms; a site where a helper changed the object kept its open form | object identical |
| `c06be39b2` | `cake.bpf.c` → 11 headers (abi, stats, kfunc, topo, state, task, vtime, seat, probe, place, dispatch); global definitions keep their order | identical except `cake_init`'s error-string line numbers and `.maps` order |
| `6333ed9d4` | one-line kernel-style comments: 703 → 213 comment-only lines (0.28 → 0.09 per code line) | object identical; `try` OK |
| `47804a4ae` | `comment_lint` ceiling 0.20, linear count, trailing comment counts as code | — |
| `5327a1f3f`, `e1333b5ba`, `34ce3abd2` | loader: `main.rs` 2233 → 633 lines; modules cli, host, layout, irq_sinks, privileges, rodata (fills), diag (exit reports); helpers and named numbers | loaded `.rodata` byte-identical except `cake_wake_hop_ns` (live probe p99); startup and probe exit rows identical in shape; same tests |
| `8b3f0dfb5` … `92b90e3d0` | measured phase: `cake_nvcsw`, `cake_vtime_floor` at enqueue and pinned wake, `cake_local_dsq` at the kthread insert, `cake_pool_served` in dispatch (identical), `cake_claim_cold` in `cake_offer_remote` | enqueue 651 → 640 insns, admit_direct / wake_admit / handoff_yields −2 each, pinned −1; stack ops 417 → 398 |
| `125604cd8` | the 2026-09-22 review fixes below, restored | object identical |
| `b36edecd1` | loader: IRQ self-check names CPUs (was `slot{i/2}.{i%2}`); sibling map cached at attach | — |

Measured phase, appsim helldivers2-mission-fitted, ABBA 45 s slots, `cake-bpfstats`
deltas, base `34ce3abd2` (binary `ebf63263`) vs tip `92b90e3d0` (binary `35119da4`), all
slots attached and restored; data `scx_cake_bench/runs/refactor_phaseB_20260923/`:

| arm | select_cpu | enqueue | dispatch | running | stopping | appsim p99 ms |
|---|---:|---:|---:|---:|---:|---:|
| base | 125.1 | 158.4 | 210.3 | 54.7 | 33.0 | 1.62 / 2.08 |
| tip | 115.7 | 137.2 | 183.3 | 50.1 | 30.3 | 1.24 / 1.18 |

Level or better on every callback, so all five stay. The size is not the change:
untouched callbacks (running, stopping, cpu_release) moved 6–8 %, the base slots ran
first and last, and no noise covariate was recorded. Treat it as "no regression" only.

Open, carried:
- The three decision chains `cake_select_cpu`, `cake_enqueue` and `cake_dispatch_search`
  (108–112 code lines each) keep their structure: splitting them moves register
  allocation in the hottest code. A measured restructure is the next readability step.

**2026-09-22 — COMPATIBILITY AND LOADER DIAGNOSTICS (no scheduling-policy change).**

| commit | what | receipt |
|---|---|---|
| `256a69e0e` | `p->on_cpu` read through CO-RE on both layouts (u8 and int flavors); an unknown layout keeps the idle kick | — |
| `879ed9c38` | pre-6.18 kernels: `cake_wake_place` reads the untrusted `rq->curr` fallback itself; the caller passes NULL across the `__arg_trusted` boundary. One extra `cake_cpu_curr` per pool-bound wake on those kernels only | — |
| `9db04489e` | one unsigned `u32` CO-RE `on_cpu` flavor (libbpf narrows an unsigned load to u8; a signed local field refuses the resize); `cake_ops` auto-attach off; startup rows aligned, detail behind `--verbose`; running-binary SHA-256 at startup and in `--version`; compat choices reported from `.bss` after attach | — |
| `125604cd8` | review fixes: enqueue `alone` indentation; the idle log prints the exit cost in use and says it is off above 64 CPUs | release clippy 0 scx_cake warnings, fmt |

None of these is measured; none changes a decision on a ≥6.18 kernel with a u8 `on_cpu`.
