# Kernel-patch proposals: what OUR OWN sched_ext patch would buy

2026-08-25. Companion to `RESEARCH_KERNEL_PATCH_SWEEP_2026-08-25.md` (upstream
sweep). Premise: CachyOS rebuilds its kernel anyway, so carrying patches is
realistic — but the portability invariant stands: **every patch benefit must be
probe-gated** (`__COMPAT` kfunc existence check at attach) so one binary still
runs everywhere and degrades to the current path on stock kernels.

## Cost anchors (measured)

- select_cpu 80 ns/call @ ~150k/s ≈ 12k us/s; BPF-side floor 65–70 ns;
  trampoline 15–20 ns structural (unpatchable).
- The 8k us/s line is 2–3k us/s out of reach in pure BPF.
- Wake path today = 3–4 kernel crossings per wake:
  `select_cpu_and` → `test_and_clear_cpu_idle` (:1369) → insert(_vtime) →
  `kick_cpu` (7 sites total).
- `cake_cpu_curr` deref chains survive at :544/:788/:887/:1512/:1673
  (sibling/cross-CPU cold possible).
- `dsq_nr_queued` ×4 (:115/:439/:1554 + WAKE_DSQ), rhashtable/rq-lock backed.

## Ranked proposals

| # | patch | mechanism | est. saving | certainty |
|---|---|---|---|---|
| P1 | **Fused place op**: one kfunc doing accept-cpu + atomic idle claim + LOCAL_ON enqueue + conditional kick. Kernel side touches rq directly — the whole ladder becomes warm native reads | collapses 3–4 crossings to 1; kills the select→claim race window | ~20–35 ns/wake on claimed path; closes most of 80→65 gap; THE path to the 8k line | high — mechanics all exist in-kernel today |
| P2 | **DSQ emptiness push**: bump a per-DSQ word on last-dequeue / first-enqueue transitions; BPF reads one word instead of nr_queued queries | event-complete (§ law), deletes 4 query sites' worst case (rq lock) | M-class at dispatch peek sites; unmeasured until built | medium-high |
| P3 | **Lazy kick**: `SCX_KICK_LAZY` flag ORs into a pending mask flushed by the next resched IPI to that CPU | herd wakes (many-to-many TaskGraph) re-kick the same CPU within µs | regime-dependent; needs a census FIRST (kicks-per-target-CPU histogram) | low until censused |
| P4 | **Packed occupant read (K3)**: one kfunc returns {pid-tag, vtime, burst} from rq->curr, no task_struct walk | replaces cold cross-CPU deref chains at 5 sites | LOW — M6 mirror went null post-mailbox; only core_contended's sibling path still pays | low-medium |
| P5 | **ops fast entry** (static-call/select_cpu prologue trim) | shaves part of the 15–20 ns trampoline tax | ≤10 ns, deep bpf-core surgery, upstream-hostile | low |

## What NOT to patch

insert (~10 ns, load-bearing §G55 — skipping it explodes enqueue+dispatch),
DSQ peek/move_to_local (floor — actual scheduler work), accounting path
(already below PELT), PI wakeups (upstream Righi v12 lands it in 7.3 — §G56,
don't duplicate).

## Order

P1 is the only patch with headroom worth its cost. Pre-work BEFORE writing it:
census the mailbox-miss path (25% of wakes fall to the full ladder today) —
if hit-rate work (multi-park, G53-chain fallback) shrinks the miss share
first, P1's payoff concentrates on exactly the wakes that remain, and the
design target may move. Register as §G57 after the census numbers exist.

P2 second: small, self-contained, aligns with the house law; can ride any
kernel-rebuild cycle independently.
