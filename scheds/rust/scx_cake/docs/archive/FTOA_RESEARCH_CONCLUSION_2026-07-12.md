# FTOA research conclusion

Date: 2026-07-12

Status: FTOA broad admission is parked; qmark-prefiltered exact admission is a
protected finding requiring a narrower signal gate. No production Cake policy
is changed by this document.

## Evidence surface

The full canonical refresh after the FTOA campaigns contains:

- 29,003 accepted normalized metric rows;
- 11,096 run IDs;
- 4,706 grouped attempts;
- 2,520 trusted, 4,087 provisional, 4,970 tainted, and 17,426 unknown rows;
- 1,189 full-source and 4,275 partial-source snapshots;
- no measured concurrent blends.

The FTOA research chain contributed 497 controlled arms across the reason
surface, corrected post-redirect observers, broad active gate, qmark recall,
qmark-active latency, and mixed cache/memory guardrails. All final campaigns
completed with zero unresolved failures and restored native EEVDF after every
arm.

## What the corrected telemetry proves

The active decision is not a general queue-depth problem:

- ambient would-direct ordered conflicts were effectively absent
  (0% pipe, 0.00059% schbench, 0.01186% futex);
- under wake pressure, ordered conflicts were consistently rare:
  0.83887% pipe, 0.87233% schbench, and 0.93004% futex;
- every observed would-direct conflict had custom-vtime DSQ depth exactly one;
  no depth-two-or-greater event occurred across roughly 37.7 million
  wake-pressure Golden direct decisions.

Therefore a depth threshold cannot solve the tradeoff. `depth > 1` disables the
mechanism, while `depth > 0` pays an exact DSQ lookup on every direct decision
to change fewer than one percent of pressure decisions and essentially none of
the ambient decisions.

The existing padded per-CPU qmark is a useful positive prefilter:

- it was set on only 1.95-2.29% of Golden direct decisions;
- ordered-conflict recall was 98.94-99.46%;
- precision was only 38.30-41.76%.

This supports `qmark && exact_depth`, but rejects qmark-only admission.

## Active outcomes

### Broad exact-depth gate

The broad F1 gate was not promotion-grade. It showed diagnostic wake-pressure
wins, but ambient pipe repeated losses and most large results failed Cake A/A,
native, or semantic-neutral controls. The corrected observer explains the
ambient loss as unconditional helper cost rather than useful policy action.

### Qmark plus exact confirmation

Candidate identity:

- binary SHA-256: `8f8c44c85df573d2...`;
- linked BPF SHA-256: `6ca0fe515a738b74...`;
- `cake_select_cpu`: 94 instructions versus 82 baseline;
- source base: `555c387a9a9fb96fb87563cb4623455386e4529a`;
- lineage champion: `champion_mdbls_golden_20260711`.

The strongest controlled result was the second pipe wake-pressure repeat:
qmark+exact `+4.60%`, while qmark-only was `-9.40%`, with usable Cake/native
brackets and a valid neutral control. The same repeat gave ambient pipe
`+0.80%`. This is a real protected finding: exact confirmation matters, and the
prefilter repairs most of the broad helper gate's ambient cost.

It is not a universal winner:

- thread direction changed across repeats and frequently had invalid neutral
  or noisy native controls;
- the mixed guardrail raised cache throughput about 6.1% but reduced memcpy
  throughput about 5.5% versus the Cake A/B midpoint;
- the full corpus records the exact-confirmed variant as mixed with a worst
  observed regression of roughly 7.94%;
- no blend, full official suite, or game ABBA has cleared.

Qmark-only is rejected. Its approximately 40% precision converts too many
false-positive marks into direct-dispatch rejection, including repeatable
severe pipe losses.

## Micro-level conclusion

The useful law is not "preserve order whenever a queue exists." It is:

```text
Only consider paying for ordered admission in a high-value handoff class.
Use qmark only to avoid the cold exact lookup.
Always confirm custom-vtime debt before changing the direct decision.
```

The next falsifiable representation is a WAKE_SYNC partition:

```text
if kernel_idle and WAKE_SYNC and qmark(final_cpu):
    if exact_custom_vtime_depth(final_cpu) > 0:
        queue normally through enqueue
otherwise:
    direct dispatch exactly as Golden
```

The opposed control should apply the same qmark-plus-exact rule only to
non-WAKE_SYNC wakes. This partitions signal class without process identity,
new state, clocks, scans, or task storage. It should preserve the measured pipe
benefit while compiling the qmark load and DSQ helper out of schbench, futex,
and memory-streaming wake paths when those wakes lack WAKE_SYNC.

Rollback is exact Golden direct dispatch. The partition must first clear pipe,
thread, schbench, futex, and both cache/memcpy fields with native A/B, Cake A/A,
and semantic-neutral controls. Only then should blends, the full suite, and game
ABBA begin.

## Platform lessons

- Observer counters and active code must share the exact predicate and event
  population. The v3 combined-queue counter and v4 all-evaluation histogram are
  retained in separate compatibility groups and cannot select policy.
- Benchmark deltas from 340-instruction observer builds measure instrumentation
  overhead, not candidate behavior.
- The corpus currently reports build/verifier and hot-path proof as missing even
  though campaign manifests contain activation, restoration, object hashes, and
  instruction audits. Propagating those proofs into `proof_packets.jsonl` is
  platform debt, not evidence that activation failed.
- Full-source provenance improved to 1,189 rows, but only 14.7% of the full
  corpus is reconstructable. Promotion decisions must stay on recent
  source-complete campaigns.
