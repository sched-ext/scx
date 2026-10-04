# Exact reciprocal quotient experiment — registered 2026-09-30

Question: does a complete normalized reciprocal quotient reduce Cake's division
cost while preserving every unsigned quotient and scheduling decision?

The user requested implementation and will perform the live scheduler test.
OS noise excludes performance acceptance during this implementation session.
Default policy remains on native division; `--division-free` selects the candidate.

Steps (budget: six): preserve baseline; implement normalized reciprocal and exact
remainder correction; prove/test full-u64 arithmetic and slice equivalence;
integrate normal build/CLI; provide native CLZ/MULHI kernel extension; validate
builds and document exact manual test commands and outstanding live gates.

The reciprocal follows Algorithm 2 of Möller and Granlund, *Improved division by
invariant integers*: https://gmplib.org/~tege/division-paper.pdf. Quotient recovery
specializes the reciprocal to a single-word numerator, with one remainder
correction. The candidate contains no dynamic division, floating point, or
per-task reciprocal cache. CLZ/MULHI have portable software implementations;
the installed CTZ/POPCNT patch does not yet expose their native kfuncs.

Invariants: exact unsigned floor division for every nonzero u64 divisor; explicit
BPF zero-divisor result 0; bounded table index and shifts; no new scheduling
policy, task storage, clocks, atomics, or hot-path telemetry; opt-in only.
Stop/repair on arithmetic mismatch, undefined behavior, verifier rejection,
native/fallback mismatch, or build failure. Native instruction counts are
attribution; only clean matched complete-expression timings can establish a win.
