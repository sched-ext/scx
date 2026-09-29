# Pool serving, frame jitter, and aim feel — 2026-09-28

C showed a small measured average-frame/throughput improvement in KovaaK's,
with mixed unfiltered frame tails and higher mean adjacent-frame jitter.
Small nanosecond gains count as useful positive results; magnitude alone is
not grounds to dismiss them. Repeatability, perceptibility, and an aim-feel
improvement remain unestablished. The tested C policy is published to nightly
for wider testing; this does not establish a universal performance win.

## What was tested

- A: `f53aabda92c8bf79e50b1ec544b193e733744776`, the pool-tag residue fix on
  nightly `99377e26ffb49dc446eab97f775d40b3bacc86fa`.
- Historical B: `c6adabf395a557d9b343af9fa877c1e6e75a6311`, claim pool work
  before moving it and return the claim if the move fails. Not a game arm here.
- C: `f3ae91cf2cf075a5a1b819a416171bcae589f314`, B plus early own-queue mark
  clearing and a pool-aware continuation-kick guard. C occupies the B position
  in the ABBA order; the historical B experiment is a different identity.
- Two ABBA blocks, eight nominal 60-second captures, 525,783 frames over
  477.138 seconds. All frames and captures remain in the primary analysis.
- KovaaK's Correction Accuracy – Close I freeplay, animated target, idle
  player, no shooting or synthesized input during capture. Intended camera
  consistency was imperfect: retained screenshots show perspective changes.
- All eight source/activation identities and normal scheduler stops verified;
  native scheduling restored after testing. Native was not a comparison arm.
- The tested host ran kernel `7.2.7-1-cachyos`. This does not establish results
  for Helldivers, active aiming, other hardware, or heavy background workloads.

The nightly source carries these changes in the default policy. A normal
`cargo build --locked --release -p scx_cake` includes them; no special Cargo
feature, profile selection, or `--toggle` is needed at runtime. Users must
rebuild/update from the new nightly source; an older installed release does
not acquire the changes. Existing scheduler launch permissions still apply.

## Measured result, all captures

Arithmetic means of four full-capture slot metrics per arm. Time values below
are rounded to nanoseconds; C minus A is negative for shorter times. These are
descriptive estimates, not significance claims.

| Metric | A | C | C minus A |
|---|---:|---:|---:|
| Average FPS | 1100.612 | 1103.364 | +2.752 (+0.250%) |
| Average frame time, ns | 908,591 | 906,339 | -2,252 |
| p95 frame time, ns | 973,646 | 973,787 | +141 |
| p99 frame time, ns | 1,087,642 | 1,088,487 | +845 |
| p99.9 frame time, ns | 2,045,975 | 2,044,366 | -1,609 |
| Frame-time standard deviation, ns | 97,418 | 97,759 | +341 |
| Mean adjacent-frame jitter, ns | 54,396 | 55,008 | +612 |
| p95 adjacent-frame jitter, ns | 119,716 | 120,915 | +1,198 |

The primary predeclared metric was p99 frame time. It improved 0.544% in
block 1 and worsened 0.701% in block 2; aggregate +0.078% is close to zero.
FPS changed +0.542% then -0.041%; mean jitter changed +1.498% then +0.755%.
The screen did not demonstrate a repeatable tail-latency improvement.
Worst individual frames were A 3,033,500 ns and C 3,465,490 ns; those differ
from the mean of slot maxima, which is reported separately in the raw review.

## Noise and exclusion sensitivities

These analyses were requested after capture. They preserve the original
measurements and do not replace the complete-block result.

| Analysis | FPS change | Mean frame C-A, ns | p99 C-A, ns | Mean jitter C-A, ns | p95 jitter C-A, ns |
|---|---:|---:|---:|---:|---:|
| All eight captures | +0.250% | -2,252 | +845 | +612 | +1,198 |
| Exploratory noise model | +0.482% | -4,353 | -4,716 | +398 | -867 |
| Worst maximum-frame capture excluded per arm | +0.647% | -5,850 | -7,406 | +777 | -1,277 |

The noise model fits slot metric against arm, block, and estimated external
CPU load. External CPU is host busy minus the main game process; it includes
helper/kernel work and may include effects of the scheduler itself. With eight
slots, four residual degrees of freedom, and leverage 0.988 for the noisiest
C slot, this is not a calibrated causal correction. Its ordinary OLS interval
for mean-frame change is -9,182 to +475 ns, including zero/slight worsening.

The symmetric exclusion removes A block 2/slot 4 and C block 2/slot 2 by each
arm's largest maximum frame. It retains 394,643 frames and three captures per
arm, without a further noise correction. It breaks complete ABBA balance and
removes A's fastest average-FPS capture. Excluding the lowest-average-FPS
capture per arm instead yields +0.428% FPS, also a post-hoc sensitivity.

C's worst frame and the next two largest in that capture approximately align
with a five-second interval at 10.039% estimated external CPU, versus ordinary
approximately 3.6–3.8%. That supports a noise-associated outlier, not proof that
noise alone caused it. Timestamp precision and telemetry interval width limit
the association; the original extreme remains in the primary analysis.

## Jitter, rendering, and mouse input

The harness defines mean jitter as `mean(abs(ft[i] - ft[i-1]))`, calculated
within each capture. CSV frame times are milliseconds; multiply by 1,000,000
for nanoseconds. This is an absolute time, not a ratio, frame-time standard
deviation, scheduler wake jitter, or input-to-display latency variation.

A separate descriptive ratio, mean jitter divided by mean frame time, is
5.9868% for A and 6.0692% for C, using the arm-level slot means. The reported
+1.125% jitter change uses baseline jitter as its denominator; the +0.250%
FPS change uses baseline FPS. Those percentages cannot be subtracted to form
an overall score. Jitter is derived from the recorded frames, not an extra
612 ns to add to frame time. Frames can improve unevenly, giving a lower mean
frame time while adjacent differences increase.

Aim feel depends on how quickly and consistently mouse movement becomes
visible. Input sampling, scheduling, simulation, rendering/queueing, and
display timing all contribute. These captures measured frame durations;
they did not measure mouse-sample age, render-queue residence, displayed-frame
timing, end-to-end render latency, or mouse-to-display latency. Neither a
perceptible difference nor perceptual equivalence has been demonstrated.
The small throughput benefit remains useful evidence; the aim-feel verdict
requires actual aiming and end-to-end latency measurements.

## Design hypotheses and the next experiment

C's early mark clear can add a clear/set pair of atomic writes on the shared
CPU queue bitmap during dispatch and re-enqueue. It also changes continuation
kick decisions: a cleared mark can suppress an idle-CPU kick when no pool
work is pending. Variable atomic costs and changed service timing are plausible
explanations for the jitter difference, not established causes. The older
early-clear-only experiment reduced Cake CPU use but worsened frame tails;
C's pool guard changes that design, so the old result is context, not proof.

The smallest proposed follow-up is **D = C without the eager own-queue mark
clear**, retaining claim-before-move and the pool-aware kick guard. D is B
plus the guard, not historical B. It could reduce atomic churn and restore
useful continuation kicks, at the possible cost of more empty-queue probes.
D has not been implemented or tested and is not part of this nightly update.

Compare frozen C/D builds in balanced repeated blocks, preserving all frames.
Predeclare jitter endpoints and noninferiority margins for average frame time,
FPS, p99/p99.9, wake-to-run, and relevant background throughput. Use separate
diagnostic runs for queue-mark writes, kicks, failed steals, and wake timing;
instrumentation must not silently change scored captures. For aim feel, add
actual mouse input and input-to-display latency distributions. If D improves
jitter but loses throughput, consider separating the steal hint from kick
history with owner-local state, with explicit lifecycle/reset validation.

## Publication checks

The published BPF source matches the game-tested C source byte for byte;
other changes document the findings and current CLI. Release/debug compilation,
package formatting, 32 unit tests and three CLI integration tests passed.
The privileged verifier/topology test remains ignored in the ordinary test
run. Package-only Clippy (`--all-targets --no-deps -- -D warnings`) passed;
the dependency-inclusive invocation stops at the existing `type_complexity`
lint in `rust/scx_stats/src/server.rs:71`. Cargo also reports the pre-existing
unused `lib.include` manifest key in `scx_rustland_core`.

The release binary's `--help` and `--version` were checked without activation.
The only accepted toggle is `probe`, off by default. The old policy-toggle
names in the README were corrected. `--handoff-ns` is an experimental threshold
override and is not needed to obtain this default policy. These build/CLI
checks do not constitute a new game run or broader topology validation.

## Retained evidence

Full local campaign: `scx_cake_bench/runs/kovaaks_kick_abba_20260928T195312/`
in the sibling benchmark repository. This report is self-contained for nightly
readers; local raw captures and receipts are not bundled into the source push.

- `PROTOCOL.md`, `artifact_preparation.json`: original protocol and exact A/C
  source, executable, linked BPF, toolchain, and activation-target receipts.
- `REVIEW.md`, `analysis.json`, `analyze.py`: full result and reproducer.
- `noise_by_block.json`, `noise_adjustment.json`, `noise_adjustment.py`,
  `NOISE_ADJUSTED.md`: noise telemetry, model, influence checks, and limitations.
- `TRIMMED_SENSITIVITY.md`, `trimmed_worst_capture_sensitivity.json`: exclusion
  criteria, retained subset, alternate criterion, and extreme-frame timing.
- Per-block manifests/reports, activation/stop receipts, focus telemetry, and
  scene captures remain retained. Block 2's initial import collision was
  recovered into a separate output directory without rerunning captures.
