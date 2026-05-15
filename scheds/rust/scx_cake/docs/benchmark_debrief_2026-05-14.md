# scx_cake Benchmark Debrief - 2026-05-14 20:00 America/Chicago

This note captures the end-of-day checkpoint for the May 14, 2026 `scx_cake`
benchmark/mutation session. The goal remains unchanged: make `scx_cake` win each
tracked benchmark category with the highest native score and best wall-clock
behavior, using the benchmark history as the source of truth for what to keep,
mutate, or reject.

## Checkpoint

Branch:

```text
RitzDaCat/scx_cake-nightly
```

Pushed commits:

```text
6f7cc202a scx_cake checkpoint benchmark-guided cache memcpy gains
f0e5d9db7 scx_cake default release benchmark flags
```

The coherent keeper from the session was the v35 shape:

- 1 ms gaming quantum
- `queue-policy=local`
- `storm-guard=shield`
- `busy-wake-kick=policy`
- cache-simple dispatch lane
- memcpy direct-idle admission
- 15/16 memcpy vtime charge

The release defaults were changed to match the tuple that produced the strongest
scores. A no-env release build should now bake:

```text
BAKED_PROFILE = "gaming"
BAKED_QUANTUM_US = 1000
BAKED_QUEUE_POLICY = "local"
BAKED_STORM_GUARD = "shield"
BAKED_BUSY_WAKE_KICK = "policy"
BAKED_LEARNED_LOCALITY = "off"
BAKED_WAKE_CHAIN_LOCALITY = "off"
```

This matters because `cakebench` had already been scoring
`local/shield/policy`, while raw release builds still drifted back to older
defaults. That drift is now closed.

## Score Movement

These are the session-level deltas that justified the checkpoint.

| Workload / metric | Baseline | v35 checkpoint | Delta |
| --- | ---: | ---: | ---: |
| cache-only bogo ops/s | 6,188,328.72 | 7,929,175.46 | +28.1% |
| memcpy-only bogo ops/s | 5,575.34 | 6,224.35 | +11.6% |
| combined dual score | 0.4544449204 | 0.7097588406 | +56.2% |
| combined memcpy bogo ops/s | 2,662.87 | 4,158.91 | +56.2% |
| combined cache bogo ops/s | 4,324,017.61 | 4,316,088.33 | roughly flat |

The combined dual score now leads the local history over the recent P2DQ
reference score of `0.7052209959`, but the wider goal is still to win all
tracked categories, not only this local checkpoint.

## Rejected Variants

Two later variants were worse than v35 and should not be resumed blindly:

- v36: stronger `7/8` memcpy vtime charge discount. Memcpy-only fell to
  `6,180.16`, worse than v35.
- v37: 1.5 ms slice / 1 ms charge split. Memcpy-only fell to `6,098.33`, worse
  than v35.

The learning is that more aggressive stream preference does not automatically
improve the target. The useful point is a balance between cache retention and
memcpy service, not maximum bias toward either side.

## Noise Lesson

Benchmark noise was a real signal problem today. Background work such as music,
browser activity, local AI, or services can move the score enough to confuse
mutation decisions.

For future runs:

- Treat the noise sampler output as benchmark metadata, not optional trivia.
- Compare only runs with similar background-noise conditions unless explicitly
  studying noise impact.
- If a run looks surprisingly bad or surprisingly good, check the noise files
  before changing scheduler code.
- Prefer clean reruns for promotion decisions.

## What We Learned

The session moved Cake out of pure knob-tuning territory. The major improvement
came from a coherent scheduling shape: local cache retention plus memcpy-aware
service. Small one-line changes and stronger stream discounts were not enough
once that shape plateaued.

The strongest isolated scores show Cake is in the right performance region for
cache-only and memcpy-only work. The hard remaining problem is coexistence:
keeping the cache-only strength and memcpy-only strength alive at the same time
inside `stress-ng-cpu-cache-mem`.

That points to policy/subsystem work rather than another flag sweep.

## Next Pickup

Start from `f0e5d9db7`.

Before modifying scheduler code, refresh the local scoreboard:

```bash
./cakebench scores --include-singles
```

For the next mutation, keep the benchmark command shape simple and fish-safe:

```fish
begin
    set -l args score <mutation-id> --kind system
    set -a args "<hypothesis>"
    ./cakebench $args
end
```

Focus the next research lane on combined-workload coexistence:

- How does Cake preserve cache residency without starving memcpy workers?
- How does Cake give memcpy enough dispatch service without collapsing cache
  bogo ops/s?
- Can the scheduler detect mixed cache/mem pressure with fewer branches and
  less shared-state churn?
- Can dispatch service be allocated from a stable local/per-CPU signal instead
  of extra knobs?

Good next evidence:

- cache-only debug diagnostic run
- memcpy-only debug diagnostic run
- combined debug diagnostic run
- release score run under clean-noise conditions
- noise sampler comparison for accepted/rejected runs
- instruction/helper/branch/spill comparison if the next change touches a hot
  path

Avoid repeating rejected patterns:

- Do not keep increasing memcpy discount without checking cache damage.
- Do not promote a mutation from one noisy run.
- Do not rely on CLI defaults or old docs; verify generated `BAKED_*` constants
  for release behavior.
