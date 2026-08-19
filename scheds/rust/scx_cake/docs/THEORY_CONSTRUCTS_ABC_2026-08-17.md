# Constructs A/B/C — theory notes, 2026-08-17

Companion to `RESEARCH_NEW_CONSTRUCTS_2026-08-17.md`. This file holds the theory;
registrations live in `STATE.md `§` registry` §G27–§G29.

## The clock measures the engine, not the monitor

The maintainer's input that reshaped all three constructs: games run 30–2000 fps
(Kovaaks does ~1300 at 1080p), some use vsync, some VRR. Resolution:

- **Uncapped:** the engine free-runs far past the panel. Thread cadence = engine
  rate. The old 25–500 Hz band threw these votes away — at 1300 fps (769 µs
  period) cake's frame clock was blind and the geometry ran on stale defaults.
- **Vsync:** engine locked to the panel (or a divisor of it when it misses —
  the Diablo 30 Hz tick). Thread cadence = display rate. In-band either way.
- **VRR:** the panel follows the engine inside its range. Cadence = engine rate
  again, and the panel agrees with it.

In all three modes the thread cadence is the ENGINE's rhythm, and that is the
right input for everything cake consumes: the slice cap asks how often the
pipeline needs the CPU back; the patience windows ask what fraction of a
pipeline turn a wait is; construct B asks when the next wake actually arrives.
The DISPLAY deadline is a different quantity and enters through §G26's Vulkan
layer (real present timing), not through this clock. So the band is now
25–2000 Hz and the comment says engine cadence, not display refresh.

**Bucket math after the widening:** buckets stay 131 µs wide (shift 17),
512 entries; the band occupies indexes 3–305. At the fast end, 2000 / 1500 /
1300 / 1000 fps land in distinct buckets (3, 4, 5, 7). The vote is a lifetime
average (task age ÷ voluntary sleeps), heavily smoothed, so same-cadence votes
co-land instead of smearing. If real captures show high-fps modes blurring
across buckets, the fallback is log-width buckets at 1024 entries — registered
as a Phase-2 option, not built.

**The bootstrap trap the widening exposed:** the floor used to boot at the band
minimum (2 ms). With the band min now 500 µs, keeping that coupling would have
given every vote-free host (desktops, every benchmark) a permanent 250 µs slice
cap — a silent quarter-slice regime change. The floor now boots from its own
constant, `FRAME_FLOOR_BOOT_NS = 2 ms`, and only real votes move it.

**Vote pollution:** kHz worker herds (futex benches churn near 1 kHz) are now
in-band and could fake a "1000 fps game". Defenses already present: the argmax
takes a mode, the incumbent needs a 2× displacement, and benches were already
in-band at 2–10 ms cadences. The sealed A/A is the tripwire. If the census ever
shows worker cadences winning the argmax, the registered fix is a vote gate:
only tasks that sleep most of their cycle vote (`burst < period/2`) — display
stages sleep between frames, saturated workers do not.

## Construct A — the anchor equation

```
cake_frame_slice_ns = min(3/4 × frame_floor, SLICE_NS)
```

- **Why ¾:** at the 240 Hz tuning point (frame 4.16 ms) the current geometry is
  3 ms ≈ 0.72 × frame. ¾ reproduces today's behavior within 4% exactly where
  the G17/G21 wins were measured, then scales where they were not.
- **Why min():** phase 1 is tighten-only. Low-fps regimes (30–60) keep today's
  3 ms geometry; letting patience GROW to 25 ms at 30 fps is a separate dose
  question with its own risks (a sleeper catch-up window that long needs its
  own bound). A bound only moves in its safe direction without evidence — same
  rule the frame floor already follows.
- **Why benches cannot move:** no votes → the word stays at its bootstrap,
  which is SLICE_NS — the old constants reproduced exactly. The sealed A/A is
  expected null BY CONSTRUCTION, and any drift there means vote pollution, not
  geometry.
- **Easy-scene prediction (the endpoint):** 276 fps average → floor ≈ 3.6 ms →
  geometry unit ≈ 2.7 ms, ~10% tighter than today. Mechanism: a woken sleeper
  is granted less catch-up credit inside a fast frame, so the tail cost of
  serving it lands smaller. If the loss instead comes from somewhere else
  entirely, the null is itself the prune: it removes "geometry mis-scale" from
  gap 1's mechanism space.
- **Kovaaks:** 769 µs period → unit 577 µs. Patience becomes proportional to
  the pipeline for the first time; previously a 1300 fps game got the same 3 ms
  windows as a 60 fps one.

What changed on disk: band 25–2000 Hz, floor boot decoupled, one new BSS word
published per poll, 8 geometry sites converted from `SLICE_NS` constants to
shifts of the word. Slice GRANTS are untouched — `cake_task_slice` was already
frame-capped, and the kthread flat grant stays a grant question.

## Construct B — when pre-paying works

C-state depth grows with gap length: the idle governor goes deep when the
predicted idle is roughly ≥ 1–2 ms. That places B's value exactly where A
tightens nothing — low fps and vsync regimes with long, regular inter-frame
gaps. So the timer arms only when the frame period ≥ 2 ms (≤ 500 fps). At
1300 fps the gaps are too short for deep C-states and the timer stays off; no
overhead in the regime that cannot benefit.

Vsync is the sweet spot: a locked cadence gives the best prediction accuracy.
VRR wobbles with the engine, so the lead has to cover the wobble — the lead is
taken against the pessimistic floor, and a missed prediction costs one wasted
kick, bounded at one per frame (~0.04% of a core at 240 Hz, less at the low
rates where it actually arms).

## Construct C — the bit budget

2 bits in `dsq_vtime`'s low end are worth ≤ 4 ns (bit 2 is 4 ns; the pattern
value is ≤ 7 ns with 3 bits). The smallest geometry quantity anywhere in the
scheduler is the young-occupant window, unit >> 5 — about 18 µs even at
Kovaaks-tight geometry. Margin ≈ 4500×. The one real hazard is arithmetic, not
comparison: `stopping` does `dsq_vtime += scaled(used)`, and addition destroys
low bits — so the class is re-stamped after the +=, by the same owner, in the
same store. Readers get the class anywhere they already read vtime; the steal
ring and SMT placement pay zero extra loads.

## How the three compose

A sizes the patience window from the engine's rhythm; B warms the CPU before
the window opens; C decides which neighbour shares the core while it is warm.
Three independent inputs, three separable A/Bs, no shared state beyond words
that already exist.

## Scaling audit — 2026-08-17, maintainer-requested

All values µs. `geom = min(¾ × floor, 3000)`. Derived: sleeper lag and preempt
margin = geom/2, hysteresis = geom, young window = geom/32, slice cap =
floor/2, wake protect = frame/16, probe protect = frame/4.

| fps | frame | geom | lag | hyst | young | slice cap | protect | zone |
|---|---|---|---|---|---|---|---|---|
| 30 | 33333 | 3000 | 1500 | 3000 | 94 | 16667 | 2083 | inert |
| 60 | 16667 | 3000 | 1500 | 3000 | 94 | 8333 | 1042 | inert |
| 120 | 8333 | 3000 | 1500 | 3000 | 94 | 4167 | 521 | inert |
| 240 | 4167 | 3000 | 1500 | 3000 | 94 | 2083 | 260 | inert (¾×4167=3125, min caps it) |
| 360 | 2778 | 2083 | 1042 | 2083 | 65 | 1389 | 174 | active |
| 480 | 2083 | 1562 | 781 | 1562 | 49 | 1042 | 130 | active |
| 600 | 1667 | 1250 | 625 | 1250 | 39 | 833 | 104 | active |
| 1000 | 1000 | 750 | 375 | 750 | 23 | 500 | 62 | active |
| 1500 | 667 | 500 | 250 | 500 | 16 | 333 | 42 | active |

**The activation threshold is 250 fps** (¾ × 4000 µs = 3000): at or below it the
min() holds geometry at today's 3 ms exactly — G17/G21's 240 Hz wins are in the
inert zone bit-for-bit. Above it every ratio is constant: lag 37.5% of a frame,
hysteresis 75%, margin 37.5%, young 2.34%, cap 50%, protect 6.25%.

Floors checked at the fast end:
- young window (16 µs at 1500 fps) vs the 1.464 µs switch cost: crossover sits
  at ~16,000 fps — 8× beyond the band. Safe.
- slice cap (333 µs) vs the 1.464 µs slice floor: no interaction anywhere
  in-band.
- wake protect (42 µs at 1500 fps) vs worker bursts (37–60 µs): protect ≈ one
  worker burst there, so mid-burst preemption gets rare at extreme rates — one
  burst is 6–9% of a 667 µs frame, so protecting it is coherent, but this is
  the first constant to watch in a Kovaaks-class capture.
- integer math: bucket index 40 ms >> 17 = 305 < 512, no wrap; the vote gate's
  cross-multiply peaks at 2^58, no overflow; ¾ as two shifts truncates ≤ 2 ns.
- 30 fps: the 24 ms wake-starve wall is now shorter than one frame — it is an
  absolute anti-stall bound, and shorter-than-frame is its safe direction.

Pacing modes:
- **Vsync (any fixed refresh):** cadence locks to refresh or a divisor on
  misses (the Diablo 30 Hz tick is in-band). Votes concentrate in one bucket;
  cleanest case. 360 Hz+ vsynced panels land in the active zone — correct.
- **VRR / G-Sync:** the panel follows the engine, cadence wobbles. Votes are
  lifetime averages, so they drift slowly across the 131 µs buckets; the
  incumbent needs a 2× displacement to lose, and the published value is
  sum/count — exact through a drift. FPS rises drop the floor instantly (safe
  side); fps drops relax it over ~16 polls, during which geometry stays
  tighter than true — G18's direction.
- **Tearing allowed / uncapped:** the case the band widening fixed; engine
  cadence up to 2000 fps votes normally. Beyond 2000 fps (uncapped menus can
  do it) votes stop rather than lie — geometry freezes at its last value.
  Fail-safe, never garbage.
- **Menu spike → gameplay:** a 1000+ fps menu retunes geometry tight; on
  returning to 240 fps gameplay the floor climbs back in ~16–30 s, tight-side
  the whole way. Transient, safe direction.

One watch item, downgraded on live evidence: geometry staleness after a game
exits needs SOME cadence source to recover. On this host the desktop itself
votes (~143–153 Hz observed at attach, 2026-08-17), and every harness arm
re-attaches fresh, so measurements never carry stale geometry. A voteless
decay toward bootstrap stays a registered option, not built.
