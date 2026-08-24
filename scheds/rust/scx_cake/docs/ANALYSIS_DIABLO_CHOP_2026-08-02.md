# Diablo IV chop analysis — cake exonerated at the wake tier (2026-08-02)

Maintainer-reported visible chop in Diablo IV under the G23 build. Analysis
only; nothing changed. First Diablo IV data in the corpus.

## Context and identity

- `sudo ./scx_cake` attached 19:13:11, once (`enable_seq` 1), zero stalls,
  never ejected. Binary identity behaviorally CONFIRMED as the G23 tip: both
  interrupt sinks are avoided (below), which only the per-line detector can
  produce. (Byte-proof unavailable — root-owned /proc; sudoless invariant
  broken by hand-launch. Earlier "USB sink missed at attach" inference is
  FALSIFIED by this data.)
- Regime: load 3-5, MangoHud cpu_load 19.5%, gpu_load mean 64% (18 unique
  values — a live reading, not the 97.0 artifact). Brave (pid 42851) runs a
  15-thread `Thread<NN>` pool producing ~47% of ALL sched events; no Brave
  audio stream. TACT streamers near-idle during the window (1,063 wakes).

## The chop, quantified (MangoHud per-frame, 32 s, 4,575 frames)

| metric | value | reference (HD2 G22 run) |
|---|---|---|
| median frametime | 4.46 ms (~224 fps) | 3.3 ms |
| p95 / p99 / p99.9 | 20.22 / 26.25 / 33.29 ms | — / — / ~4.4 ms |
| **severe (>2× median)** | **24.92% — 1,140 of 4,575** | **0.000-0.008%** |
| worst 10 | 32.0-35.5 ms | — |

A quarter of all frames land at 20-35 ms against a 4.5 ms median, with
neither CPU (19.5%) nor GPU (64%) saturated.

## Cake's service to Diablo (percpu_wake on 25 s / 7.8M events, same window)

| role | n | mean | p99 | CPU5 share | CPU13 share |
|---|---|---|---|---|---|
| vkd3d_queue | 77k | 1.09 µs | 3 µs | 0.3% | 0.3% |
| vkd3d_fence | 80k | 2.18 µs | 20 µs | 0.8% | 1.3% |
| vkd3d-swapchain | 260k | 1.69 µs | 9 µs | 0.6% | 0.5% |
| RenderJobWorker | 23k | 4.81 µs | 56 µs | 1.6% | 1.5% |
| Diablo IV.exe (39 thr) | 227k | 2.01 µs | 10 µs | 0.7% | 0.5% |

Fair share is 6.25%/CPU: G23 crushes both sinks to 0.3-1.6% across every
role, and residual sink wakes still pay 7-18 µs means — the penalty is real
in this game too, and avoided. CPU 2 (NIC, unflagged at attach) shows a mild
penalty (fence p99 72 µs, swapchain p99 129 µs at ~4-5% share) — the
predicted "third sink flags only under net load" gap, µs-class.

## Verdict

**The chop is not scheduler-shaped.** Severe frames arrive at ~36/s; wake
delays above 1 ms are order-of-a-few per role per 25 s (max column), three
orders of magnitude short of accounting for the hitch rate, and every role's
wake service is µs-class. A 20-35 ms hitch with idle CPU capacity and µs
runqueue delays lives in blocked-time or on the GPU/present side —
candidates, in prior order: pipeline/shader recompilation after the repair
(fresh files, cold caches), GPU contention from the Brave worker pool /
compositor, engine-side asset waits. These need GPU-side instruments or the
discriminator below, not sched traces.

**Discriminating next step (user-side, 60 s):** close or fully suspend
Brave, play 30 s, re-log frames via the MangoHud socket. Severe% collapsing
implicates the browser; unchanged severe% while caches warm implicates
recompilation (it also decays on its own as the cache fills).

## The elimination chain (same evening, retest + decomposition)

**Clean-field retest** (user's Brave closed; the 15-thread `Thread<NN>` pool
turned out to be the ASSISTANT HARNESS's own Playwright headless browser —
SwiftShader software-GL, killed for the retest; a measurable noise source
this project's own tooling put on the box):

| | run 1 (churn) | run 2 (clean field) |
|---|---|---|
| severe (>2× median) | 24.92% | **25.47%** |
| median | 4.46 ms | 4.09 ms |
| gpu / cpu load | 64% / 19.5% | 49% / 13.9% |

Severe rate is INVARIANT to removing all external load → contention
falsified. Temporal shape: **1,102 / 897 isolated single-frame spikes, mean
run length 1.0, uniform 23-27% across every third of both captures** →
focus-loss throttling falsified (needs one contiguous block), shader-cache
warming heavily disfavored (needs bursts + decay). The pattern is
metronomic: ~3 fast frames, one 20-35 ms frame.

**Scheduler kill-shot** (`wake_maxdecomp.py`, 200 µs threshold, same
session): vkd3d_queue 18 / vkd3d-swapchain 132 / RenderJobWorker 95 events
per 10k transitions above 200 µs, **zero events above 1 ms on every role**;
worst holders are kwin_wayland at 224-252 µs and worker-self at 589 µs. The
cake slice-cap/preemption theory for a 30/s hitch cadence is dead — three
orders of magnitude short in magnitude and rate. Caveat: sched trace window
(19:29) precedes the frame logs (19:35/19:41) by ~6 min, same session.

**Standing attribution:** frame *pacing* on the present path — Diablo's
limiter / vkd3d-proton swapchain rhythm / 240 Hz VRR interplay (the
3-fast-1-slow shape is a fence/present-queue signature) — or engine-internal
waits. Game-config territory, not scheduler territory. First knob to try:
an in-game FPS cap (~120) or vsync toggle; a pacing sawtooth flattens under
a cap, an engine wait does not.

## Runs 3-4 + launch-option audit (same evening)

| run | severe | median | note |
|---|---|---|---|
| 3: cap 222→400 | 21.66% | 4.28 ms | median stays pinned ≈ display period (240 Hz = 4.17 ms) → **present-bound, limiter falsified** |
| 4: cap 400, HUD hidden | 22.04% | 4.15 ms | **MangoHud overlay falsified** (one 347 ms outlier, single event) |

Launch options, verified live in `/proc/80488/environ`:
`PROTON_DXVK_LOWLATENCY=1` — live; targets DXVK's d3d11 limiter, D4 is
DX12/vkd3d-proton → believed inert (training knowledge, unverified).
`VKD3D_CONFIG=descriptor_heap` — live; **NOT a valid vkd3d-proton token**
(verified against upstream README option list); a no-op that may also
replace distro defaults — remove. `PROTON_ENABLE_WAYLAND=1` — live
(WAYLAND_DISPLAY set): native wine-wayland presentation, the newest layer in
exactly the path the evidence indicts — **top remaining suspect**.
`PROTON_USE_NTSYNC=1` — live; wake service measured healthy under it, keep.
`--in-process-gpu` — NOT in the game cmdline (verified); consumed by the
launcher's CEF, irrelevant.

**Elimination ledger:** external CPU churn ✗, focus-throttle ✗, shader-cache
warming ✗, in-game limiter ✗, MangoHud overlay ✗, scheduler ✗ (wake tier and
stall/preempt tier). Standing: native-Wayland present path (test: drop
`PROTON_ENABLE_WAYLAND=1`, restart, re-log), then engine-internal waits.

## Run 5 — user settings change, perceived smooth (20:14)

n=2632, median 10.35 ms (~97 fps, GPU 68%), severe 23.75% — same pid, same
launch options, both monitors up. The median DOUBLED (heavier per-frame GPU
work at lower fps) yet the spike band did not move: 20-34 ms in this run as
in all four before it, across cap 222/400, load/no-load, HUD on/off, and a
2.4x median change. **The stall is a fixed-absolute-duration event (~20-35
ms ~= 1-2 periods of the 60 Hz secondary display) hitting ~a quarter of
presents.** Perception improved because the RELATIVE excursion shrank
(5-8x -> 2-3x of median) and ~97 fps sits deep in the VRR window — the
mechanism itself still fires. Strongest remaining discriminators unchanged:
disable the 60 Hz secondary (no restart), then drop PROTON_ENABLE_WAYLAND
(restart).

## Proton version correction (20:4x)

All runs 1-5 and the sched trace ran under **proton-cachyos 0702** (maintainer
statement: 0703 installed only after run 5; the live game process predates the
install, and the earlier "already on 0703" check read the on-disk version, not
the loaded one). 0703 adds opt-in `PROTON_VKD3D_LOWLATENCY=1` (DX12 waitable-
swapchain frame pacing — directly on the indicted layer). Next-restart order to
preserve discrimination: (1) restart with NO flag changes = isolates 0702->0703;
(2) drop PROTON_ENABLE_WAYLAND; (3) swap DXVK->VKD3D lowlatency flag.

## Run 6 — proton-cachyos 0703, flags unchanged (20:24)

n=4286, median 4.74 ms, severe **23.66%**, gpu 51%, same 20-37 ms band.
The 0702->0703 upgrade alone is falsified as a fix — condition seven the
band has survived. (Median returned to the ~4.7 ms regime, so the run-5
graphics change did not persist across the restart.) Ladder unchanged:
next restart drops PROTON_ENABLE_WAYLAND, the one after swaps
PROTON_DXVK_LOWLATENCY -> PROTON_VKD3D_LOWLATENCY (new in 0703, DX12
waitable-swapchain pacing).

## vkd3d-low-latency source review (netborg-afps fork, shipped opt-in in 0703)

Reviewed at commit `565d695`. Mechanism: on the game's Reflex SIMULATION_START
marker the layer computes a per-frame delay from the PREVIOUS frame's GPU
timeline (outlier-filtered, no averaging) and sleeps the game thread so CPU
work lands just-in-time for the GPU -- classic latency-optimal pacing done
inside vkd3d. Two engagement modes (framepacer_bridge.cpp:109): NVIDIA_Reflex
when the game calls SetSleepMode (D4 must have Reflex ON in settings, via
dxvk-nvapi), else a WaitableDXGISwapchain fallback needing no game support.
Sleep primitive (threaded_sleep.h): helper thread does the coarse OS sleep to
t-150us, caller SPINS the last 150us -- the comment says the buffer exists
"so the scheduler cannot fail to miss t". Two precision wakes per frame:
prime cake territory (measured 1-2us wake means; an IRQ-sink CPU's 40us mean
would eat a third of that buffer -- G23's sink avoidance directly protects
this pacer).

Fit for OUR band: honest read is MITIGATION, not targeted fix -- the
VRR-specific pacing paths (getVrrDelay, LOW_LATENCY_VRR, vblank derivation)
are PRESENT BUT COMMENTED OUT at this commit, so it does not model VRR
deadlines; but no-overlap CPU frames + waitable swapchain (queue depth ~1)
should shrink multi-frame present blocks if the band is queue backpressure.
Limitations (README): needs Sim-Start+Present-Begin markers for Reflex mode,
no frame generation, no Intel (36-bit timestamps), CPU parallelism reduced
by design. Ladder rung 3 stands: swap PROTON_DXVK_LOWLATENCY ->
PROTON_VKD3D_LOWLATENCY, enable Reflex in D4, one variable per restart.

## Deep hunt (fresh 25 s trace, GPU clocks, full flag audit, on-disk prefs)

**Waker fingerprint — the stall is below userspace.** Block-gap decomposition
of the fresh trace: every >=15 ms wait on the render chain ends with waker =
`swapper` (fence 581/586, queue 460/460, swapchain 192/196) — hardware
interrupts waking from idle, i.e. GPU/display signals arriving 15-48 ms late.
kwin appears 7 times in 3,400+ long wakes; no userspace component is holding
anything. Fence-thread long waits (~23/s) match the severe-frame rate.

**GPU clocks falsified as a cause:** pclk pinned 2745 MHz, mclk 10501, zero
power/thermal violations across 22 s of play at SM 50-75%.

**Full env audit notables (live /proc):** wayland forced at DLL level
(`winex11.drv=d;winewayland.drv=b`), fullscreen hack disabled, esync+fsync+
ntsync all requested (ntsync wins), `WINE_UPSCALER_REPLACE=fsr4` on an NVIDIA
box (oddity, effect unverified; DLSS-off run says not the band), Steam overlay
+ fossilize layers present (also present on HD2 at 0.008% severe — weak).
Launch path is a Steam non-Steam shortcut (pressure-vessel SLR), not bare
Battle.net.

**On-disk D4 prefs (LocalPrefs.txt): `Vsync "0"`, `Reflex "2"` (= enabled +
boost).** NEW PRIME SUSPECT: with DXVK_ENABLE_NVAPI=1, Reflex markers reach
the NVIDIA driver's VK_NV_low_latency2 sleep path TODAY (stock vkd3d
translation). A driver-side frame gate mispredicting under wayland+VRR
explains the full invariance set and the swapper-wake fingerprint. Test is
in-game Reflex OFF — applies live, no restart.

**Test order now:** (1) Reflex OFF in-game, re-log; (2) vrr test / monitor
test (kscreen, no restart); (3) wayland-off restart; (4) 0703's
PROTON_VKD3D_LOWLATENCY as the eventual replacement pacer if Reflex itself
is the problem layer.

## Run 7 — Reflex OFF (20:38): FALSIFIED, suspect nine down

LocalPrefs verified `Reflex "0"` before the run, same game instance.
n=2933, median 5.40 ms, severe **29.22%**, band 31-40 ms, gpu 54%. The
driver-side Reflex gate is not the stall. Eliminated set now: external
churn, focus, shader-warm, in-game limiter, MangoHud, DLSS, proton
0702->0703, GPU clocks, Reflex — every userspace-configurable layer inside
the game/runtime. Consistent with the swapper-wake fingerprint, what
remains is the compositor/KMS/VRR/dual-monitor layer and the wine-wayland
present path: vrr test, monitor test (both live, no restart), wayland-off
(restart).

## Run 8 — VRR OFF on DP-2 (20:40): FALSIFIED, ten down

vrrpolicy set to never (verified), logged, restored to automatic (verified).
n=2913, median 5.12 ms, severe **32.03%**, band 31-40 ms, gpu 52%. Adaptive
sync is not the stall. Note: severe% has crept 24.9 -> 29.2 -> 32.0 across
the evening's runs — scene-dependence or session aging, unattributed.
Remaining suspects, all in the fingerprint-indicted layer: the 60 Hz
secondary's influence on KWin flip scheduling (monitor test, no restart —
windows may jump when DP-3 drops), the wine-wayland present path (restart),
and KWin compositing/no-direct-scanout for a borderless surface.

## Flag provenance + game-config audit (20:5x) — WITH A CORRECTION

**CORRECTION — run 3's "limiter falsified" is VOID.** LocalPrefs.txt right
now reads `MaxForegroundFPS "222"` with `LimitForegroundFPS "1"`: the cap-400
change never persisted (as run 6's median already hinted), so run 3 compared
222 against 222 and tested nothing. The in-game limiter is BACK on the
suspect list — its sleep/wake per frame is present-adjacent and fires ~222x/s.
Also on disk: `LimitBackgroundFPS "1"` / `MaxBackgroundFPS "221"`, and
`DisplayModeWindowMode "1"` — the game runs WINDOWED/borderless, so every
frame is KWin-composited (no direct scanout), load-bearing given the
swapper-wake fingerprint. QualityPreset "2" — the Ultra change did not
persist either; D4 video-settings persistence in this prefix is unreliable
(Reflex "0" DID persist).

**Flag provenance (user asked: what is forced that I did not set):**
- User launch options (Steam shortcut): PROTON_DXVK_LOWLATENCY,
  VKD3D_CONFIG=descriptor_heap (invalid token), PROTON_ENABLE_WAYLAND,
  PROTON_USE_NTSYNC, mangohud, --in-process-gpu.
- proton-cachyos script defaults (grep-verified in `proton`): DXVK_CONFIG
  (async off, 14 compiler threads, GPL auto), DXVK_ASYNC=0,
  DXVK_ENABLE_NVAPI=1, WINE_DISABLE_FULLSCREEN_HACK=1, WINE_MOVE_HACK=1,
  WINE_USE_EGL=1, PROTON_NO_STEAMINPUT, esync+fsync enables.
- **protonfixes layer (auto-applied, NOT user-set): WINE_UPSCALER_REPLACE=
  fsr4** via `protonfixes/upscalers.py`, with a managed `dlss_version` dir in
  this game's compatdata — proton-cachyos actively swaps upscaler DLLs for
  this game; exact trigger condition unverified. On an NVIDIA+DLSS title this
  is the one genuinely-forced surprise found.

**Next in-game tests (no restart): disable LimitForegroundFPS entirely
(verify on disk before logging), and/or true fullscreen instead of windowed.**
Monitor test and wayland-off unchanged.

## Host physical audit (21:0x) — all clean, one config drift

22 s sample during play: **disk** nvme0n1 essentially idle (2 reads/s, 0.6%
util, awaits <2.5 ms) — IO falsified; **PSI** cpu/io/mem all 0.00 avg10;
**swap** untouched (98 GB free); **Tctl 55 C**; **CPU freq** boosting to
5549 MHz, mean-of-mins 5114 MHz, single benign idle dip (cpu4, 603 MHz).
None of these can produce fixed-duration 20-35 ms singleton present waits.

**Config drift found:** governor `powersave` + EPP `balance_performance` —
this box's expected state is EPP=performance (per project memory). Not the
band's cause (wrong failure shape), but a standing perf tax; restore
separately from this hunt.

## Cadence analysis (21:1x) — a ~30 Hz metronome quantized on 60 Hz periods

| run | spikes/s | inter-spike gap p50 | gap CV | dur comb on 16.67 ms |
|---|---|---|---|---|
| 6 | 31.8 | 32.5 ms | 0.41 | 42% |
| 7 | 27.2 | 38.7 ms | **0.19 (metronome)** | 37% |
| 8 | 29.2 | 37.6 ms | **0.28 (metronome)** | 50% |

The spike train ticks at ~27-32 Hz with gap p50 32-39 ms — i.e. every OTHER
vblank of the 60 Hz secondary — and spike durations cluster at 16.7 / 29.2 /
33.3 ms (60 Hz multiples dominate the comb in runs 7-8; duration clusters
run7: 29.2ms x379, 25.0 x189, 33.3 x182). A ~30 Hz beat with 60 Hz-quantized
hold durations is the mixed-refresh compositor path's signature. The monitor
test (DP-3 off, no restart) is now the decisive discriminator; wayland-off
is the fix-side test behind it.

## Run 9 — monitor test, DP-3 compositor-disabled (20:52): PARTIAL CONFIRMATION

(Physical power-off left DP-3 enabled+connected in KWin — the test required
`kscreen-doctor output.DP-3.disable`, verified, and re-enable after,
verified.) n=4519, med 6.27 ms, severe **18.34%** (from 32.03%), rate
26.3/s, gap p50 33.2 ms CV 0.38, **dur p50 15.2 ms** (from 28.8), p95 16.15,
p99.9 22.1, max 38.9.

**Read: removing the 60 Hz output subtracts exactly one 16.7 ms quantum from
every stall and halves the severe rate — DP-3 is a CONFIRMED CONTRIBUTOR.
But the ~30 Hz gating beat survives with a ~15-16.7 ms hold on a
240 Hz-only desktop.** A 60 Hz-quantized hold with no 60 Hz display present
points at an internal 60 Hz pacing fallback in the surface's present path —
the wine-native-Wayland frame-callback/feedback layer (hypothesis,
unverified). The wayland-off restart is the closing test; it is also the
community-reported fix for this driver's pacing immaturity.

## Run 10 — locked baseline for the wayland A/B (20:57)

Conditions verified live: PROTON_ENABLE_WAYLAND=1 in /proc, LocalPrefs
400/400 caps, QualityPreset 2, Reflex "1" (silently re-enabled itself — third
settings mutation tonight), both monitors enabled. n=5157, med 5.63 ms,
severe **18.23%** at 29.5/s, dur p50 **14.2 ms**, gap p50 31 ms CV 0.39,
p99.9 20.3, max 31.6, gpu 71%. The metronome persists at ~30 Hz with
~one-quantum holds; profile matches run 9 (DP-3 off) even though DP-3 is
back on — the second quantum did not return after the output cycle /
settings churn, unattributed. B-side next: identical everything, wayland
flag removed.

## Run 11 — XWayland B-side (21:04): WAYLAND FALSIFIED

User removed BOTH PROTON_ENABLE_WAYLAND and PROTON_DXVK_LOWLATENCY (absence
verified in /proc of new pid 100129; NTSYNC + VKD3D_CONFIG unchanged).
n=4387, med 5.59, severe **22.20%** at 30.7/s, gap p50 29.9 ms **CV 0.31**,
dur p50 17.0 ms, p99.9 24.9, gpu 62%. Against the locked A-side (18.23%,
29.5/s, 14.2 ms): the ~30 Hz metronome with 60 Hz-quantized holds is FULLY
INTACT on XWayland — the wine-native-Wayland driver is not the root cause
(and dxvk-lowlatency is falsified as a necessary cause alongside).

**Field after ~15 falsifications — two suspects remain:**
1. **KWin's per-surface treatment of a WINDOWED game** (DisplayModeWindowMode
   "1"): both X11 and Wayland paths composite a windowed surface through
   KWin; HD2 at 0.008% severe on the same compositor ran FULLSCREEN. Window
   mode is the one host-side variable never yet tested.
2. **The engine's own ~30 Hz tick** (sim/server cadence): would be invariant
   to every host change by construction, matches the swapper-wake (timer/net
   IRQ) fingerprint and the online-game tick model.

Discriminator: true Fullscreen in D4 display settings (Apply; disk-verify
DisplayModeWindowMode changes) — collapses = KWin windowed-surface
treatment; survives = engine-internal, and the host is exonerated end to end.

## Run 12 — BARE ENVIRONMENT (21:1x): THE STALL TRAIN COLLAPSES

User removed ALL startup items (verified in /proc pid 101693: no MANGOHUD,
no NTSYNC, no VKD3D_CONFIG, no lowlatency, no wayland — stock proton env).
Kernel-side measurement (no game-side instrument needed; the fence-wait rate
was validated against severe-frame rate all night):

| role | >=15ms waits/s instrumented | bare | drop |
|---|---|---|---|
| vkd3d_fence | 23.4/s | **0.7/s** | 33x |
| vkd3d_queue | 18.4/s | **0.7/s** | 26x |
| vkd3d-swapchain | 7.8/s | **0.4/s** | 20x |

**CORRECTION, owed and owned: the earlier "MangoHud falsified" (run 4) was
an INVALID test.** It removed the overlay DRAW (no_display) while the Vulkan
layer stayed injected and hooking every present — it discriminated pixels,
not the hook. The maintainer's direct question ("is it possible the
mangohud?") was argued down with that invalid falsification. The user's
flicker observation was the tell.

**Caveat: four variables removed at once** (MangoHud layer, PROTON_USE_NTSYNC,
VKD3D_CONFIG token, --in-process-gpu; XALIA flipped 0->1). MangoHud's layer
is the leading candidate (present hook + flicker + CUSTOMIZED build);
ntsync second. One-variable confirm: relaunch with ONLY mangohud re-added.

**PROJECT IMPLICATION if MangoHud confirms: the capture instrument itself
can inject a ~30 Hz stall train into a game.** HD2 measured 0.008% severe
under the same MangoHud, so it is game-interaction-specific (D4+vkd3d), but
every future D4 capture must cross-check against the kernel-side fence-wait
rate, and the customized MangoHud build needs a bisect.

## Artifacts

- Frame log: `~/Benchmarks/Diablo IV_2026-08-02_19-35-54.csv` (+ summary)
- Sched trace: `~/Benchmarks/diablo_sched_2026-08-02_1929.perf.data.zst`
  (911 MB → 64 MB; `zstd -d` then `percpu_wake.py <file> <roles>`)
- Diablo thread inventory, timeline (19:00 launch, 19:13:11 attach,
  19:21:39/19:23:59 session deaths, repair, relaunch): session transcript
  2026-08-02 evening.
