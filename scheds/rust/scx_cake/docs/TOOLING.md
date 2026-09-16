# scx_cake troubleshooting tooling

Every tool installed on the dev box (2026-09-02, 9800X3D, kernel 7.2.2-cachyos)
that can measure scheduling, CPU, IO, networking, GPU, or a game, with what it
detects and how it is run here. Tiers: **validity** (is the arm what it claims),
**diagnostic** (why), **score** (a number that can be kept). Never sudo; the
scoped helpers are listed where root is needed.

## Scheduler and wake path

| tool | what it measures | detects | usage | tier |
|---|---|---|---|---|
| `bench/wake_maxdecomp.py` | for chosen roles, every runnable-to-run delay above a threshold, classed QUEUE / HOLD / IDLE with the holder's comm and burst | which task held a CPU while a game stage waited, how often per 10k wakes | `python3 bench/wake_maxdecomp.py <perf.data> "RenderThread 1,GameThread,dxvk-submit" 200` (needs a sched-tracepoint `perf record -a`) | diagnostic |
| `cakebench wake-latency capture/parse` | per-role wake-to-run p50/p95/p99/max, migrations, same-CPU wake %, preempted-while-runnable, top wakers | scheduler-caused latency per thread; preemption pressure | `bash cakebench wake-latency capture --match 'GameThread\|dxvk' --duration 22 --label x`; `parse --trace file.perf.data` | diagnostic |
| `runs/overnight_game_20260901/hold_timing.py` | for each long delay: was the holder already running when the wake landed, did the wakee run on its wake target, holder burst | deliberate placement onto a busy CPU vs a race | `python3 hold_timing.py <perf.data> 300` | diagnostic |
| `runs/overnight_game_20260901/sib_overlap.py` | share of each game role's run time with its SMT sibling idle / running game / running foreign | sibling doubling (§G38/§G60) | `python3 sib_overlap.py <perf.data> 0` | diagnostic |
| `runs/overnight_game_20260901/thread_cores.py` | per game thread: run time, migrations, top CPUs; per-CPU share of game time | core concentration, home stability (1.1.3 GameThread 650 migrations vs 12,629) | `python3 thread_cores.py <perf.data>` | diagnostic |
| `bench/wake_migsplit.py`, `bench/wake_occupant.py` | wake latency split by migrated/not; who occupied the target CPU | cold-vs-warm placement cost, occupant class | `python3 bench/wake_migsplit.py <perf.data>` | diagnostic |
| `bench/migrate_cause.py`, `bench/percpu_wake.py` | migration causes; per-CPU wake counts | routing skew | see file docstrings | diagnostic |
| placement census (`cake_stats` PERCPU_ARRAY, probe commits) | which select_cpu arm placed each wake; holds >300 µs / >1 ms by queue kind | the arm behind a hold; local-DSQ (unstealable) share | build a PROBE commit, attach, read the `arms` lines at detach | diagnostic |
| `cake-bpfstats` (helper) | kernel `bpf_stats_enabled` + `bpftool prog show`: run count and ns/run per struct_ops callback | scheduler self-cost on the game's cores (1.1.3 0.8% of a CPU, nightly 2.2-2.8%) | `sudo -n /usr/local/libexec/cake-bpfstats enable`, attach 12 s, `... show > x.json`, `... disable` | diagnostic |
| `bench/fnspills.py` | stack spills per BPF function from the release object | verifier/register pressure regressions | `python3 bench/fnspills.py target/release/build/scx_cake-*/out/bpf.bpf.o` | attribution |
| `bpftool prog dump xlated|jited` | the loaded instruction stream | what the verifier actually kept after rodata pruning | `bpftool prog dump jited name cake_select_cpu` | attribution |
| `scxtop tui` / `scxtop trace` | live sched_ext view: per-CPU DSQ depth, dispatch rates, latency histograms; trace to file | queue build-up, imbalance across CPUs | `scxtop tui` while an scx scheduler is attached | diagnostic |
| `scxctl` | switch the system scheduler | arm attach/detach in harness cycles | `scxctl start/stop`, sudoless via helpers | validity |
| `/sys/kernel/sched_ext/state`, `enable_seq`, `nr_rejected` | attach state, transition count | is anything attached; lost attaches | `cat /sys/kernel/sched_ext/state` | validity |
| `bpftrace` | ad-hoc kernel tracing (tracepoints, kprobes, kfuncs) | one-off questions the fixed tools do not answer | `bpftrace -e 'tracepoint:sched:sched_switch { @[comm] = count(); }'` | diagnostic |
| `perf sched` (`record`, `latency`, `timehist`) | kernel scheduler latency and timeline per task | wake latency and run/sleep timeline without cake tooling | `perf sched record -- sleep 10; perf sched latency` | diagnostic |
| `cyclictest` | RT wake jitter of a timer thread | worst-case scheduler latency floor | `cyclictest -m -p90 -i1000 -l10000` | diagnostic |
| `schbench`, `stress-ng` | wake-latency and throughput microbenchmarks; load generators | the wallclock tier (`cakebench native-pair --workload schbench-light`) | via cakebench | score |

## CPU, cache, frequency, topology

| tool | what it measures | detects | usage | tier |
|---|---|---|---|---|
| `perf stat -p <game pid>` | cycles, instructions, IPC, cache-references/misses, L1d/LLC loads and misses, branch misses, for the game's threads (includes BPF run in their context) | IPC gap, branch-predictor thrash (+34% on the stack), cache miss rate | `perf stat -p $(pgrep -o -f Shipping.exe) -e cycles,instructions,cache-misses,branch-misses -- sleep 12` | diagnostic |
| `perf record -a` (sched tracepoints) | the trace every wake tool above consumes | source data | `perf record -a -k CLOCK_MONOTONIC -m 256M -e sched:sched_switch -e sched:sched_wakeup -e sched:sched_waking -e sched:sched_migrate_task -- sleep 20` | diagnostic |
| `/proc/stat` deltas | per-CPU user/sys/idle/irq/softirq time | core balance (1.1.3 even 10% per CPU vs 39/33/26/27 on cores 0-3), IRQ time per CPU | `runs/overnight_game_20260901/sys_ab.sh` | diagnostic |
| `/proc/interrupts` deltas | per-IRQ rates and their CPUs | nvidia 7.8k/s on CPU 13, xhci 1.6k/s on CPU 9 (the sink set) | same script | diagnostic |
| `cpupower frequency-info`, `/sys/devices/system/cpu/*/cpufreq` | governor, current/min/max frequency, boost | clock as a covariate; a locked or throttled core | `cpupower frequency-info` | validity |
| `lstopo`, `hwloc-ls`, `numactl -H` | topology: cores, SMT pairs, L2/L3, NUMA | the sibling map and LLC span cake loads from sysfs | `lstopo --no-io` | validity |
| `/sys/devices/system/cpu/cpu*/topology/thread_siblings_list` | SMT pairs | cpu c pairs with c^8 on this box | `cat` | validity |
| `vmstat 1`, `btop` | run queue length, context switches, interrupts, per-CPU load | global saturation; a runaway process (xi_map, browsers) | `vmstat 1 5` | diagnostic |
| `ps -eo pcpu,comm --sort=-pcpu` | noise sources | the covariate every arm must share | `capture_preflight.py` prints it | validity |

## IO and networking

| tool | what it measures | detects | usage | tier |
|---|---|---|---|---|
| `vmstat` (`bi/bo`, `wa`) | block IO and IO-wait | disk stalls behind a hitch (shader cache, DirectStorage) | `vmstat 1` | diagnostic |
| `ss -s`, `ss -lx`, `ss -tip` | socket summary, unix sockets (MangoHud control socket `mangohud-<pid>`), TCP info | MangoHud injection, a game's server connection | `ss -lx \| grep mangohud` | validity |
| `ethtool -S <if>` | NIC counters and drops | network drops during play | `ethtool -S eno1` | diagnostic |
| `/proc/interrupts` | NIC and NVMe IRQ rates and CPUs | IRQ landing on game cores | see above | diagnostic |
| `bpftrace` block/net tracepoints | latency of IO completions or packet paths | IO-completion wake chains | `bpftrace -e 'tracepoint:block:block_rq_complete { @ = hist(...) }'` | diagnostic |

## GPU

| tool | what it measures | detects | usage | tier |
|---|---|---|---|---|
| `nvidia-smi dmon -s pucvt` | GPU util, memory, power, clocks, temperature, throttle reasons per second | GPU-bound vs CPU-bound regime; a clock drop (Lestat's 400 MHz change) | `nvidia-smi dmon -s pucvt -d 1` | validity |
| `nvidia-smi -q -d PERFORMANCE,CLOCK` | throttle reasons, current clocks | thermal or power throttling behind a tail | `nvidia-smi -q -d PERFORMANCE` | validity |
| MangoHud CSV columns (`gpu_load`, `gpu_power`, `gpu_core_clock`, `gpu_temp`, `gpu_vram_used`) | per-frame GPU state aligned to frametimes | GPU state per arm (77% at 2745 MHz, 330 W at the KovaaKs menu) | read from `~/Benchmarks/*.csv` | validity |
| `vulkaninfo`, `vkcube`, `glxinfo` | driver and device sanity | wrong device or driver after an update | `vulkaninfo --summary` | validity |
| `gamescope` | a compositor with its own frame pacing | isolating KWin from a pacing question | `gamescope -- <game>` | diagnostic |

## Game and frames

| tool | what it measures | detects | usage | tier |
|---|---|---|---|---|
| MangoHud (`mangohud %command%` launch option; control socket `mangohud-<pid>`) | per-frame frametime, fps, CPU/GPU state, logged to `~/Benchmarks` | the frame numbers every score uses | `log_duration=60`, `control=mangohud-%p` in `~/.config/MangoHud/MangoHud.conf` | score |
| `runs/overnight_game_20260901/snip.py` | mirrored short slots (A B B A) of MangoHud logging with arms attached from receipts; avg, 1% low, 0.1% low, p99, p99.9, max per slot and per arm | the one-minute screen; `LOG_S=20` for a tail read | `LOG_S=20 python3 snip.py crate-1.1.3s n0901-g79` | screen |
| `runs/xsched_20260904/xsched.py` | N-arm mirrored MangoHud snippets for ANY scheduler binary (arms in `arms/*.json`: binary, args, expected ops prefix); per slot: ops identity, sha256, game CPU %, external CPU %, GPU util/clock | the cross-scheduler screen (cake vs lavd / cosmos / pandemonium / native) | `LOG_S=20 ROUNDS=2 TAG=hd2 python3 xsched.py native cake-g86 cosmos`; `xsched.py smoke <arm>` attach-tests | screen |
| `runs/xsched_20260904/cpuattr.py` | per arm: `perf stat` on the game (cycles, instructions, IPC, switches, migrations, misses) + per-thread CPU and voluntary/nonvoluntary switch rates from /proc | why CPU time differs between schedulers; which threads get preempted | `DUR=10 python3 cpuattr.py <game pid> cake-n cake-g86 cosmos` | diagnostic |
| `runs/xsched_20260904/chaincap.py` + `gpuchain.py` | `perf record` of sched_switch/waking + nvidia irq entry/exit + submit ioctls per arm; the analyzer follows every nvidia ISR's wakes hop by hop (fence, swapchain, display kthreads, game threads) to the next submit, classes each hop IDLE / PREEMPT / WAITED with holder, IRQ inter-arrival gaps | wallclock per hop of the GPU wait chain per scheduler | `DUR=20 python3 chaincap.py <pid> native cake-g86 cosmos`; `perf script -F comm,tid,cpu,time,event,trace > <arm>.txt`; `python3 gpuchain.py <dir> <arm>` | diagnostic |
| `runs/xsched_20260904/kthreadhop.py`, `idleatwake.py` | ISR-woken kernel threads by comm with holders and run CPUs; for each queued wake of the frame roles, how many CPUs were idle and whether select_cpu's target was busy | a placement fault (idle CPU existed) vs real saturation | `python3 idleatwake.py <dir> <arm>` | diagnostic |
| `runs/xsched_20260904/framecap.py` + `frameautopsy.py` | MangoHud logging and the sched/irq trace over the same window (t0 = CLOCK_MONOTONIC at `:logging=1;`, frames = t0 + `elapsed`); per slow frame: waits inside the frame window, worst wait role/class/holder, IRQ gaps, against normal frames | is a slow frame scheduler-caused | `LOG_S=20 python3 framecap.py cake-g86 cosmos`; `python3 frameautopsy.py <dir> cake-g86.json 11.0` | diagnostic |
| `--toggle llcsplit=1` (loader) + `runs/llc_20260904/run.sh` | presents the 9800X3D to the BPF side as two dies (cores 0-3 + 8-11, 4-7 + 12-15); with `--toggle probe=1` the census prints per-site cross-die counters (`x_hint`, `x_pool_served`, `x_steal_moved`, ...) | does every routing system respect the die; the fabric penalty is NOT emulated | `EXTRA="--toggle llcsplit=1" bash run.sh probe-split` (appsim HD2 mission, 65 s), compare with `probe-flat` | diagnostic |
| `runs/mini_20260904/mini.py`, `cycload.py` + `bursty` | the scx_flow mini benchmarker's three probes (cyclictest 4 threads pinned to CPU 0, schbench 1 msg thread + nproc workers, hackbench -l 1000 -g 10) per arm; `cycload.py` adds a fresh-occupant load on CPU 0 so cyclictest's wait behind cake's preempt gates is deterministic | timer-wake latency under a fresh occupant (§G87's rig) | `CYC_S=15 python3 cycload.py native cake-ship cosmos` | diagnostic |
| `runs/xsched_20260904/placeaudit.py` | from a sched trace, rebuilds the idle set at every wake, names the best CPU by cache rank (warm prev + sibling idle, whole free core, warm prev with sibling busy, idle thread beside a busy one, busy CPU while something idle), scores the chosen CPU, separates 'contended' (best CPU taken within 30 us) from a miss; per role, with the top best->chosen pairs and their p99 wait | is the best available CPU picked, and which decision misses cost latency vs cache; works on any scheduler's trace | `python3 placeaudit.py <dir> <arm> [sib_xor=8] [sinks=9,13]` | diagnostic |
| `cakebench game ab --game <id>` | receipted ABBA/ABCCBA cycle with focus check, harness validity, matrix and report | the scored frame route | `bash cakebench game ab --game kovaaks --duration 60 --settle 15` | score |
| `cakebench game doctor --game <id> --detect-focus-context` | focus resolution, MangoHud socket health | wrong focused window, missing socket | before any capture | validity |
| `bench/capture_preflight.py` | receipt, scxctl, attach state, noise level and sources, the time cost of a rotation | everything checkable before the game opens | `python3 bench/capture_preflight.py --game kovaaks --arms 3` | validity |
| `bench/scx_cake_thread_profile.py`, `bench/gameprobe.py` | the game's thread roster, per-thread run/wait, wake graph | which threads are the stages, who wakes whom | see docstrings | diagnostic |
| `bench/scx_cake_smt_residency.py` | live sampling of GameThread/RenderThread sibling occupancy from /proc | sibling doubling without a trace | run while the game is up | diagnostic |
| `kdotool` | KWin window search/activate (Wayland) | focusing the game for an unattended capture | `kdotool windowactivate $(kdotool search --name KovaaK)` | validity |
| `spectacle -b -n -o x.png` | a screenshot to read the scene | what the game is showing (menu, title, popup) | before a capture | validity |
| `evdev` uinput (`runs/overnight_game_20260901/press_key.py`) | one key tap through a virtual keyboard | dismissing a title screen unattended | `python3 press_key.py KEY_SPACE` | validity |
| `steam -applaunch <appid>` | launch a Steam game | unattended bring-up (KovaaKs 824270, Palworld 1623730) | `setsid steam -applaunch 824270 &` | validity |

## Wallclock and throughput

| tool | what it measures | detects | usage | tier |
|---|---|---|---|---|
| `cakebench artifact ensure`, `native-pair --readiness/--execute` | receipted exact pairs against native on named workloads | throughput or latency regressions of a construct (`--blocks 2` screen, 8 confirm) | see `cakebench --help` | score |
| `runs/toggle_wallclock_20260901/fast_ab.sh` | pipe 3M + messaging g20 ABBA in ~3 min | a quick wallclock guard on a toggle | `bash fast_ab.sh name "--toggle gNN=1" ""` | screen |
| `bench/cakeload` | a named CPU load generator (comm `cakeload`) | saturation regime for a wake test | `bench/cakeload N` | diagnostic |

## Rules that keep a number true

- Validity before value: attach identity from the log (`scx_cake 1.1.3` vs `1.2.1`, the `toggle` line), binary from the receipt.
- Never build or run agents during a live capture; builds during a slot contaminated cycle 32 on 2026-09-02.
- Rotate arms (A B B A, A B C C B A); slot position moves tails as much as the scheduler.
- Noise is a covariate shared by all arms of one rotation, never a gate. Record it.
- p99.9 needs frames: an 8 s slot has 5 frames in the 0.1% band; use 20 s slots or accumulate.
