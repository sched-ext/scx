# scx_cake tooling

Measurement tools on the dev box (9800X3D), checked against disk 2026-10-20. Paths are
in-tree `bench/` or the sibling `scx_cake_bench` repo. Tiers: **validity** (is the arm
what it claims), **diagnostic** (why), **score** (a number to keep). Never sudo; use the
scoped helpers (`sudo -n -l`). Start with `cakebench`.

🗑️ Gone from disk and never in git (checked 2026-10-20): the `scx_cake_bench/runs/`
tools of `overnight_game_20260901` (hold_timing, sib_overlap, thread_cores, sys_ab,
snip, press_key), `xsched_20260904` (xsched, cpuattr, chaincap, gpuchain, kthreadhop,
idleatwake, framecap, frameautopsy, placeaudit), `mini_20260904` (mini, cycload) and
`toggle_wallclock_20260901` (fast_ab). Their findings stay in STATE.

## 🎂 Cake tools

| Tool | Measures | Usage | Tier |
|---|---|---|---|
| `cakebench cost <A> <B> [<C> <D>]` | per-callback ns/run and appsim frames, mirrored slots, identity per slot | `bash cakebench cost <sha> <sha> --slots 2 --spec <20s.conf>` (~2 min) · `--arm-args K='[...]'` per-arm flags · `--work profile` adds cycles and instructions | score |
| `cakebench game ab --game <id>` | receipted ABBA (ABCCBA with `--baseline`) with focus check, validity, matrix, report | `bash cakebench game ab --game kovaaks --duration 60 --settle 15` | score |
| `cakebench score`, `native-pair`, `artifact ensure` | receipted pairs against native on named workloads | `--blocks 2` screens, 8 confirms; `cakebench help run` | score |
| `cakebench game doctor --game <id> --detect-focus-context` | focus resolution, MangoHud socket health | before any capture | validity |
| `bench/capture_preflight.py` | receipt, scxctl, attach state, noise level and sources, rotation time | `python3 bench/capture_preflight.py --game kovaaks --arms 3` | validity |
| `scx_cake --inspect-bpf DIR` | verifier load and per-program BPF/JIT sizes, no attach | after setcap on a receipt copy | validity |
| `cakebench wake-latency capture/parse` | per-role wake-to-run p50/p95/p99/max, migrations, same-CPU wakes, preempted-while-runnable, top wakers | `bash cakebench wake-latency capture --match 'GameThread\|dxvk' --duration 22 --label x` · `parse --trace file.perf.data` | diagnostic |
| `--toggle probe=1` census | which select arm placed each wake; placed / waited >300 µs / >1 ms per queue kind; home declines (`hd_*`) | read the `census` lines at detach | diagnostic |
| `cake-bpfstats` | `bpf_stats_enabled` + `bpftool prog show`: run count and ns/run per callback | `sudo -n /usr/local/libexec/cake-bpfstats enable\|show\|disable`; the local `bench/cake-bpfstats` is a separate read-only tool (`status`, `show`, `ftrace-dump`) that cannot enable stats | diagnostic |
| `runs/perfmap_20260927/perfmap.sh` + `perfmap.py` | `cycles:k` by cake function → kfunc → leaf | `perfmap.sh <receipt> <hogs> <secs> <out> [spec]`, `perf script -F period,ip > script.txt`, `perfmap.py <out>` | diagnostic |
| `bench/wake_maxdecomp.py` | every runnable-to-run delay over a threshold for chosen roles, classed QUEUE / HOLD / IDLE with holder and burst | `python3 bench/wake_maxdecomp.py <perf.data> "RenderThread 1,GameThread" 200` (default 1000 µs) | diagnostic |
| `bench/wake_migsplit.py` · `wake_occupant.py` · `migrate_cause.py` · `percpu_wake.py` | wake latency migrated vs not · who held the target · migration causes · per-CPU wakes | `python3 bench/wake_migsplit.py <perf.data>`; others in their docstrings | diagnostic |
| `bench/rt_displace_capture.sh` + `rt_displace.py` | 30 s trace for §G93: RT holds of game threads, hop vs stay, the burst after | `bench/rt_displace_capture.sh 30` (tracefs readable, schedstats on) · `rt_displace.py -i perf.data --tids sched_a.txt --main TID` | diagnostic |
| `bench/frame_attrib.py` | per MangoHud frame: run / RT hold / preempt / wait / block ms, hops, compositor burst; slow frames classed | `frame_attrib.py --log mangohud.csv -i perf.data --main TID --kwin TID [--log-start S]` | diagnostic |
| `bench/scx_cake_thread_profile.py` · `gameprobe.py` · `scx_cake_smt_residency.py` | thread roster, run/wait, wake graph · live sibling occupancy of the game stages | see docstrings; run while the game is up | diagnostic |
| `bench/fnspills.py` | stack spills per BPF function | `python3 bench/fnspills.py <scx>/target/release/build/scx_cake-*/out/bpf.bpf.o` | attribution |
| `bench/cakeload.c` | named CPU load (comm `cakeload`) for a saturated wake test | build first: `cc -O2 -o <scx>/target/cakeload bench/cakeload.c`, run `cakeload <threads> <pidfile>` | diagnostic |

`percpu_wake.py`, `wake_maxdecomp.py`, `gameprobe.py`, `scx_cake_smt_residency.py` and
`bench/cake-bpfstats` are local-only ([STRUCTURE](STRUCTURE.md)).

## 🐧 Linux tools and what cake uses them for

| Area | Tool → use |
|---|---|
| Scheduler | `perf record -a -k CLOCK_MONOTONIC -m 256M -e sched:sched_switch -e sched:sched_wakeup -e sched:sched_waking -e sched:sched_migrate_task -- sleep 20` → the trace every wake tool reads · `perf sched latency/timehist` → per-task latency without cake tools · `scxtop tui` → per-CPU DSQ depth, dispatch rates · `scxctl start/stop` → switch scheduler · `/sys/kernel/sched_ext/state`, `enable_seq`, `nr_rejected` → attached? lost attaches? · `bpftrace` → one-off questions · `sudo -n bpftool -j prog dump jited id <N>` → what the verifier kept · `cyclictest`, `schbench`, `hackbench`, `stress-ng` → microbenchmarks and load |
| CPU | `perf stat -p <game pid> -e cycles,instructions,cache-misses,branch-misses -- sleep 12` → IPC, misses (includes BPF run in the game's context) · `perf c2c record -a` → cache-line contention; raise the sample rate for cake lines · `/proc/stat` and `/proc/interrupts` deltas → per-CPU IRQ time, the sink set (09-02: nvidia 7.8k/s on CPU 13, xhci 1.6k/s on CPU 9) · `cpupower frequency-info` → clock as a covariate · `lstopo --no-io`, `numactl -H`, `thread_siblings_list` → topology (cpu c pairs with c^8 here) · `vmstat 1`, `btop`, `ps -eo pcpu,comm --sort=-pcpu` → saturation and noise sources |
| IO, network | `vmstat 1` (`bi/bo`, `wa`) → disk stalls behind a hitch · `ss -lx \| grep mangohud` → MangoHud socket · `ethtool -S enp10s0` → NIC drops · `bpftrace` block/net tracepoints → IO-completion wake chains |
| GPU | `nvidia-smi dmon -s pucvt -d 1` → GPU- vs CPU-bound, clock drops · `nvidia-smi -q -d PERFORMANCE` → throttle reasons · MangoHud `gpu_load`, `gpu_power`, `gpu_core_clock` columns → GPU state per arm · `vulkaninfo --summary` → device and driver sanity · `gamescope` → take KWin out of a pacing question |
| Game | MangoHud (`log_duration=60`, `control=mangohud-%p`, logs in `~/Benchmarks`) → the frames every score uses · `kdotool windowactivate` → focus the game · `spectacle -b -n -o x.png` → see the scene · `setsid steam -applaunch 824270 &` → KovaaK's (Palworld 1623730) |

## ✅ Rules that keep a number true

| Rule |
|---|
| Validity before value: scheduler identity from the log, binary from the receipt |
| No builds or agents during a live capture (a build in a slot contaminated cycle 32 on 2026-09-02) |
| Rotate arms (A B B A, A B C C B A): slot position moves tails as much as the scheduler |
| Noise is a covariate shared by every arm of a rotation, never a gate; record it |
| p99.9 needs frames: an 8 s slot has 5 frames in the 0.1 % band; use 20 s slots or accumulate |
