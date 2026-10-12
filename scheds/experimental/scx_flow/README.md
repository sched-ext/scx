# scx_flow

### What is it?

scx_flow runs the earliest strict key as the earlier of deadline plus virtual time. It adds [RED](https://web.cs.umass.edu/publication/docs/1993/UM-CS-1993-025.pdf) admission with guarantee-only tolerance plus three PRIQ tiers with insert vtime plus value ordered reject queue outside dispatch plus reclaim on completer credit with tiers-empty fallback plus aged cover. See `src/bpf/intf.h` and `src/bpf/edf.bpf.c`.

### Why?

The goal is to test strict order with prediction in the kernel and see if short bursts reach a CPU sooner. See `src/bpf/intf.h`.

### How it works?

Arrivals pass a gate first, then pass RED with residual plus exceed plus tolerance for the guarantee alone. A zero exceed admits, a critical exceed admits with no swap, else a bounded O(1) newcomer test still decides. Each CPU takes the earliest key it may run. See `src/bpf/enqueue.bpf.c` and `src/bpf/dispatch.bpf.c`.

## Typical Use Cases

- Latency-sensitive applications.
- General desktop use.
- Mixed batch workloads.

## More details

### Queues

Local plus node plus machine plus reject hold tasks across 1042 queues. Each pass drains three PRIQ tiers plus steal with move capped by slots and 8 visits plus reclaim when empty plus aged past period. Reject stays value ordered outside dispatch with overflow name for wire compat. See `src/bpf/intf.h`.

### Keys

Each strict key sets queue rank with vruntime pacing via lag bounds. Predictor shapes deadlines with shift updates. Virtual deadline adds dynamic slice over weight with one divide. Strict key holds earlier of deadline plus virtual deadline with 2ms clamp still. Remaining feeds slice plus slack only now. See `src/bpf/intf.h`.

### Admission

RED checks residual from deadline minus cost plus tolerance of zero for critical else `64us`. Newcomer victim needs cost past `128us` plus past exceed plus never critical, else admits. Newcomer-pays trades choice for bounded O(1) admission and tiers-empty plus aged reclaim bounds starvation with no drop. See `src/bpf/edf.bpf.c` and `src/rust/config.rs`.

### Gates

A gate runs first so tasks and CPUs wait. Exiting work runs at once with no wait and no gate. Fails join the value ordered reject queue with no leak. Drain stays gated with mask wins. Eligibility gates every kick, so hogs pace while lagging tasks still wake. See `src/bpf/cgroup.bpf.c`.

### Reporting

Flags `--stats`, `--monitor`, and `--no-webui` show counters as text or page at `50005`. Page keeps local, node, machine, kicks, preempt, plus RED rejects plus reclaims. Snapshots share one moment with times plus topology. Dashboard shows seventeen counters plus uptime with CPU cards plus five key merged JSON intact. See `src/rust/stats.rs`.

### Fairness

Strict order holds the earlier of deadline plus virtual deadline in each queue. Vruntime advances by slice over weight with lag clamp. Sleepers gain one slice of boost with no storm. Adaptive steps change the slice with no virtual change. Hierarchy stays flat with no share past weight. See `src/bpf/intf.h`.

### Weights

Weight tunes period bands. Shares map to 32ms, 16ms, 8ms, 4ms periods with shares 32, 64, 256, and 1024. Effective share stacks task times hint over 128 with zero mapped to 128. Heavy tasks earn near keys, light tasks earn far keys. Value holds weight with top critical. See `src/bpf/cgroup.bpf.c`.

### Locality

Locality stays with per-CPU plus per-node queues. Select takes prev idle, then waker and sibling idle, before the pick, so pairs share cache still. Placement keeps the slowest sufficient CPU with prev tie plus near minimum now. Two-way SMT assumed. Span equals online CPUs with no hotplug use. See `src/bpf/select_cpu.bpf.c`.

### Contention

Contention stays bounded with 8 visits per pass across three PRIQ tiers plus steal. Each tier moves task by slots. Steal scans 4 to 8 peers node-local first. Reclaim moves reject when tiers hold no work plus aged past period. Twelve peers cover one percent on 1024 CPUs. See `src/bpf/dispatch.bpf.c`.

### Inversion

Mask wins bound inversion with fail open. Each move checks the CPU mask and picks time first, so heads skip to the next task and tier. Reject stays outside dispatch with reclaim on same key or after. Local on stays terminal at three sites with no global use. See `src/bpf/dispatch.bpf.c`.

### Staleness

Staleness heals retrain plus fold. Stop feeds average deviation plus credit. Yields carry `10us` plus `1ms` when critical plus wall meets, else shrink `exceed>>3` capped `256us` on late else grow `slack>>3` capped `256us` on early. Misses stay lifetime, adapt window. Reclaim `128us` fallback when tiers hold no work. See `src/bpf/lifecycle.bpf.c`.

### Latency

Latency caps slice at `100us` plus key at now plus max `4ms` else slice plus `100us` with RED on deadline. Sleep below `20us` vetoes toward batch with unknown open, decoupled from the `100us` cap. Arrival preempts only when lat meets batch owner else fails closed. Resume keeps start plus cur leftover clamped to `10us` plus `100us` else `1ms`. See `src/bpf/intf.h` plus `src/bpf/preempt.bpf.c` plus `src/bpf/lifecycle.bpf.c`.

## Code map

- Rules live in `src/bpf/intf.h` with RED plus adapt helpers.
- Core lives in cgroup, weight, vtime, edf, placement, select, enqueue, preempt, dispatch, lifecycle, stats, and timer, with select plus enqueue split.
- Init lives in main plus topology still.
- Dashboard lives in snapshot, stats, topology, webui, and ui now even today still.

## Limitations

- Hotplug needs restart.
- Needs kernel `7.2` or newer.
