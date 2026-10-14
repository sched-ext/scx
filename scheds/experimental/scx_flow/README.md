# scx_flow

### What is it?

scx_flow runs the earliest strict key as the earlier of deadline plus virtual time. It adds [RED](https://web.cs.umass.edu/publication/docs/1993/UM-CS-1993-025.pdf) admission with guarantee-only tolerance plus five tiers with insert vtime plus value ordered reject queue outside dispatch plus reclaim on completer credit with tiers-empty fallback plus aged cover. See `src/bpf/intf.h` and `src/bpf/edf.bpf.c`.

### Why?

The goal is to test strict order with prediction in the kernel and see if short bursts reach a CPU sooner. See `src/bpf/intf.h`.

### How it works?

Arrivals pass a gate first, then pass RED with residual plus exceed plus tolerance for the guarantee alone. A zero exceed admits, a critical exceed admits without a swap, else an O(1) newcomer test still decides. Each CPU takes the earliest key it may run. See `src/bpf/enqueue.bpf.c` and `src/bpf/dispatch.bpf.c`.

## Typical Use Cases

- Latency-sensitive applications.
- General desktop use.
- Mixed batch workloads.

## More details

### Queues

Local plus node plus machine plus reject hold tasks across 1042 queues. Each pass drains three PRIQ tiers (local plus node plus machine) plus value ordered reject plus steal for five dispatch tiers total with move capped by slots and 8 visits plus reclaim when empty plus aged past period. Reject stays value ordered outside dispatch with overflow name for wire compat. Direct plus exiting LOCAL_ON stays terminal FIFO outside PRIQ order with no tier rank. Six latency ceilings name burst sizes apart from dispatch tiers. See `src/bpf/intf.h`.

### Keys

Each strict key sets queue rank with vruntime pacing via lag bounds. Predictor shapes deadlines with up plus down shifts plus half deviation margin. Virtual deadline adds dynamic slice over weight with one divide. Strict key holds earlier of deadline plus virtual deadline with 2ms clamp still. Remaining feeds slice plus slack only now. See `src/bpf/intf.h`.

### Admission

RED checks residual from deadline minus cost plus fixed tolerance of zero for latency-critical else `64us` for hard batch with hard scoped to non-latency via the unified test. Admit plus reclaim share the same fixed path, so both agree. Newcomer victim needs cost past fixed `256us Emax` plus past exceed plus never latency-critical, else admits. Newcomer-pays trades choice for single-check admission and tiers-empty plus aged reclaim caps starvation without dropping. Fixed bounds gate overload plus PRIQ only for tiers with LOCAL_ON terminal. See `src/bpf/edf.bpf.c` and `src/rust/config.rs`.

### Gates

A gate runs first so tasks and CPUs wait. Exiting work runs at once without waiting. Fails join the value ordered reject queue without leaking. Drain stays gated with mask wins. Eligibility gates every kick, so hogs pace while lagging tasks still wake. See `src/bpf/cgroup.bpf.c`.

### Reporting

Flags `--stats`, `--monitor`, and `--no-webui` show counters as text or page at `50005`. Page keeps local, node, machine, kicks, preempt, plus RED rejects plus reclaims. Snapshots share one moment with times plus topology. Dashboard shows sixteen counters plus uptime with CPU cards plus five key merged JSON intact. See `src/rust/stats.rs`.

### Fairness

Strict order holds the earlier of deadline plus virtual deadline in each queue. Vruntime advances by slice over weight with lag clamp. Sleepers gain one slice of boost. Adaptive steps change the slice without changing virtual time. Hierarchy stays flat. See `src/bpf/intf.h`.

### Weights

Weight tunes period bands. Shares map to 32ms, 16ms, 8ms, 4ms periods with shares 32, 64, 256, and 1024. Effective share stacks task times hint over 128 with zero mapped to 128. Heavy tasks earn near keys, light tasks earn far keys. Value holds weight with top critical. See `src/bpf/cgroup.bpf.c`.

### Locality

Locality stays with per-CPU plus per-node queues. Select takes prev idle, then waker and sibling idle, before the pick, so pairs share cache still. Placement keeps the slowest sufficient CPU with prev tie plus near minimum now. Two-way SMT assumed. Span equals online CPUs with no hotplug use. See `src/bpf/select_cpu.bpf.c`.

### Contention

One pass stays capped with 8 visits per pass across five tiers. Each tier moves task by slots. Steal scans 4 to 8 peers node-local first. Reclaim moves reject when tiers hold no work plus aged past period. Twelve peers cover one percent on 1024 CPUs. See `src/bpf/dispatch.bpf.c`.

### Inversion

Mask check caps inversion with fail open. Each move checks the CPU mask and picks time first, so heads skip to the next task and tier. Reject stays outside dispatch with reclaim on same key or after. Local on stays terminal FIFO at three sites outside PRIQ order. See `src/bpf/dispatch.bpf.c`.

### Staleness

Staleness heals math plus fold. Stop feeds average plus deviation plus credit with no sampling. Average rises with shift `3` plus falls with shift `4`, deviation widens with shift `2` plus narrows with shift `3`, and period adds average plus deviation plus half deviation. Yields carry `10us` plus `1ms` when critical plus wall meets, else shrink `exceed>>3` capped `1ms` plus half then halved per stop on late else grow `slack>>3` capped `1ms` plus half then halved per stop on early with deadband hold. Misses stay lifetime, adapt window. Reclaim shares the fixed `64us tol` plus `256us Emax` with admit and falls back without reserve when tiers hold no work. See `src/bpf/lifecycle.bpf.c`.

### Latency

Latency caps slice at `100us` plus key at now plus max `4ms` else slice plus `100us` with RED on deadline. Sleep below `20us` vetoes toward batch with unknown open, decoupled from the `100us` cap. Arrival preempts only when lat meets batch owner else fails closed with the strict key driving kick and margin plus tail still checked while placement tests the deadline plus drain. Kick threads the pre-overwrite sleep, so it agrees with RED plus slice. Resume keeps start plus cur leftover clamped to `10us` plus `100us` else `1ms`. Adapt steps cap at `1ms` then re-clamp here, so one shift never holds past the cap with fixed `256us Emax` past the cap. See `src/bpf/intf.h` plus `src/bpf/preempt.bpf.c` plus `src/bpf/lifecycle.bpf.c`.

### Tiers

Tiers pace bursts at `50us` plus `100us` plus `500us` plus `1ms` plus `5ms` with a `20ms` ceiling plus a `10us` floor under an `80ms` period. Predicted burst maps avg plus dev plus half dev margin to the ceiling with critical forced to `50us`, so audio plus UI plus IPC plus desktop plus bulk work hold room without starving. Six latency ceilings name burst sizes apart from five dispatch tiers. Fresh waits cap the dynamic slice by the tier capped at `1ms`, so small bursts pace tightly while bulk still rotates each quantum. Like fair.c, tiers pace service with no fixed hold. See `src/bpf/intf.h` plus `src/rust/config.rs`.

### Prediction

Prediction keeps math-only average plus deviation with no model. Average rises fast with shift `3` plus falls slow with shift `4`, deviation widens fast with shift `2` plus narrows slow with shift `3`, and period adds average plus deviation plus half deviation margin with `1ns` to `1s` clamp. Adapt adds proportional deadband at base shift `5` floor `8us` plus half-damp shift `1` capping one step at one quarter base, so timer jitter never hunts and ringing halves each stop. Fixed `64us` tolerance plus `256us Emax` gate overload with task at `72B` plus stats at `136B`. See `src/bpf/intf.h`.

## Code map

- Rules live in `src/bpf/intf.h` with RED plus adapt helpers.
- Core lives in cgroup, weight, vtime, edf, placement, select, enqueue, preempt, dispatch, lifecycle, stats, and timer, with select plus enqueue split.
- Init lives in main plus topology still.
- Dashboard lives in snapshot, stats, topology, webui, and ui now even today still.

## Limitations

- Hotplug needs restart.
- Needs kernel `7.2` or newer.
