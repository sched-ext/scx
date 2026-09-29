# scx_flow

scx_flow is a Linux deadline scheduler in Rust with a BPF core and 2ms slice.

### Queues

One local queue per CPU plus one shared queue per node plus one queue per machine plus one overflow tail order by deadline with homeless parks in overflow. Drain takes one move per tier in local plus node plus machine plus overflow order. See `src/bpf/intf.h` and `src/bpf/dispatch.bpf.c`.

### Keys

Release sets release plus period plus deadline with virtual runtime for ties. Hints tune the period only with placement taking idle then the previous CPU then the home. See `src/bpf/select_cpu.bpf.c` and `src/bpf/enqueue.bpf.c`.

### Admission

Admission holds use under 95 percent per CPU with 4096 hints. Rejects plus misses park in overflow with one direct kick and no wait. See `src/bpf/cgroup.bpf.c` and `src/bpf/main/deadline.bpf.c`.

### Gates

Gate runs first in every op with fail closed. Stale CPUs plus moved tasks count one gate reject with exiting work exempt. See `src/bpf/main/cpu.bpf.c` and `src/bpf/enqueue.bpf.c`.

### Reporting

Scheduling stays fixed. Reporting uses `--stats`, `--monitor`, and `--no-webui`. The dashboard serves loopback port `50005` with one IPv6 first bind plus counters plus per CPU pids plus SMT plus a snapshot download. Counters cover on CPU plus runtime plus inserts plus requeues plus completions plus local plus node plus machine plus over plus kicks plus admits plus rejects plus misses plus parks plus gate rejects. See `src/rust/stats.rs`.

## Code map

- Rules live in `src/bpf/intf.h`.
- Maps live in `src/bpf/main.bpf.c` with splits in `main/`, `enqueue/`, `dispatch/`.
- Mirrors live in `flow*.rs` with facade in `flow.rs` and checks in `config.rs`.
- Dashboard lives in `snapshot.rs`, `topology.rs`, `stats.rs`, `webui.rs`, `ui/index.html`.

## Limitations

- Hotplug needs a restart.
- Releases need a restart.
- State is `72B` plus `8B` plus `8B` plus `120B`.
- Needs kernels, `7.2` series and up.
