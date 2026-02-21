# HashMap/HashSet Non-Determinism Audit

**Date**: 2026-02-21
**Scope**: All `HashMap` and `HashSet` usage in `crates/scx_simulator/src/`

## Executive Summary

Four non-determinism sources were found and fixed:

1. `dump_task` loop iterating `HashMap<Pid, SimTask>` in non-deterministic order
2. `exit_task` loop iterating `HashMap<Pid, SimTask>` in non-deterministic order
3. `check_watchdog` returning first match from HashMap iteration (arbitrary PID)
4. `sample_dsq_lengths` iterating DSQs via non-sorted `dsq_ids()`

## Complete HashMap Inventory

### engine.rs

| HashMap | Location | Iterated? | Deterministic? | Status |
|---------|----------|-----------|----------------|--------|
| `tasks: HashMap<Pid, SimTask>` | SimulationResult (L294) | Yes: `tasks.values()` at dump_task (L960), exit_task (L973), check_watchdog (L395), init_task (L668, sorted) | **FIXED** (was non-deterministic) | Sorted by PID |
| `task_raw_to_pid: HashMap<usize, Pid>` | SimulatorState via engine L466 | No (lookup only: `.get()`, `.insert()`, `.remove()`) | N/A | Safe |
| `task_pid_to_raw: HashMap<Pid, usize>` | SimulatorState via engine L467 | No (lookup only) | N/A | Safe |
| `task_cgroup_map: HashMap<Pid, *mut c_void>` | engine L645 (local) | No (lookup only: `.get()`, `.insert()`) | N/A | Safe |
| `per_cpu: HashMap<CpuId, Vec<Event>>` | group_events_by_cpu L273 | Consumers sort before iterating | Already safe | Already fixed |

### kfuncs.rs

| HashMap | Location | Iterated? | Deterministic? | Status |
|---------|----------|-----------|----------------|--------|
| `task_raw_to_pid: HashMap<usize, Pid>` | SimulatorState L98 | No (lookup only) | N/A | Safe |
| `task_pid_to_raw: HashMap<Pid, usize>` | SimulatorState L100 | No (lookup only) | N/A | Safe |
| `task_last_cpu: HashMap<Pid, CpuId>` | SimulatorState L116 | No (lookup only) | N/A | Safe |

### dsq.rs

| HashMap | Location | Iterated? | Deterministic? | Status |
|---------|----------|-----------|----------------|--------|
| `dsqs: HashMap<DsqId, Dsq>` | DsqManager L160 | Yes: `sorted_dsq_ids()` (sorted) | **FIXED** | Removed non-sorted `dsq_ids()` method |

### cgroup.rs

| HashMap | Location | Iterated? | Deterministic? | Status |
|---------|----------|-----------|----------------|--------|
| `cgroups: HashMap<CgroupId, CgroupInfo>` | CgroupRegistry L64 | Yes: `iter_descendants()` sorts children; `Drop` frees (order-independent); `values().find()` for unique lookup | Already safe | No change needed |
| `name_to_id: HashMap<String, CgroupId>` | CgroupRegistry L66 | No (lookup only) | N/A | Safe |

### stats.rs

| HashMap | Location | Iterated? | Deterministic? | Status |
|---------|----------|-----------|----------------|--------|
| `tasks: HashMap<Pid, TaskStats>` | SimulationStats L131 | Yes: summation only (order-independent) | N/A (post-sim) | Safe |
| `cpus: HashMap<CpuId, CpuStats>` | SimulationStats L133 | Yes: summation only | N/A (post-sim) | Safe |
| Various local HashMaps | L152-160 | Lookup only during event replay | N/A (post-sim) | Safe |

### bpf_trace.rs

| HashMap | Location | Iterated? | Deterministic? | Status |
|---------|----------|-----------|----------------|--------|
| `task_names: HashMap<Pid, String>` | L126 | Lookup only | N/A (parsing) | Safe |
| Various local HashMaps | L240-246 | Lookup only during trace replay | N/A (post-sim) | Safe |
| `parse_key_values` return | L564 | Local parsing | N/A (parsing) | Safe |

### rtapp.rs

| HashMap | Location | Iterated? | Deterministic? | Status |
|---------|----------|-----------|----------------|--------|
| `name_to_pid: HashMap<String, Pid>` | L435 | Lookup only | N/A (parsing) | Safe |

### det_hashmap.rs

| HashMap | Location | Iterated? | Deterministic? | Status |
|---------|----------|-----------|----------------|--------|
| `DetHashMap<K, V>` wrapper | L41 | Yes: all iteration methods sort keys | Deterministic by design | Safe |

### real_run.rs (binary)

| HashMap | Location | Iterated? | Deterministic? | Status |
|---------|----------|-----------|----------------|--------|
| `pid_to_name: HashMap<i32, &str>` | L390 | Lookup only | N/A (UI) | Safe |

## Other Non-Deterministic Patterns Checked

### HashSet
**None found** in the codebase.

### Pointer comparison/sorting
The `sim_cgroup_lookup_ancestor` function uses `values().find()` to match by
raw pointer value. This always returns exactly 0 or 1 results (unique pointers),
so it is deterministic.

### System time reads
All time in the simulator uses `state.clock` or `cpu.local_clock` (simulated time).
No `SystemTime::now()` or `Instant::now()` in simulation paths.

### Thread-local state
Thread-local `SIM_STATE` pointer is set/cleared around each ops callback via
`enter_sim`/`exit_sim`. Deterministic under the token-passing concurrency model.

## Previously Fixed (not in this audit)

- `kicked_cpus` -> BTreeMap (deterministic iteration)
- `task_ops_state` -> BTreeMap (deterministic iteration)
- `init_task` loop -> sorted by PID
- `cgroup children` -> sorted by cgid in `iter_descendants()`
- `per_cpu event batch` -> sorted before processing
