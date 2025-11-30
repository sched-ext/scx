#include <scx/common.bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/* 
 * XXXETSAL Single counter for now, can adjust later. All the code
 * except for bpf_perf_event_read_value is compatible with multiple
 * counters.
 */
#define SCX_MAX_PMU_COUNTERS (1)

/* Cannot define an array of per-cpu counters, do so manually. */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 4096);
} scx_pmu_map SEC(".maps");

/*
 * Per-task PMU counter value snapshot. The value for each index
 * corresponds to the last value found for the counter. The generation
 * is used to lazily invalidate values from uninstalled events.
 */
struct scx_pmu_counters {
	u64 start[SCX_MAX_PMU_COUNTERS];
	u64 agg[SCX_MAX_PMU_COUNTERS];
	bool switched;
	u32 gen;
};

/* PMU event to index in the perf array. */
u64 scx_event_idx[SCX_MAX_PMU_COUNTERS];

/* Start at 1 so that the initial per-task counter vals are invalid at gen 0. */
u64 scx_pmu_gen = 1;

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u32);
	__type(value, struct scx_pmu_counters);
} scx_pmu_tasks SEC(".maps");

int scx_pmu_event_stop(struct task_struct __arg_trusted *p)
{
	struct scx_pmu_counters *cntrs;
	struct bpf_perf_event_value value;
	int idx;
	int ret;

	cntrs = bpf_task_storage_get(&scx_pmu_tasks, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cntrs)
		return -ENOENT;

	bpf_for(idx, 0, SCX_MAX_PMU_COUNTERS) {
		/* Is the counter even installed? */
		if (scx_event_idx[idx] == 0ULL)
			continue;

		/*
		 * We updated the counters we were using. Invalidate
		 * previous measurements.
		 */
		if (unlikely(cntrs->gen != scx_pmu_gen)) {
			cntrs->agg[idx] = 0;
			continue;
		}

		ret = bpf_perf_event_read_value(&scx_pmu_map, BPF_F_CURRENT_CPU, &value, sizeof(value));
		if (ret)
			return ret;

		if (unlikely(!cntrs->switched && value.enabled != value.running)) {
			bpf_printk("SWITCHED: %ld vs %ld", value.enabled, value.running);
			cntrs->switched = true;
		}

		/* Add the delta for this scheduling interval. */
		cntrs->agg[idx] += value.counter - cntrs->start[idx];

	}

	cntrs->gen = scx_pmu_gen;

	return 0;
}

int scx_pmu_event_start(struct task_struct __arg_trusted *p, bool update)
{
	struct bpf_perf_event_value value;
	struct scx_pmu_counters *cntrs;
	int idx;
	int ret;

	cntrs = bpf_task_storage_get(&scx_pmu_tasks, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cntrs)
		return -ENOENT;

	bpf_for(idx, 0, SCX_MAX_PMU_COUNTERS) {
		/* Is the counter even installed? */
		if (scx_event_idx[idx] == 0ULL)
			continue;

		/* If we modified the installed counters invalidate and continue. */
		if (unlikely(cntrs->gen != scx_pmu_gen))
			cntrs->agg[idx] = 0;

		ret = bpf_perf_event_read_value(&scx_pmu_map, BPF_F_CURRENT_CPU, &value, sizeof(value));
		if (ret)
			return ret;

		if (update) {
			/* Add the delta for this scheduling interval. */
			cntrs->agg[idx] += value.counter - cntrs->start[idx];
		}

		cntrs->start[idx] = value.counter;

	}

	cntrs->gen = scx_pmu_gen;

	return 0;
}

static
int scx_pmu_event_to_idx(u64 event)
{
	int i;

	bpf_for(i, 0, SCX_MAX_PMU_COUNTERS) {
		if (scx_event_idx[i] == event)
			break;
	}

	/* i == SCX_MAX_PMU_COUNTERS means NOT_FOUND. */
	return i;
}

static
int scx_pmu_find_free_idx(void)
{
	int i;

	bpf_for(i, 0, SCX_MAX_PMU_COUNTERS) {
		if (scx_event_idx[i] == 0ULL)
			break;
	}

	/* i == SCX_MAX_PMU_COUNTERS means array is full. */
	return i;
}

/*
 * Register a task from the PMU tracker.
 */
__weak
int scx_pmu_task_init(struct task_struct __arg_trusted *p)
{
	struct scx_pmu_counters *cntrs;

	cntrs = bpf_task_storage_get(&scx_pmu_tasks, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cntrs)
		return -ENOMEM;

	/* Mark the values as invalid, will only return valid on first schedule. */
	cntrs->gen = 0;

	return 0;
}

/*
 * Unregister a task from the PMU tracker.
 */
__weak
int scx_pmu_task_fini(struct task_struct __arg_trusted *p)
{

	bpf_task_storage_delete(&scx_pmu_tasks, p);

	return 0;
}

/*
 * Start tracking a PMU for all registered tasks. NOTE: This is not the
 * actual perf counter, it is all the module-wide metadata. The counter
 * must be installed by userspace.
 */
__weak
int scx_pmu_install(u64 event)
{
	int idx;

	idx = scx_pmu_find_free_idx();
	if (unlikely(idx >= SCX_MAX_PMU_COUNTERS || idx < 0))
		return -ENOSPC;

	scx_event_idx[idx] = event;

	scx_pmu_gen += 1;

	return 0;
}

/*
 * Stop tracking a PMU for all registered tasks.
 */
__weak
int scx_pmu_uninstall(u64 event)
{
	int idx;

	idx = scx_pmu_event_to_idx(event);
	if (unlikely(idx >= SCX_MAX_PMU_COUNTERS || idx < 0))
		return -ENOENT;

	scx_event_idx[idx] = 0;

	scx_pmu_gen += 1;

	return 0;
}


__weak
int scx_pmu_read(struct task_struct __arg_trusted *p, u64 event, u64 *value, bool clear)
{
	struct scx_pmu_counters *cntrs;
	int idx;

	idx = scx_pmu_event_to_idx(event);
	if (idx == SCX_MAX_PMU_COUNTERS)
		return -EINVAL;

	cntrs = bpf_task_storage_get(&scx_pmu_tasks, p, 0, 0);
	if (!cntrs)
		return -ENOENT;

	if (unlikely(!value))
		return -EINVAL;

	if (unlikely(idx < 0 || idx >= SCX_MAX_PMU_COUNTERS))
		return -EINVAL;

	*value = cntrs->agg[idx];

	if (clear)
		cntrs->agg[idx] = 0;

	return 0;
}

SEC("?tp_btf/sched_switch")
int scx_pmu_switch_tc(u64 *ctx)
{
	struct task_struct *prev, *next;
	int ret;

	prev = (struct task_struct *)ctx[1];
	next = (struct task_struct *)ctx[2];

	if (!prev->pid)
		goto next;

	ret = scx_pmu_event_stop(prev);
	if (ret)
		return ret;

next:
	if (!next->pid)
		return 0;

	/* Skip update when there was no previous task to obtain delta */
	return scx_pmu_event_start(next, false);
}

SEC("?fentry/scx_tick")
int scx_pmu_tick_tc(u64 *ctx)
{
	struct task_struct *p;

	p = bpf_get_current_task_btf();
	if (!p)
		return 0;

	if (!p->pid) {
		return 0;
	}

	/* Tracepoints not allowed to return errors. */
	scx_pmu_event_start(p, true);

	return 0;
}
