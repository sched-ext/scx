/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


/*
 * Cost accounting struct that is used in both the per CPU and global context.
 * Budgets are allowed to recurse to parent structs.
 */
struct cost {
	s64		budget[MAX_LAYERS];
	s64		capacity[MAX_LAYERS];
	u32		pref_layer;
	u32		idx;
	bool		overflow;
	bool		has_parent;
};


/*
 * Map used for global cost accounting. Can be extended to support NUMA nodes.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cost);
	__uint(max_entries, MAX_NUMA_NODES + 1);
	__uint(map_flags, 0);
} cost_data SEC(".maps");

/*
 * CPU map for cost accounting. When budget is expired it requests budget from
 * global entries.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cost);
	__uint(max_entries, 1);
} cpu_cost_data SEC(".maps");

static __always_inline struct cost *lookup_cost(u32 cost_id)
{
	struct cost *costc;

	costc = bpf_map_lookup_elem(&cost_data, &cost_id);
	if (!costc) {
		scx_bpf_error("cost not found");
		return NULL;
	}

	return costc;
}

static __always_inline struct cost *lookup_cpu_cost(s32 cpu)
{
	struct cost *costc;
	u32 zero = 0;

	if (cpu < 0)
		costc = bpf_map_lookup_elem(&cpu_cost_data, &zero);
	else
		costc = bpf_map_lookup_percpu_elem(&cpu_cost_data,
						   &zero, cpu);
	if (!costc) {
		scx_bpf_error("cost not found");
		return NULL;
	}

	return costc;
}

/*
 * Initializes a cost.
 */
static struct cost *initialize_cost(u32 cost_idx, u32 parent_idx,
				    bool is_cpu, bool has_parent,
				    bool overflow)
{
	struct cost *costc;

	if (is_cpu) {
		if (!(costc = lookup_cpu_cost(cost_idx)))
			return NULL;
	} else {
		if (!(costc = lookup_cost(cost_idx)))
			return NULL;
	}

	if (has_parent)
		costc->idx = parent_idx;
	else
		costc->idx = cost_idx;

	costc->has_parent = has_parent;
	costc->overflow = overflow;
	costc->pref_layer = bpf_get_smp_processor_id() % nr_layers;

	return costc;
}

/*
 * Initializes the cost of a layer.
 */
static void initialize_cost_layer(struct cost *costc, u32 layer_id, s64 capacity)
{
	costc->capacity[layer_id] = capacity;
	costc->budget[layer_id] = capacity;
}

/*
 * Returns the preferred layer based on the layer with the maximum budget.
 */
static u32 preferred_cost(struct cost *costc)
{
	u32 layer_id, id, max_layer = 0;
	s64 max_budget = 0;
	u32 rotation = bpf_get_smp_processor_id() % nr_layers;

	bpf_for(id, 0, nr_layers) {
		// If there is two equally weighted layers that have the same
		// budget we rely on rotating the layers based on the cpu. This
		// may not work well on low core machines.
		layer_id = rotate_layer_id(id, rotation);
		if (layer_id > nr_layers) {
			scx_bpf_error("invalid layer");
			return 0;
		}
		if (costc->budget[layer_id] > max_budget) {
			max_budget = costc->budget[layer_id];
			max_layer = layer_id;
		}
	}

	return max_layer;
}

/*
 * Refreshes the budget of a cost.
 */
int refresh_budget(int cost_id)
{
	struct cost *costc;

	if (!(costc = lookup_cost(cost_id))) {
		scx_bpf_error("failed to lookup cost %d", cost_id);
		return 0;
	}

	u32 layer_id, id;
	u32 rotation = bpf_get_smp_processor_id() % nr_layers;
	bpf_for(id, 0, nr_layers) {
		layer_id = rotate_layer_id(id, rotation);
		if (layer_id > nr_layers) {
			scx_bpf_error("invalid layer");
			return 0;
		}
		s64 capacity = costc->capacity[layer_id];
		__sync_lock_test_and_set(MEMBER_VPTR(*costc, .budget[layer_id]),
					 capacity);
	}

	return 0;
}

/*
 * Refreshes all budgets for all costs.
 */
int refresh_budgets(void)
{
	refresh_budget(0);

	return 0;
}

/*
 * Acquires a budget from a parent cost account.
 */
s64 acquire_budget(struct cost *costc, u32 layer_id, s64 amount)
{
	s64 budget = 0;

	if (layer_id >= MAX_LAYERS || layer_id < 0) {
		scx_bpf_error("invalid parent cost");
		return budget;
	}

	if (!costc || !costc->has_parent)
		return budget;


	struct cost *parent_cost;
	if (!(parent_cost = lookup_cost(costc->idx)))
		return budget;

	__sync_fetch_and_sub(&parent_cost->budget[layer_id], amount);

	if (parent_cost->budget[layer_id] < 0)
		refresh_budgets();

	return amount;
}

/*
 * Records the cost to the CPU budget. If the CPU is out of cost the CPU will
 * acquire budget by either retrieving budget from the global context or
 * refreshing all budgets.
 */
static int record_cpu_cost(struct cost *costc, u32 layer_id, s64 amount)
{
	if (layer_id >= MAX_LAYERS || !costc) {
		scx_bpf_error("invalid layer %d", layer_id);
		return 0;
	}

	__sync_fetch_and_sub(&costc->budget[layer_id], amount);

	if (costc->budget[layer_id] <= 0) {
		if (costc->has_parent) {
			s64 budget = acquire_budget(costc, layer_id,
						    costc->capacity[layer_id] + amount);
			if (budget > 0) {
				__sync_fetch_and_add(MEMBER_VPTR(*costc, .budget[layer_id]),
						     costc->capacity[layer_id]);
			}
		}
	}

	u32 pref_layer = preferred_cost(costc);
	if (pref_layer > nr_layers) {
		scx_bpf_error("invalid pref_layer");
		return 0;
	}

	costc->pref_layer = pref_layer;

	return 0;
}

/*
 * Returns the slice_ns of a layer if there is appropriate budget.
 */
int has_budget(struct cost *costc, struct layer *layer)
{
	if (!layer || !costc) {
		scx_bpf_error("can't happen");
		return 0;
	}

	u32 layer_id = layer->idx;
	if (layer_id > nr_layers) {
		scx_bpf_error("invalid layer %d", layer_id);
		return 0;
	}

	s64 budget = *MEMBER_VPTR(*costc, .budget[layer_id]);
	u64 layer_slice_ns = layer->slice_ns > 0 ? layer->slice_ns : slice_ns;

	if (budget > layer_slice_ns)
		return slice_ns;

	return 0;
}

/*
 * Initializes all budgets.
 */
static void initialize_budgets(u64 refresh_intvl_ns)
{
	struct layer *layer;
	struct cost *costc;
	int layer_id;
	u64 layer_weight_dur, layer_weight_sum = 0;
	s32 cpu;
	u32 global = 0;

	bpf_for(layer_id, 0, nr_layers) {
		layer = &layers[layer_id];
		if (!layer) {
			scx_bpf_error("failed to lookup layer %d", layer_id);
			return;
		}
		layer_weight_sum += layer->weight;
	}

	costc = initialize_cost(global, global, false, false, false);
	if (!costc) {
		scx_bpf_error("failed to initialize global budget");
		return;
	}

	bpf_for(layer_id, 0, nr_layers) {
		layer = &layers[layer_id];
		if (!layer) {
			scx_bpf_error("failed to lookup layer %d", layer_id);
			return;
		}
		u64 layer_slice_ns = layer->slice_ns > 0 ? layer->slice_ns : slice_ns;

		layer_weight_dur = (layer->weight * ((u64)refresh_intvl_ns * nr_possible_cpus)) /
				    layer_weight_sum;
		initialize_cost_layer(costc, layer_id, (s64)layer_weight_dur);
		trace("COST GLOBAL[%d][%s] budget %lld",
		      layer_id, layer->name, costc->budget[layer_id]);

		// TODO: add L3 budgets for topology awareness

		bpf_for(cpu, 0, nr_possible_cpus) {
			costc = initialize_cost(cpu, global, true,
						      true, false);
			if (!costc) {
				scx_bpf_error("failed to cpu budget: %d", cpu);
				return;
			}
			layer_weight_dur = (layer->weight * layer_slice_ns * refresh_intvl_ns) /
					    layer_weight_sum;
			initialize_cost_layer(costc, layer_id, (s64)layer_weight_dur);
			trace("COST CPU[%d][%d][%s] budget %lld",
			      cpu, layer_id, layer->name, costc->budget[layer_id]);
		}
	}
}
