/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#include "cost.bpf.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>



/*
 * Converts a fallback DSQ to a cost id for accessing a cost struct.
 */
static __always_inline int fallback_dsq_cost_id(u64 fallback_dsq)
{
	if (fallback_dsq < HI_FALLBACK_DSQ_BASE) {
		scx_bpf_error("invalid fallback dsq");
		return 0;
	}
	return (int)fallback_dsq - HI_FALLBACK_DSQ_BASE;
}

/*
 * Returns the fallback DSQ id for a budget id.
 */
static u64 budget_id_to_fallback_dsq(u32 budget_id)
{
	if (budget_id == MAX_GLOBAL_BUDGETS)
		return LO_FALLBACK_DSQ;
	return HI_FALLBACK_DSQ_BASE + budget_id;
}

/*
 * Returns true if the cost has preferred fallback DSQ budget
 */
static bool has_pref_fallback_budget(struct cost *costc)
{
	return costc->pref_budget > nr_layers && costc->pref_budget <= MAX_GLOBAL_BUDGETS;
}

/*
 * Map used for global cost accounting. Can be extended to support NUMA nodes.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cost);
	__uint(max_entries, 1);
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
 * Initializes a budget.
 */
static __noinline void initialize_budget(struct cost *costc, u32 budget_id, s64 capacity)
{
	if (budget_id >= MAX_GLOBAL_BUDGETS) {
		scx_bpf_error("invalid budget id %d", budget_id);
		return;
	}
	costc->capacity[budget_id] = capacity;
	costc->budget[budget_id] = capacity;
}

/*
 * Calculates the preferred budget and layer based based on maximum budget.
 */
static void calc_preferred_cost(struct cost *costc)
{
	u32 layer_id, id, budget_id, pref_budget = 0, max_layer = 0;
	s64 max_budget = 0;
	u64 dsq_id;
	u32 rotation = bpf_get_smp_processor_id() % nr_layers;

	bpf_for(id, 0, nr_layers) {
		/* 
		 * If there is two equally weighted layers that have the same
		 * budget we rely on rotating the layers based on the cpu. This
		 * may not work well on low core machines.
		 */
		layer_id = rotate_layer_id(id, rotation);
		if (layer_id > nr_layers) {
			scx_bpf_error("invalid layer");
			return;
		}
		if (costc->budget[layer_id] > max_budget) {
			max_budget = costc->budget[layer_id];
			max_layer = layer_id;
			pref_budget = max_layer;
		}
	}
	// Hi fallback DSQs
	bpf_for(id, 0, nr_llcs) {
		if (costc->budget[id] > max_budget) {
			max_budget = costc->budget[id];
			pref_budget = id;
		}
	}
	budget_id = fallback_dsq_cost_id(LO_FALLBACK_DSQ);
	if (budget_id > MAX_GLOBAL_BUDGETS) {
		scx_bpf_error("invalid budget");
		return;
	}
	if (costc->budget[budget_id] > max_budget) {
		pref_budget = budget_id;
	}

	costc->pref_layer = max_layer;
	costc->pref_budget = pref_budget;

	return;
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
int record_cpu_cost(struct cost *costc, u32 budget_id, s64 amount)
{
	if (budget_id > MAX_GLOBAL_BUDGETS || !costc) {
		scx_bpf_error("invalid budget %d", budget_id);
		return 0;
	}

	__sync_fetch_and_sub(&costc->budget[budget_id], amount);

	if (costc->budget[budget_id] <= 0) {
		if (costc->has_parent) {
			s64 budget = acquire_budget(costc, budget_id,
						    costc->capacity[budget_id] + amount);
			if (budget > 0) {
				__sync_fetch_and_add(&costc->budget[budget_id],
						     costc->capacity[budget_id]);
			}
		}
	}
	calc_preferred_cost(costc);

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
	struct cost *costc, *global_costc;
	int layer_id, llc_id;
	u64 dsq_id, layer_weight_dur, layer_weight_sum = 0;
	s32 cpu;
	u32 budget_id;

	bpf_for(layer_id, 0, nr_layers) {
		layer = &layers[layer_id];
		if (!layer) {
			scx_bpf_error("failed to lookup layer %d", layer_id);
			return;
		}
		layer_weight_sum += layer->weight;
	}
	layer_weight_sum += HI_FALLBACK_DSQ_WEIGHT;
	layer_weight_sum += LO_FALLBACK_DSQ_WEIGHT;

	global_costc = initialize_cost(COST_GLOBAL_KEY, COST_GLOBAL_KEY,
				       false, false, false);
	if (!global_costc) {
		scx_bpf_error("failed to initialize global budget");
		return;
	}

	bpf_for(layer_id, 0, nr_layers) {
		layer = &layers[layer_id];
		if (!layer) {
			scx_bpf_error("failed to lookup layer %d", layer_id);
			return;
		}

		layer_weight_dur = (layer->weight * ((u64)refresh_intvl_ns * slice_ns * nr_possible_cpus)) /
				    layer_weight_sum;
		initialize_budget(global_costc, layer_id, (s64)layer_weight_dur);
		trace("COST GLOBAL[%d][%s] budget %lld",
		      layer_id, layer->name, global_costc->budget[layer_id]);

		// TODO: add L3 budgets for topology awareness

		bpf_for(cpu, 0, nr_possible_cpus) {
			costc = initialize_cost(cpu, COST_GLOBAL_KEY, true,
						true, false);
			if (!costc) {
				scx_bpf_error("failed to cpu budget: %d", cpu);
				return;
			}
			layer_weight_dur = (layer->weight * slice_ns * refresh_intvl_ns) /
					    layer_weight_sum;
			initialize_budget(costc, layer_id, (s64)layer_weight_dur);
			if (cpu == 0)
				trace("COST CPU[%d][%d][%s] budget %lld",
				      cpu, layer_id, layer->name, costc->budget[layer_id]);
		}
	}

	/*
	 * XXX: since any task from any layer can get kicked to the fallback
	 * DSQ we use the default slice to calculate the default budget.
	 */
	layer_weight_dur = (LO_FALLBACK_DSQ_WEIGHT * slice_ns * refresh_intvl_ns * nr_possible_cpus) /
			    layer_weight_sum;
	initialize_budget(global_costc, fallback_dsq_cost_id(LO_FALLBACK_DSQ),
			  (s64)layer_weight_dur);

	bpf_for(llc_id, 0, nr_llcs) {
		dsq_id = llc_hi_fallback_dsq_id(llc_id);
		budget_id = fallback_dsq_cost_id(dsq_id);

		layer_weight_dur = (HI_FALLBACK_DSQ_WEIGHT * slice_ns * refresh_intvl_ns * nr_possible_cpus) /
				    layer_weight_sum;
		initialize_budget(global_costc, budget_id, (s64)layer_weight_dur);

		bpf_for(cpu, 0, nr_possible_cpus) {
			costc = lookup_cpu_cost(cpu);
			if (!costc) {
				scx_bpf_error("failed to cpu budget: %d", cpu);
				return;
			}

			// On first iteration always setup the lo fallback dsq budget.
			if (llc_id == 0) {
				budget_id = fallback_dsq_cost_id(LO_FALLBACK_DSQ);
				layer_weight_dur = (LO_FALLBACK_DSQ_WEIGHT * slice_ns * refresh_intvl_ns) /
						    layer_weight_sum;
				initialize_budget(costc, budget_id,
						  (s64)layer_weight_dur);
			}

			layer_weight_dur = (HI_FALLBACK_DSQ_WEIGHT * slice_ns * refresh_intvl_ns) /
					    layer_weight_sum;
			initialize_budget(costc, budget_id, (s64)layer_weight_dur);
			if (cpu == 0 && llc_id == 0 && budget_id < MAX_GLOBAL_BUDGETS)
				trace("COST CPU DSQ[%d][%d] budget %lld",
				      cpu, budget_id, costc->budget[budget_id]);
		}
	}
}
