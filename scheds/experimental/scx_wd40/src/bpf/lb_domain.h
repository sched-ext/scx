#pragma once

#include <lib/sdt_task.h>

int lb_domain_init(void);
dom_ptr lb_domain_alloc(u32 dom_id);
void lb_domain_free(dom_ptr domc);
dom_ptr try_lookup_dom_ctx(u32 dom_id);
dom_ptr lookup_dom_ctx(u32 dom_id);

__weak s32 alloc_dom(u32 dom_id);
__weak s32 create_dom(u32 dom_id);
int dom_xfer_task(struct task_struct *p __arg_trusted, u32 new_dom_id, u64 now);

extern volatile scx_bitmap_t node_data[MAX_NUMA_NODES];
extern const volatile u32 load_half_life;
extern const volatile u32 debug;
extern volatile u64 slice_ns;
extern const volatile u32 nr_doms;
extern const volatile u32 nr_nodes;

#define lookup_task_ctx(p) ((task_ptr) scx_task_data(p))
u32 dom_node_id(u32 dom_id);
void dom_dcycle_adj(dom_ptr domc, u32 weight, u64 now, bool runnable);

static inline u64 min(u64 a, u64 b)
{
	return a <= b ? a : b;
}

int stat_add(enum stat_idx idx, u64 addend);
static inline u64 dom_min_vruntime(dom_ptr domc)
{
	return READ_ONCE(domc->min_vruntime);
}

void place_task_dl(struct task_struct *p, task_ptr taskc, u64 enq_flags);
void running_update_vtime(struct task_struct *p, task_ptr taskc);
void stopping_update_vtime(struct task_struct *p);

u64 update_freq(u64 freq, u64 interval);
void init_vtime(struct task_struct *p, task_ptr taskc);
void task_pick_and_set_domain(task_ptr taskc,
				     struct task_struct *p,
				     const struct cpumask *cpumask,
				     bool init_dsq_vtime);
bool task_set_domain(struct task_struct *p __arg_trusted,
			    u32 new_dom_id, bool init_dsq_vtime);
/*
 * Per-CPU context
 */
struct pcpu_ctx {
	u32 dom_rr_cur; /* used when scanning other doms */
	dom_ptr domc;
} __attribute__((aligned(CACHELINE_SIZE)));

extern struct pcpu_ctx pcpu_ctx[MAX_CPUS];
