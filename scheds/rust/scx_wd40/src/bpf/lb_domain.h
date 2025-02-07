
#include <lib/sdt_task.h>

struct lb_domain {
	union sdt_id		tid;

	struct bpf_spin_lock vtime_lock;
	struct bpf_cpumask __kptr *cpumask;
	struct bpf_cpumask __kptr *direct_greedy_cpumask;
	struct bpf_cpumask __kptr *node_cpumask;

	dom_ptr domc;
};

extern volatile dom_ptr dom_ctxs[MAX_DOMS];
extern struct sdt_allocator lb_domain_allocator;

int lb_domain_init(void);
dom_ptr lb_domain_alloc(u32 dom_id);
void lb_domain_free(dom_ptr domc);
struct lb_domain *lb_domain_get(u32 dom_id);
dom_ptr try_lookup_dom_ctx(u32 dom_id);
dom_ptr lookup_dom_ctx(u32 dom_id);
struct bpf_spin_lock *lookup_dom_vtime_lock(dom_ptr domc);

__weak s32 create_node(u32 node_id);
__weak s32 create_dom(u32 dom_id);
int dom_xfer_task(struct task_struct *p __arg_trusted, u32 new_dom_id, u64 now);

extern const volatile u32 load_half_life;
extern const volatile u32 debug;
extern const volatile u64 numa_cpumasks[MAX_NUMA_NODES][MAX_CPUS / 64];
extern volatile u64 slice_ns;
extern const volatile u32 nr_doms;
extern const volatile u32 nr_nodes;

struct task_ctx *lookup_task_ctx(struct task_struct *p);
struct task_ctx *try_lookup_task_ctx(struct task_struct *p);
extern struct bpf_cpumask __kptr *all_cpumask;
u32 dom_node_id(u32 dom_id);
void dom_dcycle_adj(dom_ptr domc, u32 weight, u64 now, bool runnable);

static inline u64 min(u64 a, u64 b)
{
	return a <= b ? a : b;
}

static inline
s32 create_save_cpumask(struct bpf_cpumask **kptr)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		scx_bpf_error("Failed to create cpumask");
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(kptr, cpumask);
	if (cpumask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(cpumask);
	}

	return 0;
}

static inline
bool cpumask_intersects_domain(const struct cpumask *cpumask, u32 dom_id)
{
	struct lb_domain *lb_domain;
	struct bpf_cpumask *dmask;

	lb_domain = lb_domain_get(dom_id);
	if (!lb_domain)
		return false;

	dmask = lb_domain->cpumask;
	if (!dmask)
		return false;

	return bpf_cpumask_intersects(cpumask, cast_mask(dmask));
}


int stat_add(enum stat_idx idx, u64 addend);
static inline u64 dom_min_vruntime(dom_ptr domc)
{
	return READ_ONCE_ARENA(u64, domc->min_vruntime);
}

void place_task_dl(struct task_struct *p, struct task_ctx *taskc,
			  u64 enq_flags);

void running_update_vtime(struct task_struct *p,
				 struct task_ctx *taskc,
				 dom_ptr domc);
void stopping_update_vtime(struct task_struct *p, struct task_ctx *taskc,
				  dom_ptr domc);

u64 update_freq(u64 freq, u64 interval);
void init_vtime(struct task_struct *p, struct task_ctx *taskc);
void task_pick_and_set_domain(struct task_ctx *taskc,
				     struct task_struct *p,
				     const struct cpumask *cpumask,
				     bool init_dsq_vtime);
bool task_set_domain(struct task_struct *p __arg_trusted,
			    u32 new_dom_id, bool init_dsq_vtime);
struct task_ctx *lookup_task_ctx_mask(struct task_struct *p, struct bpf_cpumask **p_cpumaskp);

/*
 * Per-CPU context
 */
struct pcpu_ctx {
	u32 dom_rr_cur; /* used when scanning other doms */
	u32 dom_id;
	struct bpf_cpumask __kptr *bpfmask;
} __attribute__((aligned(CACHELINE_SIZE)));

extern struct pcpu_ctx pcpu_ctx[MAX_CPUS];

/*
 * XXX We do not want to be sharing functions from main to other modules,
 * but since we are implementing arena CPU masks the code below is on its
 * way out anyway.
 */

struct bpfmask_wrapper {
	struct bpf_cpumask __kptr *instance;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct task_struct *);
	__type(value, struct bpfmask_wrapper);
	__uint(max_entries, 1000000);
	__uint(map_flags, 0);
} task_masks __weak SEC(".maps");

static inline
struct bpf_cpumask *lookup_task_bpfmask(struct task_struct *p)
{
	struct bpfmask_wrapper *wrapper;

	wrapper = bpf_map_lookup_elem(&task_masks, &p);
	if (!wrapper) {
		scx_bpf_error("lookup_mask_bpfmask failed for task %p", p);
		return NULL;
	}

	return wrapper->instance;
}
