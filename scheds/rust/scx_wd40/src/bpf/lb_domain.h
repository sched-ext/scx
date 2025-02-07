
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
