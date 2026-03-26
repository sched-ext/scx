#include <scx/common.bpf.h>

#include "sdt_task.h"

struct lb_domain {
	union sdt_id		tid;

	struct bpf_spin_lock vtime_lock;
	struct bpf_cpumask __kptr *cpumask;
	struct bpf_cpumask __kptr *direct_greedy_cpumask;
	struct bpf_cpumask __kptr *node_cpumask;

	dom_ptr domc;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct lb_domain);
	__uint(max_entries, MAX_DOMS);
	__uint(map_flags, 0);
} lb_domain_map SEC(".maps");

volatile dom_ptr dom_ctxs[MAX_DOMS];
struct sdt_allocator lb_domain_allocator;

__hidden __noinline
int lb_domain_init(void)
{
	return sdt_alloc_init(&lb_domain_allocator, sizeof(struct dom_ctx));
}

__hidden __noinline
dom_ptr lb_domain_alloc(u32 dom_id)
{
	struct sdt_data __arena *data = NULL;
	struct lb_domain lb_domain;
	dom_ptr domc;
	int ret;

	data = sdt_alloc(&lb_domain_allocator);
	cast_kern(data);

	lb_domain.tid = data->tid;
	lb_domain.domc = (dom_ptr)data->payload;

	ret = bpf_map_update_elem(&lb_domain_map, &dom_id, &lb_domain,
				    BPF_EXIST);
	if (ret) {
		sdt_free_idx(&lb_domain_allocator, data->tid.idx);
		return NULL;
	}

	domc = lb_domain.domc;
	cast_kern(domc);

	return domc;
}

__hidden
void lb_domain_free(dom_ptr domc)
{
	struct lb_domain *lb_domain;
	u32 key = domc->id;

	sdt_subprog_init_arena();

	lb_domain = bpf_map_lookup_elem(&lb_domain_map, &key);
	if (!lb_domain)
		return;

	sdt_free_idx(&lb_domain_allocator, lb_domain->tid.idx);
	lb_domain->domc = NULL;

	bpf_map_delete_elem(&lb_domain_map, &key);
}

static __always_inline
struct lb_domain *lb_domain_get(u32 dom_id)
{
	return bpf_map_lookup_elem(&lb_domain_map, &dom_id);
}

static dom_ptr try_lookup_dom_ctx_arena(u32 dom_id)
{
	struct lb_domain *lb_domain;

	lb_domain = lb_domain_get(dom_id);
	if (!lb_domain)
		return NULL;

	return lb_domain->domc;
}

static dom_ptr try_lookup_dom_ctx(u32 dom_id)
{
	dom_ptr domc;

	domc = try_lookup_dom_ctx_arena(dom_id);

	cast_kern(domc);

	return domc;
}

static dom_ptr lookup_dom_ctx(u32 dom_id)
{
	dom_ptr domc;

	domc = try_lookup_dom_ctx(dom_id);
	if (!domc)
		scx_bpf_error("Failed to lookup dom[%u]", dom_id);

	return domc;
}

static struct bpf_spin_lock *lookup_dom_vtime_lock(dom_ptr domc)
{
	struct lb_domain *lb_domain;

	lb_domain = lb_domain_get(domc->id);
	if (!lb_domain) {
		scx_bpf_error("Failed to lookup dom map value");
		return NULL;
	}

	return &lb_domain->vtime_lock;
}
