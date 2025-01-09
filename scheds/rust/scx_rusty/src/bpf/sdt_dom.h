#include <scx/common.bpf.h>

#include <lib/sdt_task.h>

struct sdt_dom_map_val {
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
	__type(value, struct sdt_dom_map_val);
	__uint(max_entries, MAX_DOMS);
	__uint(map_flags, 0);
} sdt_dom_map SEC(".maps");

struct sdt_allocator sdt_dom_allocator;

__hidden __noinline
int sdt_dom_init(void)
{
	return sdt_alloc_init(&sdt_dom_allocator, sizeof(struct dom_ctx));
}

__hidden __noinline
dom_ptr sdt_dom_alloc(u32 dom_id)
{
	struct sdt_data __arena *data = NULL;
	struct sdt_dom_map_val mval;
	dom_ptr domc;
	int ret;

	data = sdt_alloc(&sdt_dom_allocator);
	cast_kern(data);

	mval.tid = data->tid;
	mval.domc = (dom_ptr)data->payload;

	ret = bpf_map_update_elem(&sdt_dom_map, &dom_id, &mval,
				    BPF_EXIST);
	if (ret) {
		sdt_free_idx(&sdt_dom_allocator, data->tid.idx);
		return NULL;
	}

	domc = mval.domc;
	cast_kern(domc);

	return domc;
}

__hidden
void sdt_dom_free(dom_ptr domc)
{
	struct sdt_dom_map_val *mval;
	u32 key = domc->id;

	sdt_arena_verify();

	mval = bpf_map_lookup_elem(&sdt_dom_map, &key);
	if (!mval)
		return;

	sdt_free_idx(&sdt_dom_allocator, mval->tid.idx);
	mval->domc = NULL;

	bpf_map_delete_elem(&sdt_dom_map, &key);
}

static __always_inline
struct sdt_dom_map_val *sdt_dom_val(u32 dom_id)
{
	return bpf_map_lookup_elem(&sdt_dom_map, &dom_id);
}

static dom_ptr try_lookup_dom_ctx_arena(u32 dom_id)
{
	struct sdt_dom_map_val *mval;

	mval = sdt_dom_val(dom_id);
	if (!mval)
		return NULL;

	return mval->domc;
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
	struct sdt_dom_map_val *mval;

	mval = sdt_dom_val(domc->id);
	if (!mval) {
		scx_bpf_error("Failed to lookup dom map value");
		return NULL;
	}

	return &mval->vtime_lock;
}
