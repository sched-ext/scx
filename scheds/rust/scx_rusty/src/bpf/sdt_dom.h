#include <scx/common.bpf.h>

#include <lib/sdt_task.h>

#define SCX_CPUMASK_MAX_SIZE (4)

struct sdt_dom_map_val {
	union sdt_id		tid;

	struct bpf_spin_lock vtime_lock;
	struct bpf_cpumask __kptr *cpumask;
	struct bpf_cpumask __kptr *direct_greedy_cpumask;
	struct bpf_cpumask __kptr *node_cpumask;

	struct dom_ctx __arena	*domc;
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
struct dom_ctx __arena *sdt_dom_alloc(u32 dom_id)
{
	struct sdt_data __arena *data = NULL;
	struct sdt_dom_map_val mval;
	struct dom_ctx *domc;
	int ret;

	data = sdt_alloc(&sdt_dom_allocator);
	cast_kern(data);

	mval.tid = data->tid;
	mval.domc = (struct dom_ctx __arena *)data->payload;

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
void sdt_dom_free(struct dom_ctx *domc)
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

static struct dom_ctx *try_lookup_dom_ctx_arena(u32 dom_id)
{
	struct sdt_dom_map_val *mval;

	mval = sdt_dom_val(dom_id);
	if (!mval)
		return NULL;

	return mval->domc;
}

static struct dom_ctx *try_lookup_dom_ctx(u32 dom_id)
{
	struct dom_ctx __arena *domc;

	domc = try_lookup_dom_ctx_arena(dom_id);

	cast_kern(domc);

	return domc;
}

static struct dom_ctx *lookup_dom_ctx(u32 dom_id)
{
	struct dom_ctx *domc;

	domc = try_lookup_dom_ctx(dom_id);
	if (!domc)
		scx_bpf_error("Failed to lookup dom[%u]", dom_id);

	return domc;
}

static struct bpf_spin_lock *lookup_dom_vtime_lock(struct dom_ctx *domc)
{
	struct sdt_dom_map_val *mval;

	mval = sdt_dom_val(domc->id);
	if (!mval) {
		scx_bpf_error("Failed to lookup dom map value");
		return NULL;
	}

	return &mval->vtime_lock;
}
