#include <scx/common.bpf.h>

#include <lib/sdt_task.h>

#define SCX_CPUMASK_MAX_SIZE (4)

struct sdt_dom_map_val {
	union sdt_id		tid;

	struct sdt_data __arena	*data;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct sdt_dom_map_val);
	__uint(max_entries, MAX_DOMS);
	__uint(map_flags, 0);
} sdt_dom_map SEC(".maps");

struct sdt_allocator sdt_dom_allocator;

static __always_inline
int sdt_dom_init(void)
{
	return sdt_alloc_init(&sdt_dom_allocator, sizeof(struct dom_ctx));
}

static __always_inline
struct dom_ctx __arena *sdt_dom_alloc(void)
{
	struct sdt_data __arena *data = NULL;
	struct sdt_dom_map_val mval;
	struct dom_ctx *dom;
	u64 key;
	int ret;

	data = sdt_alloc(&sdt_dom_allocator);
	cast_kern(data);

	mval.tid = data->tid;
	mval.data = data;

	key = (u64) data;
	ret = bpf_map_update_elem(&sdt_dom_map, &key, &mval,
				    BPF_NOEXIST);
	if (ret) {
		sdt_free_idx(&sdt_dom_allocator, data->tid.idx);
		return NULL;
	}

	dom = (struct dom_ctx __arena *)data->payload;
	cast_kern(dom);

	return (struct dom_ctx __arena *)data->payload;
}

static __always_inline
void sdt_dom_free(struct dom_ctx *dom)
{
	struct sdt_dom_map_val *mval;
	u64 key = (u64) dom;

	sdt_arena_verify();

	mval = bpf_map_lookup_elem(&sdt_dom_map, &key);
	if (!mval)
		return;

	sdt_free_idx(&sdt_dom_allocator, mval->tid.idx);
	mval->data = NULL;

	bpf_map_delete_elem(&sdt_dom_map, &key);
}
