/* Build with pool_regressions.py, which includes the current Cake callbacks. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include "intf.h"

#define CAKE_RMW_FULL(op, ptr, value) __atomic_fetch_##op(ptr, value, __ATOMIC_SEQ_CST)
#define cake_stat_inc(site) ((void)(site))
#define __noinline __attribute__((noinline))
#define SCX_DEQ_SLEEP 1
#define SCX_DSQ_GLOBAL (1ULL << 63)

struct cake_groove { u16 pool_tag; };
struct task_struct {
	struct { u64 slice; } scx;
	struct cake_groove storage;
	u64 verdict_slice;
	bool allocation_failure;
};
struct cake_llc_slot { u64 pending, unserved; };
static struct { struct cake_llc_slot pool[MAX_LLCS]; } cake;
static u32 depth[MAX_LLCS], kicks[MAX_LLCS];
static int cake_grooves, storage_reads;

static struct cake_groove *cake_groove_of(struct task_struct *p)
{
	return p->allocation_failure ? NULL : &p->storage;
}

static struct cake_groove *bpf_task_storage_get(int *map, struct task_struct *p,
						void *value, u64 flags)
{
	assert(map == &cake_grooves && !value && !flags);
	storage_reads++;
	return p->allocation_failure ? NULL : &p->storage;
}

/* Each modeled CPU belongs to its own LLC. */
static u32 cake_llc_of(s32 cpu) { return (u32)cpu; }
static u64 cake_pool_dsq(u32 llc) { return LLC_WAKE_DSQ_BASE + llc; }
static void cake_wake_mark_set(u32 llc) { (void)llc; }

static u64 fallback_flags;
static bool cake_dsq_insert(struct task_struct *p, u64 dsq, u64 slice, u64 flags)
{
	assert(dsq == SCX_DSQ_GLOBAL && !p->verdict_slice);
	p->verdict_slice = slice;
	fallback_flags = flags;
	return true;
}

static bool cake_dsq_insert_vtime(struct task_struct *p, u64 dsq, u64 slice,
				  u64 vtime, u64 flags)
{
	assert(dsq >= LLC_WAKE_DSQ_BASE && !p->verdict_slice);
	(void)vtime;
	(void)flags;
	p->verdict_slice = slice;
	return true;
}

static void land(struct task_struct *p, u32 llc)
{
	assert(p->verdict_slice);
	p->scx.slice = p->verdict_slice;
	p->verdict_slice = 0;
	depth[llc]++;
}

static bool cake_move_to_local(u64 dsq, s32 cpu, s32 count)
{
	u32 llc = dsq - LLC_WAKE_DSQ_BASE;

	assert(cpu == (s32)llc && count == (s32)depth[llc]);
	if (!depth[llc])
		return false;
	depth[llc]--;
	return true;
}

static void scx_bpf_kick_cpu(s32 cpu, u64 flags)
{
	assert(flags == 0);
	kicks[cake_llc_of(cpu)]++;
}

#include "callbacks.h"

static void test_repool(void)
{
	struct task_struct task = {};

	cake_pool_insert(&task, 0, SLICE_NS, 0, 0);
	land(&task, 0);
	depth[0]--;
	task.scx.slice = SLICE_NS;
	cake_pool_seen(&task);
	cake_pool_insert(&task, 1, SLICE_NS, 0, 0);
	assert(!cake.pool[0].pending && cake.pool[1].pending == 1);
	cake_idle_interlock(0);
	assert(!cake.pool[0].unserved && !kicks[0]);
	land(&task, 1);
	assert(cake_pool_serve(cake_pool_dsq(1), 1, 1, depth[1]));
	cake_pool_seen(&task);
	assert(!cake.pool[1].pending && !cake.pool[1].unserved);
}

int main(void)
{
	struct task_struct canceled = {}, overwritten = {}, real = {}, unpooled = {};
	struct task_struct unsupported = { .allocation_failure = true };

	cake_pool_seen(&unpooled);
	cake_quiescent(&unpooled, SCX_DEQ_SLEEP);
	assert(!storage_reads);

	/* An insert verdict precedes kernel publication. Preserve this idle wake. */
	cake_pool_insert(&real, 1, SLICE_NS, 0, 0);
	cake_idle_interlock(1);
	assert(!depth[1] && kicks[1] == 1);

	cake_pool_insert(&canceled, 0, SLICE_NS, 0, 0);
	land(&canceled, 0);
	cake_pool_insert(&overwritten, 0, SLICE_NS, 0, 0);
	land(&overwritten, 0);
	cake_quiescent(&canceled, 0);
	depth[0]--;
	canceled.scx.slice = SLICE_NS;
	cake_quiescent(&canceled, 0);
	assert(cake.pool[0].pending == 1);
	overwritten.scx.slice = SLICE_NS + 2;
	cake_quiescent(&overwritten, 0);
	depth[0]--;
	assert(overwritten.scx.slice == SLICE_NS + 2);
	for (int i = 0; i < 100; i++)
		cake_idle_interlock(0);
	assert(!kicks[0] && !cake.pool[0].pending && !cake.pool[0].unserved);
	assert(cake.pool[1].pending == 1 && cake.pool[1].unserved == 1);

	/* Kernel slice residue can look exactly like the other pool's token. */
	unpooled.scx.slice = SLICE_NS + 2;
	cake_pool_seen(&unpooled);
	cake_quiescent(&unpooled, 0);
	assert(cake.pool[1].pending == 1);

	land(&real, 1);
	assert(cake_pool_serve(cake_pool_dsq(1), 1, 1, depth[1]));
	cake_pool_seen(&real);
	cake_quiescent(&real, 0);
	cake_idle_interlock(1);
	assert(!depth[1] && kicks[1] == 1);
	assert(!cake.pool[1].pending && !cake.pool[1].unserved);

	/* A store allocation failure still grants the task a dispatchable queue. */
	cake_pool_insert(&unsupported, 0, SLICE_NS, 0, 42);
	assert(unsupported.verdict_slice == SLICE_NS && fallback_flags == 42);
	assert(!cake.pool[0].pending && !cake.pool[0].unserved);
	test_repool();
	puts("Pool cancellation, deferred publication, slice residue, requeue and allocation fallback passed.");
}
