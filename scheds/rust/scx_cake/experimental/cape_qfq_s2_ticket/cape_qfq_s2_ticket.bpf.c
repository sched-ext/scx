// SPDX-License-Identifier: GPL-2.0-only
/*
 * CAPE-Q S2 canonical-cover ticket container -- source shape only.
 *
 * This translation is intentionally not linked into scx_cake. It isolates the
 * arena-pointer lifetime law needed before an ordered visibility ticket can be
 * used by S2. It is not a sched_ext scheduler and has no verifier authority.
 */

#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <lib/atq.h>
#include <lib/rbtree.h>
#include <lib/sdt_task.h>

char _license[] SEC("license") = "GPL";

#define CAPEQ_S2_MAX_CPUS 16U
#define CAPEQ_S2_MAX_PATH_NODES 3U
#define CAPEQ_S2_MAX_COVER 8U
#define CAPEQ_S2_MAX_NESTED_MUTATORS 4U
#define CAPEQ_S2_STALE_BOUND \
	(CAPEQ_S2_MAX_CPUS * CAPEQ_S2_MAX_NESTED_MUTATORS)

#define CAPEQ_S2_POLICY_COMPOSITION_COMPLETE 0
#define CAPEQ_S2_ORDER_KEY_COMPLETE 0
#define CAPEQ_S2_BUILD_INTEGRATED 0

enum capeq_s2_ticket_state {
	CAPEQ_S2_TICKET_FREE = 0,
	CAPEQ_S2_TICKET_LINKED = 1,
	CAPEQ_S2_TICKET_CLAIMED = 2,
	CAPEQ_S2_TICKET_RETIRED = 3,
	CAPEQ_S2_TICKET_RECLAIMING = 4,
};

#define CAPEQ_S2_TICKET_STATE_MASK 0x7U
#define CAPEQ_S2_TICKET_DETACHED (1U << 8)

struct capeq_s2_ticket {
	/* One distinct common/rbnode is required for every cover membership. */
	scx_task_common common;
	union sdt_id tid;
	u64 task_cookie;
	u64 task_epoch;
	u64 order_key;
	u64 sequence;
	u32 state_word;
	s32 pid;
	s32 claimant_cpu;
	u16 topology_node;
	u8 group;
	u8 cover_slot;
};

struct capeq_s2_ticket_snapshot {
	u64 ticket_id;
	u64 task_cookie;
	u64 task_epoch;
	u64 order_key;
	u64 sequence;
	s32 pid;
	u16 topology_node;
	u8 group;
	u8 cover_slot;
};

static struct scx_allocator capeq_s2_ticket_allocator;

static __always_inline u32 capeq_s2_ticket_state(u32 word)
{
	return word & CAPEQ_S2_TICKET_STATE_MASK;
}

static __always_inline bool capeq_s2_ticket_detached(u32 word)
{
	return word & CAPEQ_S2_TICKET_DETACHED;
}

/*
 * The returned arena pointer is safe only because the ticket is transitioned
 * to CLAIMED while the ATQ lock is still held. Owner detach cannot recycle a
 * CLAIMED ticket; claimant release becomes the only possible reclaimer.
 */
static __always_inline struct capeq_s2_ticket __arena *
capeq_s2_ticket_from_common(scx_task_common __arena *common)
{
	return container_of(common, struct capeq_s2_ticket, common);
}

__weak int capeq_s2_ticket_allocator_init(void)
{
	return scx_alloc_init(&capeq_s2_ticket_allocator,
			      sizeof(struct capeq_s2_ticket));
}

static __always_inline int
capeq_s2_ticket_reclaim(struct capeq_s2_ticket __arena *ticket,
			 u32 expected)
{
	u32 reclaiming;
	s32 idx;

	if (capeq_s2_ticket_state(expected) != CAPEQ_S2_TICKET_RETIRED ||
	    !capeq_s2_ticket_detached(expected))
		return -EINVAL;

	reclaiming = (expected & ~CAPEQ_S2_TICKET_STATE_MASK) |
		     CAPEQ_S2_TICKET_RECLAIMING;
	if (cmpxchg(&ticket->state_word, expected, reclaiming) != expected)
		return -EAGAIN;

	/* No ticket dereference is legal after this free. */
	idx = ticket->tid.idx;
	return scx_alloc_free_idx(&capeq_s2_ticket_allocator, (u64)(u32)idx);
}

static __always_inline void
capeq_s2_ticket_abort_alloc(struct capeq_s2_ticket __arena *ticket)
{
	u32 word = CAPEQ_S2_TICKET_RETIRED | CAPEQ_S2_TICKET_DETACHED;

	WRITE_ONCE(ticket->state_word, word);
	if (capeq_s2_ticket_reclaim(ticket, word))
		scx_bpf_error("CAPE-Q S2 ticket allocation rollback failed");
}

__weak u64 capeq_s2_ticket_alloc(u64 task_cookie, u64 task_epoch,
				u64 order_key, u64 sequence, s32 pid,
				u16 topology_node, u8 group, u8 cover_slot)
{
	struct sdt_data __arena *data;
	struct capeq_s2_ticket __arena *ticket;

	if (topology_node >= 25 || group >= 14 ||
	    cover_slot >= CAPEQ_S2_MAX_COVER)
		return 0;

	data = scx_alloc(&capeq_s2_ticket_allocator);
	if (!data)
		return 0;
	ticket = (struct capeq_s2_ticket __arena *)data->payload;

	/* rb_insert_node() resets all tree links before publication. */
	ticket->common.atq = NULL;
	ticket->tid = data->tid;
	ticket->task_cookie = task_cookie;
	ticket->task_epoch = task_epoch;
	ticket->order_key = order_key;
	ticket->sequence = sequence;
	ticket->pid = pid;
	ticket->claimant_cpu = -1;
	ticket->topology_node = topology_node;
	ticket->group = group;
	ticket->cover_slot = cover_slot;
	WRITE_ONCE(ticket->state_word, CAPEQ_S2_TICKET_LINKED);

	return (u64)ticket;
}

__weak int capeq_s2_ticket_insert(scx_atq_t __arg_arena *atq,
				  struct capeq_s2_ticket __arg_arena *ticket)
{
	int ret;

	if (!atq || !ticket ||
	    capeq_s2_ticket_state(READ_ONCE(ticket->state_word)) !=
		CAPEQ_S2_TICKET_LINKED || ticket->common.atq)
		return -EINVAL;

	ret = scx_atq_insert_vtime(atq, &ticket->common, ticket->order_key);
	if (ret)
		capeq_s2_ticket_abort_alloc(ticket);
	return ret;
}

/*
 * Copy scalars under the queue lock. Unlike public scx_atq_peek(), no arena
 * pointer escapes after unlock, so exact owner removal and recycle are safe.
 */
__weak int capeq_s2_ticket_snapshot_head(
	scx_atq_t __arg_arena *atq,
	struct capeq_s2_ticket_snapshot *snapshot __arg_trusted)
{
	struct capeq_s2_ticket __arena *ticket;
	scx_task_common __arena *common;
	u64 key, common_ptr;
	u32 word;
	int ret;

	if (!atq || !snapshot)
		return -EINVAL;
	ret = scx_atq_lock(atq);
	if (ret)
		return ret;
	ret = rb_least(atq->tree, &key, &common_ptr);
	if (ret)
		goto out;
	common = (scx_task_common __arena *)common_ptr;
	ticket = capeq_s2_ticket_from_common(common);
	word = READ_ONCE(ticket->state_word);
	if (common->atq != atq ||
	    capeq_s2_ticket_state(word) != CAPEQ_S2_TICKET_LINKED ||
	    key != ticket->order_key) {
		ret = -ESTALE;
		goto out;
	}

	snapshot->ticket_id = (u64)ticket->tid.val;
	snapshot->task_cookie = ticket->task_cookie;
	snapshot->task_epoch = ticket->task_epoch;
	snapshot->order_key = ticket->order_key;
	snapshot->sequence = ticket->sequence;
	snapshot->pid = ticket->pid;
	snapshot->topology_node = ticket->topology_node;
	snapshot->group = ticket->group;
	snapshot->cover_slot = ticket->cover_slot;
out:
	scx_atq_unlock(atq);
	return ret;
}

/*
 * Reacquire the same ATQ lock and claim only the exact still-current head.
 * Allocator generation in tid.val rejects remove/free/reuse ABA.
 */
__weak u64 capeq_s2_ticket_claim_head(
	scx_atq_t __arg_arena *atq,
	const struct capeq_s2_ticket_snapshot *snapshot __arg_trusted,
	s32 cpu)
{
	struct capeq_s2_ticket __arena *ticket;
	scx_task_common __arena *common;
	u64 key, common_ptr;
	u32 word;
	int ret;

	if (!atq || !snapshot || cpu < 0 || cpu >= CAPEQ_S2_MAX_CPUS)
		return 0;
	ret = scx_atq_lock(atq);
	if (ret)
		return 0;
	ret = rb_least(atq->tree, &key, &common_ptr);
	if (ret)
		goto fail;
	common = (scx_task_common __arena *)common_ptr;
	ticket = capeq_s2_ticket_from_common(common);
	word = READ_ONCE(ticket->state_word);
	if (common->atq != atq ||
	    capeq_s2_ticket_state(word) != CAPEQ_S2_TICKET_LINKED ||
	    (u64)ticket->tid.val != snapshot->ticket_id ||
	    ticket->task_cookie != snapshot->task_cookie ||
	    ticket->task_epoch != snapshot->task_epoch ||
	    ticket->order_key != snapshot->order_key || key != snapshot->order_key ||
	    ticket->sequence != snapshot->sequence ||
	    ticket->pid != snapshot->pid ||
	    ticket->topology_node != snapshot->topology_node ||
	    ticket->group != snapshot->group ||
	    ticket->cover_slot != snapshot->cover_slot)
		goto fail;

	ret = rb_remove_node(atq->tree, &common->node);
	if (ret)
		goto fail;
	if (!atq->size) {
		scx_atq_unlock(atq);
		scx_bpf_error("CAPE-Q S2 ATQ size underflow on claim");
		return 0;
	}
	atq->size -= 1;
	common->atq = NULL;
	ticket->claimant_cpu = cpu;
	WRITE_ONCE(ticket->state_word,
		   (word & ~CAPEQ_S2_TICKET_STATE_MASK) |
		   CAPEQ_S2_TICKET_CLAIMED);
	scx_atq_unlock(atq);
	return (u64)ticket;
fail:
	scx_atq_unlock(atq);
	return 0;
}

/*
 * Exact owner cleanup. If a claimant already removed the ticket, owner detach
 * below transfers reclamation responsibility to claimant release.
 */
__weak int capeq_s2_ticket_retire_linked(
	struct capeq_s2_ticket __arg_arena *ticket)
{
	scx_atq_t __arena *atq;
	u32 word;
	int ret;

	if (!ticket)
		return -EINVAL;
	atq = READ_ONCE(ticket->common.atq);
	if (!atq)
		return 0;
	ret = scx_atq_lock(atq);
	if (ret)
		return ret;
	word = READ_ONCE(ticket->state_word);
	if (ticket->common.atq != atq ||
	    capeq_s2_ticket_state(word) != CAPEQ_S2_TICKET_LINKED) {
		scx_atq_unlock(atq);
		return 0;
	}
	ret = rb_remove_node(atq->tree, &ticket->common.node);
	if (ret) {
		scx_atq_unlock(atq);
		return ret;
	}
	if (!atq->size) {
		scx_atq_unlock(atq);
		scx_bpf_error("CAPE-Q S2 ATQ size underflow on retire");
		return -EUCLEAN;
	}
	atq->size -= 1;
	ticket->common.atq = NULL;
	WRITE_ONCE(ticket->state_word,
		   (word & ~CAPEQ_S2_TICKET_STATE_MASK) |
		   CAPEQ_S2_TICKET_RETIRED);
	scx_atq_unlock(atq);
	return 0;
}

/*
 * Owner calls detach only after removing this pointer from the task's current
 * cover vector. This function may recycle the ticket; caller must not touch the
 * pointer afterwards.
 */
__weak int capeq_s2_ticket_detach_owner(
	struct capeq_s2_ticket __arg_arena *ticket)
{
	u32 old, detached;

	if (!ticket)
		return -EINVAL;
	old = __sync_fetch_and_or(&ticket->state_word,
				  CAPEQ_S2_TICKET_DETACHED);
	detached = old | CAPEQ_S2_TICKET_DETACHED;
	switch (capeq_s2_ticket_state(old)) {
	case CAPEQ_S2_TICKET_CLAIMED:
		/* Claimant observes DETACHED and becomes the reclaimer. */
		return 0;
	case CAPEQ_S2_TICKET_RETIRED:
		return capeq_s2_ticket_reclaim(ticket, detached);
	case CAPEQ_S2_TICKET_LINKED:
		scx_bpf_error("CAPE-Q S2 detached a linked ticket");
		return -EUCLEAN;
	default:
		return -EALREADY;
	}
}

/*
 * Claimed pointer remains safe until this release. If owner already detached,
 * claimant transitions directly to RECLAIMING and frees. Otherwise it publishes
 * RETIRED and returns without another pointer dereference; owner will detach.
 */
__weak int capeq_s2_ticket_release_claim(
	struct capeq_s2_ticket __arg_arena *ticket, s32 cpu)
{
	u32 old, retired, reclaiming;
	s32 idx;

	if (!ticket || cpu < 0 || cpu >= CAPEQ_S2_MAX_CPUS)
		return -EINVAL;
	for (u32 attempt = 0; attempt < 4; attempt++) {
		old = READ_ONCE(ticket->state_word);
		if (capeq_s2_ticket_state(old) != CAPEQ_S2_TICKET_CLAIMED ||
		    ticket->claimant_cpu != cpu)
			return -EINVAL;
		ticket->claimant_cpu = -1;
		if (capeq_s2_ticket_detached(old)) {
			reclaiming = (old & ~CAPEQ_S2_TICKET_STATE_MASK) |
				     CAPEQ_S2_TICKET_RECLAIMING;
			if (cmpxchg(&ticket->state_word, old, reclaiming) != old)
				continue;
			idx = ticket->tid.idx;
			return scx_alloc_free_idx(&capeq_s2_ticket_allocator,
						  (u64)(u32)idx);
		}
		retired = (old & ~CAPEQ_S2_TICKET_STATE_MASK) |
			  CAPEQ_S2_TICKET_RETIRED;
		if (cmpxchg(&ticket->state_word, old, retired) == old)
			return 0;
	}
	scx_bpf_error("CAPE-Q S2 claim release CAS bound exhausted");
	return -EAGAIN;
}

/*
 * Full S2 must bind these primitives to:
 *   - canonical effective-mask cover publication;
 *   - one task-state QUEUED->INVALIDATING CAS;
 *   - bounded stale-head help (CAPEQ_S2_STALE_BOUND);
 *   - per-node CAPE-Q group selection;
 *   - unique and wrap-safe order keys; and
 *   - one-entry per-CPU staging DSQ handoff.
 */
