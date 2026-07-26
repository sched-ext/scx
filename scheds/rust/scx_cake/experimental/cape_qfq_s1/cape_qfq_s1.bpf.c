/* SPDX-License-Identifier: GPL-2.0 */
/*
 * CAPE-Q S1 verifier candidate: single-domain custody and SMP arbitration.
 *
 * SOURCE-ONLY QUARANTINE
 * ----------------------
 * This file is deliberately not referenced by scx_cake/build.rs, Cargo, or
 * the production Cake BPF source.  It is an emitted-source target for static
 * conformance work only.  It has not been compiled, verifier-loaded, attached,
 * benchmarked, or promoted.
 *
 * What is represented here:
 *   - the exact 2,752-byte single-entry ARRAY value from the offline proof;
 *   - the exact 32-byte TASK_STORAGE value and packed custody epoch;
 *   - direct-insert -> scalar publication -> core physical commit ordering;
 *   - one scalar-only spinlock critical section at a time;
 *   - task-linear logical dispatch reservation before the physical move;
 *   - snapshot DSQ iteration and kernel-authoritative scx_bpf_dsq_move();
 *   - synchronous ops.dequeue() reservation closure after a successful move;
 *   - bounded scan, move, and publication-gap failure handling; and
 *   - 14 physical priority DSQs for sparse QFQ groups [8..20, 22]; and
 *   - constant-work ER/IR/EB/IB classify, eligibility, and unblock steps;
 *   - dispatch-to-running service custody including core-sched execution; and
 *   - forced global-policy return after each partial service stop.
 *
 * What is intentionally NOT represented yet:
 *   - continuous cgroup-weight updates and exit_task teardown;
 *   - wrap-aware timestamp comparison;
 *   - S2 affinity-visible topology sharding and cross-domain lag translation;
 *   - any verifier, runtime, score, promotion, or policy authority.
 *
 * The current selector services the lowest eligible-ready dense group.  The
 * source is still quarantined and mechanically unproved, so
 * CAPEQ_POLICY_COMPLETE must remain zero.
 */
#include <scx/common.bpf.h>

#define CAPEQ_POLICY_COMPLETE 0
#define CAPEQ_VERIFIER_LOAD_PROVEN 0
#define CAPEQ_RUNTIME_PROVEN 0

#define CAPEQ_GROUP_COUNT 14U
#define CAPEQ_ALL_GROUP_MASK ((1U << CAPEQ_GROUP_COUNT) - 1U)
#define CAPEQ_SLOTS_PER_GROUP 32U
#define CAPEQ_SLOT_COUNT (CAPEQ_GROUP_COUNT * CAPEQ_SLOTS_PER_GROUP)
#define CAPEQ_REQUEST_NS 3000000ULL
#define CAPEQ_WEIGHT_SCALE 1024ULL
#define CAPEQ_MIN_SLOT_SHIFT 8U
#define CAPEQ_EMPTY_RETRY_BUDGET 8U
#define CAPEQ_SCAN_BUDGET 64U
#define CAPEQ_MOVE_BUDGET 16U
#define CAPEQ_DSQ_BASE 0x4341504500000000ULL
#define CAPEQ_WATCHDOG_MS 5000U

#define CAPEQ_MEM_STATE_BITS 2U
#define CAPEQ_MEM_GROUP_SHIFT CAPEQ_MEM_STATE_BITS
#define CAPEQ_MEM_SLOT_SHIFT (CAPEQ_MEM_GROUP_SHIFT + 4U)
#define CAPEQ_MEM_EPOCH_SHIFT (CAPEQ_MEM_SLOT_SHIFT + 5U)
#define CAPEQ_MEM_FRACTION_SHIFT (CAPEQ_MEM_EPOCH_SHIFT + 32U)
#define CAPEQ_MEM_GROUP_MASK 0x0fULL
#define CAPEQ_MEM_SLOT_MASK 0x1fULL
#define CAPEQ_MEM_EPOCH_MASK 0xffffffffULL
#define CAPEQ_MEM_FRACTION_MASK 0x1ffffULL
#define CAPEQ_MEM_USED_BITS (CAPEQ_MEM_FRACTION_SHIFT + 17U)
#define CAPEQ_MEM_DISPATCH_BIT (1ULL << CAPEQ_MEM_USED_BITS)

#define CAPEQ_SERVICE_COUNT_BITS 16U
#define CAPEQ_RUNNING_COUNT_MASK ((1U << CAPEQ_SERVICE_COUNT_BITS) - 1U)
#define CAPEQ_DISPATCH_COUNT_SHIFT CAPEQ_SERVICE_COUNT_BITS
#define CAPEQ_DISPATCH_COUNT_ONE (1U << CAPEQ_DISPATCH_COUNT_SHIFT)

#define CAPEQ_PAYLOAD_PRIO_MASK 0x3fU
#define CAPEQ_PAYLOAD_VALID (1U << 6)
#define CAPEQ_PAYLOAD_SLEEP (1U << 7)
#define CAPEQ_PAYLOAD_RESERVED (1U << 8)

#define CAPEQ_KEY_META_MASK 0xffULL
#define CAPEQ_KEY_PRIO_MASK 0x3fULL

#define CAPEQ_TASK_FRAC_BITS 17U
#define CAPEQ_TASK_FRAC_ONE (1ULL << CAPEQ_TASK_FRAC_BITS)
#define CAPEQ_DOMAIN_FRAC_BITS 32U
#define CAPEQ_DOMAIN_FRAC_MASK 0xffffffffULL

#define CAPEQ_MEM_PACK(state, dense, slot, epoch, fraction)       \
	((u64)(state) | ((u64)(dense) << CAPEQ_MEM_GROUP_SHIFT) | \
	 ((u64)(slot) << CAPEQ_MEM_SLOT_SHIFT) |                  \
	 ((u64)(epoch) << CAPEQ_MEM_EPOCH_SHIFT) |                \
	 ((u64)(fraction) << CAPEQ_MEM_FRACTION_SHIFT))
#define CAPEQ_MEM_STATE(word) ((u32)((word) & 0x3ULL))
#define CAPEQ_MEM_GROUP(word) \
	((u32)(((word) >> CAPEQ_MEM_GROUP_SHIFT) & CAPEQ_MEM_GROUP_MASK))
#define CAPEQ_MEM_SLOT(word) \
	((u32)(((word) >> CAPEQ_MEM_SLOT_SHIFT) & CAPEQ_MEM_SLOT_MASK))
#define CAPEQ_MEM_EPOCH(word) \
	((u32)(((word) >> CAPEQ_MEM_EPOCH_SHIFT) & CAPEQ_MEM_EPOCH_MASK))
#define CAPEQ_MEM_FRACTION(word) \
	((u32)(((word) >> CAPEQ_MEM_FRACTION_SHIFT) & CAPEQ_MEM_FRACTION_MASK))
#define CAPEQ_MEM_RESERVED(word) ((word) >> CAPEQ_MEM_USED_BITS)
#define CAPEQ_MEM_DISPATCH_RESERVED(word) (!!((word) & CAPEQ_MEM_DISPATCH_BIT))
#define CAPEQ_MEM_INVALID_RESERVED(word) \
	((word) >> (CAPEQ_MEM_USED_BITS + 1U))
#define CAPEQ_MEM_WITH_DISPATCH_RESERVATION(word) \
	((word) | CAPEQ_MEM_DISPATCH_BIT)

#define CAPEQ_RUNNING_COUNT(word) ((word) & CAPEQ_RUNNING_COUNT_MASK)
#define CAPEQ_DISPATCH_COUNT(word) ((word) >> CAPEQ_DISPATCH_COUNT_SHIFT)

#define CAPEQ_PAYLOAD_PACK(prio, valid, sleep)                \
	((u32)(prio) | ((valid) ? CAPEQ_PAYLOAD_VALID : 0U) | \
	 ((sleep) ? CAPEQ_PAYLOAD_SLEEP : 0U))
#define CAPEQ_PAYLOAD_FROM_MEM(word) \
	(CAPEQ_MEM_GROUP(word) | (CAPEQ_MEM_SLOT(word) << 4U))
#define CAPEQ_PAYLOAD_PRIO(word) \
	(CAPEQ_PAYLOAD_FROM_MEM(word) & CAPEQ_PAYLOAD_PRIO_MASK)
#define CAPEQ_PAYLOAD_IS_VALID(word) \
	(!!(CAPEQ_PAYLOAD_FROM_MEM(word) & CAPEQ_PAYLOAD_VALID))
#define CAPEQ_PAYLOAD_IS_SLEEP(word) \
	(!!(CAPEQ_PAYLOAD_FROM_MEM(word) & CAPEQ_PAYLOAD_SLEEP))
#define CAPEQ_PAYLOAD_HAS_RESERVED(word) \
	(!!(CAPEQ_PAYLOAD_FROM_MEM(word) & CAPEQ_PAYLOAD_RESERVED))
#define CAPEQ_MEM_PACK_LIFE(state, prio, valid, sleep, epoch, fraction)        \
	CAPEQ_MEM_PACK(                                                        \
		(state), CAPEQ_PAYLOAD_PACK((prio), (valid), (sleep)) & 0x0fU, \
		(CAPEQ_PAYLOAD_PACK((prio), (valid), (sleep)) >> 4U) & 0x1fU,  \
		(epoch), (fraction))

#define CAPEQ_KEY_PACK(key, prio) ((u64)(key) | (u64)(prio))
#define CAPEQ_KEY_VALUE(tagged) ((u64)(tagged) & ~CAPEQ_KEY_META_MASK)
#define CAPEQ_KEY_PRIO(tagged) ((u32)((tagged) & CAPEQ_KEY_PRIO_MASK))
#define CAPEQ_KEY_RESERVED(tagged) \
	((u32)(((tagged) & CAPEQ_KEY_META_MASK) & ~CAPEQ_KEY_PRIO_MASK))

#ifndef SCHED_IDLE
#define SCHED_IDLE 5
#endif

enum capeq_membership_state {
	CAPEQ_MEM_ACTIVE    = 0,
	CAPEQ_MEM_PUBLISHED = 1,
	CAPEQ_MEM_RUNNING   = 2,
	CAPEQ_MEM_QUIESCENT = 3,
};

enum capeq_scheduler_state {
	CAPEQ_SCHED_OPERATIONAL = 0,
	CAPEQ_SCHED_ABORTING	= 1,
	CAPEQ_SCHED_BYPASS	= 2,
};

enum capeq_abort_reason {
	CAPEQ_ABORT_NONE		     = 0,
	CAPEQ_ABORT_INSERT_REJECTED	     = 1,
	CAPEQ_ABORT_BAD_MEMBERSHIP	     = 2,
	CAPEQ_ABORT_TASK_EPOCH_OVERFLOW	     = 3,
	CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW = 4,
	CAPEQ_ABORT_COUNTER_OVERFLOW	     = 5,
	CAPEQ_ABORT_COUNTER_UNDERFLOW	     = 6,
	CAPEQ_ABORT_RING_COLLISION	     = 7,
	CAPEQ_ABORT_SCAN_BUDGET		     = 8,
	CAPEQ_ABORT_UNCHANGED_EMPTY_SCAN     = 9,
	CAPEQ_ABORT_BAD_LIFECYCLE	     = 10,
	CAPEQ_ABORT_ACTIVE_WEIGHT	     = 11,
	CAPEQ_ABORT_RUNTIME_REGRESSION	     = 12,
	CAPEQ_ABORT_RUNTIME_OVERSERVICE	     = 13,
	CAPEQ_ABORT_LAG_RANGE		     = 14,
	CAPEQ_ABORT_RESERVED_MOVE_FAILED      = 15,
};

enum capeq_group_state {
	CAPEQ_GROUP_NONE = 0,
	CAPEQ_GROUP_ER	 = 1,
	CAPEQ_GROUP_IR	 = 2,
	CAPEQ_GROUP_EB	 = 3,
	CAPEQ_GROUP_IB	 = 4,
};

struct capeq_group {
	u64 start;
	u64 finish;
	u32 slot_mask;
	u32 current_slot;
	u32 state;
	u32 dense_id;
};

struct capeq_domain {
	/* The verifier requires a top-level, constant, four-byte-aligned lock. */
	struct bpf_spin_lock lock;
	u32		     scheduler_state;
	u32		     abort_reason;
	/* low16 dispatched/executing service; high16 logical move reservations */
	u32		     running_count;
	u64		     mutation_seq;
	u32		     total_count;
	u32		     er_mask;
	u32		     ir_mask;
	u32		     eb_mask;
	u32		     ib_mask;
	u32		     virtual_fraction;
	u64		     virtual_time;
	u64		     active_weight;

	/* Offset 64: cold bounded geometry follows the serialized hot header. */
	struct capeq_group groups[CAPEQ_GROUP_COUNT];
	u32		   slot_counts[CAPEQ_SLOT_COUNT];
	u8		   empty_retries[CAPEQ_SLOT_COUNT];
};

struct capeq_task_ctx {
	u64 membership;
	u64 start;
	u64 deadline;
	u64 aux;
};

_Static_assert(sizeof(struct capeq_group) == 32,
	       "CAPE-Q group record must remain 32 bytes");
_Static_assert(__builtin_offsetof(struct capeq_domain, groups) == 64,
	       "CAPE-Q serialized hot header must remain one cache line");
_Static_assert(sizeof(struct capeq_domain) == 2752,
	       "CAPE-Q S1 domain value must match the offline layout proof");
_Static_assert(sizeof(struct capeq_task_ctx) == 32,
	       "CAPE-Q task storage must match the offline layout proof");
_Static_assert(CAPEQ_GROUP_COUNT *CAPEQ_SLOTS_PER_GROUP == 448,
	       "CAPE-Q dense counter geometry changed");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct capeq_domain);
} capeq_domains SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct capeq_task_ctx);
} capeq_tasks SEC(".maps");

char	      _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);

/* Sparse mathematical groups [8..20, 22], monotonically dense-mapped. */
static const u8 capeq_dense_to_sparse[CAPEQ_GROUP_COUNT] = {
	8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 22,
};

/* nice -20..19 followed by SCHED_IDLE; generated from the proven geometry. */
static const u8 capeq_prio_to_dense[41] = {
	0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3,  3,  3,  4,  4,  4,  5,  5,  5,  6,  6,
	6, 7, 7, 7, 8, 8, 8, 9, 9, 9, 10, 10, 10, 11, 11, 11, 11, 12, 12, 13,
};

/* Raw Linux nice weights followed by SCHED_IDLE weight 3. */
static const u32 capeq_raw_weight[41] = {
	88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949,
	11916, 9548,  7620,  6100,  4904,  3906,  3121,	 2501,	1991,
	1586,  1277,  1024,  820,   655,   526,	  423,	 335,	272,
	215,   172,   137,   110,   87,	   70,	  56,	 45,	36,
	29,    23,    18,    15,    3,
};

/* floor((1024 << 20) / raw Linux nice weight), plus idle weight 3. */
static const u64 capeq_recip_weight[41] = {
	12097,	  14964,    19009,    23204,	29587,	  36830,     46174,
	57404,	  71827,    90109,    112457,	140911,	  176023,    218952,
	274895,	  344037,   429324,   539297,	677012,	  840831,    1048576,
	1309441,  1639300,  2041334,  2538396,	3205199,  3947580,   4994148,
	6242685,  7837531,  9761289,  12341860, 15339168, 19173961,  23860929,
	29826161, 37025580, 46684427, 59652323, 71582788, 357913941,
};

static __always_inline struct capeq_domain *capeq_domain_lookup(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&capeq_domains, &key);
}

static __always_inline struct capeq_task_ctx *
capeq_task_lookup(struct task_struct *p)
{
	return bpf_task_storage_get(&capeq_tasks, p, 0, 0);
}

static __always_inline u32 capeq_prio_index(const struct task_struct *p)
{
	s32 index;

	if (p->policy == SCHED_IDLE)
		return 40;
	index = (s32)p->static_prio - 100;
	if (index < 0)
		return 0;
	if (index > 39)
		return 39;
	return (u32)index;
}

static __always_inline u64 capeq_request_vtime(u32 prio_index)
{
	return (CAPEQ_REQUEST_NS * capeq_recip_weight[prio_index]) >> 20;
}

static __always_inline u64 capeq_real_to_vtime(u32 prio_index, u64 real_ns)
{
	u64 weight    = capeq_raw_weight[prio_index];
	u64 numerator = real_ns * CAPEQ_WEIGHT_SCALE;

	return (numerator + weight - 1) / weight;
}

static __always_inline void capeq_report_abort(u32 reason)
{
	scx_bpf_error("CAPE-Q S1 custody abort reason=%u", reason);
}

/*
 * Direct insertion is deliberately performed before auxiliary publication.
 * The core commits the physical custom-DSQ insertion only after this callback
 * returns.  Any inconsistency after a recorded root insertion is fail-stop.
 */
void BPF_STRUCT_OPS(capeq_enqueue, struct task_struct *p __arg_trusted,
		    u64 enq_flags)
{
	struct capeq_domain   *domain = capeq_domain_lookup();
	struct capeq_task_ctx *taskc  = capeq_task_lookup(p);
	struct capeq_group    *group;
	u64 old_membership, old_tagged_key = 0, old_aux = 0, start, remaining_ns;
	u64 frontier, floor_v, limit, rounded_start, tagged_key, slot_size, delta;
	u32 prio_index, dense, sparse, slot, counter_index, epoch, fraction;
	u32 bit, state_count, higher, blocker = 0, state, occupied;
	u32 rotated, regression, highest;
	u32 abort_reason = CAPEQ_ABORT_NONE;
	bool inserted, published_reenqueue, reenqueue, reservation_reenqueue;
	bool eligible, blocked = false;
	bool active_service = false;

	if (!domain || !taskc) {
		capeq_report_abort(CAPEQ_ABORT_BAD_MEMBERSHIP);
		return;
	}

	old_membership = READ_ONCE(taskc->membership);
	if (CAPEQ_MEM_INVALID_RESERVED(old_membership)) {
		capeq_report_abort(CAPEQ_ABORT_BAD_MEMBERSHIP);
		return;
	}
	published_reenqueue =
		CAPEQ_MEM_STATE(old_membership) == CAPEQ_MEM_PUBLISHED;
	reservation_reenqueue = published_reenqueue &&
				 CAPEQ_MEM_DISPATCH_RESERVED(old_membership);
	reenqueue = published_reenqueue && !reservation_reenqueue;
	if ((published_reenqueue && !(enq_flags & SCX_ENQ_REENQ)) ||
	    (!published_reenqueue &&
	     (CAPEQ_MEM_STATE(old_membership) != CAPEQ_MEM_ACTIVE ||
	      !CAPEQ_PAYLOAD_IS_VALID(old_membership) ||
	      CAPEQ_PAYLOAD_HAS_RESERVED(old_membership)))) {
		capeq_report_abort(CAPEQ_ABORT_BAD_LIFECYCLE);
		return;
	}
	epoch = CAPEQ_MEM_EPOCH(old_membership);
	if (epoch == (u32)~0U) {
		capeq_report_abort(CAPEQ_ABORT_TASK_EPOCH_OVERFLOW);
		return;
	}

	if (published_reenqueue) {
		old_tagged_key = READ_ONCE(taskc->aux);
		dense		= CAPEQ_MEM_GROUP(old_membership);
		slot		= CAPEQ_MEM_SLOT(old_membership);
		prio_index     = CAPEQ_KEY_PRIO(old_tagged_key);
		if (dense >= CAPEQ_GROUP_COUNT || slot >= CAPEQ_SLOTS_PER_GROUP ||
		    CAPEQ_KEY_RESERVED(old_tagged_key) || prio_index >= 41U) {
			capeq_report_abort(CAPEQ_ABORT_BAD_MEMBERSHIP);
			return;
		}
	} else {
		prio_index = CAPEQ_PAYLOAD_PRIO(old_membership);
		old_aux = READ_ONCE(taskc->aux);
		if (prio_index >= 41U || old_aux > 1U) {
			capeq_report_abort(CAPEQ_ABORT_BAD_MEMBERSHIP);
			return;
		}
		active_service = old_aux == 1U;
	}

	start	     = READ_ONCE(taskc->start);
	remaining_ns = READ_ONCE(taskc->deadline);
	fraction     = CAPEQ_MEM_FRACTION(old_membership);
	if (!remaining_ns || remaining_ns > CAPEQ_REQUEST_NS) {
		capeq_report_abort(CAPEQ_ABORT_BAD_LIFECYCLE);
		return;
	}
	if (reenqueue) {
		sparse		= capeq_dense_to_sparse[dense];
		slot_size	= 1ULL << (sparse + CAPEQ_MIN_SLOT_SHIFT);
		rounded_start = CAPEQ_KEY_VALUE(old_tagged_key);
	} else {
		dense	     = capeq_prio_to_dense[prio_index];
		sparse	     = capeq_dense_to_sparse[dense];
		slot_size   = 1ULL << (sparse + CAPEQ_MIN_SLOT_SHIFT);
		frontier    = READ_ONCE(domain->virtual_time);
		floor_v     = frontier & ~(slot_size - 1);
		if (floor_v > ~0ULL - slot_size) {
			capeq_report_abort(CAPEQ_ABORT_RING_COLLISION);
			return;
		}
		limit		= frontier == floor_v ? floor_v : floor_v + slot_size;
		rounded_start = start < floor_v ? floor_v :
						   start & ~(slot_size - 1);
		if (rounded_start > limit)
			rounded_start = limit;
		slot = (u32)((rounded_start >>
			      (sparse + CAPEQ_MIN_SLOT_SHIFT)) &
			     (CAPEQ_SLOTS_PER_GROUP - 1));
	}
	if (rounded_start > ~0ULL - (slot_size << 1)) {
		capeq_report_abort(CAPEQ_ABORT_RING_COLLISION);
		return;
	}
	group = &domain->groups[dense];
	bit   = 1U << dense;
	/*
	 * Eligible groups cannot regress their front.  Clamp the approximate
	 * physical key before direct insertion; the publication lock below
	 * revalidates the snapshot and fail-stops if a concurrent mutation won.
	 */
	if (!reenqueue && READ_ONCE(group->slot_mask) &&
	    ((READ_ONCE(domain->er_mask) | READ_ONCE(domain->eb_mask)) & bit) &&
	    rounded_start < READ_ONCE(group->start)) {
		rounded_start = READ_ONCE(group->start);
		slot = (u32)((rounded_start >>
			      (sparse + CAPEQ_MIN_SLOT_SHIFT)) &
			     (CAPEQ_SLOTS_PER_GROUP - 1));
	}
	counter_index = dense * CAPEQ_SLOTS_PER_GROUP + slot;
	tagged_key    = CAPEQ_KEY_PACK(rounded_start, prio_index);

	/* Record the complete direct verdict before publishing membership. */
	inserted = scx_bpf_dsq_insert_vtime(p, CAPEQ_DSQ_BASE + dense,
					    remaining_ns, rounded_start,
					    enq_flags);

	/* CAPEQ_LOCK_BEGIN enqueue_publish */
	bpf_spin_lock(&domain->lock);
	if (domain->scheduler_state != CAPEQ_SCHED_OPERATIONAL) {
		abort_reason = domain->abort_reason;
	} else if (!inserted) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_INSERT_REJECTED;
		abort_reason		= CAPEQ_ABORT_INSERT_REJECTED;
	} else if (taskc->membership != old_membership ||
		   (published_reenqueue && taskc->aux != old_tagged_key) ||
		   (!published_reenqueue && taskc->aux != old_aux)) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_BAD_MEMBERSHIP;
		abort_reason		= CAPEQ_ABORT_BAD_MEMBERSHIP;
	} else if (domain->mutation_seq == ~0ULL) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
		abort_reason		= CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
	} else if (!reenqueue &&
		   (domain->total_count == (u32)~0U ||
		    domain->slot_counts[counter_index] == (u32)~0U ||
		    (active_service &&
		     !CAPEQ_RUNNING_COUNT(domain->running_count)) ||
		    (reservation_reenqueue &&
		     !CAPEQ_DISPATCH_COUNT(domain->running_count)))) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_COUNTER_OVERFLOW;
		abort_reason		= CAPEQ_ABORT_COUNTER_OVERFLOW;
	} else if (reenqueue) {
		state_count = !!(domain->er_mask & bit) +
			      !!(domain->ir_mask & bit) +
			      !!(domain->eb_mask & bit) +
			      !!(domain->ib_mask & bit);
		delta = rounded_start - group->start;
		if (!domain->total_count || !domain->slot_counts[counter_index] ||
		    !(group->slot_mask & (1U << slot)) || state_count != 1U ||
		    group->dense_id != dense || rounded_start < group->start ||
		    (delta & (slot_size - 1)) ||
		    (delta >> (sparse + CAPEQ_MIN_SLOT_SHIFT)) >=
			    CAPEQ_SLOTS_PER_GROUP ||
		    ((group->current_slot +
		      (u32)(delta >> (sparse + CAPEQ_MIN_SLOT_SHIFT))) &
		     (CAPEQ_SLOTS_PER_GROUP - 1)) != slot) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_RING_COLLISION;
			abort_reason		= CAPEQ_ABORT_RING_COLLISION;
		} else {
			domain->mutation_seq++;
			domain->empty_retries[counter_index] = 0;
			taskc->aux			 = old_tagged_key;
			taskc->membership = CAPEQ_MEM_PACK(
				CAPEQ_MEM_PUBLISHED, dense, slot, epoch + 1,
				fraction);
		}
	} else {
		if (!group->slot_mask) {
			occupied = domain->er_mask | domain->ir_mask |
				   domain->eb_mask | domain->ib_mask;
			if (!occupied && !domain->running_count &&
			    rounded_start > domain->virtual_time) {
				domain->virtual_time = rounded_start;
				domain->virtual_fraction = 0;
			}
			group->start	    = rounded_start;
			group->finish	    = rounded_start + (slot_size << 1);
			group->current_slot = slot;
			group->dense_id	    = dense;
			domain->er_mask &= ~bit;
			domain->ir_mask &= ~bit;
			domain->eb_mask &= ~bit;
			domain->ib_mask &= ~bit;
			eligible = rounded_start <= domain->virtual_time;
			higher = domain->er_mask &
				 (~((1U << dense) - 1U) & CAPEQ_ALL_GROUP_MASK);
			if (higher) {
				blocker = (u32)__builtin_ctz(higher);
				if (!domain->groups[blocker].slot_mask) {
					domain->scheduler_state = CAPEQ_SCHED_ABORTING;
					domain->abort_reason = CAPEQ_ABORT_BAD_MEMBERSHIP;
					abort_reason = CAPEQ_ABORT_BAD_MEMBERSHIP;
				} else {
					blocked = group->finish >
						domain->groups[blocker].finish;
				}
			}
			if (!abort_reason) {
				state = eligible ?
					(blocked ? CAPEQ_GROUP_EB : CAPEQ_GROUP_ER) :
					(blocked ? CAPEQ_GROUP_IB : CAPEQ_GROUP_IR);
				group->state = state;
				if (state == CAPEQ_GROUP_ER)
					domain->er_mask |= bit;
				else if (state == CAPEQ_GROUP_IR)
					domain->ir_mask |= bit;
				else if (state == CAPEQ_GROUP_EB)
					domain->eb_mask |= bit;
				else
					domain->ib_mask |= bit;
			}
		} else {
			state_count = !!(domain->er_mask & bit) +
				      !!(domain->ir_mask & bit) +
				      !!(domain->eb_mask & bit) +
				      !!(domain->ib_mask & bit);
			if (state_count != 1U || group->dense_id != dense ||
			    group->current_slot >= CAPEQ_SLOTS_PER_GROUP ||
			    !(group->slot_mask & (1U << group->current_slot))) {
				domain->scheduler_state = CAPEQ_SCHED_ABORTING;
				domain->abort_reason =
					CAPEQ_ABORT_RING_COLLISION;
				abort_reason = CAPEQ_ABORT_RING_COLLISION;
			}
			if (!abort_reason && rounded_start < group->start) {
				delta = group->start - rounded_start;
				regression = (u32)(delta >>
						   (sparse + CAPEQ_MIN_SLOT_SHIFT));
				rotated = (group->slot_mask >> group->current_slot) |
					  (group->slot_mask <<
					   ((32U - group->current_slot) & 31U));
				highest = rotated ?
						 31U - (u32)__builtin_clz(rotated) :
						 0;
				if ((domain->er_mask & bit) || (domain->eb_mask & bit) ||
				    (delta & (slot_size - 1)) ||
				    regression >= CAPEQ_SLOTS_PER_GROUP ||
				    (rotated && highest + regression >=
							CAPEQ_SLOTS_PER_GROUP) ||
				    domain->slot_counts[counter_index]) {
					domain->scheduler_state = CAPEQ_SCHED_ABORTING;
					domain->abort_reason = CAPEQ_ABORT_RING_COLLISION;
					abort_reason = CAPEQ_ABORT_RING_COLLISION;
				} else {
					group->start	      = rounded_start;
					group->finish	      = rounded_start +
							(slot_size << 1);
					group->current_slot = slot;
					domain->er_mask &= ~bit;
					domain->ir_mask &= ~bit;
					domain->eb_mask &= ~bit;
					domain->ib_mask &= ~bit;
					eligible = rounded_start <= domain->virtual_time;
					higher = domain->er_mask &
						 (~((1U << dense) - 1U) &
						  CAPEQ_ALL_GROUP_MASK);
					blocked = false;
					if (higher) {
						blocker = (u32)__builtin_ctz(higher);
						if (!domain->groups[blocker].slot_mask) {
							domain->scheduler_state =
								CAPEQ_SCHED_ABORTING;
							domain->abort_reason =
								CAPEQ_ABORT_BAD_MEMBERSHIP;
							abort_reason =
								CAPEQ_ABORT_BAD_MEMBERSHIP;
						} else {
							blocked = group->finish >
								domain->groups[blocker].finish;
						}
					}
					if (!abort_reason) {
						state = eligible ?
							(blocked ? CAPEQ_GROUP_EB :
								   CAPEQ_GROUP_ER) :
							(blocked ? CAPEQ_GROUP_IB :
								   CAPEQ_GROUP_IR);
						group->state = state;
						if (state == CAPEQ_GROUP_ER)
							domain->er_mask |= bit;
						else if (state == CAPEQ_GROUP_IR)
							domain->ir_mask |= bit;
						else if (state == CAPEQ_GROUP_EB)
							domain->eb_mask |= bit;
						else
							domain->ib_mask |= bit;
					}
				}
			}
			if (!abort_reason && rounded_start >= group->start) {
				delta = rounded_start - group->start;
				if ((delta & (slot_size - 1)) ||
				    (delta >> (sparse + CAPEQ_MIN_SLOT_SHIFT)) >
					    CAPEQ_SLOTS_PER_GROUP - 2U ||
				    ((group->current_slot +
				      (u32)(delta >>
					    (sparse + CAPEQ_MIN_SLOT_SHIFT))) &
				     (CAPEQ_SLOTS_PER_GROUP - 1)) != slot) {
					domain->scheduler_state = CAPEQ_SCHED_ABORTING;
					domain->abort_reason = CAPEQ_ABORT_RING_COLLISION;
					abort_reason = CAPEQ_ABORT_RING_COLLISION;
				}
			}
		}
		if (!abort_reason) {
			if (active_service)
				domain->running_count--;
			if (reservation_reenqueue)
				domain->running_count -= CAPEQ_DISPATCH_COUNT_ONE;
			domain->slot_counts[counter_index]++;
			domain->total_count++;
			domain->empty_retries[counter_index] = 0;
			group->slot_mask |= 1U << slot;
			domain->mutation_seq++;
			taskc->aux	  = tagged_key;
			taskc->membership = CAPEQ_MEM_PACK(CAPEQ_MEM_PUBLISHED,
							   dense, slot,
							   epoch + 1, fraction);
		}
	}
	bpf_spin_unlock(&domain->lock);
	/* CAPEQ_LOCK_END enqueue_publish */

	if (abort_reason)
		capeq_report_abort(abort_reason);
}

/*
 * Called for both a successful iterator move and an external custody exit.
 * A successful scx_bpf_dsq_move() physically moves first, then synchronously
 * nests this callback before returning to the dispatching CPU.
 */
void BPF_STRUCT_OPS(capeq_dequeue, struct task_struct *p __arg_trusted,
		    u64 deq_flags)
{
	struct capeq_domain   *domain = capeq_domain_lookup();
	struct capeq_task_ctx *taskc  = capeq_task_lookup(p);
	struct capeq_group    *group;
	u64 membership, slot_size, tagged_key, key, delta, old_finish;
	u32 dense, sparse, slot, counter_index, count, prio_index, fraction;
	u32 current_slot, rotated, distance, bit, state_count, old_state;
	u32 higher, next, lower, lower_ready, highest_lower, moved, state;
	u32 blocker = 0;
	u32 abort_reason = CAPEQ_ABORT_NONE;
	bool eligible, blocked = false, front_changed = false;
	bool dispatch_exit = deq_flags == 0;
	bool service_exit = dispatch_exit ||
				    !!(deq_flags & SCX_DEQ_CORE_SCHED_EXEC);
	bool dispatch_reserved = false;
	bool release_lower = false;

	if (!domain || !taskc)
		return;
	membership = READ_ONCE(taskc->membership);
	if (CAPEQ_MEM_STATE(membership) != CAPEQ_MEM_PUBLISHED)
		return;

	/* CAPEQ_LOCK_BEGIN dequeue_unpublish */
	bpf_spin_lock(&domain->lock);
	membership = taskc->membership;
	dispatch_reserved = CAPEQ_MEM_DISPATCH_RESERVED(membership);
	if (CAPEQ_MEM_STATE(membership) != CAPEQ_MEM_PUBLISHED) {
		/* A competing kernel-authoritative move or dequeue already won. */
	} else if (CAPEQ_MEM_INVALID_RESERVED(membership)) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_BAD_MEMBERSHIP;
		abort_reason		= CAPEQ_ABORT_BAD_MEMBERSHIP;
	} else if (domain->mutation_seq == ~0ULL ||
		   (service_exit &&
		    CAPEQ_RUNNING_COUNT(domain->running_count) ==
			    CAPEQ_RUNNING_COUNT_MASK) ||
		   (dispatch_reserved &&
		    !CAPEQ_DISPATCH_COUNT(domain->running_count))) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
		abort_reason		= CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
	} else if (dispatch_reserved) {
		dense	      = CAPEQ_MEM_GROUP(membership);
		slot	      = CAPEQ_MEM_SLOT(membership);
		tagged_key    = taskc->aux;
		prio_index    = CAPEQ_KEY_PRIO(tagged_key);
		fraction      = CAPEQ_MEM_FRACTION(membership);
		if (dense >= CAPEQ_GROUP_COUNT || slot >= CAPEQ_SLOTS_PER_GROUP ||
		    CAPEQ_KEY_RESERVED(tagged_key) || prio_index >= 41U) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_BAD_MEMBERSHIP;
			abort_reason		= CAPEQ_ABORT_BAD_MEMBERSHIP;
		} else {
			/* Logical removal happened at the reservation linearization. */
			domain->running_count -= CAPEQ_DISPATCH_COUNT_ONE;
			if (service_exit)
				domain->running_count++;
			domain->mutation_seq++;
			taskc->aux = service_exit ? 1U : 0U;
			taskc->membership = CAPEQ_MEM_PACK_LIFE(
				CAPEQ_MEM_ACTIVE, prio_index, true, false,
				CAPEQ_MEM_EPOCH(membership), fraction);
		}
	} else {
		dense	   = CAPEQ_MEM_GROUP(membership);
		slot	   = CAPEQ_MEM_SLOT(membership);
		tagged_key = taskc->aux;
		prio_index = CAPEQ_KEY_PRIO(tagged_key);
		fraction   = CAPEQ_MEM_FRACTION(membership);
		if (dense >= CAPEQ_GROUP_COUNT ||
		    slot >= CAPEQ_SLOTS_PER_GROUP ||
		    CAPEQ_KEY_RESERVED(tagged_key) || prio_index >= 41U) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_BAD_MEMBERSHIP;
			abort_reason		= CAPEQ_ABORT_BAD_MEMBERSHIP;
		} else {
			counter_index = dense * CAPEQ_SLOTS_PER_GROUP + slot;
			group	      = &domain->groups[dense];
			count	      = domain->slot_counts[counter_index];
			sparse	      = capeq_dense_to_sparse[dense];
			slot_size = 1ULL << (sparse + CAPEQ_MIN_SLOT_SHIFT);
			key	   = CAPEQ_KEY_VALUE(tagged_key);
			bit	   = 1U << dense;
			state_count = !!(domain->er_mask & bit) +
				      !!(domain->ir_mask & bit) +
				      !!(domain->eb_mask & bit) +
				      !!(domain->ib_mask & bit);
			old_state = domain->er_mask & bit ? CAPEQ_GROUP_ER :
				    domain->ir_mask & bit ? CAPEQ_GROUP_IR :
				    domain->eb_mask & bit ? CAPEQ_GROUP_EB :
						    CAPEQ_GROUP_IB;
			old_finish = group->finish;
		}
		if (!abort_reason && (!count || !domain->total_count ||
				      !(group->slot_mask & (1U << slot)) ||
				      state_count != 1U ||
				      group->dense_id != dense ||
				      key < group->start ||
				      ((key - group->start) & (slot_size - 1)) ||
				      ((key - group->start) >>
				       (sparse + CAPEQ_MIN_SLOT_SHIFT)) >=
					      CAPEQ_SLOTS_PER_GROUP)) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_COUNTER_UNDERFLOW;
			abort_reason		= CAPEQ_ABORT_COUNTER_UNDERFLOW;
		} else if (!abort_reason) {
			domain->slot_counts[counter_index] = count - 1;
			domain->total_count--;
			domain->mutation_seq++;
			if (service_exit)
				domain->running_count++;
			taskc->aux	  = service_exit ? 1U : 0U;
			taskc->membership = CAPEQ_MEM_PACK_LIFE(
				CAPEQ_MEM_ACTIVE, prio_index, true, false,
				CAPEQ_MEM_EPOCH(membership), fraction);
			if (count == 1) {
				domain->empty_retries[counter_index] = 0;
				group->slot_mask &= ~(1U << slot);
				front_changed = slot == group->current_slot;
				if (!group->slot_mask) {
					group->start	    = 0;
					group->finish	    = 0;
					group->current_slot = 0;
					group->state	    = CAPEQ_GROUP_NONE;
					domain->er_mask &= ~bit;
					domain->ir_mask &= ~bit;
					domain->eb_mask &= ~bit;
					domain->ib_mask &= ~bit;
				} else if (front_changed) {
					current_slot = group->current_slot &
						       31U;
					rotated	 = (group->slot_mask >>
						    current_slot) |
						   (group->slot_mask
						    << ((32U - current_slot) &
							31U));
					distance = (u32)__builtin_ctz(rotated);
					group->current_slot =
						(current_slot + distance) & 31U;
					group->start +=
						(u64)distance * slot_size;
					group->finish =
						group->start + (slot_size << 1);
					domain->er_mask &= ~bit;
					domain->ir_mask &= ~bit;
					domain->eb_mask &= ~bit;
					domain->ib_mask &= ~bit;
					eligible = group->start <= domain->virtual_time;
					higher = domain->er_mask &
						 (~((1U << dense) - 1U) &
						  CAPEQ_ALL_GROUP_MASK);
					if (higher) {
						blocker = (u32)__builtin_ctz(higher);
						if (!domain->groups[blocker].slot_mask) {
							domain->scheduler_state =
								CAPEQ_SCHED_ABORTING;
							domain->abort_reason =
								CAPEQ_ABORT_BAD_MEMBERSHIP;
							abort_reason =
								CAPEQ_ABORT_BAD_MEMBERSHIP;
						} else {
							blocked = group->finish >
								domain->groups[blocker].finish;
						}
					}
					if (!abort_reason) {
						state = eligible ?
							(blocked ? CAPEQ_GROUP_EB :
								   CAPEQ_GROUP_ER) :
							(blocked ? CAPEQ_GROUP_IB :
								   CAPEQ_GROUP_IR);
						group->state = state;
						if (state == CAPEQ_GROUP_ER)
							domain->er_mask |= bit;
						else if (state == CAPEQ_GROUP_IR)
							domain->ir_mask |= bit;
						else if (state == CAPEQ_GROUP_EB)
							domain->eb_mask |= bit;
						else
							domain->ib_mask |= bit;
					}
				}
			}
			if (!abort_reason && old_state == CAPEQ_GROUP_ER &&
			    (!group->slot_mask || front_changed)) {
				release_lower = true;
				higher = domain->er_mask &
					 (~((1U << (dense + 1U)) - 1U) &
					  CAPEQ_ALL_GROUP_MASK);
				if (higher) {
					next = (u32)__builtin_ctz(higher);
					if (!domain->groups[next].slot_mask) {
						domain->scheduler_state =
							CAPEQ_SCHED_ABORTING;
						domain->abort_reason =
							CAPEQ_ABORT_BAD_MEMBERSHIP;
						abort_reason = CAPEQ_ABORT_BAD_MEMBERSHIP;
					} else if (domain->groups[next].finish <= old_finish) {
						release_lower = false;
					}
				}
				if (!abort_reason && release_lower) {
					lower = (1U << dense) - 1U;
					if (!dispatch_exit) {
						lower_ready = domain->er_mask & lower;
						if (lower_ready) {
							highest_lower = 31U -
								(u32)__builtin_clz(lower_ready);
							lower &= ~((1U << highest_lower) - 1U);
						}
					}
					moved = domain->eb_mask & lower;
					domain->er_mask |= moved;
					domain->eb_mask &= ~lower;
					moved = domain->ib_mask & lower;
					domain->ir_mask |= moved;
					domain->ib_mask &= ~lower;
				}
			}
		}
	}
	bpf_spin_unlock(&domain->lock);
	/* CAPEQ_LOCK_END dequeue_unpublish */

	if (abort_reason)
		capeq_report_abort(abort_reason);
}

/* Restore a source-ordered quiescent lag token to an active eligibility key. */
void BPF_STRUCT_OPS(capeq_runnable, struct task_struct *p, u64 enq_flags)
{
	struct capeq_domain   *domain = capeq_domain_lookup();
	struct capeq_task_ctx *taskc  = capeq_task_lookup(p);
	u64  membership, eligible = 0, remaining_ns, active_weight;
	u64  lag_magnitude, max_lag, weight;
	u32  prio_index, fraction, domain_fraction, eligible_fraction = 0;
	u32  abort_reason = CAPEQ_ABORT_NONE;
	s64  lag;
	bool isolated, wakeup, slept;

	if (!domain || !taskc) {
		capeq_report_abort(CAPEQ_ABORT_BAD_MEMBERSHIP);
		return;
	}
	wakeup = !!(enq_flags & SCX_ENQ_WAKEUP);

	/* CAPEQ_LOCK_BEGIN runnable_transition */
	bpf_spin_lock(&domain->lock);
	membership = taskc->membership;
	if (domain->scheduler_state != CAPEQ_SCHED_OPERATIONAL) {
		abort_reason = domain->abort_reason;
	} else if (CAPEQ_MEM_RESERVED(membership) ||
		   CAPEQ_MEM_STATE(membership) != CAPEQ_MEM_QUIESCENT ||
		   !CAPEQ_PAYLOAD_IS_VALID(membership) ||
		   CAPEQ_PAYLOAD_HAS_RESERVED(membership)) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_BAD_LIFECYCLE;
		abort_reason		= CAPEQ_ABORT_BAD_LIFECYCLE;
	} else if (domain->mutation_seq == ~0ULL) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
		abort_reason		= CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
	} else {
		prio_index   = CAPEQ_PAYLOAD_PRIO(membership);
		fraction     = CAPEQ_MEM_FRACTION(membership);
		lag	     = (s64)taskc->start;
		remaining_ns = taskc->deadline;
		slept	     = CAPEQ_PAYLOAD_IS_SLEEP(membership);
		if (prio_index >= 41U || !remaining_ns ||
		    remaining_ns > CAPEQ_REQUEST_NS) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_BAD_LIFECYCLE;
			abort_reason		= CAPEQ_ABORT_BAD_LIFECYCLE;
		} else {
			weight	= capeq_raw_weight[prio_index];
			max_lag = (CAPEQ_REQUEST_NS * CAPEQ_WEIGHT_SCALE +
				   weight - 1) /
				  weight;
			if (lag >= 0)
				lag_magnitude = (u64)lag;
			else
				lag_magnitude = (u64)(-(lag + 1)) + 1;
			if (lag_magnitude > max_lag ||
			    (lag >= 0 && lag_magnitude == max_lag &&
			     fraction)) {
				domain->scheduler_state = CAPEQ_SCHED_ABORTING;
				domain->abort_reason	= CAPEQ_ABORT_LAG_RANGE;
				abort_reason		= CAPEQ_ABORT_LAG_RANGE;
			}
		}
		if (!abort_reason) {
			active_weight = domain->active_weight;
			if (active_weight > (u64)(u32)~0U - weight) {
				domain->scheduler_state = CAPEQ_SCHED_ABORTING;
				domain->abort_reason =
					CAPEQ_ABORT_ACTIVE_WEIGHT;
				abort_reason = CAPEQ_ABORT_ACTIVE_WEIGHT;
			}
		}
		if (!abort_reason) {
			isolated = active_weight == 0;
			domain_fraction =
				domain->virtual_fraction >>
				(CAPEQ_DOMAIN_FRAC_BITS - CAPEQ_TASK_FRAC_BITS);
			if (isolated) {
				lag	 = 0;
				fraction = 0;
			}
			eligible = domain->virtual_time;
			if (lag >= 0) {
				if (eligible < (u64)lag) {
					/* Explicit non-wrapping S1 credit clamp. */
					eligible	  = 0;
					eligible_fraction = 0;
				} else {
					eligible -= (u64)lag;
					if (domain_fraction < fraction) {
						if (!eligible) {
							eligible_fraction = 0;
						} else {
							eligible--;
							eligible_fraction =
								domain_fraction +
								CAPEQ_TASK_FRAC_ONE -
								fraction;
						}
					} else {
						eligible_fraction =
							domain_fraction -
							fraction;
					}
				}
			} else {
				lag_magnitude = (u64)(-(lag + 1)) + 1;
				if (eligible > ~0ULL - lag_magnitude) {
					domain->scheduler_state =
						CAPEQ_SCHED_ABORTING;
					domain->abort_reason =
						CAPEQ_ABORT_RING_COLLISION;
					abort_reason =
						CAPEQ_ABORT_RING_COLLISION;
				} else {
					eligible += lag_magnitude;
					if (domain_fraction < fraction) {
						eligible--;
						eligible_fraction =
							domain_fraction +
							CAPEQ_TASK_FRAC_ONE -
							fraction;
					} else {
						eligible_fraction =
							domain_fraction -
							fraction;
					}
				}
			}
		}
		if (!abort_reason) {
			domain->active_weight = active_weight + weight;
			domain->mutation_seq++;
			taskc->start	= eligible;
			taskc->deadline = (wakeup || slept) ? CAPEQ_REQUEST_NS :
							      remaining_ns;
			taskc->aux	= 0;
			taskc->membership = CAPEQ_MEM_PACK_LIFE(
				CAPEQ_MEM_ACTIVE, prio_index, true, false,
				CAPEQ_MEM_EPOCH(membership), eligible_fraction);
		}
	}
	bpf_spin_unlock(&domain->lock);
	/* CAPEQ_LOCK_END runnable_transition */

	if (abort_reason)
		capeq_report_abort(abort_reason);
	else
		scx_bpf_task_set_dsq_vtime(p, eligible);
}

/* Snapshot runtime only after core dequeue and exec_start publication. */
void BPF_STRUCT_OPS(capeq_running, struct task_struct *p)
{
	struct capeq_domain   *domain = capeq_domain_lookup();
	struct capeq_task_ctx *taskc  = capeq_task_lookup(p);
	u64		       membership, runtime_now = p->se.sum_exec_runtime;
	u32 prio_index, fraction, abort_reason = CAPEQ_ABORT_NONE;

	if (!domain || !taskc) {
		capeq_report_abort(CAPEQ_ABORT_BAD_MEMBERSHIP);
		return;
	}

	/* CAPEQ_LOCK_BEGIN running_transition */
	bpf_spin_lock(&domain->lock);
	membership = taskc->membership;
	if (domain->scheduler_state != CAPEQ_SCHED_OPERATIONAL) {
		abort_reason = domain->abort_reason;
	} else if (CAPEQ_MEM_RESERVED(membership) ||
		   CAPEQ_MEM_STATE(membership) != CAPEQ_MEM_ACTIVE ||
		   !CAPEQ_PAYLOAD_IS_VALID(membership) ||
		   CAPEQ_PAYLOAD_HAS_RESERVED(membership)) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_BAD_LIFECYCLE;
		abort_reason		= CAPEQ_ABORT_BAD_LIFECYCLE;
	} else if (domain->mutation_seq == ~0ULL) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
		abort_reason		= CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
	} else {
		prio_index = CAPEQ_PAYLOAD_PRIO(membership);
		fraction   = CAPEQ_MEM_FRACTION(membership);
		if (prio_index >= 41U || !taskc->deadline ||
		    taskc->deadline > CAPEQ_REQUEST_NS || taskc->aux != 1U ||
		    !CAPEQ_RUNNING_COUNT(domain->running_count)) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_BAD_LIFECYCLE;
			abort_reason		= CAPEQ_ABORT_BAD_LIFECYCLE;
		} else {
			domain->mutation_seq++;
			taskc->aux	  = runtime_now;
			taskc->membership = CAPEQ_MEM_PACK_LIFE(
				CAPEQ_MEM_RUNNING, prio_index, true, false,
				CAPEQ_MEM_EPOCH(membership), fraction);
		}
	}
	bpf_spin_unlock(&domain->lock);
	/* CAPEQ_LOCK_END running_transition */

	if (abort_reason)
		capeq_report_abort(abort_reason);
}

/* Charge exact real service into the aggregate Q32 and per-task Q17 clocks. */
void BPF_STRUCT_OPS(capeq_stopping, struct task_struct *p, bool runnable)
{
	struct capeq_domain   *domain = capeq_domain_lookup();
	struct capeq_task_ctx *taskc  = capeq_task_lookup(p);
	u64 membership, runtime_now = p->se.sum_exec_runtime, baseline;
	u64 service_ns, remaining_ns, weight, numerator, delta, remainder;
	u64 fractional_delta, accumulated, carry, charge_q, charge_whole;
	u64 charge_fraction, task_accumulated, task_carry, new_start = 0;
	u64 old_v = 0, new_v = 0, changed;
	u32 prio_index, fraction, new_fraction = 0;
	u32 flip, eligible_mask, moved;
	u32 abort_reason = CAPEQ_ABORT_NONE;

	(void)runnable;
	if (!domain || !taskc) {
		capeq_report_abort(CAPEQ_ABORT_BAD_MEMBERSHIP);
		return;
	}

	/* CAPEQ_LOCK_BEGIN stopping_transition */
	bpf_spin_lock(&domain->lock);
	membership = taskc->membership;
	if (domain->scheduler_state != CAPEQ_SCHED_OPERATIONAL) {
		abort_reason = domain->abort_reason;
	} else if (CAPEQ_MEM_RESERVED(membership) ||
		   CAPEQ_MEM_STATE(membership) != CAPEQ_MEM_RUNNING ||
		   !CAPEQ_PAYLOAD_IS_VALID(membership) ||
		   CAPEQ_PAYLOAD_HAS_RESERVED(membership)) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_BAD_LIFECYCLE;
		abort_reason		= CAPEQ_ABORT_BAD_LIFECYCLE;
	} else {
		prio_index   = CAPEQ_PAYLOAD_PRIO(membership);
		fraction     = CAPEQ_MEM_FRACTION(membership);
		baseline     = taskc->aux;
		remaining_ns = taskc->deadline;
		if (runtime_now < baseline) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason = CAPEQ_ABORT_RUNTIME_REGRESSION;
			abort_reason	     = CAPEQ_ABORT_RUNTIME_REGRESSION;
		} else if (prio_index >= 41U || !remaining_ns ||
			   remaining_ns > CAPEQ_REQUEST_NS ||
			   !domain->active_weight ||
			   domain->active_weight > (u64)(u32)~0U ||
			   !CAPEQ_RUNNING_COUNT(domain->running_count)) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_BAD_LIFECYCLE;
			abort_reason		= CAPEQ_ABORT_BAD_LIFECYCLE;
		}
	}
	if (!abort_reason) {
		service_ns = runtime_now - baseline;
		if (service_ns > remaining_ns) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason = CAPEQ_ABORT_RUNTIME_OVERSERVICE;
			abort_reason	     = CAPEQ_ABORT_RUNTIME_OVERSERVICE;
		} else if (domain->mutation_seq == ~0ULL) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason =
				CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
			abort_reason = CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
		}
	}
	if (!abort_reason) {
		old_v = domain->virtual_time;
		weight		 = capeq_raw_weight[prio_index];
		numerator	 = service_ns * CAPEQ_WEIGHT_SCALE;
		delta		 = numerator / domain->active_weight;
		remainder	 = numerator % domain->active_weight;
		fractional_delta = (remainder << CAPEQ_DOMAIN_FRAC_BITS) /
				   domain->active_weight;
		accumulated	 = domain->virtual_fraction + fractional_delta;
		carry		 = accumulated >> CAPEQ_DOMAIN_FRAC_BITS;
		if (delta > ~0ULL - old_v ||
		    carry > ~0ULL - old_v - delta) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_RING_COLLISION;
			abort_reason		= CAPEQ_ABORT_RING_COLLISION;
		}
	}
	if (!abort_reason) {
		charge_q	 = service_ns * CAPEQ_WEIGHT_SCALE *
				   CAPEQ_TASK_FRAC_ONE / weight;
		charge_whole	 = charge_q >> CAPEQ_TASK_FRAC_BITS;
		charge_fraction	 = charge_q & CAPEQ_MEM_FRACTION_MASK;
		task_accumulated = fraction + charge_fraction;
		task_carry	 = task_accumulated >> CAPEQ_TASK_FRAC_BITS;
		if (charge_whole > ~0ULL - taskc->start ||
		    task_carry > ~0ULL - taskc->start - charge_whole) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_RING_COLLISION;
			abort_reason		= CAPEQ_ABORT_RING_COLLISION;
		} else {
			new_start    = taskc->start + charge_whole + task_carry;
			new_fraction = task_accumulated &
				       CAPEQ_MEM_FRACTION_MASK;
		}
	}
	if (!abort_reason) {
		new_v = old_v + delta + carry;
		domain->virtual_time = new_v;
		domain->virtual_fraction = accumulated & CAPEQ_DOMAIN_FRAC_MASK;
		/*
		 * QFQ eligibility changes only when an integer V bit flips.  Sparse
		 * groups [8..20,22] are projected into the dense 14-bit masks in
		 * constant work; no group scan is required.
		 */
		changed = old_v ^ new_v;
		if (changed) {
			flip = 64U - (u32)__builtin_clzll(changed);
			if (flip <= CAPEQ_MIN_SLOT_SHIFT + 8U)
				eligible_mask = 0;
			else if (flip <= CAPEQ_MIN_SLOT_SHIFT + 21U)
				eligible_mask =
					(1U << (flip - CAPEQ_MIN_SLOT_SHIFT - 8U)) - 1U;
			else if (flip <= CAPEQ_MIN_SLOT_SHIFT + 22U)
				eligible_mask = (1U << 13U) - 1U;
			else
				eligible_mask = CAPEQ_ALL_GROUP_MASK;
			moved = domain->ir_mask & eligible_mask;
			domain->er_mask |= moved;
			domain->ir_mask &= ~eligible_mask;
			moved = domain->ib_mask & eligible_mask;
			domain->eb_mask |= moved;
			domain->ib_mask &= ~eligible_mask;
		}
		domain->running_count--;
		domain->mutation_seq++;
		taskc->start	  = new_start;
		taskc->deadline	  = service_ns == remaining_ns ?
					    CAPEQ_REQUEST_NS :
					    remaining_ns - service_ns;
		taskc->aux	  = 0;
		taskc->membership = CAPEQ_MEM_PACK_LIFE(
			CAPEQ_MEM_ACTIVE, prio_index, true, false,
			CAPEQ_MEM_EPOCH(membership), new_fraction);
	}
	bpf_spin_unlock(&domain->lock);
	/* CAPEQ_LOCK_END stopping_transition */

	if (abort_reason)
		capeq_report_abort(abort_reason);
	else {
		/* Force every partial stop back through ops.enqueue and CAPE-Q. */
		p->scx.slice = 0;
		scx_bpf_task_set_dsq_vtime(p, new_start);
	}
}

/* Convert active eligibility to bounded signed lag before task attributes move. */
void BPF_STRUCT_OPS(capeq_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct capeq_domain   *domain = capeq_domain_lookup();
	struct capeq_task_ctx *taskc  = capeq_task_lookup(p);
	u64		       membership, weight, max_lag, difference, active_aux;
	u32  prio_index, fraction, domain_fraction, lag_fraction = 0;
	u32  abort_reason = CAPEQ_ABORT_NONE;
	s64  lag	  = 0;
	bool sleep = !!(deq_flags & SCX_DEQ_SLEEP), clamp = false;
	bool service_exit = false;

	if (!domain || !taskc) {
		capeq_report_abort(CAPEQ_ABORT_BAD_MEMBERSHIP);
		return;
	}

	/* CAPEQ_LOCK_BEGIN quiescent_transition */
	bpf_spin_lock(&domain->lock);
	membership = taskc->membership;
	if (domain->scheduler_state != CAPEQ_SCHED_OPERATIONAL) {
		abort_reason = domain->abort_reason;
	} else if (CAPEQ_MEM_RESERVED(membership) ||
		   CAPEQ_MEM_STATE(membership) != CAPEQ_MEM_ACTIVE ||
		   !CAPEQ_PAYLOAD_IS_VALID(membership) ||
		   CAPEQ_PAYLOAD_HAS_RESERVED(membership)) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_BAD_LIFECYCLE;
		abort_reason		= CAPEQ_ABORT_BAD_LIFECYCLE;
	} else if (domain->mutation_seq == ~0ULL) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
		abort_reason		= CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
	} else {
		prio_index = CAPEQ_PAYLOAD_PRIO(membership);
		fraction   = CAPEQ_MEM_FRACTION(membership);
		active_aux = taskc->aux;
		service_exit = active_aux == 1U;
		if (prio_index >= 41U || !taskc->deadline ||
		    taskc->deadline > CAPEQ_REQUEST_NS || active_aux > 1U ||
		    (service_exit &&
		     !CAPEQ_RUNNING_COUNT(domain->running_count))) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_BAD_LIFECYCLE;
			abort_reason		= CAPEQ_ABORT_BAD_LIFECYCLE;
		} else {
			weight = capeq_raw_weight[prio_index];
			if (domain->active_weight < weight ||
			    domain->active_weight > (u64)(u32)~0U) {
				domain->scheduler_state = CAPEQ_SCHED_ABORTING;
				domain->abort_reason =
					CAPEQ_ABORT_ACTIVE_WEIGHT;
				abort_reason = CAPEQ_ABORT_ACTIVE_WEIGHT;
			}
		}
	}
	if (!abort_reason) {
		max_lag = (CAPEQ_REQUEST_NS * CAPEQ_WEIGHT_SCALE + weight - 1) /
			  weight;
		domain_fraction =
			domain->virtual_fraction >>
			(CAPEQ_DOMAIN_FRAC_BITS - CAPEQ_TASK_FRAC_BITS);
		if (domain->virtual_time >= taskc->start) {
			difference = domain->virtual_time - taskc->start;
			if (difference > max_lag ||
			    (difference == max_lag &&
			     domain_fraction > fraction)) {
				clamp = true;
				lag   = (s64)max_lag;
			} else if (domain_fraction >= fraction) {
				lag	     = (s64)difference;
				lag_fraction = domain_fraction - fraction;
			} else if (!difference) {
				lag	     = -1;
				lag_fraction = domain_fraction +
					       CAPEQ_TASK_FRAC_ONE - fraction;
			} else {
				lag	     = (s64)(difference - 1);
				lag_fraction = domain_fraction +
					       CAPEQ_TASK_FRAC_ONE - fraction;
			}
		} else {
			difference = taskc->start - domain->virtual_time;
			if (difference > max_lag ||
			    (difference == max_lag &&
			     fraction > domain_fraction)) {
				clamp = true;
				lag   = -(s64)max_lag;
			} else if (domain_fraction >= fraction) {
				lag	     = -(s64)difference;
				lag_fraction = domain_fraction - fraction;
			} else {
				lag	     = -(s64)(difference + 1);
				lag_fraction = domain_fraction +
					       CAPEQ_TASK_FRAC_ONE - fraction;
			}
		}
		if (clamp)
			lag_fraction = 0;
		if (service_exit)
			domain->running_count--;
		domain->active_weight -= weight;
		domain->mutation_seq++;
		taskc->start	  = (u64)lag;
		taskc->aux	  = 0;
		taskc->membership = CAPEQ_MEM_PACK_LIFE(
			CAPEQ_MEM_QUIESCENT, prio_index, true, sleep,
			CAPEQ_MEM_EPOCH(membership), lag_fraction);
	}
	bpf_spin_unlock(&domain->lock);
	/* CAPEQ_LOCK_END quiescent_transition */

	if (abort_reason)
		capeq_report_abort(abort_reason);
}

/* Preserve weighted signed Q17 lag across source-ordered nice changes. */
void BPF_STRUCT_OPS(capeq_set_weight, struct task_struct *p, u32 weight_arg)
{
	struct capeq_domain   *domain = capeq_domain_lookup();
	struct capeq_task_ctx *taskc  = capeq_task_lookup(p);
	u64 membership, old_weight, new_weight, max_lag, magnitude;
	u64 new_max_lag;
	u32 old_prio, new_prio = capeq_prio_index(p), fraction;
	u32 new_fraction = 0, abort_reason = CAPEQ_ABORT_NONE;
	s64 lag, lag_q, numerator, rescaled, new_lag;
	s64 remainder;

	(void)weight_arg;
	if (!domain || !taskc) {
		capeq_report_abort(CAPEQ_ABORT_BAD_MEMBERSHIP);
		return;
	}

	/* CAPEQ_LOCK_BEGIN set_weight_transition */
	bpf_spin_lock(&domain->lock);
	membership = taskc->membership;
	if (domain->scheduler_state != CAPEQ_SCHED_OPERATIONAL) {
		abort_reason = domain->abort_reason;
	} else if (CAPEQ_MEM_RESERVED(membership) ||
		   CAPEQ_MEM_STATE(membership) != CAPEQ_MEM_QUIESCENT ||
		   !CAPEQ_PAYLOAD_IS_VALID(membership) ||
		   CAPEQ_PAYLOAD_HAS_RESERVED(membership) || new_prio >= 41U) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_BAD_LIFECYCLE;
		abort_reason		= CAPEQ_ABORT_BAD_LIFECYCLE;
	} else if (domain->mutation_seq == ~0ULL) {
		domain->scheduler_state = CAPEQ_SCHED_ABORTING;
		domain->abort_reason	= CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
		abort_reason		= CAPEQ_ABORT_DOMAIN_SEQUENCE_OVERFLOW;
	} else {
		old_prio = CAPEQ_PAYLOAD_PRIO(membership);
		fraction = CAPEQ_MEM_FRACTION(membership);
		lag	 = (s64)taskc->start;
		if (old_prio >= 41U || !taskc->deadline ||
		    taskc->deadline > CAPEQ_REQUEST_NS) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_BAD_LIFECYCLE;
			abort_reason		= CAPEQ_ABORT_BAD_LIFECYCLE;
		} else {
			old_weight = capeq_raw_weight[old_prio];
			new_weight = capeq_raw_weight[new_prio];
			max_lag	   = (CAPEQ_REQUEST_NS * CAPEQ_WEIGHT_SCALE +
				      old_weight - 1) /
				     old_weight;
			magnitude = lag >= 0 ? (u64)lag : (u64)(-(lag + 1)) + 1;
			if (magnitude > max_lag ||
			    (lag >= 0 && magnitude == max_lag && fraction)) {
				domain->scheduler_state = CAPEQ_SCHED_ABORTING;
				domain->abort_reason	= CAPEQ_ABORT_LAG_RANGE;
				abort_reason		= CAPEQ_ABORT_LAG_RANGE;
			}
		}
	}
	if (!abort_reason) {
		lag_q	  = lag * (s64)CAPEQ_TASK_FRAC_ONE + fraction;
		numerator = lag_q * (s64)old_weight;
		rescaled  = numerator / (s64)new_weight;
		new_lag	  = rescaled / (s64)CAPEQ_TASK_FRAC_ONE;
		remainder = rescaled % (s64)CAPEQ_TASK_FRAC_ONE;
		if (remainder < 0) {
			new_lag--;
			remainder += CAPEQ_TASK_FRAC_ONE;
		}
		new_fraction = (u32)remainder;
		new_max_lag  = (CAPEQ_REQUEST_NS * CAPEQ_WEIGHT_SCALE +
				new_weight - 1) /
			       new_weight;
		magnitude    = new_lag >= 0 ? (u64)new_lag :
					      (u64)(-(new_lag + 1)) + 1;
		if (magnitude > new_max_lag ||
		    (new_lag >= 0 && magnitude == new_max_lag &&
		     new_fraction)) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_LAG_RANGE;
			abort_reason		= CAPEQ_ABORT_LAG_RANGE;
		}
	}
	if (!abort_reason) {
		domain->mutation_seq++;
		taskc->start	  = (u64)new_lag;
		taskc->membership = CAPEQ_MEM_PACK_LIFE(
			CAPEQ_MEM_QUIESCENT, new_prio, true,
			CAPEQ_PAYLOAD_IS_SLEEP(membership),
			CAPEQ_MEM_EPOCH(membership), new_fraction);
	}
	bpf_spin_unlock(&domain->lock);
	/* CAPEQ_LOCK_END set_weight_transition */

	if (abort_reason)
		capeq_report_abort(abort_reason);
}

/*
 * Snapshot and iteration are advisory.  A candidate becomes a CAPE-Q policy
 * winner only when dispatch_reserve revalidates it and removes it from logical
 * ER state under the domain lock.  The subsequent unlocked move has physical
 * single-winner authority; nested dequeue closes or cancels the reservation.
 */
void BPF_STRUCT_OPS(capeq_dispatch, s32 cpu, struct task_struct *prev)
{
	struct capeq_domain   *domain = capeq_domain_lookup();
	struct capeq_task_ctx *taskc;
	struct capeq_group    *group;
	struct task_struct    *p;
	u64 membership, reserved_membership = 0, tagged_key = 0, key, slot_size;
	u64 rounded_start, mutation_seq = 0, dsq_id, old_finish, old_v, new_v;
	u64 changed;
	u32 mask, union_mask, ineligible, eligible_mask, moved, sparse, count;
	u32 dense = 0, slot = 0, counter_index = 0, flip, prio_index;
	u32 bit, state_count, old_state, current_slot, rotated, distance;
	u32 higher, next, lower, state, fraction, blocker = 0;
	u32 scanned = 0, attempted = 0;
	u32 abort_reason = CAPEQ_ABORT_NONE;
	bool have_snapshot = false, budget_exhausted = false;
	bool saw_published_key = false, stale_snapshot = false;
	bool reservation_acquired = false, front_changed = false;
	bool release_lower = false, eligible, blocked = false;

	(void)prev;
	if (!domain)
		return;

	/* CAPEQ_LOCK_BEGIN dispatch_snapshot */
	bpf_spin_lock(&domain->lock);
	if (domain->scheduler_state == CAPEQ_SCHED_OPERATIONAL) {
		union_mask = domain->er_mask | domain->ir_mask |
			     domain->eb_mask | domain->ib_mask;
		if ((union_mask & ~((1U << CAPEQ_GROUP_COUNT) - 1)) ||
		    (domain->er_mask & (domain->ir_mask | domain->eb_mask |
					domain->ib_mask)) ||
		    (domain->ir_mask & (domain->eb_mask | domain->ib_mask)) ||
		    (domain->eb_mask & domain->ib_mask) ||
		    (!!union_mask != !!domain->total_count)) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_BAD_MEMBERSHIP;
			abort_reason		= CAPEQ_ABORT_BAD_MEMBERSHIP;
		}
		mask = domain->er_mask;
		ineligible = domain->ir_mask | domain->ib_mask;
		if (!abort_reason && !mask &&
		    (domain->eb_mask || domain->ib_mask)) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_BAD_MEMBERSHIP;
			abort_reason		= CAPEQ_ABORT_BAD_MEMBERSHIP;
		} else if (!abort_reason && !mask && ineligible &&
			   !domain->running_count) {
			dense = (u32)__builtin_ctz(ineligible);
			old_v = domain->virtual_time;
			new_v = domain->groups[dense].start;
			if (!domain->groups[dense].slot_mask || new_v <= old_v ||
			    domain->mutation_seq == ~0ULL) {
				domain->scheduler_state = CAPEQ_SCHED_ABORTING;
				domain->abort_reason = CAPEQ_ABORT_BAD_MEMBERSHIP;
				abort_reason = CAPEQ_ABORT_BAD_MEMBERSHIP;
			} else {
				domain->virtual_time = new_v;
				domain->virtual_fraction = 0;
				changed = old_v ^ new_v;
				flip = 64U - (u32)__builtin_clzll(changed);
				if (flip <= CAPEQ_MIN_SLOT_SHIFT + 8U)
					eligible_mask = 0;
				else if (flip <= CAPEQ_MIN_SLOT_SHIFT + 21U)
					eligible_mask =
						(1U << (flip - CAPEQ_MIN_SLOT_SHIFT - 8U)) - 1U;
				else if (flip <= CAPEQ_MIN_SLOT_SHIFT + 22U)
					eligible_mask = (1U << 13U) - 1U;
				else
					eligible_mask = CAPEQ_ALL_GROUP_MASK;
				moved = domain->ir_mask & eligible_mask;
				domain->er_mask |= moved;
				domain->ir_mask &= ~eligible_mask;
				moved = domain->ib_mask & eligible_mask;
				domain->eb_mask |= moved;
				domain->ib_mask &= ~eligible_mask;
				domain->mutation_seq++;
				mask = domain->er_mask;
				if (!mask) {
					domain->scheduler_state = CAPEQ_SCHED_ABORTING;
					domain->abort_reason =
						CAPEQ_ABORT_BAD_MEMBERSHIP;
					abort_reason = CAPEQ_ABORT_BAD_MEMBERSHIP;
				}
			}
		}
		if (!abort_reason && mask) {
			dense = (u32)__builtin_ctz(mask);
			slot  = domain->groups[dense].current_slot;
			if (slot >= CAPEQ_SLOTS_PER_GROUP ||
			    !(domain->groups[dense].slot_mask & (1U << slot)) ||
			    !(domain->er_mask & (1U << dense))) {
				domain->scheduler_state = CAPEQ_SCHED_ABORTING;
				domain->abort_reason = CAPEQ_ABORT_BAD_MEMBERSHIP;
				abort_reason = CAPEQ_ABORT_BAD_MEMBERSHIP;
			} else {
				rounded_start = domain->groups[dense].start;
				mutation_seq  = domain->mutation_seq;
				counter_index =
					dense * CAPEQ_SLOTS_PER_GROUP + slot;
				if (!domain->slot_counts[counter_index]) {
					domain->scheduler_state = CAPEQ_SCHED_ABORTING;
					domain->abort_reason =
						CAPEQ_ABORT_COUNTER_UNDERFLOW;
					abort_reason = CAPEQ_ABORT_COUNTER_UNDERFLOW;
				} else {
					have_snapshot = true;
				}
			}
		}
	}
	bpf_spin_unlock(&domain->lock);
	/* CAPEQ_LOCK_END dispatch_snapshot */

	if (abort_reason) {
		capeq_report_abort(abort_reason);
		return;
	}
	if (!have_snapshot)
		return;
	dsq_id = CAPEQ_DSQ_BASE + dense;

	bpf_for_each(scx_dsq, p, dsq_id, 0) {
		if (scanned >= CAPEQ_SCAN_BUDGET) {
			budget_exhausted = true;
			break;
		}
		scanned++;
		taskc = bpf_task_storage_get(&capeq_tasks, p, 0, 0);
		if (!taskc)
			continue;
		membership = READ_ONCE(taskc->membership);
		tagged_key = READ_ONCE(taskc->aux);
		if (CAPEQ_MEM_RESERVED(membership) ||
		    CAPEQ_MEM_STATE(membership) != CAPEQ_MEM_PUBLISHED ||
		    CAPEQ_MEM_GROUP(membership) != dense ||
		    CAPEQ_MEM_SLOT(membership) != slot ||
		    CAPEQ_KEY_RESERVED(tagged_key) ||
		    CAPEQ_KEY_PRIO(tagged_key) >= 41U ||
		    CAPEQ_KEY_VALUE(tagged_key) != rounded_start ||
		    p->scx.dsq_vtime != rounded_start)
			continue;
		saw_published_key = true;
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		if (attempted >= CAPEQ_MOVE_BUDGET) {
			budget_exhausted = true;
			break;
		}

		/* CAPEQ_LOCK_BEGIN dispatch_reserve */
		bpf_spin_lock(&domain->lock);
		membership = taskc->membership;
		tagged_key = taskc->aux;
		if (domain->scheduler_state != CAPEQ_SCHED_OPERATIONAL) {
			abort_reason = domain->abort_reason;
		} else if (domain->mutation_seq != mutation_seq) {
			stale_snapshot = true;
		} else if (CAPEQ_MEM_RESERVED(membership) ||
			   CAPEQ_MEM_STATE(membership) != CAPEQ_MEM_PUBLISHED ||
			   CAPEQ_MEM_GROUP(membership) != dense ||
			   CAPEQ_MEM_SLOT(membership) != slot ||
			   CAPEQ_KEY_RESERVED(tagged_key) ||
			   CAPEQ_KEY_PRIO(tagged_key) >= 41U ||
			   CAPEQ_KEY_VALUE(tagged_key) != rounded_start) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_BAD_MEMBERSHIP;
			abort_reason		= CAPEQ_ABORT_BAD_MEMBERSHIP;
		} else if (domain->mutation_seq == ~0ULL ||
			   CAPEQ_DISPATCH_COUNT(domain->running_count) ==
				   CAPEQ_RUNNING_COUNT_MASK) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_COUNTER_OVERFLOW;
			abort_reason		= CAPEQ_ABORT_COUNTER_OVERFLOW;
		} else {
			group	      = &domain->groups[dense];
			count	      = domain->slot_counts[counter_index];
			bit	      = 1U << dense;
			sparse	      = capeq_dense_to_sparse[dense];
			slot_size     = 1ULL << (sparse + CAPEQ_MIN_SLOT_SHIFT);
			key	      = CAPEQ_KEY_VALUE(tagged_key);
			prio_index    = CAPEQ_KEY_PRIO(tagged_key);
			fraction      = CAPEQ_MEM_FRACTION(membership);
			state_count   = !!(domain->er_mask & bit) +
					!!(domain->ir_mask & bit) +
					!!(domain->eb_mask & bit) +
					!!(domain->ib_mask & bit);
			old_state     = domain->er_mask & bit ? CAPEQ_GROUP_ER :
					CAPEQ_GROUP_NONE;
			old_finish    = group->finish;
			if (!count || !domain->total_count || state_count != 1U ||
			    old_state != CAPEQ_GROUP_ER ||
			    (u32)__builtin_ctz(domain->er_mask) != dense ||
			    group->dense_id != dense || group->current_slot != slot ||
			    !(group->slot_mask & (1U << slot)) ||
			    key != group->start ||
			    ((key - group->start) & (slot_size - 1))) {
				domain->scheduler_state = CAPEQ_SCHED_ABORTING;
				domain->abort_reason = CAPEQ_ABORT_BAD_MEMBERSHIP;
				abort_reason = CAPEQ_ABORT_BAD_MEMBERSHIP;
			} else {
				domain->slot_counts[counter_index] = count - 1;
				domain->total_count--;
				domain->mutation_seq++;
				domain->running_count += CAPEQ_DISPATCH_COUNT_ONE;
				reserved_membership =
					CAPEQ_MEM_WITH_DISPATCH_RESERVATION(membership);
				taskc->membership = reserved_membership;
				if (count == 1) {
					domain->empty_retries[counter_index] = 0;
					group->slot_mask &= ~(1U << slot);
					front_changed = slot == group->current_slot;
					if (!group->slot_mask) {
						group->start = 0;
						group->finish = 0;
						group->current_slot = 0;
						group->state = CAPEQ_GROUP_NONE;
						domain->er_mask &= ~bit;
						domain->ir_mask &= ~bit;
						domain->eb_mask &= ~bit;
						domain->ib_mask &= ~bit;
					} else if (front_changed) {
						current_slot = group->current_slot & 31U;
						rotated = (group->slot_mask >> current_slot) |
							  (group->slot_mask <<
							   ((32U - current_slot) & 31U));
						distance = (u32)__builtin_ctz(rotated);
						group->current_slot =
							(current_slot + distance) & 31U;
						group->start += (u64)distance * slot_size;
						group->finish =
							group->start + (slot_size << 1);
						domain->er_mask &= ~bit;
						domain->ir_mask &= ~bit;
						domain->eb_mask &= ~bit;
						domain->ib_mask &= ~bit;
						eligible = group->start <= domain->virtual_time;
						higher = domain->er_mask &
							 (~((1U << dense) - 1U) &
							  CAPEQ_ALL_GROUP_MASK);
						blocked = false;
						if (higher) {
							blocker = (u32)__builtin_ctz(higher);
							if (!domain->groups[blocker].slot_mask) {
								domain->scheduler_state =
									CAPEQ_SCHED_ABORTING;
								domain->abort_reason =
									CAPEQ_ABORT_BAD_MEMBERSHIP;
								abort_reason =
									CAPEQ_ABORT_BAD_MEMBERSHIP;
							} else {
								blocked = group->finish >
									domain->groups[blocker].finish;
							}
						}
						if (!abort_reason) {
							state = eligible ?
								(blocked ? CAPEQ_GROUP_EB :
									   CAPEQ_GROUP_ER) :
								(blocked ? CAPEQ_GROUP_IB :
									   CAPEQ_GROUP_IR);
							group->state = state;
							if (state == CAPEQ_GROUP_ER)
								domain->er_mask |= bit;
							else if (state == CAPEQ_GROUP_IR)
								domain->ir_mask |= bit;
							else if (state == CAPEQ_GROUP_EB)
								domain->eb_mask |= bit;
							else
								domain->ib_mask |= bit;
						}
					}
				}
				if (!abort_reason && old_state == CAPEQ_GROUP_ER &&
				    (!group->slot_mask || front_changed)) {
					release_lower = true;
					higher = domain->er_mask &
						 (~((1U << (dense + 1U)) - 1U) &
						  CAPEQ_ALL_GROUP_MASK);
					if (higher) {
						next = (u32)__builtin_ctz(higher);
						if (!domain->groups[next].slot_mask) {
							domain->scheduler_state =
								CAPEQ_SCHED_ABORTING;
							domain->abort_reason =
								CAPEQ_ABORT_BAD_MEMBERSHIP;
							abort_reason =
								CAPEQ_ABORT_BAD_MEMBERSHIP;
						} else if (domain->groups[next].finish <=
							   old_finish) {
							release_lower = false;
						}
					}
					if (!abort_reason && release_lower) {
						lower = (1U << dense) - 1U;
						moved = domain->eb_mask & lower;
						domain->er_mask |= moved;
						domain->eb_mask &= ~lower;
						moved = domain->ib_mask & lower;
						domain->ir_mask |= moved;
						domain->ib_mask &= ~lower;
					}
				}
				if (!abort_reason)
					reservation_acquired = true;
			}
		}
		bpf_spin_unlock(&domain->lock);
		/* CAPEQ_LOCK_END dispatch_reserve */

		if (abort_reason) {
			capeq_report_abort(abort_reason);
			return;
		}
		if (stale_snapshot)
			return;
		if (!reservation_acquired)
			return;
		attempted++;
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_LOCAL, 0))
			return;

		/* CAPEQ_LOCK_BEGIN dispatch_move_result */
		bpf_spin_lock(&domain->lock);
		membership = taskc->membership;
		if (domain->scheduler_state == CAPEQ_SCHED_OPERATIONAL &&
		    membership == reserved_membership && taskc->aux == tagged_key) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason = CAPEQ_ABORT_RESERVED_MOVE_FAILED;
			abort_reason = CAPEQ_ABORT_RESERVED_MOVE_FAILED;
		}
		bpf_spin_unlock(&domain->lock);
		/* CAPEQ_LOCK_END dispatch_move_result */

		if (abort_reason)
			capeq_report_abort(abort_reason);
		return;
	}

	/* CAPEQ_LOCK_BEGIN dispatch_finish */
	bpf_spin_lock(&domain->lock);
	if (domain->scheduler_state == CAPEQ_SCHED_OPERATIONAL &&
	    domain->mutation_seq == mutation_seq &&
	    domain->slot_counts[counter_index]) {
		if (budget_exhausted) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason	= CAPEQ_ABORT_SCAN_BUDGET;
			abort_reason		= CAPEQ_ABORT_SCAN_BUDGET;
		} else if (!saw_published_key &&
			   domain->empty_retries[counter_index] ==
				   CAPEQ_EMPTY_RETRY_BUDGET - 1) {
			domain->scheduler_state = CAPEQ_SCHED_ABORTING;
			domain->abort_reason = CAPEQ_ABORT_UNCHANGED_EMPTY_SCAN;
			abort_reason	     = CAPEQ_ABORT_UNCHANGED_EMPTY_SCAN;
		} else if (!saw_published_key) {
			domain->empty_retries[counter_index]++;
		}
	}
	bpf_spin_unlock(&domain->lock);
	/* CAPEQ_LOCK_END dispatch_finish */

	if (abort_reason)
		capeq_report_abort(abort_reason);
}

s32 BPF_STRUCT_OPS(capeq_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct capeq_task_ctx *taskc;

	(void)args;
	taskc = bpf_task_storage_get(&capeq_tasks, p, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc)
		return -ENOMEM;
	taskc->membership = 0;
	taskc->start	  = 0;
	taskc->deadline	  = 0;
	taskc->aux	  = 0;
	return 0;
}

void BPF_STRUCT_OPS(capeq_enable, struct task_struct *p)
{
	struct capeq_domain   *domain = capeq_domain_lookup();
	struct capeq_task_ctx *taskc  = capeq_task_lookup(p);
	u64		       virtual_time;
	u32		       prio_index;

	if (!domain || !taskc)
		return;
	prio_index	  = capeq_prio_index(p);
	virtual_time	  = READ_ONCE(domain->virtual_time);
	taskc->membership = CAPEQ_MEM_PACK_LIFE(CAPEQ_MEM_QUIESCENT, prio_index,
						true, true, 0, 0);
	taskc->start	  = 0;
	taskc->deadline	  = CAPEQ_REQUEST_NS;
	taskc->aux	  = 0;
	scx_bpf_task_set_dsq_vtime(p, virtual_time);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(capeq_init)
{
	struct capeq_domain *domain = capeq_domain_lookup();
	s32		     index, ret;

	if (!domain)
		return -ENOMEM;
	domain->scheduler_state	 = CAPEQ_SCHED_OPERATIONAL;
	domain->abort_reason	 = CAPEQ_ABORT_NONE;
	domain->running_count	 = 0;
	domain->mutation_seq	 = 0;
	domain->total_count	 = 0;
	domain->er_mask		 = 0;
	domain->ir_mask		 = 0;
	domain->eb_mask		 = 0;
	domain->ib_mask		 = 0;
	domain->virtual_fraction = 0;
	domain->virtual_time	 = 0;
	domain->active_weight	 = 0;

	bpf_for(index, 0, CAPEQ_GROUP_COUNT) {
		domain->groups[index].start = 0;
		domain->groups[index].finish = 0;
		domain->groups[index].slot_mask = 0;
		domain->groups[index].current_slot = 0;
		domain->groups[index].state = CAPEQ_GROUP_NONE;
		domain->groups[index].dense_id = (u32)index;
		ret = scx_bpf_create_dsq(CAPEQ_DSQ_BASE + (u32)index, -1);
		if (ret)
			return ret;
	}
	bpf_for(index, 0, CAPEQ_SLOT_COUNT) {
		domain->slot_counts[index] = 0;
		domain->empty_retries[index] = 0;
	}
	return 0;
}

void BPF_STRUCT_OPS(capeq_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cape_qfq_s1_custody_ops, .runnable = (void *)capeq_runnable,
	       .enqueue	   = (void *)capeq_enqueue,
	       .dequeue	   = (void *)capeq_dequeue,
	       .dispatch   = (void *)capeq_dispatch,
	       .running	   = (void *)capeq_running,
	       .stopping   = (void *)capeq_stopping,
	       .quiescent  = (void *)capeq_quiescent,
	       .set_weight = (void *)capeq_set_weight,
	       .enable	   = (void *)capeq_enable,
	       .init_task = (void *)capeq_init_task, .init = (void *)capeq_init,
	       .exit = (void *)capeq_exit, .timeout_ms = CAPEQ_WATCHDOG_MS,
	       .flags = SCX_OPS_ENQ_LAST,
	       .name = "cape_qfq_s1_custody");
