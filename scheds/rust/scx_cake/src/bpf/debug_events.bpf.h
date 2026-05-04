/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CAKE_DEBUG_EVENTS_BPF_H
#define __CAKE_DEBUG_EVENTS_BPF_H

#define CAKE_DBG_EVENT_META(kind, slot, aux) \
	((((u64)(aux)) << 16) | (((u64)(slot)) << 8) | (u64)(kind))

#ifdef CAKE_RELEASE
#define cake_emit_dbg_event(p, cpu, kind, slot, value_ns, aux) do { } while (0)
#else
static __always_inline void cake_copy_comm(char *dst, const char *src)
{
	*((u64 *)&dst[0]) = *((const u64 *)&src[0]);
	*((u64 *)&dst[8]) = *((const u64 *)&src[8]);
}

static __noinline void cake_emit_dbg_event_packed(
	struct task_struct *p,
	u32 cpu,
	u64 value_ns,
	u64 meta)
{
	struct cake_debug_event *ev;
	u32 aux = (u32)(meta >> 16);
	u8 slot = (u8)(meta >> 8);
	u8 kind = (u8)meta;

	if (!CAKE_STATS_ACTIVE)
		return;

	ev = bpf_ringbuf_reserve(&debug_ringbuf, sizeof(*ev), 0);
	if (!ev)
		return;

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->value_ns = value_ns;
	ev->pid = p ? p->pid : 0;
	ev->aux = aux;
	ev->cpu = cpu;
	ev->kind = kind;
	ev->slot = slot;
	if (p)
		cake_copy_comm(ev->comm, p->comm);
	ev->ts_ns = bpf_ktime_get_ns();
	bpf_ringbuf_submit(ev, 0);
}

#define cake_emit_dbg_event(p, cpu, kind, slot, value_ns, aux) \
	cake_emit_dbg_event_packed((p), (cpu), (value_ns), \
				   CAKE_DBG_EVENT_META((kind), (slot), (aux)))

#if CAKE_DEBUG_EVENT_STREAM
static __always_inline u32 cake_debug_mix32(u32 h)
{
	h ^= h >> 16;
	h *= 0x7feb352dU;
	h ^= h >> 15;
	h *= 0x846ca68bU;
	h ^= h >> 16;
	return h;
}

static __always_inline bool cake_debug_should_sample_wake_edge(u32 pid, u32 peer_pid,
							       u8 kind, u64 ts_ns)
{
	u64 epoch = ts_ns / CAKE_WAKE_EDGE_SAMPLE_NS;
	u32 h = pid * 2654435761U;

	h ^= peer_pid * 2246822519U;
	h ^= (u32)epoch * 3266489917U;
	h ^= (u32)(epoch >> 32);
	h ^= (u32)kind * 668265263U;
	h = cake_debug_mix32(h);

	return (h & (CAKE_WAKE_EDGE_SAMPLE_DENOM - 1)) == 0;
}

static __always_inline u32 cake_debug_wake_edge_sample_weight(bool important)
{
	return important ? 1U : CAKE_WAKE_EDGE_SAMPLE_DENOM;
}

static __noinline void cake_emit_wake_edge_enqueue_event(
	struct cake_task_ctx __arena *tctx,
	struct task_struct *waker,
	struct task_struct *wakee)
{
	struct cake_debug_event *ev;
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	u64 ts_ns;
	u32 wakee_pid;
	u32 waker_pid;
	u8 flags = CAKE_WAKE_EDGE_EVENT_FLAG_SAMPLED;

	if (!tctx || !waker || !wakee || !CAKE_STATS_ACTIVE)
		return;

	ts_ns = bpf_ktime_get_ns();
	wakee_pid = wakee->pid;
	waker_pid = waker->pid;
	if (!cake_debug_should_sample_wake_edge(
		    wakee_pid, waker_pid, CAKE_DBG_EVENT_WAKE_EDGE_ENQUEUE, ts_ns))
		return;

	ev = bpf_ringbuf_reserve(&debug_ringbuf, sizeof(*ev), 0);
	if (!ev) {
		cake_debug_atomic_inc(&wake_edge_missed_updates);
		return;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->pid = wakee_pid;
	ev->tgid = wakee->tgid;
	ev->aux = CAKE_WAKE_EDGE_SAMPLE_DENOM;
	ev->peer_pid = waker_pid;
	ev->peer_tgid = waker->tgid;
	ev->cpu = (u16)cpu;
	ev->peer_cpu = (u16)cpu;
	ev->kind = CAKE_DBG_EVENT_WAKE_EDGE_ENQUEUE;
	ev->flags = flags;
	cake_copy_comm(ev->comm, wakee->comm);
	ev->ts_ns = bpf_ktime_get_ns();
	bpf_ringbuf_submit(ev, 0);
}

static __noinline void cake_emit_wake_edge_run_event(
	struct cake_task_ctx __arena *tctx,
	struct task_struct *p,
	u32 cpu,
	u64 wait_ns,
	u64 packed)
{
	struct cake_debug_event *ev;
	u32 edge_meta = (u32)packed;
	u16 place_meta = (u16)(packed >> 32);
	u8 reason = (u8)edge_meta;
	u16 target_cpu = (u16)(edge_meta >> 8);
	u64 ts_ns;
	u32 pid;
	u32 peer_pid;
	bool important;
	u8 flags = 0;

	if (!tctx || !p || !CAKE_STATS_ACTIVE)
		return;
	if (reason <= CAKE_WAKE_REASON_NONE || reason >= CAKE_WAKE_REASON_MAX)
		return;

	ts_ns = bpf_ktime_get_ns();
	pid = p->pid;
	peer_pid = tctx->telemetry.wakeup_source_pid;
	important = wait_ns >= CAKE_SLOW_WAKEWAIT_NS ||
		    (target_cpu < CAKE_MAX_CPUS && (u16)cpu != target_cpu);
	if (!important && !cake_debug_should_sample_wake_edge(
				  pid, peer_pid, CAKE_DBG_EVENT_WAKE_EDGE_RUN,
				  ts_ns))
		return;

	if (!important)
		flags |= CAKE_WAKE_EDGE_EVENT_FLAG_SAMPLED;
	else
		flags |= CAKE_WAKE_EDGE_EVENT_FLAG_IMPORTANT;
	if (target_cpu < CAKE_MAX_CPUS && (u16)cpu == target_cpu)
		flags |= CAKE_WAKE_EDGE_EVENT_FLAG_HIT_OR_SAME;

	ev = bpf_ringbuf_reserve(&debug_ringbuf, sizeof(*ev), 0);
	if (!ev) {
		cake_debug_atomic_inc(&wake_edge_missed_updates);
		return;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->value_ns = wait_ns;
	ev->pid = pid;
	ev->tgid = p->tgid;
	ev->aux = cake_debug_wake_edge_sample_weight(important);
	ev->peer_pid = peer_pid;
	ev->peer_tgid = tctx->telemetry.waker_tgid;
	ev->cpu = (u16)cpu;
	ev->target_cpu = target_cpu;
	ev->peer_cpu = tctx->telemetry.waker_cpu;
	ev->kind = CAKE_DBG_EVENT_WAKE_EDGE_RUN;
	ev->slot = reason;
	ev->reason = reason;
	ev->path = (u8)(edge_meta >> 24);
	ev->home_place = (u8)place_meta;
	ev->waker_place = (u8)(place_meta >> 8);
	ev->flags = flags;
	cake_copy_comm(ev->comm, p->comm);
	ev->ts_ns = bpf_ktime_get_ns();
	bpf_ringbuf_submit(ev, 0);
}

static __noinline void cake_emit_wake_edge_follow_event(
	struct cake_task_ctx __arena *tctx,
	struct task_struct *p,
	u32 cpu,
	u64 gap_ns,
	bool same_cpu)
{
	struct cake_debug_event *ev;
	u8 reason;
	u64 ts_ns;
	u32 pid;
	u32 peer_pid;
	u8 flags = 0;

	if (!tctx || !p || !CAKE_STATS_ACTIVE)
		return;

	reason = tctx->telemetry.postwake_reason;
	if (reason <= CAKE_WAKE_REASON_NONE || reason >= CAKE_WAKE_REASON_MAX)
		return;

	ts_ns = bpf_ktime_get_ns();
	pid = p->pid;
	peer_pid = tctx->telemetry.wakeup_source_pid;
	if (same_cpu && !cake_debug_should_sample_wake_edge(
				  pid, peer_pid,
				  CAKE_DBG_EVENT_WAKE_EDGE_FOLLOW, ts_ns))
		return;

	if (same_cpu)
		flags |= CAKE_WAKE_EDGE_EVENT_FLAG_SAMPLED;
	else
		flags |= CAKE_WAKE_EDGE_EVENT_FLAG_IMPORTANT;
	if (same_cpu)
		flags |= CAKE_WAKE_EDGE_EVENT_FLAG_HIT_OR_SAME;

	ev = bpf_ringbuf_reserve(&debug_ringbuf, sizeof(*ev), 0);
	if (!ev) {
		cake_debug_atomic_inc(&wake_edge_missed_updates);
		return;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->value_ns = gap_ns;
	ev->pid = pid;
	ev->tgid = p->tgid;
	ev->aux = same_cpu ? CAKE_WAKE_EDGE_SAMPLE_DENOM : 1U;
	ev->peer_pid = peer_pid;
	ev->peer_tgid = tctx->telemetry.waker_tgid;
	ev->cpu = (u16)cpu;
	ev->target_cpu = (u16)cpu;
	ev->peer_cpu = tctx->telemetry.postwake_first_cpu;
	ev->kind = CAKE_DBG_EVENT_WAKE_EDGE_FOLLOW;
	ev->slot = reason;
	ev->reason = reason;
	ev->flags = flags;
	cake_copy_comm(ev->comm, p->comm);
	ev->ts_ns = bpf_ktime_get_ns();
	bpf_ringbuf_submit(ev, 0);
}
#endif /* CAKE_DEBUG_EVENT_STREAM */
#endif /* CAKE_RELEASE */

#endif /* __CAKE_DEBUG_EVENTS_BPF_H */
