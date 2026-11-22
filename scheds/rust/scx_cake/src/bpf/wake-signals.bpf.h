/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CAKE_WAKE_SIGNALS_BPF_H
#define CAKE_WAKE_SIGNALS_BPF_H

extern u64 scx_bpf_task_wake_signal_v1(struct task_struct *p) __weak __ksym;
extern u64 scx_bpf_cpu_irq_ns_v1(s32 cpu) __weak __ksym;
extern const int __preempt_count __ksym __weak;
extern const unsigned long local_interrupt_disable_state __ksym __weak;

const volatile bool cake_signals_enabled;
const volatile bool cake_signals_policy;
const volatile bool cake_signals_observe;

#define CAKE_SIGNAL_TTL_NS 2000000ULL
#define CAKE_IRQ_SAMPLE_NS 250000ULL
#define CAKE_IRQ_WINDOW_NS 4000000ULL
#define CAKE_SIGNAL_SLOTS 4096
#define CAKE_STAMP_TIME_SHIFT 10
#define CAKE_STAMP_HOP_SHIFT 32
#define CAKE_STAMP_PID_SHIFT 35
/* preempt_count fields (include/linux/preempt.h): softirq in bits 8-15 on every layout. */
#define CAKE_PREEMPT_SOFTIRQ	(0xffU << 8)
/* Hardirq and NMI: bits 16-19 and 20-23, or 24-27 and 28 behind a hardirq-disable count. */
#define CAKE_PREEMPT_IRQ_PLAIN	((0xfU << 16) | (0xfU << 20))
#define CAKE_PREEMPT_IRQ_COUNTED	((0xfU << 24) | (0x1U << 28))

struct cake_signal_counters {
	u64 values[CAKE_SIGNAL_STATS];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct cake_signal_counters);
} cake_signal_stats SEC(".maps");

struct cake_irq_sample {
	u64 stamp;
	u64 total;
	u64 pressure;
	u64 pad[STATE_SLOT_WORDS - 3];
};

struct cake_irq_sample cake_irq_samples[MAX_CPUS]
	__attribute__((aligned(STATE_SLOT_BYTES)));

static __always_inline struct cake_signal_counters *cake_signal_counters(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&cake_signal_stats, &key);
}

/* Common MONOTONIC time is required for remote wake and IRQ sample ages. */
static __always_inline bool cake_signal_fresh(u64 token, u64 now)
{
	u64 stamp = token & ~3ULL;

	return (token & 3) && now >= stamp && now - stamp <= CAKE_SIGNAL_TTL_NS;
}

/* One u64 per slot: pid, hop count and root input time in 1.024 us units. */
static u64 cake_signal_stamps[CAKE_SIGNAL_SLOTS] __attribute__((aligned(STATE_SLOT_BYTES)));
_Static_assert(CAKE_SIGNAL_HOPS < 8, "the stamp holds three hop bits");
_Static_assert((CAKE_SIGNAL_SLOTS & (CAKE_SIGNAL_SLOTS - 1)) == 0,
	       "signal stamp slots must be a power of two");

static __always_inline u64 *cake_signal_slot(u32 pid)
{
	return &cake_signal_stamps[pid & (CAKE_SIGNAL_SLOTS - 1)];
}

static __always_inline u64 cake_signal_stamp(u32 pid, u64 hops, u64 root)
{
	return ((u64)pid << CAKE_STAMP_PID_SHIFT) | (hops << CAKE_STAMP_HOP_SHIFT) |
	       (u32)(root >> CAKE_STAMP_TIME_SHIFT);
}

static __always_inline bool cake_signal_stamp_live(u64 stamp, u32 pid, u64 now)
{
	u32 age = (u32)(now >> CAKE_STAMP_TIME_SHIFT) - (u32)stamp;

	return (stamp >> CAKE_STAMP_PID_SHIFT) == pid &&
	       age <= (CAKE_SIGNAL_TTL_NS >> CAKE_STAMP_TIME_SHIFT);
}

/* An interrupt's current task did not cause the wake; unknown context counts as one. */
static __always_inline bool cake_signal_task_context(void)
{
	u32 irq = CAKE_PREEMPT_SOFTIRQ;

	if (!bpf_ksym_exists(&__preempt_count))
		return false;
	/* The counted interrupt-disable state came with the layout that holds its count. */
	if (bpf_ksym_exists(&local_interrupt_disable_state))
		irq |= CAKE_PREEMPT_IRQ_COUNTED;
	else
		irq |= CAKE_PREEMPT_IRQ_PLAIN;
	return !(*(u32 *)bpf_this_cpu_ptr(&__preempt_count) & irq);
}

/* Stamps the wakee of a fresh input wake, or of a task woken by one, up to CAKE_SIGNAL_HOPS. */
static __always_inline u64 cake_signal_inherit(struct task_struct *p, u64 token, bool fresh,
					       u64 now, struct cake_signal_counters *s)
{
	u64 *slot = cake_signal_slot((u32)p->pid);
	struct task_struct *waker;
	u64 hops, root, waker_token;

	if (fresh && (token & 1)) {
		WRITE_ONCE(*slot, cake_signal_stamp((u32)p->pid, 0, token & ~3ULL));
		return 0;
	}
	if (!cake_signal_task_context()) {
		if (s)
			s->values[CAKE_SIGNAL_IRQ_WAKER]++;
		goto clear;
	}
	waker = bpf_get_current_task_btf();
	waker_token = scx_bpf_task_wake_signal_v1(waker);
	if ((waker_token & 1) && cake_signal_fresh(waker_token, now)) {
		hops = 1;
		root = waker_token & ~3ULL;
	} else {
		u64 stamp = READ_ONCE(*cake_signal_slot((u32)waker->pid));

		if (!cake_signal_stamp_live(stamp, (u32)waker->pid, now))
			goto clear;
		hops = ((stamp >> CAKE_STAMP_HOP_SHIFT) & 7) + 1;
		root = (u64)(u32)stamp << CAKE_STAMP_TIME_SHIFT;
	}
	if (hops > CAKE_SIGNAL_HOPS) {
		if (s)
			s->values[CAKE_SIGNAL_HOP_LIMIT]++;
		goto clear;
	}
	WRITE_ONCE(*slot, cake_signal_stamp((u32)p->pid, hops, root));
	if (s)
		s->values[CAKE_SIGNAL_INHERIT_BASE + hops - 1]++;
	return hops;
clear:
	if (READ_ONCE(*slot) >> CAKE_STAMP_PID_SHIFT == (u32)p->pid) {
		WRITE_ONCE(*slot, 0);
		if (s)
			s->values[CAKE_SIGNAL_CLEARED]++;
	}
	return 0;
}

/* ttwu: only a real wakeup has a waker; fork and exec placement inherit nothing. */
static __always_inline bool cake_signal_wake(struct task_struct *p, bool ttwu)
{
	struct cake_signal_counters *s = NULL;
	u64 token, now, hops = 0;
	bool fresh;

	if (!cake_signals_enabled)
		return false;
	token = scx_bpf_task_wake_signal_v1(p);
	now = bpf_ktime_get_ns();
	fresh = token && cake_signal_fresh(token, now);
	if (cake_signals_observe) {
		s = cake_signal_counters();
		if (s) {
			if (token & 1)
				s->values[CAKE_SIGNAL_SELECT_INPUT]++;
			if (token & 2)
				s->values[CAKE_SIGNAL_SELECT_FENCE]++;
			if (!token)
				s->values[CAKE_SIGNAL_SELECT_UNKNOWN]++;
			if (token && !fresh)
				s->values[now < (token & ~3ULL) ? CAKE_SIGNAL_CLOCK_ERROR :
					  CAKE_SIGNAL_EXPIRED_SELECT]++;
		}
	}
	if (ttwu)
		hops = cake_signal_inherit(p, token, fresh, now, s);
	return cake_signals_policy && (fresh || hops);
}

/* Only the owning CPU updates its IRQ sample; remote property callbacks skip it. */
static __always_inline void cake_signal_running(struct task_struct *p, u32 cpu)
{
	struct cake_signal_counters *s = NULL;
	struct cake_irq_sample *sample;
	u64 now, total, elapsed, delta;

	if (!cake_signals_enabled)
		return;
	now = bpf_ktime_get_ns();
	if (cake_signals_observe) {
		u64 token = scx_bpf_task_wake_signal_v1(p);

		s = cake_signal_counters();
		if (s) {
			if (!token)
				s->values[CAKE_SIGNAL_RUNNING_UNKNOWN]++;
			if (token && now >= (token & ~3ULL)) {
				u64 age = now - (token & ~3ULL);
				u32 bucket = age ? 63 - __builtin_clzll(age) : 0;

				if (bucket > CAKE_SIGNAL_LOG2_BANDS - 1)
					bucket = CAKE_SIGNAL_LOG2_BANDS - 1;
#pragma unroll
				for (int i = 0; i < 2; i++) {
					if (!(token & (1ULL << i)))
						continue;
					s->values[CAKE_SIGNAL_RUNNING + i]++;
					s->values[CAKE_SIGNAL_WAKE_NS_SUM + i] += age;
					if (age > s->values[CAKE_SIGNAL_WAKE_NS_MAX + i])
						s->values[CAKE_SIGNAL_WAKE_NS_MAX + i] = age;
					s->values[CAKE_SIGNAL_WAKE_LOG2 +
						  i * CAKE_SIGNAL_LOG2_BANDS + bucket]++;
				}
			} else if (token) {
				s->values[CAKE_SIGNAL_CLOCK_ERROR]++;
			}
		}
	}
	if (cpu != bpf_get_smp_processor_id())
		return;
	sample = &cake_irq_samples[cpu & (MAX_CPUS - 1)];
	elapsed = now - sample->stamp;
	if (sample->stamp && elapsed < CAKE_IRQ_SAMPLE_NS)
		return;
	total = scx_bpf_cpu_irq_ns_v1((s32)cpu);
	if (s)
		s->values[CAKE_SIGNAL_IRQ_SAMPLES]++;
	if (total == ~0ULL) {
		sample->stamp = now;
		sample->total = ~0ULL;
		sample->pressure = 0;
		if (s)
			s->values[CAKE_SIGNAL_IRQ_UNKNOWN]++;
		return;
	}
	delta = total - sample->total;
	if (!sample->stamp || elapsed > CAKE_IRQ_WINDOW_NS || total < sample->total ||
	    delta > elapsed) {
		sample->pressure = 0;
	} else {
		bool hot = delta > (elapsed >> 3);

		sample->pressure = (now & ~3ULL) | (hot ? 1 : 2);
		if (s && hot)
			s->values[CAKE_SIGNAL_IRQ_HOT]++;
	}
	sample->stamp = now;
	sample->total = total;
}

static __always_inline bool cake_signal_irq_hot(u32 cpu)
{
	u64 pressure;

	if (!cake_signals_policy)
		return false;
	pressure = READ_ONCE(cake_irq_samples[cpu & (MAX_CPUS - 1)].pressure);
	return (pressure & 1) && cake_signal_fresh(pressure, bpf_ktime_get_ns());
}

#endif
