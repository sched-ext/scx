/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CAKE_WAKE_SIGNALS_BPF_H
#define CAKE_WAKE_SIGNALS_BPF_H

extern u64 scx_bpf_task_wake_signal_v1(struct task_struct *p) __weak __ksym;
extern u64 scx_bpf_cpu_irq_ns_v1(s32 cpu) __weak __ksym;

const volatile bool cake_signals_enabled;
const volatile bool cake_signals_policy;
const volatile bool cake_signals_observe;

#define CAKE_SIGNAL_TTL_NS 2000000ULL
#define CAKE_IRQ_SAMPLE_NS 250000ULL
#define CAKE_IRQ_WINDOW_NS 4000000ULL
#define CAKE_SIGNAL_STATS 79

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

static __always_inline bool cake_signal_wake(struct task_struct *p)
{
	u64 token, now = 0;
	bool fresh = false;

	if (!cake_signals_enabled)
		return false;
	token = scx_bpf_task_wake_signal_v1(p);
	if (token) {
		now = bpf_ktime_get_ns();
		fresh = cake_signal_fresh(token, now);
	}
	if (cake_signals_observe) {
		struct cake_signal_counters *s = cake_signal_counters();

		if (s) {
			if (token & 1)
				s->values[0]++;
			if (token & 2)
				s->values[1]++;
			if (!token)
				s->values[2]++;
			if (token && !fresh)
				s->values[now < (token & ~3ULL) ? 7 : 6]++;
		}
	}
	return cake_signals_policy && fresh;
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
				s->values[5]++;
			if (token && now >= (token & ~3ULL)) {
				u64 age = now - (token & ~3ULL);
				u32 bucket = age ? 63 - __builtin_clzll(age) : 0;

				if (bucket > 31)
					bucket = 31;
#pragma unroll
				for (int i = 0; i < 2; i++) {
					if (!(token & (1ULL << i)))
						continue;
					s->values[3 + i]++;
					s->values[11 + i] += age;
					if (age > s->values[13 + i])
						s->values[13 + i] = age;
					s->values[15 + i * 32 + bucket]++;
				}
			} else if (token) {
				s->values[7]++;
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
		s->values[8]++;
	if (total == ~0ULL) {
		sample->stamp = now;
		sample->total = ~0ULL;
		sample->pressure = 0;
		if (s)
			s->values[9]++;
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
			s->values[10]++;
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
