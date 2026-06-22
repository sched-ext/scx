/* Helper functions — included by main.bpf.c via #include */

static inline struct task_ctx *lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
				    (struct task_struct *)p, 0, 0);
}

static inline struct task_ctx *alloc_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
				    (struct task_struct *)p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline struct flow_cpu_state *lookup_cpu_state(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&cpu_state, &key);
}

#define FLOW_CPUSTAT_INC(_cstate, _field)					\
	do {									\
		typeof(_cstate) __cstate = (_cstate);				\
		if (__cstate)							\
			__cstate->_field++;					\
		else								\
			__sync_fetch_and_add(&_field, 1);			\
	} while (0)

static __always_inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

static __always_inline bool is_pinned_kthread(const struct task_struct *p)
{
	return is_kthread(p) && p->nr_cpus_allowed == 1;
}

static __always_inline bool is_non_migratable(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

static __always_inline s64 clamp_budget(s64 budget_ns)
{
	if (budget_ns > (s64)FLOW_BUDGET_MAX_NS)
		return FLOW_BUDGET_MAX_NS;
	if (budget_ns < -(s64)FLOW_BUDGET_MIN_NS)
		return -(s64)FLOW_BUDGET_MIN_NS;
	return budget_ns;
}

static __always_inline u64 task_slice_ns(const struct task_ctx *tctx)
{
	if (tctx && tctx->budget_ns > 0) {
		u64 budget_ns = tctx->budget_ns;
		u64 reserved_max_ns = tune_reserved_max_ns;

		if (reserved_max_ns < FLOW_SLICE_MIN_NS)
			reserved_max_ns = FLOW_SLICE_MIN_NS;
		else if (reserved_max_ns > FLOW_SLICE_RESERVED_TUNE_MAX_NS)
			reserved_max_ns = FLOW_SLICE_RESERVED_TUNE_MAX_NS;

		if (budget_ns < FLOW_SLICE_MIN_NS)
			return FLOW_SLICE_MIN_NS;
		if (budget_ns > reserved_max_ns)
			return reserved_max_ns;
		return budget_ns;
	}

	return FLOW_SLICE_MIN_NS;
}

static __always_inline bool valid_sched_cpu(s32 cpu)
{
	return cpu >= 0 && (u64)cpu < nr_cpu_ids;
}

static __always_inline void clear_wake_target(struct task_ctx *tctx)
{
	if (!tctx)
		return;

	tctx->wake_cpu = -1;
	tctx->wake_cpu_idle = false;
	tctx->wake_cpu_valid = false;
}

static __always_inline void reset_task_ctx(struct task_ctx *tctx, u64 now, bool sleeping)
{
	if (!tctx)
		return;

	tctx->budget_ns = (s64)FLOW_SLICE_MIN_NS;
	tctx->last_refill_ns = 0;
	tctx->last_run_at = 0;
	tctx->last_sleep_ns = 0;
	tctx->sleep_started_at = sleeping ? now : 0;
	tctx->last_cpu = -1;
	tctx->last_llc = -1;
	tctx->runnable_cpu = -1;
	tctx->first_run = true;
	clear_wake_target(tctx);
}

static __always_inline s64 calc_budget_refill(const struct task_struct *p, u64 sleep_ns)
{
	s64 refill_ns;
	u64 refill_base;

	if (!sleep_ns)
		return 0;

	if (sleep_ns > FLOW_SLEEP_MAX_NS)
		sleep_ns = FLOW_SLEEP_MAX_NS;

	refill_base = sleep_ns / FLOW_REFILL_DIV;
	if (!refill_base)
		return 0;

	refill_ns = (s64)scale_by_task_weight((struct task_struct *)p, refill_base);
	if (sleep_ns >= FLOW_INTERACTIVE_SLEEP_MIN_NS) {
		u64 interactive_floor_ns = tune_interactive_floor_ns;

		if (interactive_floor_ns < FLOW_INTERACTIVE_FLOOR_MIN_NS)
			interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_MIN_NS;
		else if (interactive_floor_ns > FLOW_INTERACTIVE_FLOOR_MAX_NS)
			interactive_floor_ns = FLOW_INTERACTIVE_FLOOR_MAX_NS;

		if (refill_ns < (s64)interactive_floor_ns)
			refill_ns = (s64)interactive_floor_ns;
	}

	return refill_ns;
}

static __always_inline void update_budget_on_wakeup(const struct task_struct *p,
						    struct task_ctx *tctx,
						    u64 now)
{
	s64 refill_ns;
	u64 sleep_ns;

	if (!tctx)
		return;

	tctx->last_refill_ns = 0;

	if (!tctx->sleep_started_at || now <= tctx->sleep_started_at) {
		tctx->last_sleep_ns = 0;
		return;
	}

	sleep_ns = now - tctx->sleep_started_at;
	refill_ns = calc_budget_refill(p, sleep_ns);
	tctx->budget_ns = clamp_budget(tctx->budget_ns + refill_ns);
	tctx->last_refill_ns = refill_ns;
	tctx->last_sleep_ns = sleep_ns;
	tctx->sleep_started_at = 0;
}
