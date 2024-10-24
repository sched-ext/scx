/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define CLOCK_BOOTTIME 7
#define MAX_TOKEN_BUCKETS 16
#define MAX_PER_CPU_TOKEN_BUCKETS 16
#define GLOBAL_REFRESH_TIMER 0
#define PER_CPU_REFRESH_TIMER 1

const volatile u32 token_bucket_refresh_intvl_ns = 100 * NSEC_PER_MSEC;

const volatile u32 nr_token_buckets = 16;
const volatile u32 nr_percpu_token_buckets = 16;
static bool initialized_buckets = false;


struct refresh_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, struct refresh_timer);
} refresh_timer_data SEC(".maps");


struct token_bucket {
	int		tokens;
	int		capacity;
	int		rate_per_sec;
	u64		last_update;
	bool		has_parent;
	bool		overflow;
	u32		idx;
	struct bpf_spin_lock	lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct token_bucket);
	__uint(max_entries, MAX_TOKEN_BUCKETS);
	__uint(map_flags, 0);
} token_bucket_data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct token_bucket);
	__uint(max_entries, MAX_PER_CPU_TOKEN_BUCKETS);
} cpu_token_bucket SEC(".maps");


static struct token_bucket *lookup_token_bucket(u32 bucket_id)
{
	struct token_bucket *buck;

	buck = bpf_map_lookup_elem(&token_bucket_data, &bucket_id);
	if (!buck)
		return NULL;

	return buck;
}

static struct token_bucket *lookup_cpu_token_bucket(u32 bucket_id, s32 cpu)
{
	struct token_bucket *buck;

	if (cpu < 0)
		buck = bpf_map_lookup_elem(&cpu_token_bucket, &bucket_id);
	else
		buck = bpf_map_lookup_percpu_elem(&cpu_token_bucket, &bucket_id, cpu);

	return buck;
}


/*
 * Returns if a bucket was successfully consumed.
 */
static bool consume_bucket(struct token_bucket *buck)
{
	bool consumed = false;

	bpf_spin_lock(&buck->lock);
	if (buck->tokens > 0) {
		buck->tokens -= 1;
		consumed = true;
	}
	bpf_spin_unlock(&buck->lock);

	return consumed;
}

/*
 * Returns if a cpu bucket is empty.
 */
static bool cpu_bucket_empty(struct token_bucket *buck)
{
	return buck->tokens == 0;
}

/*
 * Returns if a cpu bucket was successfully consumed.
 */
static bool consume_cpu_bucket(struct token_bucket *buck, bool overflow)
{
	if (buck->tokens > 0) {
		__sync_fetch_and_sub(&buck->tokens, 1);
		if (buck->tokens <= 0)
			trace("BUCKET[%d] expired", buck->idx);

		return true;
	}

	if (overflow && buck->overflow) {
		struct token_bucket *parent_buck;

		parent_buck = lookup_token_bucket(buck->idx);
		if (!parent_buck)
			return false;

		if (consume_bucket(parent_buck))
			return true;

		// The parent is empty as well so wait until next refresh
		// before trying again.
		trace("BUCKET[%d] overflow max", buck->idx);
		buck->overflow = false;
	}

	return false;
}

/*
 * Returns all the tokens from a bucket.
 */
static int drain_cpu_bucket(u32 bucket_id, s32 cpu)
{
	struct token_bucket *buck;
	u64 zero = 0;

	if (!(buck = lookup_cpu_token_bucket(bucket_id, -1)))
		return 0;

	if (buck->tokens > 0) {
		return __sync_lock_test_and_set(&buck->tokens, zero);
	}

	return 0;
}

/*
 * Returns a partial number of tokens from a bucket.
 */
static int partial_drain_cpu_bucket(u32 bucket_id, s32 cpu, int count)
{
	struct token_bucket *buck;
	int cur_tokens;

	if (!(buck = lookup_cpu_token_bucket(bucket_id, -1)))
		return 0;

	cur_tokens = buck->tokens;
	if (cur_tokens < 0)
		return 0;

	if (count > cur_tokens)
		count = cur_tokens;

	__sync_fetch_and_sub(&buck->tokens, count);

	return count;
}

/*
 * Refreshes a token bucket. This should typically be called by the bpf timer
 * initialized by start_token_buckets.
 */
int refresh_token_bucket(u32 bucket_id)
{
	struct token_bucket *buck;
	u64 refresh_intvl;

	if (!(buck = lookup_token_bucket(bucket_id)))
		return -ENOENT;

	if (buck->rate_per_sec == 0)
		return 0;

	u64 now = bpf_ktime_get_ns();
	bpf_spin_lock(&buck->lock);
	if (buck->last_update > now) {
		bpf_spin_unlock(&buck->lock);
		scx_bpf_error("invalid bucket time for bucket %d", bucket_id);
		return -EINVAL;
	}

	refresh_intvl = now - buck->last_update;
	if (refresh_intvl < NSEC_PER_MSEC) {
		bpf_spin_unlock(&buck->lock);
		return -EINVAL;
	}

	buck->tokens += buck->rate_per_sec * (refresh_intvl / NSEC_PER_MSEC * MSEC_PER_SEC);
	if (buck->tokens > buck->capacity)
		buck->tokens = buck->capacity;

	buck->last_update = now;
	bpf_spin_unlock(&buck->lock);
	trace("BUCKET[%d] refreshed %llu", bucket_id, buck->tokens);

	return 0;
}
/*
 * Refreshes a per cpu token bucket. This should typically be called by the bpf
 * timer initialized by start_token_buckets.
 */
int refresh_cpu_token_bucket(u32 bucket_id, s32 cpu, int amount)
{
	struct token_bucket *buck;
	u64 refresh_intvl;
	int new_tokens, cur_tokens;

	if (!(buck = lookup_cpu_token_bucket(bucket_id, cpu)))
		return -ENOENT;

	if (buck->rate_per_sec == 0)
		return 0;

	u64 now = bpf_ktime_get_ns();
	if (buck->last_update > now) {
		scx_bpf_error("invalid bucket time for bucket %d", bucket_id);
		return -EINVAL;
	}

	refresh_intvl = now - buck->last_update;
	if (refresh_intvl < NSEC_PER_MSEC) {
		return -EINVAL;
	}

	if (buck->tokens == buck->capacity) {
		buck->overflow = true;
		buck->last_update = now;
		return 0;
	}

	if (amount > 0) {
		new_tokens = amount;
	} else {
		new_tokens = (buck->rate_per_sec * refresh_intvl) / NSEC_PER_MSEC * MSEC_PER_SEC;
	}
	cur_tokens = buck->tokens;

	if (new_tokens + cur_tokens > buck->capacity) {
		if (cur_tokens < buck->capacity) {
			__sync_fetch_and_add(&buck->tokens,
					     buck->capacity - cur_tokens);
		}
	} else {
		__sync_fetch_and_add(&buck->tokens, new_tokens);
	}

	buck->overflow = true;
	buck->last_update = now;
	trace("BUCKET[%d] cpu %d refreshed %llu", bucket_id, cpu, buck->tokens);

	return 0;
}

/*
 * Initializes a bucket. This should be for all buckets before calling
 * start_token_buckets.
 */
static int initialize_bucket(u32 bucket_id, u64 capacity, u64 rate_per_sec)
{
	struct token_bucket *buck;

	if (!(buck = lookup_token_bucket(bucket_id)))
		return -ENOENT;

	if (!initialized_buckets)
		initialized_buckets = true;

	bpf_spin_lock(&buck->lock);
	u64 now = bpf_ktime_get_ns();
	buck->capacity = capacity;
	if (buck->tokens > buck->capacity)
		buck->tokens = buck->capacity;
	buck->rate_per_sec = rate_per_sec;
	buck->last_update = now;
	bpf_spin_unlock(&buck->lock);

	return 0;
}

/*
 * Initializes a per cpu bucket. This should be for all buckets before calling
 * start_token_buckets.
 */
int initialize_cpu_bucket(s32 cpu, u32 bucket_id,
			  int capacity, int rate_per_sec, bool overflow)
{
	struct token_bucket *buck;

	if (!(buck = lookup_cpu_token_bucket(bucket_id, cpu)))
		return -ENOENT;

	if (!initialized_buckets)
		initialized_buckets = true;

	u64 now = bpf_ktime_get_ns();
	buck->capacity = capacity;
	if (buck->tokens > buck->capacity)
		buck->tokens = buck->capacity;

	buck->idx = bucket_id;
	buck->last_update = now;
	buck->overflow = overflow;
	buck->rate_per_sec = rate_per_sec;

	return 0;
}

/*
 * Refreshes all token buckets.
 */
int refresh_token_buckets(void)
{
	u32 bucket_id;

	if (nr_token_buckets > MAX_TOKEN_BUCKETS) {
		scx_bpf_error("Invalid nr_token_buckets %d", nr_token_buckets);
		return -EINVAL;
	}

	bpf_for(bucket_id, 0, nr_layers) {
		refresh_token_bucket(bucket_id);
	}

	return 0;
}

/*
 * Refreshes all per cpu token buckets.
 */
int refresh_cpu_token_buckets(void)
{
	u32 bucket_id;
	s32 cpu;

	if (nr_token_buckets > MAX_TOKEN_BUCKETS) {
		scx_bpf_error("Invalid nr_token_buckets %d", nr_token_buckets);
		return -EINVAL;
	}

	bpf_for(bucket_id, 0, nr_layers)
		bpf_for(cpu, 0, nr_possible_cpus)
			refresh_cpu_token_bucket(bucket_id, cpu, 0);

	return 0;
}

/*
 * Callback for bpf timer, do not call directly.
 */
static int on_refresh_timer_intvl(void *map, int *key, struct bpf_timer *timer)
{
	int err;

	refresh_token_buckets();

	err = bpf_timer_start(timer, token_bucket_refresh_intvl_ns, 0);
	if (err)
		scx_bpf_error("Failed to update token bucket timer");

	return 0;
}

/*
 * Callback for per cpu bpf timer, do not call directly.
 */
static int on_cpu_refresh_timer_intvl(void *map, int *key, struct bpf_timer *timer)
{
	int err;

	refresh_cpu_token_buckets();

	err = bpf_timer_start(timer, token_bucket_refresh_intvl_ns, 0);
	if (err)
		scx_bpf_error("Failed to update token bucket timer");

	return 0;
}

/*
 * Starts the bpf timer that refreshes all token buckets on an interval.
 * Buckets should be initialized with initialize_bucket before calling this
 * method.
 */
static s32 start_token_buckets(u32 key)
{
	struct bpf_timer *timer;
	int err;

	if (!initialized_buckets) {
		scx_bpf_error("Token bucket started without no buckets");
		return -EINVAL;
	}

	timer = bpf_map_lookup_elem(&refresh_timer_data, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup refresh timer");
		return -ENOENT;
	}

	bpf_timer_init(timer, &refresh_timer_data, CLOCK_BOOTTIME);
	switch (key) {
		case GLOBAL_REFRESH_TIMER:
			bpf_timer_set_callback(timer, on_refresh_timer_intvl);
			break;
		case PER_CPU_REFRESH_TIMER:
			bpf_timer_set_callback(timer, on_cpu_refresh_timer_intvl);
			break;
		default:
			scx_bpf_error("Failed to initialize token bucket");
			return -ENOENT;
	}

	err = bpf_timer_start(timer, 0, 0);
	if (err) {
		scx_bpf_error("Failed to initialize token bucket");
		return err;
	}
	return err;
}
