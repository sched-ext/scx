/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Latency criticality tracking library for sched_ext schedulers.
 *
 * Provides per-task latency criticality computation by tracking wake/sleep
 * frequency, runtime, and waker/wakee relationship propagation to score
 * how latency-sensitive each task is.
 *
 * Usage:
 *  - Embed struct lat_cri_data in your task_ctx.
 *  - Call the inline helpers from your scheduler's BPF callbacks.
 *  - Call lat_cri_compute() to produce the final criticality score.
 *
 * The library reuses __calc_avg and log2_u64 from common.bpf.h.
 *
 * Copyright (c) 2023-2025 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#ifndef __SCX_LIB_LAT_CRI_H
#define __SCX_LIB_LAT_CRI_H

#include <scx/common.bpf.h>

/*
 * Constants for latency criticality computation.
 */
enum lat_cri_consts {
	LAT_CRI_FREQ_MAX		= 100000,	/* shortest interval: 10usec */
	LAT_CRI_RUNTIME_MAX		= (1000ULL * 1000ULL * 1000ULL), /* 1 second */
	LAT_CRI_RUNTIME_SCALE		= (500ULL * 1000ULL),	/* 500usec, min slice */
	LAT_CRI_INH_RECEIVER_SHIFT	= 2,	/* 25.0% of receiver's latency criticality */
	LAT_CRI_INH_GIVER_SHIFT	= 3,	/* 12.5% of giver's latency criticality */
	LAT_CRI_TIME_ONE_SEC		= (1000ULL * 1000ULL * 1000ULL),
};

/*
 * Per-task latency criticality tracking data.
 * Embed this in your scheduler's task context.
 */
struct lat_cri_data {
	u64	wait_freq;		/* EWMA frequency of sleeping (consumer) */
	u64	wake_freq;		/* EWMA frequency of waking others (producer) */
	u64	avg_runtime;		/* EWMA runtime per schedule */
	u64	acc_runtime;		/* accumulated runtime this cycle */
	u64	run_freq;		/* scheduling frequency in a second */
	u64	last_runnable_clk;	/* last time when a task became runnable */
	u64	last_running_clk;	/* last time when scheduled in */
	u64	last_stopping_clk;	/* last time when scheduled out */
	u64	last_quiescent_clk;	/* last time when a task went to sleep */
	u16	lat_cri;		/* computed latency criticality score */
	u16	lat_cri_waker;		/* inherited from waker */
	u16	lat_cri_wakee;		/* inherited from wakee */
};

/*
 * lat_cri_compute - Compute the latency criticality score.
 *
 * @lcd: pointer to lat_cri_data
 * @weight_factor: scheduler-specific weight factor (e.g., based on flags,
 *                 nice priority, lock holding, etc.)
 *
 * Computes: (log2(wait*wake) + log2(runtime*weight))^2
 * with waker/wakee inheritance, stores result in lcd->lat_cri,
 * and resets lat_cri_waker/lat_cri_wakee.
 *
 * Returns the computed lat_cri value.
 */
u16 lat_cri_compute(struct lat_cri_data *lcd, u64 weight_factor);

/*
 * lat_cri_calc_avg_freq - Calculate EWMA frequency from an interval.
 *
 * @old_freq: previous frequency value
 * @interval: time interval in nanoseconds
 * @decay: EWMA decay shift (e.g., 3 for 87.5% old / 12.5% new)
 *
 * Returns the new EWMA frequency.
 */
static __always_inline u64
lat_cri_calc_avg_freq(u64 old_freq, u64 interval, u32 decay)
{
	u64 new_freq;

	new_freq = LAT_CRI_TIME_ONE_SEC / interval;
	return __calc_avg(old_freq, new_freq, decay);
}

/*
 * lat_cri_task_runnable - Called when a task becomes runnable.
 *
 * Resets accumulated runtime for the new runnable-to-quiescent cycle.
 *
 * @lcd: pointer to lat_cri_data
 */
static __always_inline void
lat_cri_task_runnable(struct lat_cri_data *lcd)
{
	lcd->acc_runtime = 0;
}

/*
 * lat_cri_task_running - Called when a task starts running on a CPU.
 *
 * Updates run_freq and last_running_clk.
 *
 * @lcd: pointer to lat_cri_data
 * @now: current timestamp
 * @has_scheduled: whether the task has been scheduled before
 * @decay: EWMA decay shift
 */
static __always_inline void
lat_cri_task_running(struct lat_cri_data *lcd, u64 now,
		     bool has_scheduled, u32 decay)
{
	if (has_scheduled) {
		u64 wait_period = time_delta(now, lcd->last_quiescent_clk);
		u64 interval = lcd->avg_runtime + wait_period;

		if (interval > 0)
			lcd->run_freq = lat_cri_calc_avg_freq(
						lcd->run_freq, interval, decay);
	}
	lcd->last_running_clk = now;
}

/*
 * lat_cri_account_runtime - Accumulate runtime during execution.
 *
 * @lcd: pointer to lat_cri_data
 * @runtime_delta: runtime to add (nanoseconds)
 */
static __always_inline void
lat_cri_account_runtime(struct lat_cri_data *lcd, u64 runtime_delta)
{
	lcd->acc_runtime += runtime_delta;
}

/*
 * lat_cri_task_stopping - Called when a task stops running.
 *
 * Updates avg_runtime and last_stopping_clk.
 *
 * @lcd: pointer to lat_cri_data
 * @now: current timestamp
 * @decay: EWMA decay shift
 */
static __always_inline void
lat_cri_task_stopping(struct lat_cri_data *lcd, u64 now, u32 decay)
{
	lcd->avg_runtime = __calc_avg(lcd->avg_runtime, lcd->acc_runtime, decay);
	lcd->last_stopping_clk = now;
}

/*
 * lat_cri_task_quiescent - Called when a task goes to sleep.
 *
 * Updates wait_freq and last_quiescent_clk.
 *
 * @lcd: pointer to lat_cri_data
 * @now: current timestamp
 * @decay: EWMA decay shift
 */
static __always_inline void
lat_cri_task_quiescent(struct lat_cri_data *lcd, u64 now, u32 decay)
{
	u64 interval = time_delta(now, lcd->last_quiescent_clk);

	if (interval > 0) {
		lcd->wait_freq = lat_cri_calc_avg_freq(
					lcd->wait_freq, interval, decay);
		lcd->last_quiescent_clk = now;
	}
}

/*
 * lat_cri_update_wake_freq - Update waker's wake frequency.
 *
 * Called on the waker's lat_cri_data when it wakes another task.
 *
 * @waker_lcd: waker's lat_cri_data
 * @now: current timestamp
 * @min_interval: minimum interval to consider (filters rapid re-wakes)
 * @decay: EWMA decay shift
 */
static __always_inline void
lat_cri_update_wake_freq(struct lat_cri_data *waker_lcd, u64 now,
			 u64 min_interval, u32 decay)
{
	u64 interval = time_delta(now, READ_ONCE(waker_lcd->last_runnable_clk));

	if (interval >= min_interval) {
		WRITE_ONCE(waker_lcd->wake_freq,
			   lat_cri_calc_avg_freq(waker_lcd->wake_freq,
						 interval, decay));
		WRITE_ONCE(waker_lcd->last_runnable_clk, now);
	}
}

/*
 * lat_cri_propagate - Bidirectional latency criticality inheritance.
 *
 * Forward-propagates waker's lat_cri to wakee, and backward-propagates
 * wakee's lat_cri to waker. This maintains momentum through task chains
 * and handles priority inversion.
 *
 * @wakee_lcd: wakee's lat_cri_data
 * @waker_lcd: waker's lat_cri_data
 * @waker_lat_cri: waker's current lat_cri value
 * @wakee_lat_cri: wakee's current lat_cri value
 */
static __always_inline void
lat_cri_propagate(struct lat_cri_data *wakee_lcd,
		  struct lat_cri_data *waker_lcd,
		  u16 waker_lat_cri, u16 wakee_lat_cri)
{
	wakee_lcd->lat_cri_waker = waker_lat_cri;
	if (waker_lcd->lat_cri_wakee < wakee_lat_cri)
		waker_lcd->lat_cri_wakee = wakee_lat_cri;
}

/*
 * lat_cri_init - Initialize lat_cri_data timestamps.
 *
 * @lcd: pointer to lat_cri_data (should be zeroed first)
 * @now: current timestamp
 * @initial_avg_runtime: initial average runtime estimate
 */
static __always_inline void
lat_cri_init(struct lat_cri_data *lcd, u64 now, u64 initial_avg_runtime)
{
	lcd->last_runnable_clk = now;
	lcd->last_running_clk = now;
	lcd->last_stopping_clk = now;
	lcd->last_quiescent_clk = now;
	lcd->avg_runtime = initial_avg_runtime;
}

#endif /* __SCX_LIB_LAT_CRI_H */
