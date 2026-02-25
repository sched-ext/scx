/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Latency criticality computation for sched_ext schedulers.
 *
 * Copyright (c) 2023-2025 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#include <scx/common.bpf.h>
#include <lib/lat_cri.h>

/*
 * Helper to clamp a frequency to the maximum.
 */
static __always_inline u64 clamp_freq(u64 freq)
{
	return freq < LAT_CRI_FREQ_MAX ? freq : LAT_CRI_FREQ_MAX;
}

/*
 * lat_cri_compute - Compute latency criticality score.
 *
 * The formula is:
 *   wait_ft = min(wait_freq, FREQ_MAX) + 1
 *   wake_ft = min(wake_freq, FREQ_MAX) + 1
 *   runtime_ft = max(RUNTIME_MAX - avg_runtime, 0) / RUNTIME_SCALE + 1
 *   log_wwf = log2(wait_ft * wake_ft)
 *   lat_cri = (log_wwf + log2(runtime_ft * weight_factor))^2
 *
 * Then waker/wakee inheritance is applied:
 *   lat_cri_giver = lat_cri_waker + lat_cri_wakee
 *   if giver > 2*lat_cri:
 *     lat_cri += min((giver - 2*lat_cri) >> GIVER_SHIFT,
 *                    lat_cri >> RECEIVER_SHIFT)
 *
 * Stores result in lcd->lat_cri and resets lat_cri_waker/lat_cri_wakee.
 */
__weak u16
lat_cri_compute(struct lat_cri_data *lcd, u64 weight_factor)
{
	u64 wait_ft, wake_ft, runtime_ft;
	u64 log_wwf, lat_cri, lat_cri_giver;

	/*
	 * A task is more latency-critical as its wait or wake frequencies
	 * are higher and its runtime is shorter.
	 */
	wait_ft = clamp_freq(lcd->wait_freq) + 1;
	wake_ft = clamp_freq(lcd->wake_freq) + 1;

	if (LAT_CRI_RUNTIME_MAX > lcd->avg_runtime) {
		u64 delta = LAT_CRI_RUNTIME_MAX - lcd->avg_runtime;
		runtime_ft = delta / LAT_CRI_RUNTIME_SCALE;
	} else {
		runtime_ft = 0;
	}
	runtime_ft += 1;

	/*
	 * Wake and wait frequencies represent how much a task acts as
	 * producer and consumer respectively. Log2 linearizes the
	 * exponentially skewed distribution.
	 */
	log_wwf = log2_u64(wait_ft * wake_ft);
	lat_cri = log_wwf + log2_u64(runtime_ft * weight_factor);

	/*
	 * Amplify to better differentiate latency-critical from
	 * non-latency-critical tasks.
	 */
	lat_cri = lat_cri * lat_cri;

	/*
	 * Context-aware latency criticality via waker/wakee inheritance.
	 *
	 * Forward propagation keeps the waker's momentum to the wakee.
	 * Backward propagation boosts low-priority wakers (priority inversion).
	 * Inheritance decays geometrically and is capped.
	 */
	lat_cri_giver = (u64)lcd->lat_cri_waker + (u64)lcd->lat_cri_wakee;
	if (lat_cri_giver > (2 * lat_cri)) {
		u64 giver_inh = (lat_cri_giver - (2 * lat_cri)) >>
				LAT_CRI_INH_GIVER_SHIFT;
		u64 receiver_max = lat_cri >> LAT_CRI_INH_RECEIVER_SHIFT;
		lat_cri += giver_inh < receiver_max ? giver_inh : receiver_max;
	}

	lcd->lat_cri = lat_cri;
	lcd->lat_cri_waker = 0;
	lcd->lat_cri_wakee = 0;

	return lat_cri;
}
