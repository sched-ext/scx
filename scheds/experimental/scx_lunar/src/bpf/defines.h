// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef DEFINES_H
#define DEFINES_H

#define NS_PER_US 1000ULL
#define NS_PER_MS (1000ULL * NS_PER_US)

#define STARVE_BUDGET_INTERACTIVE_NS (25ULL * NS_PER_MS)
#define STARVE_BUDGET_NORMAL_NS (50ULL * NS_PER_MS)
#define STARVE_BUDGET_GREEDY_NS (75ULL * NS_PER_MS)

#define STARVE_OVERRIDE_COOLDOWN_NS (10ULL * NS_PER_MS)

#define SLICE_NS (1000 * NS_PER_US)

#define RESUME_SLICE_MIN_NS (50 * NS_PER_US)

#define BALANCE_INTERVAL_NS (10ULL * NS_PER_MS)
#define BALANCE_SAMPLES 2

// ---------------------------------------------------------------------------
// Duty
// ---------------------------------------------------------------------------
#define DUTY_INIT_RUN_NS (80ULL * NS_PER_MS)
#define DUTY_WINDOW_NS (100ULL * NS_PER_MS)
#define DUTY_SAMPLES_NEEDED 3
#define DUTY_SAMPLES_MAX 1000

#define DUTY_RANGE 1024

#define DUTY_CAP_LC ((5 * DUTY_RANGE) / 100)
#define DUTY_CAP_INTERACTIVE ((10 * DUTY_RANGE) / 100)
#define DUTY_CAP_NORMAL ((80 * DUTY_RANGE) / 100)

#define DUTY_HYST ((1 * DUTY_RANGE) / 100)

// ---------------------------------------------------------------------------
// Latency criticality
// ---------------------------------------------------------------------------
#define CRIT_INTERVAL_REF (1000ULL * NS_PER_MS)
#define CRIT_INTERVAL_MIN (10ULL * NS_PER_US)
#define CRIT_MAX 40

#define CRIT_EDGE_LC 5
#define CRIT_EDGE_INTERACTIVE 3
#define CRIT_EDGE_NORMAL 1

// ---------------------------------------------------------------------------
// Tiers and DSQs
// ---------------------------------------------------------------------------
#define DSQ_TYPE_LC 1
#define DSQ_TYPE_INTERACTIVE 2
#define DSQ_TYPE_NORMAL 3
#define DSQ_TYPE_GREEDY 4
#define DSQ_TYPE_EMPTY 5
#define DSQ_TYPE_AMOUNT 4

#define DSQ_CPU_QUEUE_BASE_LC 1536
#define DSQ_CPU_QUEUE_BASE_INTERACTIVE 2048
#define DSQ_CPU_QUEUE_BASE_NORMAL 2560
#define DSQ_CPU_QUEUE_BASE_GREEDY 3072

#define MAX_CPUS 512

#endif  // DEFINES_H
