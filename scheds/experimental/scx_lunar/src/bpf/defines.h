// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef DEFINES_H
#define DEFINES_H

#define SCHED_MODE_DSQ_PER_LLC 0
#define SCHED_MODE_DSQ_PER_CPU 1

#define NS_PER_US 1000ULL
#define NS_PER_MS (1000ULL * NS_PER_US)

#define NS_PER_MS_LL (s64) NS_PER_MS

#define SLICE_LC (500 * NS_PER_US)
#define SLICE_INTERACTIVE (500 * NS_PER_US)
#define SLICE_NORMAL (500 * NS_PER_US)
#define SLICE_GREEDY (500 * NS_PER_US)

#define DUTY_INIT_RUN_NS (60ULL * NS_PER_MS)
#define DUTY_WINDOW_NS (100ULL * NS_PER_MS)
#define DUTY_SAMPLES_NEEDED 4
#define DUTY_SAMPLES_MAX 1000

#define DUTY_RANGE 1024

#define DUTY_EDGE_LC ((13 * DUTY_RANGE) / 100)
#define DUTY_EDGE_INTERACTIVE ((25 * DUTY_RANGE) / 100)
#define DUTY_EDGE_NORMAL ((50 * DUTY_RANGE) / 100)

#define DUTY_HYST ((3 * DUTY_RANGE) / 100)

#define MAX_RT_PRIO 100

#define DSQ_TYPE_LC 1
#define DSQ_TYPE_INTERACTIVE 2
#define DSQ_TYPE_NORMAL 3
#define DSQ_TYPE_GREEDY 4
#define DSQ_TYPE_EMPTY 5
#define DSQ_TYPE_AMOUNT 5

#define DEFAULT_DSQ_LOCAL_ON 0xC000000000000000ULL

#define DSQ_CPU_QUEUE_BASE_LC 1536
#define DSQ_CPU_QUEUE_BASE_INTERACTIVE 2048
#define DSQ_CPU_QUEUE_BASE_NORMAL 2560
#define DSQ_CPU_QUEUE_BASE_BATCH 3072
#define DSQ_CPU_QUEUE_BASE_GREEDY 3584

#define QUEUE_START DSQ_TYPE_GREEDY

#define MAX_CPUS 512

#endif  // DEFINES_H
