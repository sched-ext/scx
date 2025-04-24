// This file is consumed by bindgen, called from our build.rs file.

#include <linux/perf_event.h>

// for __NR_perf_event_open
#include <asm/unistd.h>
#include <asm/perf_regs.h>

// bindgen won't capture preprocessor macro definitions, so we have to do this.
enum perf_event_ioctls {
    ENABLE = PERF_EVENT_IOC_ENABLE,
    DISABLE = PERF_EVENT_IOC_DISABLE,
    REFRESH = PERF_EVENT_IOC_REFRESH,
    RESET = PERF_EVENT_IOC_RESET,
    PERIOD = PERF_EVENT_IOC_PERIOD,
    SET_OUTPUT = PERF_EVENT_IOC_SET_OUTPUT,
    SET_FILTER = PERF_EVENT_IOC_SET_FILTER,
    ID = PERF_EVENT_IOC_ID,
    SET_BPF = PERF_EVENT_IOC_SET_BPF,
    PAUSE_OUTPUT = PERF_EVENT_IOC_PAUSE_OUTPUT,
    QUERY_BPF = PERF_EVENT_IOC_QUERY_BPF,
    MODIFY_ATTRIBUTES = PERF_EVENT_IOC_MODIFY_ATTRIBUTES,
};
