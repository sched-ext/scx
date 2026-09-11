#ifndef __SCX_METRICS_INTF_H
#define __SCX_METRICS_INTF_H

#ifndef __KERNEL__
typedef unsigned int u32;
#endif

struct cpu_snapshot {
	u32 runnable_tasks;
	u32 online_cpus;
	u32 busy_cpus;
};

#endif
