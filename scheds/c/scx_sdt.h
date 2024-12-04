#pragma once
struct scx_stats {
	int	seq;
	pid_t	pid;
	__u64	enqueue;
	__u64	exit;
	__u64	init;
	__u64	select_busy_cpu;
	__u64	select_idle_cpu;
};
