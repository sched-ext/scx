// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sched.h>
#include <stdint.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <sys/utsname.h>

static int readtext(const char *path, char *buf, size_t size)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	int n = read(fd, buf, size - 1);
	close(fd);
	if (n >= 0) buf[n] = 0;
	return n;
}
static uint64_t now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}
static int run(const char *label, char **args)
{
	int status;
	pid_t pid = fork();
	if (!pid) { execv(args[0], args); perror(args[0]); _exit(127); }
	if (pid < 0 || waitpid(pid, &status, 0) < 0) return 127;
	int rc = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
	printf("RUN label=%s rc=%d\n", label, rc);
	return rc;
}
static uint64_t calculate(uint64_t x)
{
	for (int j = 0; j < 20000; j++) {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
	}
	return x;
}
struct completion { uint64_t checksum, late_max, elapsed; int errors, frames; };

static int workload(int sim)
{
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	int count = ncpu * 2;
	if (count > 32) count = 32;
	int pipes[32][2], gates[32][2], failed = 0;
	pid_t pids[32];
	uint64_t checksum = 0, late_max = 0;
	uint64_t expected[32];
	for (int i = 0; i < count; i++) {
		expected[i] = i + 1;
		for (int k = 0; k < (sim ? 160 : 64); k++) expected[i] = calculate(expected[i]);
	}
	for (int i = 0; i < count; i++) {
		if (pipe(pipes[i]) || pipe(gates[i])) return 1;
		pids[i] = fork();
		if (pids[i] < 0) return 1;
		if (!pids[i]) {
			close(pipes[i][0]); close(gates[i][1]);
			cpu_set_t set; CPU_ZERO(&set); CPU_SET(i % ncpu, &set);
			struct completion c = {0};
			c.errors = !!sched_setaffinity(0, sizeof(set), &set);
			char start;
			if (read(gates[i][0], &start, 1) != 1) _exit(3);
			uint64_t began = now(), x = i + 1;
			int frames = sim ? 160 : 64;
			for (int k = 0; k < frames; k++) {
				uint64_t target = now() + 1000000;
				x = calculate(x);
				if (i % 2 == 0) {
					struct timespec ts = {target / 1000000000, target % 1000000000};
					if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL)) c.errors++;
					uint64_t t = now(), late = t > target ? t - target : 0;
					if (late > c.late_max) c.late_max = late;
				} else sched_yield();
				c.frames++;
			}
			c.elapsed = now() - began; c.checksum = x;
			if (write(pipes[i][1], &c, sizeof(c)) != sizeof(c)) _exit(4);
			_exit(c.errors != 0);
		}
		close(pipes[i][1]); close(gates[i][0]);
	}
	uint64_t began = now();
	for (int i = 0; i < count; i++) {
		if (write(gates[i][1], "x", 1) != 1) failed++;
		close(gates[i][1]);
	}
	for (int i = 0; i < count; i++) {
		struct completion c = {0}; int status;
		if (read(pipes[i][0], &c, sizeof(c)) != sizeof(c)) failed++;
		close(pipes[i][0]);
		if (waitpid(pids[i], &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) failed++;
		int frames = sim ? 160 : 64;
		failed += c.checksum != expected[i] || c.frames != frames || c.errors;
		checksum ^= c.checksum;
		if (c.late_max > late_max) late_max = c.late_max;
	}
	printf("WORKLOAD sim=%d cpus=%d workers=%d frames=%d steps=%llu checksum=%llu elapsed_ns=%llu wake_late_max_ns=%llu failed=%d\n",
	       sim, ncpu, count, count * (sim ? 160 : 64),
	       (unsigned long long)count * (sim ? 160 : 64) * 20000,
	       (unsigned long long)checksum, (unsigned long long)(now() - began),
	       (unsigned long long)late_max, failed);
	return failed != 0;
}

static int smoke(const char *label, int portable, int sim)
{
	pid_t pid = fork(); int status = 0, enabled = 0, exited = 0;
	if (!pid) {
		if (portable) execl("/work/scx_cake", "scx_cake", "--portable-bitops", NULL);
		else execl("/work/scx_cake", "scx_cake", NULL);
		_exit(127);
	}
	if (pid < 0) return 1;
	char state[128], ops[128] = "";
	for (int i = 0; i < 200; i++) {
		if (waitpid(pid, &status, WNOHANG) == pid) { exited = 1; break; }
		if (readtext("/sys/kernel/sched_ext/state", state, sizeof(state)) > 0 && !strncmp(state, "enabled", 7) &&
		    readtext("/sys/kernel/sched_ext/root/ops", ops, sizeof(ops)) > 0 && !strncmp(ops, "cake", 4)) { enabled = 1; break; }
		usleep(50000);
	}
	char direct[32] = "absent", cmd[4096] = "";
	readtext("/sys/kernel/sched_ext/root/dsq_direct_entries", direct, sizeof(direct));
	readtext("/proc/cmdline", cmd, sizeof(cmd));
	int expected = strstr(cmd, "cake_baseline=1") ? -1 :
		strstr(cmd, "sched_ext.dsq_direct=0") ? 0 : 2048;
	int actual = !strncmp(direct, "absent", 6) ? -1 : atoi(direct);
	printf("INDEX expected=%d actual=%d\n", expected, actual);
	printf("SCHEDULER_ID=%s", ops);
	int errors = actual != expected;
	if (enabled && !errors) errors |= workload(sim);
	else errors = 1;
	int live = !exited && waitpid(pid, &status, WNOHANG) == 0;
	if (live) { kill(pid, SIGINT); waitpid(pid, &status, 0); }
	int restored = readtext("/sys/kernel/sched_ext/state", state, sizeof(state)) > 0 && !strncmp(state, "disabled", 8);
	int failed = !enabled || !live || errors || !restored || !WIFEXITED(status) || WEXITSTATUS(status);
	printf("SMOKE label=%s enabled=%d live=%d restored=%d failed=%d\n", label, enabled, live, restored, failed);
	return failed;
}

int main(void)
{
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	int fd = open("/dev/console", O_RDWR);
	if (fd >= 0) { dup2(fd, 0); dup2(fd, 1); dup2(fd, 2); }
	setbuf(stdout, NULL);
	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	struct utsname uts; uname(&uts);
	char cmd[4096], state[128]; readtext("/proc/cmdline", cmd, sizeof(cmd));
	int sim = !!strstr(cmd, "cake_sim=1"), failed = 0;
	printf("VM_KERNEL=%s CMDLINE=%s\n", uts.release, cmd);
	if (strstr(cmd, "cake_poc_off=1")) {
		fd = open("/proc/sys/kernel/sched_poc_selector", O_WRONLY);
		if (fd < 0 || write(fd, "0\n", 2) != 2) failed = 1;
		if (fd >= 0) close(fd);
		char value[32] = "missing";
		readtext("/proc/sys/kernel/sched_poc_selector", value, sizeof(value));
		printf("GUEST_POC_SELECTOR=%s", value);
		if (value[0] != '0') failed = 1;
	}
	if (!sim && !failed) {
		failed |= run("DSQ_LIFECYCLE_1", (char *[]){"/work/dsq-test", NULL});
		if (!failed) failed |= run("DSQ_LIFECYCLE_2", (char *[]){"/work/dsq-test", NULL});
		if (!failed) failed |= run("CAKE_AUTO_LOAD", (char *[]){"/work/scx_cake", "--inspect-bpf", "/results/auto", NULL});
		if (!failed) failed |= run("CAKE_PORTABLE_LOAD", (char *[]){"/work/scx_cake", "--portable-bitops", "--inspect-bpf", "/results/portable", NULL});
	}
	if (!failed) failed |= smoke("auto", 0, sim);
	if (!failed && !sim) failed |= smoke("portable", 1, 0);
	readtext("/sys/kernel/sched_ext/state", state, sizeof(state));
	printf("VM_COMPLETE failed=%d final=%s", failed, state);
	reboot(RB_POWER_OFF);
	while (1) pause();
}
