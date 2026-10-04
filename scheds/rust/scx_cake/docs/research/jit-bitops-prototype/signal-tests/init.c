// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
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
static int smoke(const char *mode, int fixture)
{
	int status = 0, enabled = 0, exited = 0, failed = 0;
	char path[128], state[128], ops[128];
	snprintf(path, sizeof(path), "/results/%s.csv", mode);
	pid_t pid = fork();
	if (!pid) {
		if (!strcmp(mode, "off"))
			execl("/work/scx_cake", "scx_cake", "--kernel-signals", mode, NULL);
		else
			execl("/work/scx_cake", "scx_cake", "--kernel-signals", mode, "--signal-report", path, NULL);
		_exit(127);
	}
	if (pid < 0) return 1;
	for (int i = 0; i < 200; i++) {
		if (waitpid(pid, &status, WNOHANG) == pid) { exited = 1; break; }
		if (readtext("/sys/kernel/sched_ext/state", state, sizeof(state)) > 0 &&
		    !strncmp(state, "enabled", 7) &&
		    readtext("/sys/kernel/sched_ext/root/ops", ops, sizeof(ops)) > 0 &&
		    !strncmp(ops, "cake", 4)) { enabled = 1; break; }
		usleep(50000);
	}
	if (enabled) {
		if (fixture)
			failed |= run("CAKE_SIGNAL_WORKLOAD", (char *[]){"/work/signals-test", "--workload-only", NULL});
		else
			for (int i = 0; i < 200; i++) usleep(1000);
	} else failed = 1;
	int live = !exited && waitpid(pid, &status, WNOHANG) == 0;
	if (live) { kill(pid, SIGINT); waitpid(pid, &status, 0); }
	int restored = readtext("/sys/kernel/sched_ext/state", state, sizeof(state)) > 0 &&
		!strncmp(state, "disabled", 8);
	failed |= !enabled || !live || !restored || !WIFEXITED(status) || WEXITSTATUS(status);
	if (strcmp(mode, "off") && enabled) {
		char report[16384] = "";
		if (readtext(path, report, sizeof(report)) <= 0) failed = 1;
		printf("SIGNAL_REPORT_BEGIN mode=%s\n%sSIGNAL_REPORT_END\n", mode, report);
		if (fixture && (!strstr(report, "# enabled=true") ||
		    strstr(report, "\nrunning_input,0\n") ||
		    strstr(report, "\nrunning_fence,0\n") ||
		    !strstr(report, "\nclock_error,0\n"))) failed = 1;
	}
	printf("SMOKE mode=%s enabled=%d live=%d restored=%d failed=%d\n", mode, enabled, live, restored, failed);
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
	mount("debugfs", "/sys/kernel/debug", "debugfs", 0, NULL);
	struct utsname uts; uname(&uts);
	char cmd[4096] = "", state[128] = ""; readtext("/proc/cmdline", cmd, sizeof(cmd));
	int fixture = !strstr(cmd, "cake_production=1"), failed = 0;
	int no_irq = !!strstr(cmd, "tsc=noirqtime");
	printf("VM_KERNEL=%s CMDLINE=%s\n", uts.release, cmd);
	if (strstr(cmd, "cake_poc_off=1")) {
		fd = open("/proc/sys/kernel/sched_poc_selector", O_WRONLY);
		if (fd < 0 || write(fd, "0\n", 2) != 2) failed = 1;
		if (fd >= 0) close(fd);
	}
	if (fixture && !failed)
		failed |= run("SIGNAL_CONTRACT", (char *[]){"/work/signals-test", no_irq ? "--no-irq" : NULL, NULL});
	const char *modes[] = {"off", "observe", "on"};
	for (int i = 0; i < 3 && !failed; i++) {
		char path[128];
		snprintf(path, sizeof(path), "/results/load-%s", modes[i]);
		failed |= run("CAKE_LOAD", (char *[]){"/work/scx_cake", "--kernel-signals", (char *)modes[i], "--inspect-bpf", path, NULL});
		if (!failed) failed |= smoke(modes[i], fixture);
	}
	readtext("/sys/kernel/sched_ext/state", state, sizeof(state));
	printf("VM_COMPLETE failed=%d final=%s", failed, state);
	reboot(RB_POWER_OFF);
	while (1) pause();
}
