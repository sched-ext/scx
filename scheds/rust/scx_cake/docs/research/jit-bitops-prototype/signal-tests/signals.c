// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <drm/drm.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sched.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>

struct results {
	uint64_t selected, running, stop_nonzero, tagged_runs, irq, bad_irq, exit_kind;
	uint64_t running_at, zero_runs;
	uint32_t target;
};
struct test_case {
	const char *name;
	int fd, producer, mode, pinned, cause, available;
	uint32_t handle;
};
static volatile struct results *result;
static int input_fd, input_source, drm_fd;
static int no_irq;
static uint64_t now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}
static int asleep(pid_t pid, const char *site)
{
	char path[64], buf[1024], *end;
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	int fd = open(path, O_RDONLY);
	if (fd < 0) return 0;
	int n = read(fd, buf, sizeof(buf)-1);
	close(fd);
	if (n <= 0) return 0;
	buf[n] = 0; end = strrchr(buf, ')');
	if (!end || (end[2] != 'S' && end[2] != 'D')) return 0;
	snprintf(path, sizeof(path), "/proc/%d/wchan", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0) return 0;
	n = read(fd, buf, sizeof(buf)-1);
	close(fd);
	if (n <= 1) return 0;
	buf[n] = 0;
	return strstr(buf, site) != NULL;
}
static int make_input(void)
{
	input_source = open("/dev/uinput", O_WRONLY | O_CLOEXEC);
	if (input_source < 0) return -1;
	if (ioctl(input_source, UI_SET_EVBIT, EV_KEY) ||
	    ioctl(input_source, UI_SET_KEYBIT, KEY_A) ||
	    ioctl(input_source, UI_SET_EVBIT, EV_REL) ||
	    ioctl(input_source, UI_SET_RELBIT, REL_X)) return -1;
	struct uinput_setup setup = {.id = {.bustype = BUS_VIRTUAL}};
	strcpy(setup.name, "cake-signal-validation");
	if (ioctl(input_source, UI_DEV_SETUP, &setup) || ioctl(input_source, UI_DEV_CREATE)) return -1;
	for (int retry = 0; retry < 100; retry++) {
		for (int i = 0; i < 32; i++) {
			char path[64], name[128] = "";
			snprintf(path, sizeof(path), "/dev/input/event%d", i);
			int fd = open(path, O_RDONLY | O_NONBLOCK);
			if (fd < 0) continue;
			if (ioctl(fd, EVIOCGNAME(sizeof(name)), name) >= 0 &&
			    !strcmp(name, setup.name)) {
				fcntl(fd, F_SETFL, 0);
				return fd;
			}
			close(fd);
		}
		usleep(10000);
	}
	return -1;
}
static int wait_event(struct test_case *c, int ready)
{
	int ep = -1, nested = -1;
	if (c->pinned) {
		cpu_set_t set; CPU_ZERO(&set); CPU_SET(0, &set);
		if (sched_setaffinity(0, sizeof(set), &set)) return 1;
	}
	if (c->mode == 2 || c->mode == 3) {
		ep = epoll_create1(0);
		struct epoll_event ev = {.events = EPOLLIN, .data.fd = c->fd};
		if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ev)) return 2;
		if (c->mode == 3) {
			nested = epoll_create1(0); ev.data.fd = ep;
			if (nested < 0 || epoll_ctl(nested, EPOLL_CTL_ADD, ep, &ev)) return 3;
		}
	}
	if (write(ready, "x", 1) != 1) return 4;
	int ret = 0;
	if (c->mode == 0 && c->cause == 1) {
		struct input_event events[32];
		ret = read(c->fd, events, sizeof(events)) > 0 ? 0 : 5;
	} else if (c->mode == 0) {
		ret = ioctl(c->fd, _IO('C', 1), 0) ? 6 : 0;
	} else if (c->mode == 1) {
		struct pollfd pfd = {.fd = c->fd, .events = POLLIN};
		ret = poll(&pfd, 1, 3000) == 1 && (pfd.revents & POLLIN) ? 0 : 7;
	} else if (c->mode == 4) {
		uint32_t handle = c->handle;
		struct drm_syncobj_wait wait = {
			.handles = (uintptr_t)&handle, .count_handles = 1,
			.timeout_nsec = now() + 3000000000ULL,
		};
		ret = ioctl(drm_fd, DRM_IOCTL_SYNCOBJ_WAIT, &wait) ? 8 : 0;
	} else {
		struct epoll_event ev;
		ret = epoll_wait(nested >= 0 ? nested : ep, &ev, 1, 3000) == 1 ? 0 : 9;
	}
	usleep(20000);
	if (nested >= 0) close(nested);
	if (ep >= 0) close(ep);
	return ret;
}
static int trigger(struct test_case *c)
{
	if (c->cause == 1) {
		struct input_event events[] = {
			{.type = EV_KEY, .code = KEY_A, .value = 1},
			{.type = EV_REL, .code = REL_X, .value = 1},
			{.type = EV_KEY, .code = KEY_A, .value = 0},
			{.type = EV_SYN, .code = SYN_REPORT},
		};
		return write(c->producer, events, sizeof(events)) == sizeof(events) ? 0 : -1;
	}
	if (c->available) {
		int sync = ioctl(c->producer, _IO('C', 3), 0);
		struct drm_syncobj_handle import = {.handle = c->handle, .fd = sync,
			.flags = DRM_SYNCOBJ_FD_TO_HANDLE_FLAGS_IMPORT_SYNC_FILE};
		int r = sync < 0 ? -1 : ioctl(drm_fd, DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE, &import);
		if (sync >= 0) close(sync);
		return r;
	}
	if (c->cause == 0) {
		uint64_t value = 1;
		return write(c->producer, &value, sizeof(value)) == sizeof(value) ? 0 : -1;
	}
	return ioctl(c->producer, _IO('C', 2), 0);
}
static int run_case(struct test_case c)
{
	int ready[2], status = 0, failed = 0;
	const char *site = c.mode == 4 ? "drm_syncobj" : "";
	if (pipe(ready)) return 1;
	if (c.cause == 1) {
		struct input_event events[64];
		fcntl(c.fd, F_SETFL, O_NONBLOCK);
		while (read(c.fd, events, sizeof(events)) > 0) {}
		fcntl(c.fd, F_SETFL, 0);
	}
	pid_t child = fork();
	if (!child) {
		close(ready[0]); alarm(5);
		_exit(wait_event(&c, ready[1]));
	}
	close(ready[1]);
	char ch;
	if (child < 0 || read(ready[0], &ch, 1) != 1) failed = 1;
	close(ready[0]);
	int blocked = 0;
	for (int i = 0; !failed && i < 1000; i++) {
		if (asleep(child, site)) { blocked = 1; break; }
		usleep(1000);
	}
	if (!blocked) failed = 1;
	if (c.mode == 4) {
		char path[64], buf[128] = "";
		snprintf(path, sizeof(path), "/proc/%d/wchan", child);
		int fd = open(path, O_RDONLY);
		if (fd >= 0) { (void)read(fd, buf, sizeof(buf) - 1); close(fd); }
		printf("WAIT_SITE mode=%d wchan=%s\n", c.mode, buf);
	}
	if (result) {
		memset((void *)result, 0, sizeof(*result));
		result->target = child;
	}
	uint64_t before = now();
	if (c.cause == 1) {
		struct input_event empty = {.type = EV_SYN, .code = SYN_REPORT};
		if (write(c.producer, &empty, sizeof(empty)) != sizeof(empty)) failed = 1;
		usleep(2000);
		if (!asleep(child, site) || (result && result->tagged_runs)) failed = 1;
	}
	if (trigger(&c)) failed = 1;
	if (c.cause == 2 && ioctl(c.producer, _IO('C', 2), 0)) failed = 1;
	if (child > 0 && (waitpid(child, &status, 0) != child ||
	    !WIFEXITED(status) || WEXITSTATUS(status))) failed = 1;
	uint64_t token = result ? result->running : 0;
	if (result) {
		if (c.cause) {
			failed |= (token & 3) != (unsigned)c.cause || result->tagged_runs != 1;
			failed |= (token & ~3ULL) + 3 < before || result->running_at < (token & ~3ULL);
			if (!c.pinned) failed |= result->selected != token;
		} else {
			failed |= token != 0 || result->tagged_runs != 0;
		}
		failed |= result->stop_nonzero != 0 || !result->zero_runs ||
			result->bad_irq != UINT64_MAX || result->exit_kind;
		if (no_irq) failed |= result->irq != UINT64_MAX;
		else failed |= result->irq == UINT64_MAX;
	}
	printf("SIGNAL_CASE name=%s pinned=%d cause=%d blocked=%d token=%llu selected=%llu runs=%llu zero=%llu after_run=%llu irq=%llu child_status=%d failed=%d\n",
	       c.name, c.pinned, c.cause, blocked, (unsigned long long)token,
	       result ? (unsigned long long)result->selected : 0,
	       result ? (unsigned long long)result->tagged_runs : 0,
	       result ? (unsigned long long)result->zero_runs : 0,
	       result ? (unsigned long long)result->stop_nonzero : 0,
	       result ? (unsigned long long)result->irq : 0, status, failed);
	if (result) result->target = 0;
	return failed != 0;
}
static int drm_cases(void)
{
	int failed = 0;
	drm_fd = open("/dev/dri/renderD128", O_RDWR);
	if (drm_fd < 0) { perror("software DRM fixture"); return 1; }
	for (int type = 0; type < 3; type++) {
		int fixture = open("/dev/cake-signal-test", O_RDWR);
		struct drm_syncobj_create create = {0};
		if (fixture < 0 || ioctl(drm_fd, DRM_IOCTL_SYNCOBJ_CREATE, &create)) return 1;
		if (type != 2) {
			int sync = ioctl(fixture, _IO('C', 3), 0);
			struct drm_syncobj_handle import = {.handle = create.handle, .fd = sync,
				.flags = DRM_SYNCOBJ_FD_TO_HANDLE_FLAGS_IMPORT_SYNC_FILE};
			if (sync < 0 || ioctl(drm_fd, DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE, &import)) return 1;
			close(sync);
		}
		int efd = eventfd(0, EFD_CLOEXEC);
		if (efd < 0) return 1;
		if (type != 0) {
			struct drm_syncobj_eventfd event = {.handle = create.handle, .fd = efd,
				.flags = type == 2 ? DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE : 0};
			if (ioctl(drm_fd, DRM_IOCTL_SYNCOBJ_EVENTFD, &event)) return 1;
		}
		struct test_case c = {
			.name = type == 0 ? "syncobj_wait" : type == 1 ? "syncobj_eventfd_complete" : "syncobj_available_unknown",
			.fd = efd, .producer = fixture, .mode = type == 0 ? 4 : 3,
			.cause = type == 2 ? 0 : 2, .available = type == 2,
			.handle = create.handle,
		};
		failed += run_case(c);
		ioctl(fixture, _IO('C', 2), 0);
		struct drm_syncobj_destroy destroy = {.handle = create.handle};
		if (ioctl(drm_fd, DRM_IOCTL_SYNCOBJ_DESTROY, &destroy)) failed++;
		close(efd); close(fixture);
	}
	close(drm_fd);
	return failed;
}
int main(int argc, char **argv)
{
	struct bpf_object *object = NULL;
	struct bpf_link *link = NULL;
	int failed = 0, workload_only = argc > 1 && !strcmp(argv[1], "--workload-only");
	no_irq = argc > 1 && !strcmp(argv[1], "--no-irq");
	setbuf(stdout, NULL);
	if (!workload_only) {
		object = bpf_object__open_file("/work/signals.bpf.o", NULL);
		if (libbpf_get_error(object) || !object || bpf_object__load(object)) return 1;
		struct bpf_map *data = bpf_object__find_map_by_name(object, ".bss");
		struct bpf_map *ops = bpf_object__find_map_by_name(object, "signals_ops");
		if (!data || !ops) return 2;
		result = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, bpf_map__fd(data), 0);
		if (result == MAP_FAILED) return 3;
		link = bpf_map__attach_struct_ops(ops);
		if (!link || libbpf_get_error(link)) return 4;
	}
	input_fd = make_input();
	if (input_fd < 0) { perror("input fixture"); return 5; }
	for (int pinned = 0; pinned < 2; pinned++) {
		for (int mode = 0; mode < 4; mode++) {
			struct test_case c = {.name = (const char *[]){"input_read", "input_poll", "input_epoll", "input_nested_epoll"}[mode],
				.fd = input_fd, .producer = input_source, .mode = mode, .pinned = pinned, .cause = 1};
			failed += run_case(c);
		}
		for (int mode = 0; mode < 4; mode++) {
			int fixture = open("/dev/cake-signal-test", O_RDWR);
			int sync = ioctl(fixture, _IO('C', 3), 0);
			if (fixture < 0 || sync < 0) return 6;
			struct test_case c = {.name = (const char *[]){"fence_direct_wait", "syncfile_poll", "syncfile_epoll", "syncfile_nested_epoll"}[mode],
				.fd = mode == 0 ? fixture : sync, .producer = fixture, .mode = mode, .pinned = pinned, .cause = 2};
			failed += run_case(c);
			close(sync); close(fixture);
		}
	}
	failed += drm_cases();
	int efd = eventfd(0, 0);
	failed += run_case((struct test_case){.name = "ordinary_eventfd_unknown", .fd = efd,
		.producer = efd, .mode = 3, .cause = 0});
	close(efd);
	ioctl(input_source, UI_DEV_DESTROY);
	close(input_fd); close(input_source);
	if (link) bpf_link__destroy(link);
	if (result) munmap((void *)result, 4096);
	if (object) bpf_object__close(object);
	printf("SIGNAL_TEST cases=20 workload_only=%d failed=%d\n", workload_only, failed);
	return failed != 0;
}
