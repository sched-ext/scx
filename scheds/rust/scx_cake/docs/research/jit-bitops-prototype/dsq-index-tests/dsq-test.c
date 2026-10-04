// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

struct results {
	unsigned long long checks, errors, creates, duplicates, misses, race_ops;
	unsigned long long small_inserts, large_inserts, small_moves, large_moves, peeks;
	unsigned long long exit_kind;
};
struct worker { int fd, cpu, errors; };

static void *race(void *arg)
{
	struct worker *w = arg;
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(w->cpu, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask)) {
		w->errors++;
		return NULL;
	}
	for (int i = 0; i < 128; i++) {
		LIBBPF_OPTS(bpf_test_run_opts, opt);
		if (bpf_prog_test_run_opts(w->fd, &opt) || opt.retval)
			w->errors++;
		usleep(100);
	}
	return NULL;
}

int main(void)
{
	struct bpf_object *obj;
	struct bpf_link *link;
	struct bpf_map *ops, *data;
	struct bpf_program *prog;
	struct results *r;
	int failures = 0, ncpu = sysconf(_SC_NPROCESSORS_ONLN);

	setbuf(stdout, NULL);
	obj = bpf_object__open_file("/work/dsq-test.bpf.o", NULL);
	if (!obj || libbpf_get_error(obj) || bpf_object__load(obj))
		return 1;
	ops = bpf_object__find_map_by_name(obj, "dsq_test_ops");
	data = bpf_object__find_map_by_name(obj, ".bss");
	if (!ops || !data)
		return 2;
	r = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, bpf_map__fd(data), 0);
	if (r == MAP_FAILED)
		return 3;
	link = bpf_map__attach_struct_ops(ops);
	if (!link || libbpf_get_error(link))
		return 4;
	prog = bpf_object__find_program_by_name(obj, "dsq_test_race");
	if (!prog)
		return 5;
	pthread_t threads[8];
	struct worker w[8];
	for (int i = 0; i < 8; i++) {
		w[i] = (struct worker){.fd = bpf_program__fd(prog), .cpu = i % ncpu};
		if (pthread_create(&threads[i], NULL, race, &w[i]))
			return 6;
	}
	for (int i = 0; i < 8; i++) {
		pthread_join(threads[i], NULL);
		failures += w[i].errors;
	}
	usleep(100000);
	failures += r->errors != 0 || r->race_ops != 32768 || r->checks < 66561;
	failures += !r->small_inserts || !r->large_inserts || !r->small_moves || !r->large_moves || !r->peeks;
	failures += r->exit_kind != 0;
	bpf_link__destroy(link);
	printf("DSQ_TEST checks=%llu errors=%llu creates=%llu duplicates=%llu misses=%llu race_ops=%llu small_inserts=%llu large_inserts=%llu small_moves=%llu large_moves=%llu peeks=%llu failed=%d\n",
	       r->checks, r->errors, r->creates, r->duplicates, r->misses, r->race_ops,
	       r->small_inserts, r->large_inserts, r->small_moves, r->large_moves, r->peeks, failures);
	munmap(r, 4096);
	bpf_object__close(obj);
	return failures != 0;
}
