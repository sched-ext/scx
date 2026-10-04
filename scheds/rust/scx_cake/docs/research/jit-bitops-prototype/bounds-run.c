// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void illegal_instruction(int signal, siginfo_t *info, void *context)
{
	Dl_info location = {};

	dladdr(info->si_addr, &location);
	dprintf(2, "SIGILL object=%s offset=%#lx\n", location.dli_fname,
		(unsigned long)info->si_addr - (unsigned long)location.dli_fbase);
	_Exit(128 + signal);
}

static int quiet(enum libbpf_print_level level, const char *format, va_list args)
{
	return 0;
}

static int save(const char *dir, const char *name, const char *ext,
		const void *data, size_t size)
{
	char path[1024];
	FILE *f;
	int failed;

	snprintf(path, sizeof(path), "%s/%s.%s", dir, name, ext);
	f = fopen(path, "wb");
	if (!f)
		return 1;
	failed = fwrite(data, 1, size, f) != size;
	return fclose(f) || failed;
}

static int dump(struct bpf_program *prog, const char *dir)
{
	struct bpf_prog_info sizes = {}, info = {};
	uint32_t size = sizeof(info);
	void *bpf, *jit;
	int failed;

	if (bpf_obj_get_info_by_fd(bpf_program__fd(prog), &sizes, &size))
		return 1;
	info.xlated_prog_len = sizes.xlated_prog_len;
	info.jited_prog_len = sizes.jited_prog_len;
	bpf = calloc(1, info.xlated_prog_len);
	jit = calloc(1, info.jited_prog_len);
	if (!bpf || !jit)
		exit(2);
	info.xlated_prog_insns = (uintptr_t)bpf;
	info.jited_prog_insns = (uintptr_t)jit;
	if (bpf_obj_get_info_by_fd(bpf_program__fd(prog), &info, &size))
		return 1;
	failed = save(dir, bpf_program__name(prog), "bpf.bin", bpf, info.xlated_prog_len);
	if (!info.jited_prog_insns || !info.jited_prog_len)
		failed = 1;
	else
		failed |= save(dir, bpf_program__name(prog), "jit.bin", jit, info.jited_prog_len);
	free(bpf);
	free(jit);
	return failed;
}

static unsigned int expected(const char *name, uint64_t x)
{
	unsigned int value;

	if (strstr(name, "nonzero") && !x)
		return 0;
	if (strstr(name, "signed") && (int64_t)x >= 0)
		return 0;
	if (strstr(name, "or1"))
		x |= 1;
	if (strstr(name, "topbit"))
		x |= 1ULL << 63;
	if (strstr(name, "_zero"))
		x = 0;
	if (strstr(name, "full"))
		x = ~0ULL;
	if (strstr(name, "popcnt")) {
		value = 0;
		while (x) {
			asm volatile("" : "+r" (x));
			value += x & 1;
			x >>= 1;
		}
	} else if (strstr(name, "ctz"))
		value = x ? __builtin_ctzll(x) : 64;
	else
		value = x ? __builtin_clzll(x) : 64;
	if (!strncmp(name, "control_", 8))
		value &= 63;
	return value + 1;
}

int main(int argc, char **argv)
{
	struct bpf_object *catalog, *obj;
	struct bpf_program *entry, *prog, *selected;
	char *log = calloc(1, 4 * 1024 * 1024);
	uint64_t values[65], inputs[386], random = 0xd1b54a32d192ed03ULL;
	uint32_t key = 0;
	int failed = 0, pass = 0, reject = 0, runs = 0, old;

	if (argc != 4 || !log)
		return 2;
	struct sigaction handler = {.sa_sigaction = illegal_instruction, .sa_flags = SA_SIGINFO};
	sigaction(SIGILL, &handler, NULL);
	setbuf(stdout, NULL);
	old = !strcmp(argv[3], "old");
	libbpf_set_print(quiet);
	for (int i = 0; i < 65; i++)
		values[i] = i + 1;
	inputs[0] = 0;
	inputs[1] = ~0ULL;
	for (int i = 0; i < 64; i++) {
		inputs[2 + i] = 1ULL << i;
		inputs[66 + i] = ~(1ULL << i);
	}
	for (int i = 130; i < 386; i++) {
		random ^= random << 13;
		random ^= random >> 7;
		random ^= random << 17;
		inputs[i] = random;
	}
	catalog = bpf_object__open_file(argv[1], NULL);
	if (!catalog)
		return 2;
	bpf_object__for_each_program(entry, catalog) {
		const char *name = bpf_program__name(entry);
		int negative = !strncmp(name, "bad_", 4) ||
			       (old && strncmp(name, "control_", 8));
		int err, errors = 0, input_fd;
		struct bpf_map *map;

		memset(log, 0, 4 * 1024 * 1024);
		obj = bpf_object__open_file(argv[1], NULL);
		if (!obj)
			return 2;
		selected = NULL;
		bpf_object__for_each_program(prog, obj) {
			int match = !strcmp(bpf_program__name(prog), name);

			bpf_program__set_autoload(prog, match);
			if (match) {
				selected = prog;
				bpf_program__set_flags(prog, bpf_program__flags(prog) | BPF_F_TEST_STATE_FREQ);
				bpf_program__set_log_buf(prog, log, 4 * 1024 * 1024);
				bpf_program__set_log_level(prog, 2);
			}
		}
		err = bpf_object__load(obj);
		errors |= save(argv[2], name, "verifier.log", log, strlen(log));
		if (negative) {
			int reason = strstr(log, "invalid access to map value") ||
				     strstr(log, "unbounded memory access") ||
				     strstr(log, "math between map_value pointer and register") ||
				     strstr(log, "min value is negative");

			errors |= !err || !reason;
			reject++;
			printf("%s rejected=%d expected_reason=%d failed=%d\n", name, !!err, reason, errors);
		} else if (err) {
			errors = 1;
			printf("%s load_error=%d\n", name, err);
		} else {
			input_fd = -1;
			bpf_object__for_each_map(map, obj)
				if (strstr(bpf_map__name(map), ".bss"))
					input_fd = bpf_map__fd(map);
			errors |= input_fd < 0;
			errors |= bpf_map_update_elem(bpf_object__find_map_fd_by_name(obj, "table64"), &key, values, BPF_ANY) != 0;
			errors |= bpf_map_update_elem(bpf_object__find_map_fd_by_name(obj, "table65"), &key, values, BPF_ANY) != 0;
			for (int i = 0; i < 386 && !errors; i++) {
				LIBBPF_OPTS(bpf_test_run_opts, opts);

				errors |= bpf_map_update_elem(input_fd, &key, &inputs[i], BPF_ANY) != 0;
				errors |= bpf_prog_test_run_opts(bpf_program__fd(selected), &opts) != 0;
				errors |= opts.retval != expected(name, inputs[i]);
				runs++;
				if (errors)
					printf("MISMATCH %s input=%llx got=%u expected=%u\n", name, (unsigned long long)inputs[i], opts.retval, expected(name, inputs[i]));
			}
			errors |= dump(selected, argv[2]);
			pass++;
			printf("%s loaded=1 failed=%d\n", name, errors);
		}
		failed |= errors;
		bpf_object__close(obj);
	}
	printf("BOUNDS_COMPLETE old=%d positive=%d negative=%d executions=%d failed=%d\n", old, pass, reject, runs, failed);
	bpf_object__close(catalog);
	free(log);
	return failed || pass != (old ? 3 : 17) || reject != (old ? 27 : 13);
}
