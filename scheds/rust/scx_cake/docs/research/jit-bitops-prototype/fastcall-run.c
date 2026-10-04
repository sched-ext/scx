// SPDX-License-Identifier: GPL-2.0
/* Standalone load/run/JIT inspection for the unary fastcall kernel patch. */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int save(const char *dir, const char *name, const char *suffix,
		const void *data, size_t size)
{
	char path[1024];
	FILE *f;
	int failed;

	if (snprintf(path, sizeof(path), "%s/%s.%s", dir, name, suffix) >= sizeof(path))
		return 1;
	f = fopen(path, "wb");
	if (!f)
		return 1;
	failed = fwrite(data, 1, size, f) != size;
	return fclose(f) || failed;
}

static int inspect(struct bpf_program *prog, const char *dir, int expected_stack)
{
	struct bpf_prog_info sizes = {}, info = {};
	__u32 len = sizeof(sizes);
	struct bpf_insn *insns;
	void *jit;
	const char *name = bpf_program__name(prog);
	int stack = 0, failed = 0;

	if (bpf_obj_get_info_by_fd(bpf_program__fd(prog), &sizes, &len))
		return 1;
	insns = calloc(1, sizes.xlated_prog_len);
	jit = calloc(1, sizes.jited_prog_len);
	if (!insns || !jit)
		exit(2);
	info.xlated_prog_len = sizes.xlated_prog_len;
	info.jited_prog_len = sizes.jited_prog_len;
	info.xlated_prog_insns = (__u64)(unsigned long)insns;
	info.jited_prog_insns = (__u64)(unsigned long)jit;
	len = sizeof(info);
	if (bpf_obj_get_info_by_fd(bpf_program__fd(prog), &info, &len) ||
	    !info.xlated_prog_insns || !info.jited_prog_insns || !info.jited_prog_len) {
		failed = 1;
		goto out;
	}
	for (unsigned int i = 0; i < info.xlated_prog_len / sizeof(*insns); i++) {
		struct bpf_insn *p = &insns[i];

		if (((BPF_CLASS(p->code) == BPF_STX || BPF_CLASS(p->code) == BPF_ST) &&
		     p->dst_reg == BPF_REG_10) ||
		    (BPF_CLASS(p->code) == BPF_LDX && p->src_reg == BPF_REG_10))
			stack++;
	}
	if (!strncmp(name, "scalar_fastcall_", 16))
		failed |= stack != expected_stack;
	failed |= save(dir, name, "bpf.bin", insns, info.xlated_prog_len);
	failed |= save(dir, name, "jit.bin", jit, info.jited_prog_len);
	printf("%s: bpf_bytes=%u jit_bytes=%u stack_accesses=%d expected=%d inspect_failed=%d\n",
	       name, info.xlated_prog_len, info.jited_prog_len, stack,
	       !strncmp(name, "scalar_fastcall_", 16) ? expected_stack : -1, failed);
out:
	free(insns);
	free(jit);
	return failed;
}

int main(int argc, char **argv)
{
	const char *negative = "scalar_mulhi_is_not_fastcall";
	struct bpf_object *obj;
	struct bpf_program *prog;
	char *log = calloc(1, 1024 * 1024);
	int count = 0, failed = 0, expected_stack, err;

	if (argc != 4 || (strcmp(argv[3], "0") && strcmp(argv[3], "8"))) {
		fprintf(stderr, "Usage: %s scalar_bitops.bpf.o existing-output-dir expected-stack-accesses(0|8)\n", argv[0]);
		return 2;
	}
	expected_stack = atoi(argv[3]);
	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj || !log)
		return 2;
	bpf_object__for_each_program(prog, obj)
		if (!strcmp(bpf_program__name(prog), negative))
			bpf_program__set_autoload(prog, false);
	if (bpf_object__load(obj))
		return 1;
	bpf_object__for_each_program(prog, obj) {
		LIBBPF_OPTS(bpf_test_run_opts, opts);

		if (!bpf_program__autoload(prog))
			continue;
		err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
		printf("%s: error=%d retval=%u\n", bpf_program__name(prog), err, opts.retval);
		failed |= err != 0 || opts.retval != 0;
		failed |= inspect(prog, argv[2], expected_stack);
		count++;
	}
	bpf_object__close(obj);
	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj)
		return 2;
	bpf_object__for_each_program(prog, obj) {
		bool selected = !strcmp(bpf_program__name(prog), negative);

		bpf_program__set_autoload(prog, selected);
		if (selected) {
			bpf_program__set_log_buf(prog, log, 1024 * 1024);
			bpf_program__set_log_level(prog, 1);
		}
	}
	err = bpf_object__load(obj);
	failed |= !err || !strstr(log, "R3 !read_ok");
	failed |= save(argv[2], negative, "verifier.log", log, strlen(log));
	printf("NEGATIVE_MULHI rejected=%d expected_reason=%d\n", !!err, !!strstr(log, "R3 !read_ok"));
	bpf_object__close(obj);
	free(log);
	printf("SELFTEST_COMPLETE positives=%d failed=%d\n", count, failed);
	return failed || count != 6;
}
