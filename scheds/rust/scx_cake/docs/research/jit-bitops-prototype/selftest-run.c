// SPDX-License-Identifier: GPL-2.0
/* Execute the kernel patch's syscall selftests without attaching anything. */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	int count = 0, failed = 0;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s scalar_bitops.bpf.o\n", argv[0]);
		return 2;
	}
	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj || bpf_object__load(obj))
		return 1;
	bpf_object__for_each_program(prog, obj) {
		LIBBPF_OPTS(bpf_test_run_opts, opts);
		int err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);

		printf("%s: error=%d retval=%u\n", bpf_program__name(prog), err, opts.retval);
		failed |= err != 0 || opts.retval != 0;
		count++;
	}
	bpf_object__close(obj);
	return failed || count != 3;
}
