# Userspace tests for scheds/include/scx/compat.h. Unlike the arena
# selftests in the parent directory, these run on the host and need no
# kernel support -- only the libbpf headers.
.PHONY: test clean

CC ?= cc
CFLAGS ?= -O2 -Wall -Werror
CFLAGS += -I../../../scheds/include

TESTS = test_enum64_recovery

test: $(TESTS)
	@rc=0; \
	for t in $(TESTS); do \
		echo "=== $$t ==="; \
		./$$t || rc=1; \
	done; \
	exit $$rc

test_enum64_recovery: test_enum64_recovery.c \
		../../../scheds/include/scx/compat.h \
		../../../scheds/include/scx/enums_abi.autogen.h
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TESTS)
