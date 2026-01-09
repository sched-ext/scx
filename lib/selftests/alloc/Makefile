.PHONY: clean test

BASEDIR=$(realpath ../../../)
INCLUDEDIR=$(BASEDIR)/scheds/include

BPF_SOURCES = $(wildcard *.bpf.c) $(wildcard $(BASEDIR)/lib/alloc/*.bpf.c)
BPF_OBJECTS = $(notdir $(BPF_SOURCES:.bpf.c=.bpf.o))
BPF_OBJECTS_NOASAN = $(notdir $(BPF_SOURCES:.bpf.c=_noasan.bpf.o))
vpath %.bpf.c ../../alloc .

BPFTOOL?=$(shell which bpftool || echo $(BASEDIR)/bpftool/src/bpftool)

ifndef KERNEL
$(error "KERNEL" variable not set. Point it to your local linux/ repo with bpftool compiled before running make.)
endif

LIBBPF_DIR=$(KERNEL)/tools/bpf/bpftool/libbpf/

INCLUDES=-I$(LIBBPF_DIR)/include -I$(INCLUDEDIR) -I$(INCLUDEDIR)/arch -I$(INCLUDEDIR)/arch/bpf-compat -I$(INCLUDEDIR)/lib

BPF_CFLAGS=--target=bpf -g -O2 -D__TARGET_ARCH_x86 -mcpu=v3 -mlittle-endian
BPF_CFLAGS+=-Wall -Wno-compare-distinct-pointer-types -Wno-incompatible-pointer-types-discards-qualifiers
# XXX Remove when moving to the kernel
BPF_CFLAGS+=-D__BPF_FEATURE_ADDR_SPACE_CAST -DENABLE_ATOMICS_TESTS

BPF_ASAN_FLAGS=-fsanitize=kernel-address -fno-stack-protector -fno-builtin
BPF_ASAN_FLAGS+= -mllvm -asan-instrument-address-spaces=1 -mllvm -asan-shadow-addr-space=1
BPF_ASAN_FLAGS+= -mllvm -asan-use-stack-safety=0 -mllvm -asan-stack=0
BPF_ASAN_FLAGS+= -mllvm -asan-kernel=1
BPF_ASAN_FLAGS+= -mllvm -asan-constructor-kind=none
BPF_ASAN_FLAGS+= -mllvm -asan-destructor-kind=none
BPF_ASAN_FLAGS+= -DBPF_ARENA_ASAN

BPF_CFLAGS+= -I$(LIBBPF_DIR)/include -I$(BASEDIR)/scheds/vmlinux -I/usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS+=$(INCLUDES)

CFLAGS=-O2 -no-pie
CFLAGS+=$(INCLUDES)
LDFLAGS= -L$(LIBBPF_DIR) -lbpf -lelf -lz -lzstd

all: selftest selftest_noasan

selftest: selftest.c selftest.skel.h
	clang $(CFLAGS) -DBPF_ARENA_ASAN $< $(LDFLAGS) -o $@

selftest_noasan: selftest.c selftest_noasan.skel.h
	clang $(CFLAGS) $< $(LDFLAGS) -o $@

selftest.skel.h: main.bpf.o
	$(BPFTOOL) gen skeleton $< name "selftest" > $@

selftest_noasan.skel.h: main_noasan.bpf.o
	$(BPFTOOL) gen skeleton $< name "selftest_noasan" > $@

main.bpf.o: $(BPF_OBJECTS)
	$(BPFTOOL) gen object $@ $^

main_noasan.bpf.o: $(BPF_OBJECTS_NOASAN)
	$(BPFTOOL) gen object $@ $^

%.bpf.o: %.bpf.c
	clang $(BPF_CFLAGS) $(BPF_ASAN_FLAGS) -c $< -o $@
	clang $(BPF_CFLAGS) $(BPF_ASAN_FLAGS) -S -emit-llvm -o $(basename $@).ll  $<
	clang $(BPF_CFLAGS) $(BPF_ASAN_FLAGS) -target bpf -O2 -S -o $(basename $@).s  $<

%_noasan.bpf.o: %.bpf.c
	clang $(BPF_CFLAGS) -c $< -o $@
	clang $(BPF_CFLAGS) -S -emit-llvm -o $(basename $@).ll  $<
	clang $(BPF_CFLAGS) -target bpf -O2 -S -o $(basename $@).s  $<

clean:
	rm -f *.skel.h *.bpf.o selftest *.ll *.s *.tmp selftest_noasan
