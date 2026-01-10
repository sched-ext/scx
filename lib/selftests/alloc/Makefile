.PHONY: clean test

BASEDIR=$(realpath ../../../)
INCLUDEDIR=$(BASEDIR)/scheds/include

BPF_SOURCES = $(wildcard *.bpf.c) $(wildcard $(BASEDIR)/lib/alloc/*.bpf.c)
BPF_OBJECTS = $(notdir $(BPF_SOURCES:.bpf.c=.bpf.o))
vpath %.bpf.c ../../alloc .

BPFTOOL?=$(shell which bpftool || echo $(BASEDIR)/bpftool/src/bpftool)

ifndef KERNEL
$(error "KERNEL" variable not set. Point it to your local linux/ repo with bpftool compiled before running make.)
endif

LIBBPF_DIR=$(KERNEL)/tools/bpf/bpftool/libbpf/

INCLUDES=-I$(LIBBPF_DIR)/include -I$(INCLUDEDIR) -I$(INCLUDEDIR)/arch -I$(INCLUDEDIR)/arch/bpf-compat -I$(INCLUDEDIR)/lib

BPF_CFLAGS=--target=bpf -g -O2 -D__TARGET_ARCH_x86 -mcpu=v3 -mlittle-endian
BPF_CFLAGS+=-Wall -Wno-compare-distinct-pointer-types -Wno-incompatible-pointer-types-discards-qualifiers
BPF_ASAN_FLAGS=-fsanitize=kernel-address -fno-stack-protector -fno-builtin

BPF_LLVM_FLAGS+= -mllvm -asan-instrument-address-spaces=1 -mllvm -asan-shadow-addr-space=1
BPF_LLVM_FLAGS+= -mllvm -asan-use-stack-safety=0 -mllvm -asan-stack=0
BPF_LLVM_FLAGS+= -mllvm -asan-kernel=1
BPF_LLVM_FLAGS+= -mllvm -asan-constructor-kind=none
BPF_LLVM_FLAGS+= -mllvm -asan-destructor-kind=none

BPF_FLAGS=$(BPF_CFLAGS) $(BPF_ASAN_FLAGS) $(BPF_LLVM_FLAGS)

BPF_CFLAGS+= -I$(LIBBPF_DIR)/include -I$(BASEDIR)/scheds/vmlinux -I/usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS+=$(INCLUDES)

CFLAGS=-O2 -no-pie
CFLAGS+=$(INCLUDES)
LDFLAGS= -L$(LIBBPF_DIR) -lbpf -lelf -lz -lzstd

test: selftest
	sudo ./$<

selftest: selftest.c selftest.skel.h
	clang $(CFLAGS) $< $(LDFLAGS) -o $@

selftest.skel.h: main.bpf.o
	$(BPFTOOL) gen skeleton $< name "selftest" > $@

main.bpf.o: $(BPF_OBJECTS)
	$(BPFTOOL) gen object $@ $^

%.bpf.o: %.bpf.c
	clang $(BPF_FLAGS) -c $< -o $@
	clang $(BPF_FLAGS) -S -emit-llvm -o $(basename $@).ll  $<
	clang $(BPF_FLAGS) -target bpf -O2 -S -o $(basename $@).s  $<
clean:
	rm -f *.skel.h *.bpf.o selftest *.ll *.s
