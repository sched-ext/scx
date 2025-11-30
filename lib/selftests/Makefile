.PHONY: clean test
BPF_ALL_SOURCES = $(wildcard ../*.bpf.c) $(wildcard *.bpf.c)
BPF_SOURCES = $(filter-out ../cgroup_bw.bpf.c, $(BPF_ALL_SOURCES))
BPF_OBJECTS = $(notdir $(BPF_SOURCES:.bpf.c=.bpf.o))
BPFTOOL=bpftool

INCLUDES=-I../../scheds/include -I ../../scheds/vmlinux -I../../scheds/include/arch -I ../../scheds/include/arch/bpf-compat

BPF_CFLAGS=-O2 -g -target bpf -D__TARGET_ARCH_x86 -mcpu=v3 -Wall
BPF_CFLAGS+=-I/usr/include/bpf -I/usr/include/$(shell uname -m)-linux-gnu 
BPF_CFLAGS+=$(INCLUDES)

CC=clang

CFLAGS=-O2 -lbpf -lelf -lz -lzstd
CFLAGS+=$(INCLUDES)

test: selftest
	sudo ./$<

selftest: selftest.c selftest.skel.h
	$(CC) $(CFLAGS) $< -o $@

selftest.skel.h: main.bpf.o
	$(BPFTOOL) gen skeleton $< name "selftest" > $@

main.bpf.o: $(BPF_OBJECTS)
	$(BPFTOOL) gen object $@ $^

selftest.bpf.o: selftest.bpf.c
	$(CC) $(BPF_CFLAGS) -c $< -o $@

st_%.bpf.o: st_%.bpf.c
	$(CC) $(BPF_CFLAGS) -c $< -o $@

%.bpf.o: ../%.bpf.c
	$(CC) $(BPF_CFLAGS) -c $< -o $@
		
clean:
	rm -f *.skel.h *.bpf.o
