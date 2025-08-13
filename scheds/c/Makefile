# SCX C Schedulers Makefile
# Build C-based schedulers

# Build configuration (fallback if not inherited from root)
BPF_CLANG ?= clang
BPFTOOL ?= bpftool

# Detect architecture if not set
ifeq ($(TARGET_ARCH),)
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
	TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
	TARGET_ARCH := arm64
else ifeq ($(ARCH),s390x)
	TARGET_ARCH := s390
else ifeq ($(ARCH),arm)
	TARGET_ARCH := arm
else
	TARGET_ARCH := $(ARCH)
endif
endif

# Use pkg-config for libbpf if not set
ifeq ($(LIBBPF_CFLAGS),)
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null || echo "")
LIBBPF_LIBS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf")
endif

# BPF compilation flags if not set
ifeq ($(BPF_CFLAGS),)
BPF_CFLAGS := -g -O2 -Wall -Wno-compare-distinct-pointer-types -D__TARGET_ARCH_$(TARGET_ARCH) -mcpu=v3 -mlittle-endian
endif

# Include paths if not set
ifeq ($(BPF_INCLUDES),)
ROOT_DIR := $(shell cd ../..; pwd)
BPF_INCLUDES := -I$(ROOT_DIR)/scheds/include \
	-I$(ROOT_DIR)/scheds/include/arch/$(TARGET_ARCH) \
	-I$(ROOT_DIR)/scheds/include/bpf-compat \
	-I$(ROOT_DIR)/scheds/include/lib \
	$(LIBBPF_CFLAGS)
endif

# User C compilation flags if not set
ifeq ($(CFLAGS),)
CFLAGS := -std=gnu11 -I$(ROOT_DIR)/scheds/include $(LIBBPF_CFLAGS)
endif

# Libraries if not set
ifeq ($(LIBBPF_DEPS),)
LIBBPF_DEPS := $(LIBBPF_LIBS) -lelf -lz -lzstd
endif
ifeq ($(THREAD_DEPS),)
THREAD_DEPS := -lpthread
endif

# Scheduler lists (from meson.build)
C_SCHEDS := scx_simple scx_qmap scx_central scx_userland scx_nest scx_flatcg scx_pair scx_prev
C_SCHEDS_LIB := scx_sdt

# All targets
ALL_SCHEDS := $(C_SCHEDS) $(C_SCHEDS_LIB)

# Installation directory
INSTALL_DIR ?= /usr/local/bin

# Default target
all: $(ALL_SCHEDS)

# Build regular schedulers (no library dependency)
$(C_SCHEDS): %: %.c %.bpf.skel.h
	@echo "Building scheduler: $@"
	gcc $(CFLAGS) $< -o $@ $(LIBBPF_DEPS) $(THREAD_DEPS)

# Build library-dependent schedulers
$(C_SCHEDS_LIB): %: %.c %.bpf.skel.h ../../lib/lib.bpf.o
	@echo "Building library scheduler: $@"
	gcc $(CFLAGS) $< -o $@ $(LIBBPF_DEPS) $(THREAD_DEPS)

# Generate skeleton headers from BPF objects
%.bpf.skel.h: %.bpf.o
	@echo "Generating skeleton: $@"
	$(BPFTOOL) gen skeleton $< name $(subst .bpf.skel.h,,$@) > $@

# Special rule for library schedulers - create combined object first, then skeleton
scx_sdt.bpf.skel.h: scx_sdt.bpf.o ../../lib/lib.bpf.o
	@echo "Generating library skeleton: $@"
	$(BPFTOOL) gen object scx_sdt.l1o scx_sdt.bpf.o ../../lib/lib.bpf.o
	$(BPFTOOL) gen object scx_sdt.l2o scx_sdt.l1o
	$(BPFTOOL) gen object scx_sdt.l3o scx_sdt.l2o
	$(BPFTOOL) gen skeleton scx_sdt.l3o name scx_sdt > $@
	rm -f scx_sdt.l1o scx_sdt.l2o scx_sdt.l3o

# Compile BPF programs
%.bpf.o: %.bpf.c
	@echo "Compiling BPF: $<"
	$(BPF_CLANG) $(BPF_CFLAGS) -target bpf $(BPF_INCLUDES) -c $< -o $@

# Install schedulers
install: $(ALL_SCHEDS)
	@echo "Installing schedulers to $(INSTALL_DIR)"
	@mkdir -p $(INSTALL_DIR)
	@for sched in $(ALL_SCHEDS); do \
		echo "Installing $$sched"; \
		cp $$sched $(INSTALL_DIR)/; \
	done

# Clean build artifacts
clean:
	rm -f *.bpf.o *.bpf.skel.h *.l1o *.l2o *.l3o $(ALL_SCHEDS)

.PHONY: all install clean