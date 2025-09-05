# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2025 Meta Platforms, Inc. and affiliates.

# Always require out-of-source builds - default to O=build if not specified
ifeq ("$(origin O)", "command line")
  KBUILD_OUTPUT := $(abspath $(O))
else
  KBUILD_OUTPUT := $(CURDIR)/build
endif

# Always redirect to out-of-tree build directory unless we're already there
ifneq ($(KBUILD_OUTPUT), $(CURDIR))
# Only redirect if ROOT_SRC_DIR is not set (i.e., we're not already redirected)
ifeq ($(ROOT_SRC_DIR),)

PHONY += _all $(MAKECMDGOALS) sub-make

$(filter-out _all sub-make,$(MAKECMDGOALS)) _all: sub-make
	@:

sub-make:
	@mkdir -p $(KBUILD_OUTPUT)
	@$(MAKE) --no-print-directory -C $(KBUILD_OUTPUT) -f $(CURDIR)/Makefile \
		ROOT_SRC_DIR=$(CURDIR) \
		LIB_OBJ_DIR=$(KBUILD_OUTPUT)/lib SCHED_OBJ_DIR=$(KBUILD_OUTPUT)/scheds/c \
		$(MAKECMDGOALS)

.PHONY: $(PHONY)

# Skip the rest of the makefile when redirecting
skip-makefile := 1
endif
endif

ifeq ($(skip-makefile),)

export BPF_CLANG ?= clang
export BPFTOOL ?= bpftool

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
	TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
	TARGET_ARCH := arm64
else ifeq ($(ARCH),s390x)
	TARGET_ARCH := s390
else
	TARGET_ARCH := $(ARCH)
endif

ENDIAN ?= $(shell printf '\1\0' | od -An -t x2 | awk '{print ($$1=="0001"?"little":"big")}')

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)

export BPF_CFLAGS := -g -O2 -Wall -Wno-compare-distinct-pointer-types \
	-D__TARGET_ARCH_$(TARGET_ARCH) -mcpu=v3 -m$(ENDIAN)-endian

# ROOT_SRC_DIR is set by the top-level make call for out-of-source builds
export ROOT_SRC_DIR ?= $(CURDIR)
export BPF_INCLUDES := -I$(ROOT_SRC_DIR)/scheds/include \
	-I$(ROOT_SRC_DIR)/scheds/include/bpf-compat \
	-I$(ROOT_SRC_DIR)/scheds/include/lib \
	-I$(ROOT_SRC_DIR)/scheds/vmlinux \
	-I$(ROOT_SRC_DIR)/scheds/vmlinux/arch/$(TARGET_ARCH) \
	$(LIBBPF_CFLAGS)

export CFLAGS := -std=gnu11 -I$(ROOT_SRC_DIR)/scheds/include -I$(ROOT_SRC_DIR)/scheds/vmlinux -I$(SCHED_OBJ_DIR) $(LIBBPF_CFLAGS)

export LIBBPF_DEPS := $(LIBBPF_LIBS) -lelf -lz -lzstd
export THREAD_DEPS := -lpthread

export OBJ_DIR := $(CURDIR)
ifeq ($(LIB_OBJ_DIR),)
  export LIB_OBJ_DIR := $(ROOT_SRC_DIR)/lib
endif
ifeq ($(SCHED_OBJ_DIR),)
  export SCHED_OBJ_DIR := $(ROOT_SRC_DIR)/scheds/c
endif

# Scheduler lists for convenience targets
C_SCHEDS := scx_simple scx_qmap scx_central scx_userland scx_nest scx_flatcg scx_pair scx_prev
C_SCHEDS_LIB := scx_sdt

all: lib scheds-c

# Individual scheduler targets
$(C_SCHEDS) $(C_SCHEDS_LIB): lib
	@mkdir -p $(SCHED_OBJ_DIR)
	@$(MAKE) -C $(ROOT_SRC_DIR)/scheds/c SRC_DIR=$(ROOT_SRC_DIR)/scheds/c $@

$(LIB_OBJ_DIR) $(SCHED_OBJ_DIR):
	@mkdir -p $@

lib:
	@mkdir -p $(LIB_OBJ_DIR)
	@$(MAKE) -C $(ROOT_SRC_DIR)/lib SRC_DIR=$(ROOT_SRC_DIR)/lib

scheds-c: lib
	@mkdir -p $(SCHED_OBJ_DIR)
	@$(MAKE) -C $(ROOT_SRC_DIR)/scheds/c SRC_DIR=$(ROOT_SRC_DIR)/scheds/c

clean:
	$(MAKE) -C $(ROOT_SRC_DIR)/lib clean
	$(MAKE) -C $(ROOT_SRC_DIR)/scheds/c clean

install: all
	$(MAKE) -C $(ROOT_SRC_DIR)/scheds/c install

.PHONY: all lib scheds-c clean install $(C_SCHEDS) $(C_SCHEDS_LIB)

endif  # End of ifeq ($(skip-makefile),)
