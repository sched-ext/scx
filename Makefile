# SCX Scheduler Makefile
# Root makefile for building C schedulers

# Build configuration
export BPF_CLANG ?= clang
export BPFTOOL ?= bpftool
export CC ?= clang

# Detect architecture
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

# Detect endianness (default to little endian for most platforms)
ENDIAN := little

# Use pkg-config for libbpf
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)

# BPF compilation flags
export BPF_CFLAGS := -g -O2 -Wall -Wno-compare-distinct-pointer-types \
	-D__TARGET_ARCH_$(TARGET_ARCH) -mcpu=v3 -m$(ENDIAN)-endian

# Include paths
export ROOT_DIR := $(PWD)
export BPF_INCLUDES := -I$(ROOT_DIR)/scheds/include \
	-I$(ROOT_DIR)/scheds/include/arch/$(TARGET_ARCH) \
	-I$(ROOT_DIR)/scheds/include/bpf-compat \
	-I$(ROOT_DIR)/scheds/include/lib \
	$(LIBBPF_CFLAGS)

# User C compilation flags
export CFLAGS := -std=gnu11 -I$(ROOT_DIR)/scheds/include $(LIBBPF_CFLAGS)

# Libraries
export LIBBPF_DEPS := $(LIBBPF_LIBS) -lelf -lz -lzstd
export THREAD_DEPS := -lpthread

# Default target
all: lib scheds-c

# Build library objects
lib:
	$(MAKE) -C lib

# Build C schedulers - if other targets are specified, build only those
scheds-c: lib
	$(MAKE) -C scheds/c $(filter-out $@,$(MAKECMDGOALS))

# For individual scheduler targets, we need to declare them as phony
# so Make doesn't complain about not finding them
%:
	@:

# Clean everything
clean:
	$(MAKE) -C lib clean
	$(MAKE) -C scheds/c clean

# Install targets
install: all
	$(MAKE) -C scheds/c install

.PHONY: all lib scheds-c clean install
