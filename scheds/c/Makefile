# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2025 Meta Platforms, Inc. and affiliates.

# Handle out-of-source builds
SRC_DIR ?= $(CURDIR)
ifneq ($(SCHED_OBJ_DIR),)
  OBJ_DIR := $(SCHED_OBJ_DIR)
else
  OBJ_DIR := $(CURDIR)
endif

# Library dependency - use LIB_OBJ_DIR if set, otherwise relative path
LIB_BPF_OBJ ?= $(LIB_OBJ_DIR)/lib.bpf.o
ifeq ($(LIB_OBJ_DIR),)
  LIB_BPF_OBJ := ../../lib/lib.bpf.o
endif

C_SCHEDS := scx_simple scx_qmap scx_central scx_userland scx_nest scx_flatcg scx_pair scx_prev
C_SCHEDS_LIB := scx_sdt

ALL_SCHEDS := $(addprefix $(OBJ_DIR)/,$(C_SCHEDS) $(C_SCHEDS_LIB))

INSTALL_DIR ?= /usr/local/bin

all: $(ALL_SCHEDS)

# Convenience targets for individual schedulers (old names without path)
$(C_SCHEDS) $(C_SCHEDS_LIB): %: $(OBJ_DIR)/% ;

# Disable built-in implicit rule for C compilation to prevent conflicts
%: %.c

# Build regular schedulers (no library dependency) - from source to output dir
$(addprefix $(OBJ_DIR)/,$(C_SCHEDS)): $(OBJ_DIR)/%: $(SRC_DIR)/%.c $(OBJ_DIR)/%.bpf.skel.h
	@echo "Building scheduler: $@"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -o $@ $(LIBBPF_DEPS) $(THREAD_DEPS)

# Build library-dependent schedulers - from source to output dir
$(addprefix $(OBJ_DIR)/,$(C_SCHEDS_LIB)): $(OBJ_DIR)/%: $(SRC_DIR)/%.c $(OBJ_DIR)/%.bpf.skel.h $(LIB_BPF_OBJ)
	@echo "Building library scheduler: $@"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -o $@ $(LIBBPF_DEPS) $(THREAD_DEPS)

$(OBJ_DIR)/%.bpf.skel.h: $(OBJ_DIR)/%.bpf.o
	@echo "Generating skeleton: $@"
	@mkdir -p $(dir $@)
	$(BPFTOOL) gen skeleton $< name $(basename $(basename $(notdir $<))) > $@

# Special rule for library schedulers - create combined object first, then skeleton
$(OBJ_DIR)/scx_sdt.bpf.skel.h: $(OBJ_DIR)/scx_sdt.bpf.o $(LIB_BPF_OBJ)
	@echo "Generating library skeleton: $@"
	@mkdir -p $(dir $@)
	$(BPFTOOL) gen object $(OBJ_DIR)/scx_sdt.l1o $(OBJ_DIR)/scx_sdt.bpf.o $(LIB_BPF_OBJ)
	$(BPFTOOL) gen object $(OBJ_DIR)/scx_sdt.l2o $(OBJ_DIR)/scx_sdt.l1o
	$(BPFTOOL) gen object $(OBJ_DIR)/scx_sdt.l3o $(OBJ_DIR)/scx_sdt.l2o
	$(BPFTOOL) gen skeleton $(OBJ_DIR)/scx_sdt.l3o name scx_sdt > $@
	rm -f $(OBJ_DIR)/scx_sdt.l1o $(OBJ_DIR)/scx_sdt.l2o $(OBJ_DIR)/scx_sdt.l3o

$(OBJ_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c
	@echo "Compiling BPF: $< -> $@"
	@mkdir -p $(dir $@)
	$(BPF_CLANG) $(BPF_CFLAGS) -target bpf $(BPF_INCLUDES) -c $< -o $@

install: $(ALL_SCHEDS)
	@echo "Installing schedulers to $(INSTALL_DIR)"
	@mkdir -p $(INSTALL_DIR)
	@for sched in $(ALL_SCHEDS); do \
		echo "Installing $$sched"; \
		cp $$sched $(INSTALL_DIR)/; \
	done

clean:
	rm -f *.bpf.o *.bpf.skel.h *.l1o *.l2o *.l3o scx_simple scx_qmap scx_central scx_userland scx_nest scx_flatcg scx_pair scx_prev scx_sdt
	rm -f $(OBJ_DIR)/*.bpf.o $(OBJ_DIR)/*.bpf.skel.h $(OBJ_DIR)/*.l1o $(OBJ_DIR)/*.l2o $(OBJ_DIR)/*.l3o $(ALL_SCHEDS)

.PHONY: all install clean
