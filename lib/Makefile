# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2025 Meta Platforms, Inc. and affiliates.

# Handle out-of-source builds - use LIB_OBJ_DIR if set by parent makefile
SRC_DIR ?= $(CURDIR)
ifneq ($(LIB_OBJ_DIR),)
  OBJ_DIR := $(LIB_OBJ_DIR)
else
  OBJ_DIR := $(CURDIR)
endif

LIB_SRCS := sdt_alloc sdt_task
LIB_OBJS := $(addprefix $(OBJ_DIR)/,$(LIB_SRCS:=.bpf.o))

LIB_TARGET := $(OBJ_DIR)/lib.bpf.o

all: $(LIB_TARGET)

$(LIB_TARGET): $(LIB_OBJS)
	@echo "Building library object: $@"
	@mkdir -p $(dir $@)
	$(BPFTOOL) gen object $@ $^

$(OBJ_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c
	@echo "Compiling BPF: $< -> $@"
	@mkdir -p $(dir $@)
	$(BPF_CLANG) $(BPF_CFLAGS) -target bpf $(BPF_INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJ_DIR)/*.bpf.o $(LIB_TARGET)

.PHONY: all clean
