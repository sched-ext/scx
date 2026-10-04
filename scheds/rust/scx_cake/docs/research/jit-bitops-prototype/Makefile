# SPDX-License-Identifier: GPL-2.0
CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
OUT ?= build
CFLAGS ?= -O2 -g -Wall -Wextra -Werror

.PHONY: all
all: $(OUT)/bitops-run $(OUT)/selftest-run

$(OUT):
	mkdir -p $@

$(OUT)/bitops.bpf.o: bitops.bpf.c | $(OUT)
	$(CLANG) -O2 -g -target bpf -mcpu=v4 -Wall -Werror -c $< -o $@

$(OUT)/bitops.skel.h: $(OUT)/bitops.bpf.o
	$(BPFTOOL) gen skeleton $< name bitops > $@.new
	mv $@.new $@

$(OUT)/bitops-run: bitops-run.c $(OUT)/bitops.skel.h
	$(CC) $(CFLAGS) -I$(OUT) $< -o $@ $$(pkg-config --cflags --libs libbpf)

$(OUT)/selftest-run: selftest-run.c | $(OUT)
	$(CC) $(CFLAGS) $< -o $@ $$(pkg-config --cflags --libs libbpf)
