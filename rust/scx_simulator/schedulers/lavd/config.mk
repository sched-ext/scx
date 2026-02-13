# Per-scheduler config for lavd
# Strip const qualifiers: BPF "const volatile" globals need to be writable
EXTRA_CFLAGS_lavd := -Dconst=
# LAVD BPF source directory
LAVD_BPF_DIR := $(ROOT_DIR)/scheds/rust/scx_lavd/src/bpf
EXTRA_INCLUDES_lavd := -I$(LAVD_BPF_DIR) -Ilavd
