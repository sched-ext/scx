# Per-scheduler config for mitosis
# Strip const qualifiers: BPF "const volatile" globals need to be writable
EXTRA_CFLAGS_mitosis := -Dconst=
# Mitosis BPF source (for #include "intf.h")
MITOSIS_BPF_DIR := $(ROOT_DIR)/scheds/rust/scx_mitosis/src/bpf
EXTRA_INCLUDES_mitosis := -I$(MITOSIS_BPF_DIR)
