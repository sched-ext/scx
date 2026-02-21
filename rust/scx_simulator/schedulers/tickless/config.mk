# Per-scheduler config for tickless
# Strip const qualifiers: BPF "const volatile" globals need to be writable
EXTRA_CFLAGS_tickless := -Dconst=
# Tickless BPF source (for #include "intf.h" and "main.bpf.c")
EXTRA_INCLUDES_tickless := -I$(ROOT_DIR)/scheds/rust/scx_tickless/src/bpf
