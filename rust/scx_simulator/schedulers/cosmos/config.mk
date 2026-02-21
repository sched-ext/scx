# Per-scheduler config for cosmos
# Strip const qualifiers: BPF "const volatile" globals need to be writable
EXTRA_CFLAGS_cosmos := -Dconst=
# COSMOS BPF source (for #include "intf.h")
COSMOS_BPF_DIR := $(ROOT_DIR)/scheds/rust/scx_cosmos/src/bpf
EXTRA_INCLUDES_cosmos := -I$(COSMOS_BPF_DIR) -Icosmos

# Generate a patched copy of main.bpf.c that guards against division-by-zero.
# BPF division-by-zero returns 0; native C crashes with SIGFPE.
# The patch adds an interval==0 guard in update_freq().
#
# These rules add build targets; they must not become the default target.
# The parent Makefile sets .DEFAULT_GOAL := all before including config files.
cosmos/cosmos_main_patched.c: $(COSMOS_BPF_DIR)/main.bpf.c
	sed 's|new_freq = (100 \* NSEC_PER_MSEC) / interval;|new_freq = interval ? (100 * NSEC_PER_MSEC) / interval : 0;|' $< > $@

# Make the wrapper depend on the patched source
$(BUILD_DIR)/cosmos_wrapper.o: cosmos/cosmos_main_patched.c
