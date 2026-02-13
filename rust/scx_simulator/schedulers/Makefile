# Makefile — builds scheduler .so files for scx_simulator
#
# Auto-discovers schedulers: any subdirectory containing wrapper.c becomes
# a scheduler. Each is built into $(BUILD_DIR)/libscx_<name>.so.
#
# Invoked by build.rs:
#   make -C schedulers/ BUILD_DIR=<out_dir>/schedulers \
#        SIMULATOR_DIR=.. ROOT_DIR=../../../ \
#        BPF_INCLUDE=<DEP_BPF_INCLUDE path> CC=clang
#
# Or standalone (defaults assume relative paths from this directory):
#   make BUILD_DIR=build

# --- Paths (overridable by build.rs) ---
SIMULATOR_DIR ?= ..
ROOT_DIR      ?= $(SIMULATOR_DIR)/../..
BUILD_DIR     ?= build

# CC defaults to 'cc' (gcc) in Make, but this code requires clang.
# Override the default unless the user explicitly set CC.
ifeq ($(origin CC),default)
CC := clang
endif

# BPF_INCLUDE must point to the libbpf header directory.
# When invoked from build.rs, this is set to DEP_BPF_INCLUDE.
# For standalone use: try pkg-config, then fall back to Cargo build cache.
BPF_INCLUDE   ?= $(or \
    $(shell pkg-config --cflags-only-I libbpf 2>/dev/null | sed 's/^-I//'),\
    $(firstword $(wildcard $(ROOT_DIR)/target/debug/build/libbpf-sys-*/out/include)))

# --- Auto-discover schedulers ---
SCHEDS := $(patsubst %/wrapper.c,%,$(wildcard */wrapper.c))
SO_TARGETS := $(foreach s,$(SCHEDS),$(BUILD_DIR)/libscx_$(s).so)

# --- Common flags ---
CFLAGS := -fPIC -DSCX_BPF_UNITTEST \
          -Wno-unused-parameter -Wno-unknown-attributes

INCLUDES := -I$(SIMULATOR_DIR)/csrc \
            -I$(ROOT_DIR)/lib/scxtest \
            -I$(ROOT_DIR)/scheds/include \
            -I$(ROOT_DIR)/scheds/include/lib \
            -I$(ROOT_DIR)/scheds/vmlinux \
            -I$(ROOT_DIR)/scheds/vmlinux/arch/x86 \
            -I$(ROOT_DIR)/scheds/include/bpf-compat \
            $(if $(BPF_INCLUDE),-I$(BPF_INCLUDE))

# Shared source files compiled into every .so
SHARED_SRCS := $(SIMULATOR_DIR)/csrc/sim_bpf_stubs.c \
               $(SIMULATOR_DIR)/csrc/sim_sdt_stubs.c \
               $(SIMULATOR_DIR)/csrc/sim_sigfpe.c \
               $(ROOT_DIR)/lib/scxtest/overrides.c

# --- Per-scheduler config ---
# Each scheduler can define EXTRA_CFLAGS_<name> and EXTRA_INCLUDES_<name>
# Set default goal BEFORE including config files, so rules in config.mk
# don't accidentally become the default target.
.DEFAULT_GOAL := all
$(foreach s,$(SCHEDS),$(eval -include $(s)/config.mk))

# --- Build rules ---

.PHONY: all clean $(SCHEDS)

ifeq ($(BPF_INCLUDE),)
all $(SO_TARGETS):
	$(error BPF_INCLUDE is empty — install libbpf-devel or run 'cargo build' first to populate target/debug/build/libbpf-sys-*/out/include)
else
all: $(SO_TARGETS)
	@echo "Built $(words $(SO_TARGETS)) scheduler(s): $(SCHEDS)"
endif

# Individual scheduler targets (e.g., make simple)
$(foreach s,$(SCHEDS),$(eval $(s): $(BUILD_DIR)/libscx_$(s).so))

clean:
	rm -rf $(BUILD_DIR)

# --- Object compilation ---

# Per-scheduler wrapper.c -> <name>_wrapper.o
define WRAPPER_RULE
$(BUILD_DIR)/$(1)_wrapper.o: $(1)/wrapper.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $(EXTRA_INCLUDES_$(1)) $(EXTRA_CFLAGS_$(1)) \
		-MMD -MF $(BUILD_DIR)/$(1)_wrapper.d \
		-c -o $$@ $$<
endef

# Per-scheduler sim_bpf_stubs.c -> <name>_sim_bpf_stubs.o
define STUBS_RULE
$(BUILD_DIR)/$(1)_sim_bpf_stubs.o: $(SIMULATOR_DIR)/csrc/sim_bpf_stubs.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $(EXTRA_INCLUDES_$(1)) $(EXTRA_CFLAGS_$(1)) \
		-MMD -MF $(BUILD_DIR)/$(1)_sim_bpf_stubs.d \
		-c -o $$@ $$<
endef

# Per-scheduler sim_sdt_stubs.c -> <name>_sim_sdt_stubs.o
define SDT_STUBS_RULE
$(BUILD_DIR)/$(1)_sim_sdt_stubs.o: $(SIMULATOR_DIR)/csrc/sim_sdt_stubs.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $(EXTRA_INCLUDES_$(1)) $(EXTRA_CFLAGS_$(1)) \
		-MMD -MF $(BUILD_DIR)/$(1)_sim_sdt_stubs.d \
		-c -o $$@ $$<
endef

# Per-scheduler sim_sigfpe.c -> <name>_sim_sigfpe.o
# NOTE: compiled WITHOUT $(INCLUDES) to avoid vmlinux.h / signal.h conflicts
define SIGFPE_RULE
$(BUILD_DIR)/$(1)_sim_sigfpe.o: $(SIMULATOR_DIR)/csrc/sim_sigfpe.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) \
		-MMD -MF $(BUILD_DIR)/$(1)_sim_sigfpe.d \
		-c -o $$@ $$<
endef

# Per-scheduler overrides.c -> <name>_overrides.o
define OVERRIDES_RULE
$(BUILD_DIR)/$(1)_overrides.o: $(ROOT_DIR)/lib/scxtest/overrides.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $(EXTRA_INCLUDES_$(1)) $(EXTRA_CFLAGS_$(1)) \
		-MMD -MF $(BUILD_DIR)/$(1)_overrides.d \
		-c -o $$@ $$<
endef

# Link .o files into .so
define SO_RULE
$(BUILD_DIR)/libscx_$(1).so: $(BUILD_DIR)/$(1)_wrapper.o $(BUILD_DIR)/$(1)_sim_bpf_stubs.o $(BUILD_DIR)/$(1)_sim_sdt_stubs.o $(BUILD_DIR)/$(1)_sim_sigfpe.o $(BUILD_DIR)/$(1)_overrides.o
	$(CC) -shared -o $$@ $$^
endef

# Instantiate rules for each scheduler
$(foreach s,$(SCHEDS),$(eval $(call WRAPPER_RULE,$(s))))
$(foreach s,$(SCHEDS),$(eval $(call STUBS_RULE,$(s))))
$(foreach s,$(SCHEDS),$(eval $(call SDT_STUBS_RULE,$(s))))
$(foreach s,$(SCHEDS),$(eval $(call SIGFPE_RULE,$(s))))
$(foreach s,$(SCHEDS),$(eval $(call OVERRIDES_RULE,$(s))))
$(foreach s,$(SCHEDS),$(eval $(call SO_RULE,$(s))))

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Include generated dependency files for incremental rebuilds
-include $(wildcard $(BUILD_DIR)/*.d)
