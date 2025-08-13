# SCX Library Makefile
# Build BPF library objects

# Library source files
LIB_SRCS := sdt_alloc sdt_task
LIB_OBJS := $(LIB_SRCS:=.bpf.o)

# Output library object
LIB_TARGET := lib.bpf.o

# Default target
all: $(LIB_TARGET)

# Build the combined library object
$(LIB_TARGET): $(LIB_OBJS)
	@echo "Building library object: $@"
	$(BPFTOOL) gen object $@ $^

# Compile individual BPF source files
%.bpf.o: %.bpf.c
	@echo "Compiling BPF: $<"
	$(BPF_CLANG) $(BPF_CFLAGS) -target bpf $(BPF_INCLUDES) -c $< -o $@

# Clean build artifacts
clean:
	rm -f *.bpf.o $(LIB_TARGET)

.PHONY: all clean