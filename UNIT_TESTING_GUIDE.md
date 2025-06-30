# Unit testing guide

## Introduction

This is a guide to lay out how to approach the unit testing of the BPF side of
the sched_ext schedulers.  The user space components of the schedulers utilize
the same patterns as their respective language's unit testing framework.

## How do I run the existing tests

Currently we create separate binaries for the BPF tests, and this is handled by
`meson`. In the future the various Rust based schedulers will also automatically
do the correct thing when running `cargo test`.  For now simply run

```bash
# If you haven't compiled yet you run the following
meson setup build
meson compile -C build

# To run the tests, you can use the following command
meson test -v -C
```

## The basic design

Currently, the way to create a unit test of the BPF side of the schedulers is to
add a new file along side the existing BPF code and include the C file into this
test file.

For example, if your main BPF file is `main.bpf.c`, you create a new file called
`main.test.bpf.c` in the same directory and do something like this:

```c
#include <scx_test.h>

#include "main.bpf.c"

void test_my_function(void)
{
    scx_test_assert(my_function(5) == 5);
}

int main(int argc, char **argv)
{
    test_my_function();
    return 0;
}
```

A canonical example exists in `scheds/rust/scx_p2dq/src/bpf/main.test.bpf.c`.

You must also include the following in your `meson.build` file to ensure that it
is built properly and run when `meson test` is run

```meson
e = test_executable('scx_example_test',
  ['path/to/main.test.bpf.c'],
  dependencies: [scx_test_dep],
  c_args: scx_test_c_args,
  install: false,
  build_by_default: false,
)
test('scx_example_test', e)
```

## Stubbing out BPF and kernel functions

BPF programs are a rare beast, and thus creating stub functions for them is
tricky.  There are a few things that need to be kept in mind.

1. *Try not to modify the actual scheduler to fit the test*. This may not be
   tenable in all cases, but this is a good rule of thumb. We want to keep the
   core scheduler code as pristine as possible.

2. *A lot of helpers are weak references, this will cause crashes if you miss
   one*.  `libbpf` provides weak references to the BPF helpers, because the
   compiler knows what to do when it's building a BPF binary. But in userspace
   we need the actual symbol.  Sometimes you will get a `SIGSEGV` and `gdb` will
   resolve the symbol to `???`. This is an indication you missed a function that
   is required for your test, simply look at the frame before it to find out
   which function is missing.

3. *You must #define to override most BPF helpers*. This is because the BPF and
   the `libbpf` helpers are often named the same thing, but the `libbpf`
   versions interact with the kernel interface, they do not provide a userspace
   implementation of that functionality.  Look at
   [lib/scxtest/scx_test_map.h](lib/scxtest/scx_test_map.h) for an example of
   what this looks like.

4. *Some of the helpers are static functions*. This is the case for
   `bpf_get_prandom_u32()`, you cannot simply create a stub for this to override
   the behavior like you can with some helpers.  In this case you must override
   them with a `#define`.

5. *The rest of the BPF helpers can simply be stubbed out*. Look at
   [lib/scxtest/overrides.c](lib/scxtest/overrides.c) for an examples of these
   functions.  If you require a real implementation for these helpers simply
   provide it alongside your test.

## Outstanding items

A lot of the sched_ext library helpers haven't been stubbed out yet. This is
code like `sdt_task` and such. This will take some more care as they have
private maps that are more difficult to provide clean stubs for.

There currently is very limited functionality. `bpf_map` and `cpumask` have been
mostly covered, but anything beyond that still requires some active work to
provide stubs for.
