/*
 * simple_wrapper.c - Wrapper to compile scx_simple.bpf.c as userspace C
 *
 * This file includes the simulator wrapper infrastructure and then
 * the actual scheduler source. The header guards in common.bpf.h
 * prevent re-inclusion, so our overridden macros take effect.
 */
#include "sim_wrapper.h"
#include "sim_task.h"

/* Now include the scheduler source.
 * common.bpf.h is already included (header guard set), so our
 * BPF_STRUCT_OPS and SCX_OPS_DEFINE overrides are in effect. */
#include "scx_simple.bpf.c"
