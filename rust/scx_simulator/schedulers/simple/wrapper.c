/*
 * simple_wrapper.c - Wrapper to compile scx_simple.bpf.c as userspace C
 *
 * This file includes the simulator wrapper infrastructure and then
 * the actual scheduler source (a local copy kept in this directory).
 * The header guards in common.bpf.h prevent re-inclusion, so our
 * overridden macros take effect.
 */
#include "sim_wrapper.h"
#include "sim_task.h"

/* Now include the local copy of the scheduler source.
 * common.bpf.h is already included (header guard set), so our
 * BPF_STRUCT_OPS and SCX_OPS_DEFINE overrides are in effect. */
#include "scx_simple.bpf.c"
