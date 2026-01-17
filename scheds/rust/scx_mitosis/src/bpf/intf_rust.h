/*
 * This is a preprocessor workaround so we can differentiate
 * bindgen using intf.h for rust and the BPF program using it for C.
 *
 * __KERNEL__ doesn't work because it's not defined when our BPF program is
 * compiled.
 *
 * __BPF__ doesn't work because it IS defined when our rust program is
 * compiled.
 *
 * So we make an arbitrary define here that will be set for the rust program
 * and not for the BPF program.
 */

#define __BINDGEN_RUNNING__
#include "intf.h"
