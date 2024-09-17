// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

#include <stdbool.h>
#ifndef __kptr
#ifdef __KERNEL__
#error "__kptr_ref not defined in the kernel"
#endif
#define __kptr
#endif

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
#endif

#include <scx/ravg.bpf.h>


#define dbg(fmt, args...)	do { if (debug) bpf_printk(fmt, ##args); } while (0)
#define trace(fmt, args...)	do { if (debug > 1) bpf_printk(fmt, ##args); } while (0)
#define info(fmt, args...)	do { bpf_printk(fmt, ##args); } while (0)

#define SAFE_ACCESS(index, array_length, array, default_value) \
    (((index) < (array_length)) ? (array)[(index)] : (default_value))

enum consts {
  MAX_CPUS = 128,
  MAX_VMS = 16,
  FALLBACK_DSQ_ID = 0,
};

#endif /* __INTF_H */
