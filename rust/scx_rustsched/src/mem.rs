// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Access to arena memory by arena address.
//!
//! The verifier takes a load or a store in the arena only through a
//! pointer made by an addr_space_cast, and it types that pointer
//! PTR_TO_ARENA. It also rewrites every 64-bit ALU instruction it has seen
//! with such an operand into a 32-bit one, so that the result stays an
//! offset into the arena. An instruction that some path reaches with an
//! arena pointer and another with two numbers therefore computes the
//! numbers' result truncated to 32 bits, and newer kernels refuse the
//! program: "same insn cannot be used with and without arena pointer".
//!
//! That happens without any pointer arithmetic in the source. LLVM
//! computes a value on a path that does not use it, a comparison it made
//! branchless say, from whatever its operands' registers and stack slots
//! hold there, and a cast pointer left in one of them makes the
//! instruction an arena one.
//!
//! So no cast pointer exists outside the accessors here. Each one casts
//! and accesses in one block of assembly, and leaves no arena pointer in
//! a register: a load overwrites the pointer with what it loaded, and
//! everything else clears it. The compiler only ever sees arena addresses
//! as numbers, and nothing it spills or reuses is an arena pointer.
//!
//! An access is `base + offset`. An offset the compiler knows after
//! inlining becomes the instruction's own, which the accessors select by
//! matching on it: the match folds to one arm. Any other offset is added
//! to the address first.

use core::arch::asm;

macro_rules! by_offset {
    ($offset:expr, [$($constant:literal),*], |$o:ident| $access:expr, $fallback:expr) => {
        if core::intrinsics::is_val_statically_known($offset) {
            match $offset {
                $($constant => {
                    const $o: u64 = $constant;
                    $access
                })*
                _ => $fallback,
            }
        } else {
            $fallback
        }
    };
}

macro_rules! offsets64 {
    ($offset:expr, |$o:ident| $access:expr, $fallback:expr) => {
        by_offset!(
            $offset,
            [
                0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144,
                152, 160, 168, 176, 184, 192, 200, 208, 216, 224, 232, 240, 248, 256, 264, 272,
                280, 288, 296, 304, 312, 320, 328, 336, 344, 352, 360, 368, 376, 384, 392, 400,
                408, 416, 424, 432, 440, 448, 456, 464, 472, 480, 488, 496, 504, 512, 520, 528,
                536, 544, 552, 560, 568, 576, 584, 592, 600, 608, 616, 624, 632, 640, 648, 656,
                664, 672, 680, 688, 696, 704, 712, 720, 728, 736, 744, 752, 760, 768, 776, 784,
                792, 800, 808, 816, 824, 832, 840, 848, 856, 864, 872, 880, 888, 896, 904, 912,
                920, 928, 936, 944, 952, 960, 968, 976, 984, 992, 1000, 1008, 1016
            ],
            |$o| $access,
            $fallback
        )
    };
}

macro_rules! offsets32 {
    ($offset:expr, |$o:ident| $access:expr, $fallback:expr) => {
        by_offset!(
            $offset,
            [
                0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80,
                84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124
            ],
            |$o| $access,
            $fallback
        )
    };
}

#[inline(always)]
unsafe fn load_at<const O: u64>(base: u64) -> u64 {
    let value: u64;
    unsafe {
        asm!(
            "{value} = addr_space_cast({base}, 0, 1)",
            "{value} = *(u64 *)({value} + {offset})",
            base = in(reg) base,
            value = lateout(reg) value,
            offset = const O,
            options(nostack, readonly),
        );
    }
    value
}

/// The word at `offset` bytes from the arena address `base`.
#[inline(always)]
pub fn load(base: u64, offset: u64) -> u64 {
    unsafe { offsets64!(offset, |O| load_at::<O>(base), load_at::<0>(base + offset)) }
}

#[inline(always)]
unsafe fn store_at<const O: u64>(base: u64, value: u64) {
    unsafe {
        asm!(
            "{pointer} = addr_space_cast({base}, 0, 1)",
            "*(u64 *)({pointer} + {offset}) = {value}",
            "{pointer} = 0",
            base = in(reg) base,
            value = in(reg) value,
            pointer = out(reg) _,
            offset = const O,
            options(nostack),
        );
    }
}

/// Store `value` in the word at `offset` bytes from the arena address
/// `base`.
#[inline(always)]
pub fn store(base: u64, offset: u64, value: u64) {
    unsafe {
        offsets64!(
            offset,
            |O| store_at::<O>(base, value),
            store_at::<0>(base + offset, value)
        )
    }
}

#[inline(always)]
unsafe fn load32_at<const O: u64>(base: u64) -> u32 {
    let value: u64;
    unsafe {
        asm!(
            "{value} = addr_space_cast({base}, 0, 1)",
            "{value} = *(u32 *)({value} + {offset})",
            base = in(reg) base,
            value = lateout(reg) value,
            offset = const O,
            options(nostack, readonly),
        );
    }
    value as u32
}

/// The 32-bit word at `offset` bytes from the arena address `base`.
#[inline(always)]
pub fn load32(base: u64, offset: u64) -> u32 {
    unsafe {
        offsets32!(
            offset,
            |O| load32_at::<O>(base),
            load32_at::<0>(base + offset)
        )
    }
}

#[inline(always)]
unsafe fn store32_at<const O: u64>(base: u64, value: u32) {
    unsafe {
        asm!(
            "{pointer} = addr_space_cast({base}, 0, 1)",
            "*(u32 *)({pointer} + {offset}) = {value}",
            "{pointer} = 0",
            base = in(reg) base,
            value = in(reg) u64::from(value),
            pointer = out(reg) _,
            offset = const O,
            options(nostack),
        );
    }
}

/// Store `value` in the 32-bit word at `offset` bytes from the arena
/// address `base`.
#[inline(always)]
pub fn store32(base: u64, offset: u64, value: u32) {
    unsafe {
        offsets32!(
            offset,
            |O| store32_at::<O>(base, value),
            store32_at::<0>(base + offset, value)
        )
    }
}

/// Store `value` in the word at `address` with a release, so that the
/// store is ordered on weakly ordered CPUs too.
#[inline(always)]
pub fn release(address: u64, value: u64) {
    unsafe {
        asm!(
            "{pointer} = addr_space_cast({address}, 0, 1)",
            "store_release((u64 *)({pointer} + 0), {value})",
            "{pointer} = 0",
            address = in(reg) address,
            value = in(reg) value,
            pointer = out(reg) _,
            options(nostack),
        );
    }
}

/// Compare the word at `address` with `old` and, if equal, store `new`.
/// Returns the word's previous value: the exchange happened if that is
/// `old`.
#[inline(always)]
pub fn cas(address: u64, old: u64, new: u64) -> u64 {
    let previous: u64;
    unsafe {
        asm!(
            "{pointer} = addr_space_cast({address}, 0, 1)",
            "r0 = cmpxchg_64({pointer} + 0, r0, {new})",
            "{pointer} = 0",
            address = in(reg) address,
            new = in(reg) new,
            pointer = out(reg) _,
            inout("r0") old => previous,
            options(nostack),
        );
    }
    previous
}

/// Add `value` to the word at `address` and return its previous value.
#[inline(always)]
pub fn fetch_add(address: u64, value: u64) -> u64 {
    let previous: u64;
    unsafe {
        asm!(
            "{pointer} = addr_space_cast({address}, 0, 1)",
            "{value} = atomic_fetch_add((u64 *)({pointer} + 0), {value})",
            "{pointer} = 0",
            address = in(reg) address,
            value = inout(reg) value => previous,
            pointer = out(reg) _,
            options(nostack),
        );
    }
    previous
}

/// Add `value` to the word at `address`.
#[inline(always)]
pub fn add(address: u64, value: u64) {
    unsafe {
        asm!(
            "{pointer} = addr_space_cast({address}, 0, 1)",
            "lock *(u64 *)({pointer} + 0) += {value}",
            "{pointer} = 0",
            address = in(reg) address,
            value = in(reg) value,
            pointer = out(reg) _,
            options(nostack),
        );
    }
}

/// Set the bits of `value` in the word at `address`. The non-fetching
/// form, the only one of the bitwise atomics the arena takes.
#[inline(always)]
pub fn or(address: u64, value: u64) {
    unsafe {
        asm!(
            "{pointer} = addr_space_cast({address}, 0, 1)",
            "lock *(u64 *)({pointer} + 0) |= {value}",
            "{pointer} = 0",
            address = in(reg) address,
            value = in(reg) value,
            pointer = out(reg) _,
            options(nostack),
        );
    }
}

/// Clear the bits not in `value` in the word at `address`, as [`or`].
#[inline(always)]
pub fn and(address: u64, value: u64) {
    unsafe {
        asm!(
            "{pointer} = addr_space_cast({address}, 0, 1)",
            "lock *(u64 *)({pointer} + 0) &= {value}",
            "{pointer} = 0",
            address = in(reg) address,
            value = in(reg) value,
            pointer = out(reg) _,
            options(nostack),
        );
    }
}
