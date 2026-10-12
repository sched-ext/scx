// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Structures in the arena, with typed fields.
//!
//! Arena memory is shared by every CPU and reachable only through the
//! loads and stores of `mem`, which leave no arena pointer behind for the
//! verifier to track. A structure there is therefore not a Rust reference
//! but a handle, its arena address, and a field is read and written whole:
//!
//! ```ignore
//! scx::arena_struct! {
//!     /// What the scheduler keeps per task.
//!     pub struct TaskCtx {
//!         vtime: u64,
//!         lag: i64,
//!         queued: bool,
//!     }
//! }
//!
//! let vtime = ctx.vtime().get();
//! ctx.lag().set(-5);
//! ctx.vtime().update(|vtime| vtime + delta);
//! ```
//!
//! Each field has a method of its name that returns a `Field`, as a `Var`
//! is for a global. A field takes a 64-bit word, whatever its type, so
//! that every access is one load or store at an offset known at compile
//! time. An array of up to eight words is a field too, a running average,
//! and `Option` of another structure, which holds its address and 0 for
//! `None`. `Words<N>` is a region something else lays out, such as
//! another structure over it, see `Field::view()`.
//!
//! An `Array` is structures laid out back to back, as an allocation of
//! one count of them is.
//!
//! None of this is `unsafe`. An arena access cannot fault and cannot reach
//! memory outside the arena, whatever the address: the kernel bounds it,
//! and a page that is not there reads as zero. A handle to the wrong
//! address is a bug in the scheduler, not a memory-safety one.

use core::marker::PhantomData;

use crate::mem;

/// A type a field of an arena structure can have: how it is laid out, and
/// how it is read and written.
pub trait Value: Sized {
    /// What the field takes in the structure: whole 64-bit words.
    type Repr;

    fn load(base: u64, offset: u64) -> Self;
    fn store(base: u64, offset: u64, value: Self);
}

impl Value for u64 {
    type Repr = u64;

    #[inline(always)]
    fn load(base: u64, offset: u64) -> u64 {
        unsafe { mem::load(base, offset) }
    }

    #[inline(always)]
    fn store(base: u64, offset: u64, value: u64) {
        unsafe { mem::store(base, offset, value) }
    }
}

macro_rules! word_value {
    ($($name:ty: |$word:ident| $from:expr, |$value:ident| $into:expr;)*) => {
        $(impl Value for $name {
            type Repr = u64;

            #[inline(always)]
            fn load(base: u64, offset: u64) -> $name {
                let $word = u64::load(base, offset);
                $from
            }

            #[inline(always)]
            fn store(base: u64, offset: u64, $value: $name) {
                u64::store(base, offset, $into)
            }
        })*
    };
}
word_value! {
    i64: |word| word as i64, |value| value as u64;
    u32: |word| word as u32, |value| u64::from(value);
    i32: |word| word as i32, |value| value as u64;
    bool: |word| word != 0, |value| u64::from(value);
}

/// A short array is read and written word by word, each at an offset
/// known at compile time.
macro_rules! array_value {
    ($($count:literal: $($index:literal)*;)*) => {
        $(impl Value for [u64; $count] {
            type Repr = [u64; $count];

            #[inline(always)]
            fn load(base: u64, offset: u64) -> [u64; $count] {
                [$(u64::load(base, offset + $index * 8)),*]
            }

            #[inline(always)]
            fn store(base: u64, offset: u64, value: [u64; $count]) {
                $(u64::store(base, offset + $index * 8, value[$index]);)*
            }
        })*
    };
}
array_value! {
    2: 0 1;
    3: 0 1 2;
    4: 0 1 2 3;
    5: 0 1 2 3 4;
    6: 0 1 2 3 4 5;
    7: 0 1 2 3 4 5 6;
    8: 0 1 2 3 4 5 6 7;
}

/// A running average, its four words in order.
impl Value for crate::ravg::Ravg {
    type Repr = [u64; 4];

    #[inline(always)]
    fn load(base: u64, offset: u64) -> crate::ravg::Ravg {
        crate::ravg::Ravg {
            val: u64::load(base, offset),
            val_at: u64::load(base, offset + 8),
            old: u64::load(base, offset + 16),
            cur: u64::load(base, offset + 24),
        }
    }

    #[inline(always)]
    fn store(base: u64, offset: u64, value: crate::ravg::Ravg) {
        u64::store(base, offset, value.val);
        u64::store(base, offset + 8, value.val_at);
        u64::store(base, offset + 16, value.old);
        u64::store(base, offset + 24, value.cur);
    }
}

/// Another structure, by its address, 0 for `None`.
impl<T: Struct> Value for Option<T> {
    type Repr = u64;

    #[inline(always)]
    fn load(base: u64, offset: u64) -> Option<T> {
        T::try_from_address(u64::load(base, offset))
    }

    #[inline(always)]
    fn store(base: u64, offset: u64, value: Option<T>) {
        u64::store(base, offset, value.map_or(0, |value| value.address()))
    }
}

/// A region of `N` words that something else lays out, such as a queue
/// node: a field of this type is used through its `address()`.
#[derive(Clone, Copy)]
pub struct Words<const N: usize>(pub [u64; N]);

impl<const N: usize> Default for Words<N> {
    #[inline(always)]
    fn default() -> Self {
        Words([0; N])
    }
}

impl<const N: usize> Value for Words<N> {
    type Repr = [u64; N];

    #[inline(always)]
    fn load(base: u64, offset: u64) -> Words<N> {
        Words(core::array::from_fn(|index| {
            u64::load(base, offset + index as u64 * 8)
        }))
    }

    #[inline(always)]
    fn store(base: u64, offset: u64, value: Words<N>) {
        let mut index = 0;
        while index < N {
            u64::store(base, offset + index as u64 * 8, value.0[index]);
            index += 1;
        }
    }
}

/// One field of a structure in the arena: `OFFSET` bytes into the
/// structure at `base`.
#[derive(Clone, Copy)]
pub struct Field<T, const OFFSET: u64> {
    base: u64,
    value: PhantomData<T>,
}

impl<T: Value, const OFFSET: u64> Field<T, OFFSET> {
    /// The field of the structure at arena address `base`.
    #[inline(always)]
    pub fn of(base: u64) -> Self {
        Field {
            base,
            value: PhantomData,
        }
    }

    #[inline(always)]
    pub fn get(&self) -> T {
        T::load(self.base, OFFSET)
    }

    #[inline(always)]
    pub fn set(&self, value: T) {
        T::store(self.base, OFFSET, value)
    }

    /// Replace the value by `update` of it and return the new one. Not
    /// atomic: another CPU's store in between is lost.
    #[inline(always)]
    pub fn update(&self, update: impl FnOnce(T) -> T) -> T
    where
        T: Copy,
    {
        let value = update(self.get());
        self.set(value);
        value
    }

    /// The field's own arena address, for what takes a field by address:
    /// a queue node, or a function over the words of an array.
    #[inline(always)]
    pub fn address(&self) -> u64 {
        self.base + OFFSET
    }
}

impl<const OFFSET: u64> Field<u64, OFFSET> {
    /// Add `value` atomically and return what the field held before. For
    /// a field several CPUs update, where `update()` would lose one.
    #[inline(always)]
    pub fn fetch_add(&self, value: u64) -> u64 {
        unsafe { mem::fetch_add(self.address(), value) }
    }

    /// Add `value` atomically, `fetch_add()` without the fetch.
    #[inline(always)]
    pub fn add(&self, value: u64) {
        unsafe { mem::add(self.address(), value) }
    }

    /// Store `new` if the field holds `old`, atomically, and return what
    /// it held: `old` if the store happened.
    #[inline(always)]
    pub fn compare_exchange(&self, old: u64, new: u64) -> u64 {
        unsafe { mem::cas(self.address(), old, new) }
    }
}

impl<const OFFSET: u64> Field<u64, OFFSET> {
    /// Store `value` with an exchange, so that the store is ordered after
    /// what this CPU wrote before it on weakly ordered CPUs too: for the
    /// word that publishes the rest.
    #[inline(always)]
    pub fn release(&self, value: u64) {
        unsafe { mem::release(self.address(), value) }
    }
}

impl<const N: usize, const OFFSET: u64> Field<[u64; N], OFFSET> {
    /// Word `index` of the array alone, one load where `get()` is `N`.
    /// The index is not checked: one past the end is the next field's
    /// word, a bug but not a fault.
    #[inline(always)]
    pub fn get_at(&self, index: u64) -> u64 {
        unsafe { mem::load(self.base, OFFSET + index * 8) }
    }

    #[inline(always)]
    pub fn set_at(&self, index: u64, value: u64) {
        unsafe { mem::store(self.base, OFFSET + index * 8, value) }
    }
}

impl<const N: usize, const OFFSET: u64> Field<Words<N>, OFFSET> {
    /// The region as the structure `T`, which another module lays out over
    /// it and which must fit in it.
    #[inline(always)]
    pub fn view<T: Struct>(&self) -> T {
        const { assert!(T::SIZE <= N as u64 * 8) };
        T::from_address(self.address())
    }
}

/// A structure in the arena, as `arena_struct!` declares one: a handle to
/// its address.
pub trait Struct: Copy {
    /// The structure's layout, `#[repr(C)]`.
    type Layout;
    /// Its size in bytes.
    const SIZE: u64;

    fn from_address(address: u64) -> Self;
    fn address(&self) -> u64;
    /// Set every field to zero.
    fn zero(&self);

    /// The structure at `address`, or `None` for 0.
    #[inline(always)]
    fn try_from_address(address: u64) -> Option<Self> {
        if address == 0 {
            None
        } else {
            Some(Self::from_address(address))
        }
    }
}

/// `len` structures `T` back to back from an arena address: a handle, as
/// the structures are.
pub struct Array<T> {
    address: u64,
    len: u64,
    element: PhantomData<T>,
}

impl<T> Clone for Array<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Array<T> {}

impl<T: Struct> Array<T> {
    /// The bytes `len` structures take.
    pub const fn bytes(len: u64) -> u64 {
        len * T::SIZE
    }

    /// The `len` structures from arena address `address`.
    #[inline(always)]
    pub fn from_address(address: u64, len: u64) -> Self {
        Array {
            address,
            len,
            element: PhantomData,
        }
    }

    /// Structure `index`, or `None` past the end.
    #[inline(always)]
    pub fn get(&self, index: u64) -> Option<T> {
        if index < self.len {
            Some(T::from_address(self.address + index * T::SIZE))
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn len(&self) -> u64 {
        self.len
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The arena address of the first structure.
    #[inline(always)]
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The arena address right after the last structure.
    #[inline(always)]
    pub fn end(&self) -> u64 {
        self.address + self.len * T::SIZE
    }
}

/// Declare a structure that lives in the arena, see the module.
#[macro_export]
macro_rules! arena_struct {
    ($(#[$meta:meta])* $vis:vis struct $name:ident {
        $($(#[$field_meta:meta])* $field:ident: $type:ty),* $(,)?
    }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq)]
        $vis struct $name {
            address: u64,
        }

        const _: () = {
            #[repr(C)]
            pub struct Layout {
                $(pub $field: <$type as $crate::arena::Value>::Repr,)*
            }

            impl $crate::arena::Struct for $name {
                type Layout = Layout;
                const SIZE: u64 = core::mem::size_of::<Layout>() as u64;

                #[inline(always)]
                fn from_address(address: u64) -> Self {
                    $name::from_address(address)
                }

                #[inline(always)]
                fn address(&self) -> u64 {
                    $name::address(self)
                }

                #[inline(always)]
                fn zero(&self) {
                    $(self.$field().set(Default::default());)*
                }
            }
        };

        // A global function takes the structure as its address.
        impl $crate::sched::Abi for $name {
            type Raw = u64;

            #[inline(always)]
            fn into_raw(self) -> u64 {
                self.address
            }

            #[inline(always)]
            unsafe fn from_raw(raw: u64) -> Self {
                $name { address: raw }
            }
        }

        #[allow(dead_code)]
        impl $name {
            /// The structure at arena address `address`.
            #[inline(always)]
            $vis fn from_address(address: u64) -> Self {
                $name { address }
            }

            /// The structure's arena address, for what takes it as a word:
            /// a global function, or another structure's field.
            #[inline(always)]
            $vis fn address(&self) -> u64 {
                self.address
            }

            $(
                $(#[$field_meta])*
                #[inline(always)]
                $vis fn $field(&self) -> $crate::arena::Field<$type, {
                    core::mem::offset_of!(<$name as $crate::arena::Struct>::Layout, $field) as u64
                }> {
                    $crate::arena::Field::of(self.address)
                }
            )*
        }
    };
}
