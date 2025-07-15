use ::alloc::sync::Arc;
use ::anyhow::{anyhow, bail};
use ::chute::LendingReader as _;
use ::core::{
    cell::UnsafeCell, ffi::c_void, marker::PhantomData, mem::MaybeUninit, ops::Deref, pin::Pin, ptr::NonNull,
};
use ::fixedbitset::FixedBitSet;
use ::pin_project_lite::pin_project;
use ::rustix::io_uring::io_uring_user_data;

/// The bump-allocator backing the [`ArenaSlab`].
pub struct ArenaBump {
    /// The bump-allocator.
    bump: ::bumpalo::Bump,
    /// The free-list queue.
    free: Arc<::chute::mpmc::Queue<usize>>,
}

impl ArenaBump {
    /// Try to create a new [`ArenaBump`].
    pub fn try_new() -> crate::Result<Self> {
        let this = || {
            let bump = ::bumpalo::Bump::try_new().ok()?;
            let free = ::chute::mpmc::Queue::new();
            let free = ::alloc::sync::Arc::try_unwrap(free).map(Arc::new).ok()?;
            Some(Self { bump, free })
        };
        this().ok_or_else(|| anyhow!("allocation failed"))
    }
}

/// A bump allocator arena providing pinned references to allocated values.
///
/// The arena provides pinning and drop-safety guarantees, meaning that the
/// values allocated within it are pinned on allocation and will not be moved in
/// memory, nor will they have their destructors run, until they are explicitly
/// deallocated or the arena itself is dropped.
///
/// The safety guarantees around memory stability and pinning are upheld due to
/// the fact that the bump allocator backing the arena is prevented from being
/// reset (which requires `&mut Bump`) for the duration of the arena due to the
/// arena holding an immutable reference to the allocator.
///
/// This is useful for cases where you need to allocate values with stable
/// storage that will be used to later reconstruct references from pointers,
/// such as with `io_uring` CQE `user_data`, maintaining Strict Provenance.
pub struct ArenaSlab<'bump, T> {
    /// Bump allocator used for allocating stable memory regions.
    bump: &'bump ArenaBump,
    /// Vector of allocated but maybe-uninitialized value slots.
    data: UnsafeCell<Vec<ArenaSlot<T>>>,
    /// Reader for the free queue.
    free_rx: UnsafeCell<::chute::ClonedReader<::chute::mpmc::Reader<usize>>>,
    /// Phantom field to ensure `ArenaSlab<'bump, T>: !Send + !Sync`
    impl_unsend_unsync: PhantomData<*const ()>,
}

impl<'bump, T> ArenaSlab<'bump, T> {
    /// Create a new [`ArenaSlab`].
    pub fn new(bump: &'bump ArenaBump) -> Self {
        let data = UnsafeCell::new(Vec::new());
        let free_rx = UnsafeCell::new(bump.free.reader().cloned());
        let impl_unsend_unsync = PhantomData;
        Self {
            bump,
            data,
            free_rx,
            impl_unsend_unsync,
        }
    }

    /// Access the slot vector as a shared reference.
    ///
    /// SAFETY: Caller must ensure that no aliased mutable access causes
    /// observable modifications through this shared reference.
    unsafe fn data(&self) -> &Vec<ArenaSlot<T>> {
        let data = self.data.get();
        // SAFETY: Caller ensures safety.
        unsafe { &*data }
    }

    /// Access the slot vector as a mutable reference.
    ///
    /// SAFETY: Caller must ensure that no aliased shared reference observes
    /// modifications made through this mutable reference.
    #[allow(clippy::mut_from_ref, reason = "UnsafeCell API")]
    const unsafe fn data_mut(&self) -> &mut Vec<ArenaSlot<T>> {
        let data = self.data.get();
        // SAFETY: Caller ensures safety.
        unsafe { &mut *data }
    }

    /// Mark an [`ArenaPin`] value for removal and transform it to an
    /// [`ArenaDrop`]. On drop, the value's slot will be free for re-use.
    #[must_use]
    pub fn detach(&self, pin: ArenaPin<'bump, T>) -> ArenaDrop<'bump, T> {
        ArenaDrop::new(&self.bump.free, pin)
    }

    /// Check whether the arena slot vector is empty.
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        // SAFETY: aliasing does not leak beyond this scope.
        let data = unsafe { self.data() };
        data.is_empty()
    }

    /// Returns the length of the arena slot vector.
    fn len(&self) -> usize {
        // SAFETY: aliasing does not leak beyond this scope.
        let data = unsafe { self.data() };
        data.len()
    }

    /// Returns the next free index for the slot vector.
    fn next_free(&self) -> Option<usize> {
        let free = self.free_rx.get();
        // SAFETY: aliasing does not leak beyond this scope.
        let free = unsafe { &mut *free };
        free.next()
    }

    /// Returns an iterator of the next free indices for the slot vector.
    fn iter_free(&self) -> impl Iterator<Item = usize> {
        ::core::iter::from_fn(|| self.next_free())
    }

    /// Returns a mutable reference to the arena slot for a given index.
    ///
    /// SAFETY: Caller must ensure lookup from `idx` is a unique borrow.
    #[allow(clippy::mut_from_ref, reason = "UnsafeCell API")]
    unsafe fn slot_mut(&self, idx: usize) -> Option<&mut ArenaSlot<T>> {
        // SAFETY: Caller ensures safety.
        let data = unsafe { self.data_mut() };
        data.get_mut(idx)
    }

    /// Allocates and returns a mutable reference to memory for a value.
    fn try_alloc_uninit(&self, val: T) -> Option<&'bump mut MaybeUninit<ArenaVal<T>>> {
        let (idx, slot) = if let Some(idx) = self.next_free() {
            // SAFETY: borrow is unique because `idx` is free.
            let slot = unsafe { self.slot_mut(idx) }?;
            (idx, slot)
        } else {
            // Otherwise, allocate a new data slot and return its pointer.
            let mem = MaybeUninit::<ArenaVal<T>>::uninit();
            let mem = self.bump.bump.try_alloc(mem).ok()?;
            let ptr = NonNull::new(mem)?;
            // SAFETY: borrow restricts to slot (below); data not mutated.
            let data = unsafe { self.data_mut() };
            let idx = data.len();
            data.push(ArenaSlot::new(ptr));
            // SAFETY: `idx` guaranteed within `len` from push.
            let slot = unsafe { data.get_unchecked_mut(idx) };
            (idx, slot)
        };
        // SAFETY: The pointer was created from a valid mutable reference.
        let mem: &mut MaybeUninit<ArenaVal<T>> = unsafe { slot.ptr.as_mut() };
        let val = ArenaVal::new(idx, val);
        mem.write(val);
        Some(mem)
    }

    /// Attaches a value to the arena, returning a pinned-value on success or an
    /// error on failure. This involves allocating memory in an arena slot and
    /// moving the value into the slot.
    ///
    /// # Errors
    ///
    /// * Allocation may error.
    pub fn try_attach(&self, val: T) -> crate::Result<ArenaPin<'bump, T>> {
        self.try_attach_opt(val).ok_or_else(|| anyhow!("allocation failed"))
    }

    /// Try to attach a value to the arena, returning a pinned-value on success.
    fn try_attach_opt(&self, val: T) -> Option<ArenaPin<'bump, T>> {
        let mem = self.try_alloc_uninit(val)?;
        // SAFETY: The memory is now initialized with `val`.
        let val: &mut ArenaVal<T> = unsafe { mem.assume_init_mut() };
        // SAFETY: The value will not be moved or invalidated until dropped.
        let pin: Pin<&mut ArenaVal<T>> = unsafe { Pin::new_unchecked(val) };
        Some(ArenaPin::<T>::new(pin))
    }
}

impl<T> Drop for ArenaSlab<'_, T> {
    fn drop(&mut self) {
        let mut skip = FixedBitSet::with_capacity(self.len());
        for idx in self.iter_free() {
            skip.insert(idx);
        }
        // SAFETY: `self` is being dropped so we assume exclusive access.
        let data = unsafe { self.data_mut() };
        for (_idx, slot) in data.iter_mut().enumerate().filter(|&(idx, _)| !skip.contains(idx)) {
            // SAFETY: `self` is being dropped so we assume exclusive access.
            let mem: &mut MaybeUninit<ArenaVal<T>> = unsafe { slot.ptr.as_mut() };
            // SAFETY: `mem` should always have been initialized.
            unsafe { mem.assume_init_drop() };
        }
    }
}

/// An arena slot, as potentially uninitialized memory for a value.
#[repr(transparent)]
struct ArenaSlot<T> {
    /// A pointer to the potentially uninitialized memory.
    ptr: NonNull<MaybeUninit<ArenaVal<T>>>,
}

impl<T> ArenaSlot<T> {
    /// Create a new [`ArenaSlot`].
    const fn new(ptr: NonNull<MaybeUninit<ArenaVal<T>>>) -> Self {
        Self { ptr }
    }
}

pin_project! {
/// An arena value which carries its slot index.
#[project(!Unpin)]
#[repr(C)]
pub struct ArenaVal<T> {
    idx: usize,
    #[pin]
    val: T,
}
}

impl<T> ArenaVal<T> {
    /// Create an arena value from an index and underlying value.
    const fn new(idx: usize, val: T) -> Self {
        Self { idx, val }
    }
}

impl<T> Deref for ArenaVal<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

/// A pinned arena value.
#[repr(transparent)]
pub struct ArenaPin<'bump, T> {
    /// The pinned mutable reference to the arena value.
    val: Pin<&'bump mut ArenaVal<T>>,
}

impl<'bump, T> ArenaPin<'bump, T> {
    /// Create a pinned arena value from a pinned mutable reference.
    const fn new(val: Pin<&'bump mut ArenaVal<T>>) -> Self {
        Self { val }
    }

    /// Reborrow the pinned arena value as a mutable reference.
    pub fn as_mut(&mut self) -> Pin<&mut T> {
        self.val.as_mut().project().val
    }

    /// Reborrow the pinned arena value as a shared reference.
    pub fn as_ref(&self) -> Pin<&T> {
        self.val.as_ref().project_ref().val
    }
}

impl<T> ArenaPin<'_, T> {
    /// Try to convert io-uring user data to a pinned arena value.
    ///
    /// # SAFETY
    ///
    /// * Caller must ensure user data is already pinned to the arena.
    ///
    /// # Errors
    ///
    /// * Will error if user data pointer is unaligned.
    /// * Will error if user data pointer is null.
    pub(crate) unsafe fn try_from_user_data(value: io_uring_user_data) -> crate::Result<Self> {
        let ptr: *mut ArenaVal<T> = value.ptr().cast();
        if !ptr.is_aligned() {
            bail!("unaligned pointer");
        }
        // SAFETY: `ptr` is null or aligned and data-valid by construction and provenance.
        let Some(val) = (unsafe { ptr.as_mut() }) else {
            bail!("null pointer");
        };
        // SAFETY: `val` is pinned
        let pin = unsafe { Pin::new_unchecked(val) };
        Ok(ArenaPin::new(pin))
    }
}

/// NOTE: Caller must ensure conversions back from `io_uring_user_data` are unique.
impl<'bump, T> From<ArenaPin<'bump, T>> for io_uring_user_data {
    fn from(value: ArenaPin<'bump, T>) -> Self {
        let pin = value.val;
        // SAFETY: reference moved to kernel and `Pin` becomes unobservable.
        let val: &mut ArenaVal<T> = unsafe { Pin::into_inner_unchecked(pin) };
        let ptr: *mut ArenaVal<T> = ::core::ptr::from_mut(val);
        let ptr: *mut c_void = ptr.cast();
        Self::from_ptr(ptr)
    }
}

impl<T> Deref for ArenaPin<'_, T> {
    type Target = <ArenaVal<T> as Deref>::Target;

    #[allow(clippy::let_and_return, reason = "explicit")]
    fn deref(&self) -> &Self::Target {
        let val: &ArenaVal<T> = <Pin<&mut ArenaVal<T>> as Deref>::deref(&self.val);
        let val: &T = <ArenaVal<T> as Deref>::deref(val);
        val
    }
}

/// A pinned arena value marked for removal on drop.
pub struct ArenaDrop<'bump, T> {
    /// The free-list queue to submit the value's index to on drop.
    free_tx: &'bump ::chute::mpmc::Queue<usize>,
    /// The pinned arena value.
    pin: ArenaPin<'bump, T>,
}

impl<'bump, T> ArenaDrop<'bump, T> {
    /// Create a new [`ArenaDrop`].
    const fn new(free_tx: &'bump ::chute::mpmc::Queue<usize>, pin: ArenaPin<'bump, T>) -> Self {
        Self { free_tx, pin }
    }

    /// Reborrow the drop value as a mutable reference.
    #[cfg(test)]
    pub fn as_mut(&mut self) -> Pin<&mut T> {
        self.pin.as_mut()
    }

    /// Reborrow the drop value as a shared reference.
    #[cfg(test)]
    pub fn as_ref(&self) -> Pin<&T> {
        self.pin.as_ref()
    }
}

impl<'bump, T> Deref for ArenaDrop<'bump, T> {
    type Target = <ArenaPin<'bump, T> as Deref>::Target;

    fn deref(&self) -> &Self::Target {
        <ArenaPin<'bump, T> as Deref>::deref(&self.pin)
    }
}

impl<T> Drop for ArenaDrop<'_, T> {
    fn drop(&mut self) {
        let idx = self.pin.val.idx;
        let val = self.pin.val.as_mut();
        // SAFETY: we have exclusive access and value is being dropped.
        let val = unsafe { val.get_unchecked_mut() };
        // SAFETY: value is valid for drop.
        unsafe { ::core::ptr::drop_in_place(val) };
        self.free_tx.blocking_push(idx);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]

    use ::core::{pin::pin, time::Duration};
    use ::rand::Rng as _;

    use super::*;

    mod arena {
        use super::*;

        /// Test that a new arena is empty and has no free slots.
        #[test]
        fn new() {
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::<()>::new(&bump);
            // SAFETY: `data` not mutated.
            assert!(unsafe { slab.data() }.is_empty());
            assert!(slab.next_free().is_none());
        }

        /// Test that [`ArenaSlab`] is not [`Send`].
        #[test]
        fn not_impl_send() {
            ::static_assertions_next::assert_impl!(for(T) ArenaSlab<T>: !Send);
        }

        /// Test that [`ArenaSlab`] is not [`Sync`].
        #[test]
        fn not_impl_sync() {
            ::static_assertions_next::assert_impl!(for(T) ArenaSlab<T>: !Sync);
        }
    }

    mod arena_val {
        use super::*;

        /// Test that [`ArenaVal`] is not [`Unpin`].
        #[test]
        fn not_impl_unpin() {
            ::static_assertions_next::assert_impl!(for(T) ArenaVal<T>: !Unpin);
        }
    }

    mod arena_pin {
        use super::*;

        /// Test that [`ArenaPin`] has no [`From<io_uring_user_data>`] impl.
        ///
        /// NOTE: The conversion *must* be `unsafe`, which disallows such an impl.
        #[test]
        fn not_impl_from_io_uring_user_data() {
            ::static_assertions_next::assert_impl!(for(T) ArenaPin<T>: !From<io_uring_user_data>);
        }

        /// Test that [`ArenaPin`] has no [`TryFrom<io_uring_user_data>`] impl.
        ///
        /// NOTE: The conversion *must* be `unsafe`, which disallows such an impl.
        #[test]
        fn not_impl_try_from_io_uring_user_data() {
            ::static_assertions_next::assert_impl!(for(T) ArenaPin<T>: !TryFrom<io_uring_user_data>);
        }

        /// Test that attaching one value to an arena behaves correctly.
        #[test]
        fn try_attach_one() {
            // Create the bump allocator.
            let bump = ArenaBump::try_new().unwrap();
            // Create the slab.
            let slab = ArenaSlab::new(&bump);
            let val = 42usize;
            // Attach one value.
            let pin = slab.try_attach(val).unwrap();
            // Check the pinned value is equal to the original.
            assert_eq!(*pin, val);
            // Check the slab length has increased by one.
            assert_eq!(slab.len(), 1);
            // Check the slab free list is empty.
            assert!(slab.next_free().is_none());
        }

        /// Test that attaching many values to an arena behaves correctly.
        #[test]
        fn try_attach_many() {
            // Create the bump allocator.
            let bump = ArenaBump::try_new().unwrap();
            // Create the slab.
            let slab = ArenaSlab::new(&bump);
            let len = 10usize;
            // Attach many values.
            for val in 0..len {
                let pin = slab.try_attach(val).unwrap();
                // Check the pinned value is equal to the original.
                assert_eq!(*pin, val);
            }
            // Check the slab length has increased by many.
            assert_eq!(slab.len(), len);
            // Check the slab free list is empty.
            assert!(slab.next_free().is_none());
        }

        /// Test that [`ArenaPin::deref`] behaves correctly.
        #[test]
        fn deref() {
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);
            let val = 42usize;
            let pin = slab.try_attach(val).unwrap();
            // Check the pinned value dereferences to the original.
            assert_eq!(*pin, val);
        }

        /// Test that [`ArenaPin::as_ref`] reborrow behaves correctly.
        #[test]
        fn as_ref() {
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);
            let val = 42usize;
            let pin = slab.try_attach(val).unwrap();
            // Check the shared reference reborrow is equal to the original.
            assert_eq!(pin.as_ref(), pin!(val));
        }

        /// Test that [`ArenaPin::as_mut`] reborrow behaves correctly.
        #[test]
        fn as_mut() {
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);
            let val = 42usize;
            let mut pin = slab.try_attach(val).unwrap();
            *pin.as_mut() += 1;
            // Check the mutable reference reborrow respects a mutation.
            assert_eq!(pin.as_mut(), pin!(43));
        }

        /// Test that [`ArenaPin`] -> [`io_uring_user_data`] roundtrips are valid.
        #[test]
        fn io_uring_user_data_roundtrip() {
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);
            let val = 42usize;
            // Attach a value.
            let pin0 = slab.try_attach(val).unwrap();
            let val0 = *pin0;
            // Convert the value to an `io_uring` user data.
            let data = io_uring_user_data::from(pin0);
            // Convert the `io_uring` user data back to a value.
            // SAFETY: data is pinned to the arena.
            let pin1 = unsafe { ArenaPin::<usize>::try_from_user_data(data) }.unwrap();
            // Check the roundtrip results in an equal value to the original.
            assert_eq!(val0, *pin1);
        }

        /// Test that unaligned user data pointers fail to convert to values.
        #[test]
        #[cfg_attr(miri, ignore)] // Miri will correctly complain about UB if enabled here.
        #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: unaligned pointer")]
        fn io_uring_user_data_fail_unaligned_pointer() {
            let val = ();
            let ptr = ::core::ptr::from_ref(&val);
            let data = io_uring_user_data::from_ptr(ptr.cast_mut().cast());
            // SAFETY: should panic.
            unsafe { ArenaPin::<&mut ArenaVal<()>>::try_from_user_data(data) }.unwrap();
        }

        /// Test that null user data pointers fail to convert to values.
        #[test]
        #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: null pointer")]
        fn io_uring_user_data_fail_null_pointer() {
            let ptr: *const ArenaVal<()> = ::core::ptr::null();
            let data = io_uring_user_data::from_ptr(ptr.cast_mut().cast());
            // SAFETY: should panic.
            unsafe { ArenaPin::<&mut ArenaVal<()>>::try_from_user_data(data) }.unwrap();
        }
    }

    mod arena_drop {
        use ::core::sync::atomic::{AtomicUsize, Ordering};

        use super::*;

        #[test]
        fn drop_one_val() {
            struct DropTest {
                dropped: Arc<AtomicUsize>,
            }
            impl DropTest {
                fn new(dropped: Arc<AtomicUsize>) -> Self {
                    Self { dropped }
                }
            }
            impl Drop for DropTest {
                fn drop(&mut self) {
                    self.dropped.fetch_add(1, Ordering::AcqRel);
                }
            }
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);

            let dropped = Arc::new(AtomicUsize::new(0));
            assert_eq!(0, dropped.load(Ordering::Acquire));

            let val = DropTest::new(Arc::clone(&dropped));
            let pin = slab.try_attach(val).unwrap();
            let pin = slab.detach(pin);

            drop(pin);
            assert_eq!(1, dropped.load(Ordering::Acquire));
        }

        #[test]
        fn drop_all_vals() {
            struct DropTest {
                dropped: Arc<AtomicUsize>,
            }
            impl DropTest {
                fn new(dropped: Arc<AtomicUsize>) -> Self {
                    Self { dropped }
                }
            }
            impl Drop for DropTest {
                fn drop(&mut self) {
                    self.dropped.fetch_add(1, Ordering::AcqRel);
                }
            }
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);

            let dropped = Arc::new(AtomicUsize::new(0));
            assert_eq!(0, dropped.load(Ordering::Acquire));

            let len = 10usize;
            for _ in 0..len {
                let val = DropTest::new(Arc::clone(&dropped));
                slab.try_attach(val).unwrap();
            }

            drop(slab);
            drop(bump);

            assert_eq!(len, dropped.load(Ordering::Acquire));
        }

        #[test]
        fn drop_all_lingering_vals() {
            struct DropTest {
                dropped: Arc<AtomicUsize>,
            }
            impl DropTest {
                fn new(dropped: Arc<AtomicUsize>) -> Self {
                    Self { dropped }
                }
            }
            impl Drop for DropTest {
                fn drop(&mut self) {
                    self.dropped.fetch_add(1, Ordering::AcqRel);
                }
            }
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);

            let dropped = Arc::new(AtomicUsize::new(0));
            assert_eq!(0, dropped.load(Ordering::Acquire));

            let len = 10usize;
            for i in 0..len {
                let val = DropTest::new(Arc::clone(&dropped));
                let pin = slab.try_attach(val).unwrap();
                if i % 2usize == 0 {
                    let _det = slab.detach(pin);
                }
            }
            assert_eq!(len / 2usize, dropped.load(Ordering::Acquire));

            drop(slab);
            drop(bump);

            assert_eq!(len, dropped.load(Ordering::Acquire));
        }

        #[test]
        fn drop_one() {
            // Test that dropping a single value frees its slot.
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);
            let val = 42usize;
            let pin = slab.try_attach(val).unwrap();
            let pin = slab.detach(pin);
            drop(pin);
            assert_eq!(slab.len(), 1);
            assert!(slab.next_free().is_some());
            assert!(slab.next_free().is_none());
        }

        #[test]
        fn drop_many_per_item_single_threaded() {
            // Test that dropping many values individually (single-threaded) frees
            // only one slot (since the same slot is re-used multiple times).
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);
            let len = 10usize;
            for val in 0..len {
                let pin = slab.try_attach(val).unwrap();
                let pin = slab.detach(pin);
                assert_eq!(*pin, val);
            }
            assert_eq!(slab.len(), 1);
            assert!(slab.next_free().is_some());
            assert!(slab.next_free().is_none());
        }

        #[test]
        fn drop_many_per_item_multi_threaded() {
            // Test that dropping many values individually (multi-threaded) frees
            // some amount of slots between 1 and the total number of allocations.
            let mut rng = ::rand::rng();
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);
            let len = 10usize;
            #[rustfmt::skip]
            ::std::thread::scope(|s| {
                for val in 0 .. len {
                    let pin = slab.try_attach(val).unwrap();
                    let pin = slab.detach(pin);
                    assert_eq!(*pin, val);
                    let delay = rng.random_range(0 .. 200);
                    s.spawn(move || {
                        ::std::thread::sleep(Duration::from_millis(delay));
                        drop(pin);
                    });
                    let delay = rng.random_range(0 .. 200);
                    ::std::thread::sleep(Duration::from_millis(delay));
                }
            });
            assert!(!slab.is_empty());
            assert!(slab.len() <= 10);
        }

        #[test]
        fn drop_many_per_loop_single_threaded() {
            // Test that dropping many values (single-threaded) eventually all at
            // once frees all their slots.
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);
            let len = 10usize;
            let mut buf = Vec::with_capacity(len);
            for val in 0..len {
                let pin = slab.try_attach(val).unwrap();
                let pin = slab.detach(pin);
                assert_eq!(*pin, val);
                buf.push(pin);
            }
            assert_eq!(slab.len(), len);
            assert!(slab.next_free().is_none());
            drop(buf);
            for _ in 0..len {
                assert!(slab.next_free().is_some());
            }
            assert!(slab.next_free().is_none());
        }

        #[test]
        fn deref() {
            // Test that `deref` returns a ref to the value.
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);
            let val = 42usize;
            let pin = slab.try_attach(val).unwrap();
            let pin = slab.detach(pin);
            assert_eq!(*pin, val);
        }

        #[test]
        fn as_ref() {
            // Test that `as_ref` returns a pinned ref to the value.
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);
            let val = 42usize;
            let pin = slab.try_attach(val).unwrap();
            let pin = slab.detach(pin);
            assert_eq!(pin.as_ref(), pin!(val));
        }

        #[test]
        fn as_mut() {
            // Test that `as_mut` returns a pinned mutable ref to the value.
            let bump = ArenaBump::try_new().unwrap();
            let slab = ArenaSlab::new(&bump);
            let val = 42usize;
            let pin = slab.try_attach(val).unwrap();
            let mut pin = slab.detach(pin);
            *pin.as_mut() += 1;
            assert_eq!(pin.as_mut(), pin!(43));
        }
    }
}
