use ::alloc::sync::Arc;
use ::anyhow::bail;
use ::core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    ops::Deref,
    ptr::NonNull,
    sync::atomic::{self, AtomicU16, AtomicU64},
};
use ::rustix_uring::{IoUring, cqueue, squeue, types::BufRingEntry};

/// A buffer token generation ID source.
///
/// This is used to source a secondary field for buffer tokens in order to
/// uniquely identify them, in addition to the primary field as the address,
/// since the address may not be unique enough by itself.
static BUFFER_TOKEN_GENERATION: AtomicU64 = AtomicU64::new(0);

/// A buffer ring region for `io_uring` buffer ring entries.
///
/// This structure is the inner layer of the buffer ring API. See [`BufferRing`]
/// for the outer layer of this API.
///
/// This layer of the API manages a chunk of memory provisioned with
/// [`rustix::mm::mmap_anonymous`] and also provides bookkeeping for the tail
/// field used by the `io_uring` buffer ring structures.
struct BufferRingRegion {
    /// Memory-mapped region.
    ptr: NonNull<BufRingEntry>,
    /// Length of the ring (count of the entries).
    len: u16,
    /// Tail of the ring. Safe access restricts lifetime to self.
    tail: &'static AtomicU16,
}

impl Drop for BufferRingRegion {
    fn drop(&mut self) {
        let ring = self.ptr.as_ptr().cast();
        let size = self.size();
        // SAFETY: `ring` upholds `munmap` invariants via `mmap_anonymous`.
        #[allow(clippy::unwrap_used, reason = "should panic")]
        unsafe { ::rustix::mm::munmap(ring, size) }.unwrap();
    }
}

impl BufferRingRegion {
    /// Provisions a region of as an anonymous memory mapping.
    fn make_mmap(len: u16) -> crate::Result<NonNull<BufRingEntry>> {
        let ptr = ::core::ptr::null_mut();
        let len = usize::from(len) * size_of::<BufRingEntry>();
        let prot = ::rustix::mm::ProtFlags::READ | ::rustix::mm::ProtFlags::WRITE;
        let flags = ::rustix::mm::MapFlags::PRIVATE;
        // SAFETY: `ptr` is null.
        let ptr = unsafe { ::rustix::mm::mmap_anonymous(ptr, len, prot, flags) }?;
        // SAFETY: `ptr` is checked as non-null via rustix.
        let ptr = unsafe { NonNull::new_unchecked(ptr.cast::<BufRingEntry>()) };
        Ok(ptr)
    }

    /// Creates the [`AtomicU16`] reference for the tail field.
    ///
    /// SAFETY: Caller must ensure the resulting reference does not outlive the
    /// `BufRingEntry` it is associated with.
    ///
    /// NOTE: This function is carefully constructed to pass Miri's checks
    /// involving stacked-borrows.
    ///
    /// A naive implementation such as [`BufRingEntry::tail`] will cause Miri to
    /// complain for multiple reasons:
    ///
    /// ```ignore
    /// pub unsafe fn BufRingEntry::tail(ring_base: *const BufRingEntry) -> *const u16 {
    ///     core::ptr::addr_of!(
    ///         (*ring_base.cast::<sys::io_uring_buf_ring>())
    ///             .tail_or_bufs
    ///             .tail
    ///             .as_ref()
    ///             .tail
    ///     )
    /// }
    /// ```
    ///
    ///   1. The use of `addr_of!` is invalid for *mutable* access. Casting the
    ///      pointer to `*mut` and using it mutably violates the aliasing model.
    ///
    ///   2. The use of `.as_ref()` creates a temporary reference using
    ///      `transmute`, which assumes the union is initialized and tagged -- a
    ///      condition not satisfied, and which is UB under stacked-borrows.
    ///
    /// The solution below satisfies Miri with both the stacked-borrows model
    /// and the tree-borrows model by using pointer casts and avoiding the
    /// creation of invalid temporary references.
    unsafe fn make_tail(ptr: NonNull<BufRingEntry>) -> &'static AtomicU16 {
        let ring = ptr.as_ptr().cast::<rustix::io_uring::io_uring_buf_ring>();
        // SAFETY: Memory is valid for dereference due to `mmap_anonymous`.
        let tail = unsafe { &raw mut (*ring).tail_or_bufs.tail };
        let tail = tail.cast::<rustix::io_uring::buf_ring_tail_struct>();
        // SAFETY: Memory is valid for dereference due to `mmap_anonymous`
        let tail = unsafe { &raw mut (*tail).tail };
        // SAFETY: Memory is valid for atomic `u16` reads/writes.
        unsafe { AtomicU16::from_ptr(tail) }
    }

    /// Creates a new [`BufferRingRegion`].
    fn new(len: u16) -> crate::Result<Self> {
        let ptr = Self::make_mmap(len)?;
        // SAFETY: `tail` only accessible through `&self` restricted lifetime.
        let tail = unsafe { Self::make_tail(ptr) };
        Ok(Self { ptr, len, tail })
    }

    /// Returns a shared reference to the zeroed memory region.
    #[allow(clippy::needless_pass_by_ref_mut, reason = "returns ref mut")]
    fn as_slice_uninit_mut(&mut self) -> &mut [MaybeUninit<BufRingEntry>] {
        let data = self.ptr.as_ptr().cast::<MaybeUninit<BufRingEntry>>();
        let len = usize::from(self.len);
        // SAFETY:
        //   * `data` non-null
        //   * `data` aligned for `BufRingEntry` from `mmap_anonymous`
        //   * `data` valid for len contiguous `BufRingEntry` objects
        //   * `data` total size is within `isize::MAX` due to `mmap_anonymous`
        unsafe { ::core::slice::from_raw_parts_mut(data, len) }
    }

    /// Updates an entry in the buffer ring to refer to an available buffer.
    fn update_entry_with_buffer(
        &mut self,
        buf: &mut [MaybeUninit<u8>],
        bid: u16,
        len: u32,
        mask: u16,
        tail: u16,
        offset: u16,
    ) {
        let idx = usize::from((tail + offset) & mask);
        let buf_ring_slice = self.as_slice_uninit_mut();
        let buf_ring_entry = &mut buf_ring_slice[idx];
        // SAFETY: `buf_ring_entry` constructed from initialized `Buffer`.
        let buf_ring_entry = unsafe { buf_ring_entry.assume_init_mut() };
        let addr = buf.as_mut_ptr().cast::<::core::ffi::c_void>();
        buf_ring_entry.set_addr(addr);
        buf_ring_entry.set_len(len);
        buf_ring_entry.set_bid(bid);
    }

    /// Adds one buffer into the buffer ring for use by `io_uring`.
    fn add_buffer(&mut self, buf: &mut [MaybeUninit<u8>], bid: u16) {
        #[allow(clippy::unwrap_used, reason = "should panic")]
        let len = u32::try_from(buf.len()).unwrap();
        let mask = self.mask();
        let tail = self.tail().load(atomic::Ordering::Acquire);
        self.update_entry_with_buffer(buf, bid, len, mask, tail, 0);
        self.tail().fetch_add(1, atomic::Ordering::Release);
    }

    /// Adds many buffers into the buffer ring for use by `io_uring`.
    fn add_buffers<'ring, Bs>(&mut self, bufs: Bs, mut offset: u16)
    where
        Bs: Iterator<Item = &'ring mut Arc<[MaybeUninit<u8>]>> + ExactSizeIterator,
    {
        if bufs.len() == 0 {
            return;
        }
        let mask = self.mask();
        let tail = self.tail().load(atomic::Ordering::Acquire);
        for buf in bufs.filter_map(|arc| Arc::get_mut(arc)) {
            #[allow(clippy::unwrap_used, reason = "should panic")]
            let len = u32::try_from(buf.len()).unwrap();
            self.update_entry_with_buffer(buf, offset, len, mask, tail, offset);
            offset += 1;
        }
        self.tail().fetch_add(offset, atomic::Ordering::Release);
    }

    /// Returns the buffer ring region mask.
    const fn mask(&self) -> u16 {
        self.len - 1
    }

    /// Returns a shared reference to the buffer ring region tail.
    const fn tail(&self) -> &AtomicU16 {
        self.tail
    }

    /// Returns the size in bytes of the buffer region ring.
    fn size(&self) -> usize {
        usize::from(self.len) * size_of::<BufRingEntry>()
    }
}

/// A buffer ring for `io_uring` buffers.
///
/// This structure is the outer layer of the buffer ring API. See
/// [`BufferRingRegion`] for the inner layer of this API.
///
/// This layer manages ownership of underlying memory region for the buffer ring
/// entries alongside ownership of a boxed slice of the actual buffers which
/// will be used for IO.
///
/// [`BufferRing`] is also responsible for providing safe access to the buffers
/// in such a way that does not violate the standard memory model.
///
/// This is accomplished by requiring the user provide a previously generated
/// [`BufferRingToken`], in addition to the relevant CQE, when obtaining a
/// reference a buffer used by `io_uring` for the task completion.
///
/// Furthermore, shared access to buffers is tied to the lifetime of their
/// associated CQE, so as not to allow them to persist beyond the task
/// completion handling scope. This is not a strict requirement, and could be
/// lifted in the future if needed, but restricting scope in this way simplifies
/// reasoning about buffer usage.
///
/// Finally, access to buffers obtained through a token and CQE are reference
/// counted, and are recycled for re-use by future `io_uring` tasks when all
/// remaining references are dropped.
pub struct BufferRing {
    /// The buffer ring region, mediated through an [`UnsafeCell`] to avoid the
    /// need for exclusive mutable access to the buffer ring. Safety is
    /// maintained by disallowing general mutation and limiting the scope of
    /// references.
    mmap: UnsafeCell<BufferRingRegion>,
    /// The boxed slice of buffers used for task IO, mediated through an
    /// [`UnsafeCell`] to avoid the need for exclusive mutable access to the
    /// buffer ring. Safety is maintained by disallowing general mutation and
    /// limiting the scope of references.
    #[allow(clippy::type_complexity, reason = "simple")]
    bufs: UnsafeCell<Box<[Arc<[MaybeUninit<u8>]>]>>,
    /// The generation ID for a buffer. This is used as unique data for tokens.
    bufs_generation: u64,
    /// The buffer group ID for buffers in the ring.
    group: u16,
}

impl BufferRing {
    /// Creates a new [`BufferRing`].
    pub fn new<C, S>(uring: &IoUring<S, C>, buf_group: u16, ring_entries: u16, buf_size: usize) -> crate::Result<Self>
    where
        C: cqueue::EntryMarker,
        S: squeue::EntryMarker,
    {
        let ring_entries = usize::from(ring_entries);
        let bufs = ::core::iter::repeat_with(|| Arc::new_uninit_slice(buf_size)).take(ring_entries);
        Self::with_buffers(uring, buf_group, bufs)
    }
}

impl BufferRing {
    /// Creates a new [`BufferRing`] with provided buffers.
    fn with_buffers<S, C, Buffers>(ring: &IoUring<S, C>, buf_group: u16, bufs: Buffers) -> crate::Result<Self>
    where
        C: cqueue::EntryMarker,
        S: squeue::EntryMarker,
        Buffers: Iterator<Item = Arc<[MaybeUninit<u8>]>>,
    {
        let mut bufs = bufs.into_iter().collect::<Box<[_]>>();
        if bufs.is_empty() {
            let kind = ::std::io::ErrorKind::InvalidInput;
            return Err((::std::io::Error::new(kind, "empty buffers")).into());
        }
        let ring_entries = {
            let len = u16::try_from(bufs.len()).map_err(|_err| {
                let kind = ::std::io::ErrorKind::InvalidInput;
                let error = "buffer len larger than u16";
                ::std::io::Error::new(kind, error)
            })?;
            len.next_power_of_two()
        };
        let mut mmap = Self::create_buf_ring_region(ring, ring_entries, buf_group)?;
        mmap.add_buffers(bufs.iter_mut(), 0);
        let bufs_generation = BUFFER_TOKEN_GENERATION.fetch_add(1, atomic::Ordering::AcqRel);
        Ok(Self {
            mmap: UnsafeCell::new(mmap),
            bufs: UnsafeCell::new(bufs),
            bufs_generation,
            group: buf_group,
        })
    }

    /// Helper method for creating the [`BufferRingRegion`] backing the [`BufferRing`].
    fn create_buf_ring_region<S, C>(
        ring: &IoUring<S, C>,
        ring_entries: u16,
        buf_group: u16,
    ) -> crate::Result<BufferRingRegion>
    where
        C: cqueue::EntryMarker,
        S: squeue::EntryMarker,
    {
        let mut buf_ring_mmap = BufferRingRegion::new(ring_entries)?;
        let slice = buf_ring_mmap.as_slice_uninit_mut();
        let ring_addr = slice.as_mut_ptr().cast::<::core::ffi::c_void>();
        let submitter = ring.submitter();
        // SAFETY: `ring_addr` valid for `io_uring_buf_reg` for entire lifetime.
        unsafe { submitter.register_buf_ring(ring_addr, ring_entries, buf_group) }?;
        Ok(buf_ring_mmap)
    }

    /// Returns a mutable reference to the buffers in the ring.
    ///
    /// SAFETY:
    /// * The caller must ensure that the returned mutable reference is unique.
    /// * The caller must ensure mutations do not invalidate shared references.
    #[allow(clippy::mut_from_ref, reason = "UnsafeCell API")]
    unsafe fn bufs(&self) -> &mut Box<[Arc<[MaybeUninit<u8>]>]> {
        let ptr = self.bufs.get();
        // SAFETY: `ptr` is a valid non-null pointer.
        unsafe { &mut *ptr }
    }

    /// Returns the buffer in the ring associated with the task completion
    /// `cqe`. The provided `token` ensures that the buffer index used for
    /// lookup is tied to this buffer ring and not some other buffer ring.
    pub fn get_buf<'ring, 'cqe>(
        &'ring self,
        cqe: &'cqe cqueue::Entry,
        token: BufferRingToken,
    ) -> crate::Result<Option<BufferRef<'cqe>>>
    where
        'ring: 'cqe,
    {
        if token != self.token() {
            bail!("token invalid for buffer");
        }
        let len = cqe.result()?;
        let Some(bid) = cqueue::buffer_select(cqe.flags()) else {
            return Ok(None);
        };
        // SAFETY:
        unsafe { self.get_buf_from_raw_parts(bid, len) }
    }

    /// Returns a [`BufferRef`] given raw buffer data.
    ///
    /// SAFETY: Caller must ensure no existing [`BufferRef`] is held for `idx`.
    unsafe fn get_buf_from_raw_parts(&self, idx: u16, len: u32) -> crate::Result<Option<BufferRef<'_>>> {
        let len = usize::try_from(len)?;
        // SAFETY: mutable ref restricts to specific buf.
        let bufs = unsafe { self.bufs() };
        let Some(buf) = bufs.get_mut(usize::from(idx)).cloned() else {
            bail!("index out of range for buffer");
        };
        let buf_len = buf.len();
        if len > buf_len {
            bail!("subslice too large for buffer");
        }
        let pin = BufferRef {
            ring: self,
            idx,
            buf,
            len,
        };
        Ok(Some(pin))
    }

    /// Return buffer group ID for this buffer ring.
    pub const fn group(&self) -> u16 {
        self.group
    }

    /// Returns a mutable reference to the [`BufferRingRegion`].
    ///
    /// SAFETY:
    /// * The caller must ensure that the returned mutable reference is unique.
    /// * The caller must ensure mutations do not invalidate shared references.
    #[allow(clippy::mut_from_ref, reason = "UnsafeCell API")]
    unsafe fn mmap(&self) -> &mut BufferRingRegion {
        let ptr = self.mmap.get();
        // SAFETY: `ptr` is a valid non-null pointer.
        unsafe { &mut *ptr }
    }

    /// Generate a token for this buffer ring.
    pub fn token(&self) -> BufferRingToken {
        let addr = self.bufs.get().addr();
        let generation = self.bufs_generation;
        BufferRingToken { addr, generation }
    }
}

/// A token associating a task completion involving a buffer to a particular
/// buffer ring.
///
/// This structure is used as a check to ensure that incorrect buffer rings are
/// not accidentally used by clients.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BufferRingToken {
    /// The address of the boxed slice of buffers.
    addr: usize,
    /// The buffer ring generation. Used as an extra source of uniqueness in
    /// case somehow addresses are re-used.
    generation: u64,
}

/// A reference to a buffer from a buffer ring.
///
/// This structure is reference counted and once all references (aside from the
/// original that owns the buffer in the ring) have been dropped, the buffer is
/// scheduled for re-use by future `io_uring` task completions.
#[derive(Clone)]
pub struct BufferRef<'ring> {
    /// The ring that owns the buffer.
    ring: &'ring BufferRing,
    /// The index of the buffer in the buffer slice.
    idx: u16,
    /// The reference counted pointer to the buffer.
    buf: Arc<[MaybeUninit<u8>]>,
    /// The current data-valid length of the buffer.
    len: usize,
}

impl Drop for BufferRef<'_> {
    fn drop(&mut self) {
        // SAFETY: we only modify the buffer for which we have exclusive access
        let bufs = unsafe { self.ring.bufs() };
        // fetch the buffer from the ring
        let Some(buf) = bufs.get_mut(usize::from(self.idx)) else {
            return;
        };
        // drop the local buffer to decrement the ref-count
        self.buf = Arc::new_uninit_slice(0);
        // obtain exclusive mutable access to the buffer
        let Some(buf) = Arc::get_mut(buf) else {
            return;
        };
        // SAFETY: we only modify the entry for the exclusively accessed buffer
        let mmap = unsafe { self.ring.mmap() };
        mmap.add_buffer(buf, self.idx);
    }
}

impl Deref for BufferRef<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let ptr = self.buf.as_ptr();
        // SAFETY:
        unsafe { ::core::slice::from_raw_parts(ptr.cast(), self.len) }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::as_conversions, reason = "test")]
    #![allow(clippy::unwrap_used, reason = "test")]
    #![allow(unused_imports, reason = "test")]

    use super::*;

    mod harness {
        use super::*;

        pub mod buffer {}

        pub mod buffer_ring_region {
            use super::*;

            pub fn new<const N: u16>() -> BufferRingRegion {
                BufferRingRegion::new(N).unwrap()
            }
        }

        pub mod io_uring {
            use super::*;

            pub fn new() -> IoUring<squeue::Entry, cqueue::Entry> {
                IoUring::new(1024).unwrap()
            }
        }
    }

    mod buffer_ring_region {
        use super::*;

        const LEN: u16 = 32;

        #[test]
        fn new() {
            // create ring
            let mmap = self::harness::buffer_ring_region::new::<LEN>();
            // check that mmap len is correct
            assert_eq!(LEN, mmap.len);
        }

        #[test]
        fn as_slice_uninit_mut() {
            // create ring
            let mut mmap = self::harness::buffer_ring_region::new::<LEN>();
            // create local buffers
            let mut bufs = ::core::iter::repeat_with(|| Arc::new_uninit_slice(68))
                .take(usize::from(LEN))
                .collect::<Box<[_]>>();
            // add buffers to ring
            mmap.add_buffers(bufs.iter_mut(), 0);
            let slice = mmap.as_slice_uninit_mut();
            // check that slice of mmap has the correct length
            assert_eq!(usize::from(LEN), slice.len());
        }

        #[test]
        fn add_buffer() {
            // create ring
            let mut mmap = self::harness::buffer_ring_region::new::<1>();
            // create local buffers
            let mut buf = Box::new_uninit_slice(68);
            // add buffers to ring
            mmap.add_buffer(&mut buf, 0);
            let slice = mmap.as_slice_uninit_mut();
            // check that buffers added to ring have the correct structure
            for (i, buf) in (0..u16::MAX).zip(slice) {
                // SAFETY: `buf` already initialized.
                let buf = unsafe { buf.assume_init_ref() };
                // check that buffers in the ring have the correct bid
                assert_eq!(i, buf.bid());
            }
        }

        #[test]
        fn add_buffers() {
            // create ring
            let mut mmap = self::harness::buffer_ring_region::new::<LEN>();
            // create local buffers
            let mut bufs = ::core::iter::repeat_with(|| Arc::new_uninit_slice(68))
                .take(usize::from(LEN))
                .collect::<Box<[_]>>();
            // add buffers to ring
            mmap.add_buffers(bufs.iter_mut(), 0);
            let slice = mmap.as_slice_uninit_mut();
            // check that buffers added to ring have the correct structure
            for (i, buf) in (0..u16::MAX).zip(slice) {
                // SAFETY: `buf` already initialized
                let buf = unsafe { buf.assume_init_ref() };
                // check that buffers in the ring have the correct bid
                assert_eq!(i, buf.bid());
            }
        }

        #[test]
        fn mask() {
            // create ring
            let mmap = self::harness::buffer_ring_region::new::<LEN>();
            // check that mask equals len-1
            assert_eq!(mmap.len - 1, mmap.mask());
        }

        #[test]
        fn tail() {
            // create ring
            let mmap = self::harness::buffer_ring_region::new::<LEN>();
            // check that mmap tail is correct
            assert_eq!(0, mmap.tail().load(atomic::Ordering::Relaxed));
        }

        #[test]
        fn size() {
            // create ring
            let mmap = self::harness::buffer_ring_region::new::<LEN>();
            // check that size is correct
            assert_eq!(usize::from(mmap.len) * size_of::<BufRingEntry>(), mmap.size());
        }
    }

    mod io_uring_buf_ring {
        use super::*;

        // NOTE: This test is disabled for Miri because Miri doesn't understand
        // the syscall that creates the `io_uring`.
        #[test]
        #[cfg_attr(miri, ignore)]
        fn new() {
            let uring = self::harness::io_uring::new();
            let buf_group = 0xcafeu16;
            let bufs = ::core::iter::repeat_with(|| Arc::new_uninit_slice(68)).take(32);
            let buf_ring = BufferRing::with_buffers(&uring, buf_group, bufs).unwrap();

            // SAFETY: no mutations
            let mmap = unsafe { buf_ring.mmap() };
            // check mmap has correct len
            assert_eq!(32u16, mmap.len);
            // check mmap tail correctly set
            assert_eq!(32u16, mmap.tail().load(atomic::Ordering::Relaxed));

            // SAFETY: no mutations
            let bufs = unsafe { buf_ring.bufs() };
            // check bufs has correct len
            assert_eq!(usize::from(32u16), bufs.len());

            // check group correctly set
            assert_eq!(0xcafeu16, buf_ring.group);
        }
    }
}
