//! XOR-checksummed persistent blocks built on top of [`bstack`](https://docs.rs/bstack).
//!
//! # Overview
//!
//! This module provides XOR-based variants of all [`crate::crc`] types.
//! The checksum is a 4-byte value where each byte is the XOR of every fourth
//! data byte starting at that position (i.e. `cs[i % 4] ^= data[i]`).
//!
//! The main types:
//!
//! | Type                   | Role                                                               |
//! |------------------------|--------------------------------------------------------------------|
//! | [`BXorBlockAllocator`] | Wraps a `BStackAllocator`; produces [`BXorBlock`]s                 |
//! | [`BXorBlock`]          | Checksummed block handle; source of views, readers, and writers    |
//! | [`BXorBlockView`]      | Safe read/write window with `subview` support                      |
//! | [`BXorBlockReader`]    | Cursor-based `io::Read + io::Seek` over a view's data              |
//! | [`BXorBlockWriter`]    | Cursor-based `io::Write + io::Seek` that maintains the checksum    |
//!
//! # Write efficiency
//!
//! Unlike CRC32, XOR checksums can be updated **incrementally**: to update
//! the checksum after writing N bytes, only those N bytes (before and after
//! the write) need to be read — not the full block. For large blocks with
//! many small writes this can be orders of magnitude fewer I/O operations
//! than a full-block CRC32 recomputation.
//!
//! # Weaker integrity guarantee
//!
//! XOR detects single-bit flips in the data, but not all multi-byte errors.
//! For example, swapping two bytes at the same position-modulo-4 leaves the
//! XOR checksum unchanged. Use [`crate::crc`] when detection strength matters
//! more than write throughput.
//!
//! # Composability
//!
//! [`BXorBlockAllocator`] itself implements [`bstack::BStackAllocator`] with
//! `Allocated<'_> = BXorBlock<'_, BXorBlockAllocator<A>>`, so it can be used
//! as the inner allocator for another wrapper layer.
//!
//! # bstack `guarded` feature
//!
//! [`BXorBlock`] and [`BXorBlockView`] implement [`bstack::BStackGuardedSlice`]
//! (requires the bstack `guarded` feature, enabled by default in this crate).
//! `as_slice()` exposes only the data region (for views, the view's
//! sub-range). Both `write()` and `zero()` update the XOR checksum
//! **incrementally** — only the bytes that change are re-read from storage.
//! [`BXorBlockView`] additionally implements
//! [`bstack::BStackGuardedSliceSubview`], enabling its use in generic
//! guarded-I/O contexts.
//!
//! `len()` and `is_empty()` on [`BXorBlock`], and `len()`, `is_empty()`,
//! `read()`, `write()`, and `zero()` on [`BXorBlockView`] are provided by the
//! trait — callers must `use bstack::BStackGuardedSlice`.

use crate::{BStackRawAllocator, BlockStart};
use bstack::{
    BStack, BStackAllocator, BStackGuardedSlice, BStackGuardedSliceSubview, BStackSlice,
    BStackSliceReader, BStackSliceWriter,
};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;

/// Number of bytes appended to every allocation for the XOR checksum.
pub const CHECKSUM_LENGTH: u64 = 4;

/// Compute the 4-byte XOR checksum of `data`.
///
/// `cs[i % 4] ^= data[i]` for all `i`.
fn xor_checksum(data: &[u8]) -> u32 {
    let mut cs = [0u8; 4];
    for (i, &b) in data.iter().enumerate() {
        cs[i % 4] ^= b;
    }
    u32::from_le_bytes(cs)
}

/// Generic wrapper over any [`BStackAllocator`] that transparently appends a
/// 4-byte XOR checksum to every allocation.
///
/// `BXorBlockAllocator<A>` mirrors the allocation interface of the inner `A`
/// but returns [`BXorBlock`]s instead of raw [`BStackSlice`]s. Each block has
/// `CHECKSUM_LENGTH` (4) extra bytes appended, so `alloc(n)` allocates `n + 4`
/// bytes in the underlying stack.
///
/// ## `BStackAllocator` impl
///
/// `BXorBlockAllocator<A>` itself implements [`BStackAllocator`] with
/// `Allocated<'_> = BXorBlock<'_, BXorBlockAllocator<A>>`. This means it can
/// be used as the inner allocator for another wrapper, allowing checksum layers
/// to be stacked.
pub struct BXorBlockAllocator<A: BStackAllocator> {
    inner: A,
}

impl<A: BStackAllocator> BXorBlockAllocator<A> {
    /// Create a new `BXorBlockAllocator` wrapping `inner`.
    pub fn new(inner: A) -> Self {
        Self { inner }
    }

    /// Return a shared reference to the inner allocator.
    pub fn inner(&self) -> &A {
        &self.inner
    }

    /// Consume the wrapper and return the inner allocator.
    pub fn into_inner(self) -> A {
        self.inner
    }
}

/// A handle to an XOR-checksummed block allocated by a [`BXorBlockAllocator`].
///
/// **Backing layout:** `[data: len bytes][xor: 4 bytes LE]`
///
/// `BXorBlock` is `Copy`: every copy refers to the same physical region.
///
/// ## `BStackGuardedSlice`
///
/// `BXorBlock` implements [`bstack::BStackGuardedSlice`] (requires the bstack
/// `guarded` feature, enabled by default in this crate). `as_slice()` returns
/// only the data region. `write()` and `zero()` update the XOR checksum
/// **incrementally**: only the bytes that change are re-read, preserving the
/// efficiency advantage of the XOR scheme over CRC32. `len()` and `is_empty()`
/// are provided by this trait; callers must `use bstack::BStackGuardedSlice`.
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BXorBlock<'a, A: BStackAllocator> {
    slice: BStackSlice<'a, A>,
    len: u64,
}

impl<'a, A: BStackAllocator> Copy for BXorBlock<'a, A> {}

impl<'a, A: BStackAllocator> Clone for BXorBlock<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, A: BStackAllocator> BXorBlock<'a, A> {
    /// Serialize this block reference as a 16-byte array.
    ///
    /// The format is `[offset: u64 LE | usable_len: u64 LE]`. Reconstruct
    /// with [`BXorBlock::from_bytes`].
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.slice.start().to_le_bytes());
        out[8..].copy_from_slice(&self.len.to_le_bytes());
        out
    }

    /// Reconstruct a block reference from a 16-byte array produced by
    /// [`BXorBlock::to_bytes`].
    pub fn from_bytes(allocator: &'a A, bytes: [u8; 16]) -> Self {
        let offset = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let len = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        BXorBlock {
            slice: unsafe { BStackSlice::from_raw_parts(allocator, offset, len + CHECKSUM_LENGTH) },
            len,
        }
    }

    /// Read the stored XOR checksum from the backing store.
    pub fn checksum(&self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        unsafe { self.checksum_slice() }.read_into(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Return `true` if the stored checksum matches a freshly computed XOR
    /// of the current data bytes.
    pub fn verify(&self) -> io::Result<bool> {
        let data = unsafe { self.data_slice() }.read()?;
        let stored = self.checksum()?;
        Ok(xor_checksum(&data) == stored)
    }

    /// Return a [`BXorBlockView`] covering the full usable data region.
    pub fn view(&self) -> BXorBlockView<'a, A> {
        BXorBlockView {
            slice: self.slice,
            full_len: self.len,
            start: 0,
            end: self.len,
        }
    }

    /// Return a cursor-based reader positioned at the start of the usable data.
    pub fn reader(&self) -> BXorBlockReader<'a, A> {
        BXorBlockReader {
            inner: unsafe { self.data_slice() }.reader(),
        }
    }

    /// Return a cursor-based reader positioned at `offset` within the usable data.
    pub fn reader_at(&self, offset: u64) -> BXorBlockReader<'a, A> {
        BXorBlockReader {
            inner: unsafe { self.data_slice() }.reader_at(offset),
        }
    }

    /// Return a cursor-based writer positioned at the start of the usable data.
    ///
    /// Every write through the returned [`BXorBlockWriter`] updates the XOR
    /// checksum incrementally — only the changed bytes are re-read.
    pub fn writer(&self) -> BXorBlockWriter<'a, A> {
        let full_data = unsafe { self.data_slice() };
        BXorBlockWriter {
            inner: full_data.writer(),
            full_data,
            checksum: unsafe { self.checksum_slice() },
        }
    }

    /// Return a cursor-based writer positioned at `offset` within the usable data.
    ///
    /// Every write through the returned [`BXorBlockWriter`] updates the XOR
    /// checksum incrementally — only the changed bytes are re-read.
    pub fn writer_at(&self, offset: u64) -> BXorBlockWriter<'a, A> {
        let full_data = unsafe { self.data_slice() };
        BXorBlockWriter {
            inner: full_data.writer_at(offset),
            full_data,
            checksum: unsafe { self.checksum_slice() },
        }
    }

    /// Consume the block and return the raw underlying [`BStackSlice`].
    ///
    /// # Safety
    ///
    /// Any mutation of the returned slice bypasses checksum tracking.
    pub unsafe fn into_slice(self) -> BStackSlice<'a, A> {
        self.slice
    }

    unsafe fn data_slice(&self) -> BStackSlice<'a, A> {
        self.slice.subslice(0, self.len)
    }

    unsafe fn checksum_slice(&self) -> BStackSlice<'a, A> {
        self.slice.subslice(self.len, self.len + CHECKSUM_LENGTH)
    }
}

/// A safe read/write window into a sub-range of a [`BXorBlock`]'s usable data.
///
/// Writes update the XOR checksum **incrementally** — only the bytes being
/// changed are read, making small writes to large blocks efficient.
///
/// Like [`crate::crc::BCrcBlockView`], all writes and `verify()` operate on the
/// **full block checksum**, even through a narrow sub-view.
///
/// ## `BStackGuardedSlice` and `BStackGuardedSliceSubview`
///
/// `BXorBlockView` implements [`bstack::BStackGuardedSlice`]: `as_slice()`
/// returns the bytes covered by this view; `write()` and `zero()` update the
/// XOR checksum incrementally. `len()`, `is_empty()`, `read()`, `write()`,
/// and `zero()` are provided by this trait; callers must
/// `use bstack::BStackGuardedSlice`.
///
/// `BXorBlockView` also implements [`bstack::BStackGuardedSliceSubview`],
/// enabling its use where a `T: BStackGuardedSliceSubview` bound is required.
/// The inherent [`subview`](BXorBlockView::subview) method returns the
/// concrete `BXorBlockView` type and is preferred for direct calls.
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BXorBlockView<'a, A: BStackAllocator> {
    slice: BStackSlice<'a, A>,
    full_len: u64,
    start: u64,
    end: u64,
}

impl<'a, A: BStackAllocator> Copy for BXorBlockView<'a, A> {}

impl<'a, A: BStackAllocator> Clone for BXorBlockView<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, A: BStackAllocator> From<BXorBlock<'a, A>> for [u8; 16] {
    fn from(block: BXorBlock<'a, A>) -> [u8; 16] {
        block.to_bytes()
    }
}

impl<'a, A: BStackAllocator> BXorBlockView<'a, A> {
    /// Create a full-block view from an existing [`BXorBlock`].
    pub fn new(block: &BXorBlock<'a, A>) -> Self {
        Self {
            slice: block.slice,
            full_len: block.len,
            start: 0,
            end: block.len,
        }
    }

    /// Return a view covering `[start, end)` within this view's coordinate space.
    pub fn subview(&self, start: u64, end: u64) -> Self {
        BXorBlockView {
            slice: self.slice,
            full_len: self.full_len,
            start: self.start + start,
            end: self.start + end,
        }
    }

    /// Read all bytes in this view into `buf`.
    pub fn read_into(&self, buf: &mut [u8]) -> io::Result<()> {
        unsafe { self.data_slice() }.read_into(buf)
    }

    /// Read bytes starting at `start` within this view into `buf`.
    pub fn read_range_into(&self, start: u64, buf: &mut [u8]) -> io::Result<()> {
        unsafe { self.data_slice() }.read_range_into(start, buf)
    }

    /// Read the stored XOR checksum of the containing block.
    pub fn checksum(&self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        unsafe { self.checksum_slice() }.read_into(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Return `true` if the containing block's stored checksum matches its
    /// current full data.
    ///
    /// This always verifies the **full block**, regardless of whether this is
    /// a subview.
    pub fn verify(&self) -> io::Result<bool> {
        let data = unsafe { self.full_data_slice() }.read()?;
        let stored = self.checksum()?;
        Ok(xor_checksum(&data) == stored)
    }

    /// Overwrite bytes starting at `start` within this view and update the
    /// checksum.
    ///
    /// Only `data.len()` bytes are read from disk, not the full block.
    pub fn write_range(&self, start: u64, data: &[u8]) -> io::Result<()> {
        let block_offset = self.start + start;
        let n = data.len() as u64;
        let old = self.slice.subslice(block_offset, block_offset + n).read()?;
        unsafe { self.data_slice() }.write_range(start, data)?;
        self.update_checksum_delta(block_offset, &old, data)
    }

    /// Zero `n` bytes starting at `start` within this view and update the
    /// checksum.
    pub fn zero_range(&self, start: u64, n: u64) -> io::Result<()> {
        let block_offset = self.start + start;
        let old = self.slice.subslice(block_offset, block_offset + n).read()?;
        unsafe { self.data_slice() }.zero_range(start, n)?;
        self.xor_out_bytes(block_offset, &old)
    }

    /// Return a cursor-based reader positioned at the start of this view.
    pub fn reader(&self) -> BXorBlockReader<'a, A> {
        BXorBlockReader {
            inner: unsafe { self.data_slice() }.reader(),
        }
    }

    /// Return a cursor-based reader positioned at `offset` within this view.
    pub fn reader_at(&self, offset: u64) -> BXorBlockReader<'a, A> {
        BXorBlockReader {
            inner: unsafe { self.data_slice() }.reader_at(offset),
        }
    }

    /// Return a cursor-based writer positioned at the start of this view.
    ///
    /// Every write updates the XOR checksum incrementally.
    pub fn writer(&self) -> BXorBlockWriter<'a, A> {
        BXorBlockWriter {
            inner: unsafe { self.data_slice() }.writer(),
            full_data: unsafe { self.full_data_slice() },
            checksum: unsafe { self.checksum_slice() },
        }
    }

    /// Return a cursor-based writer positioned at `offset` within this view.
    ///
    /// Every write updates the XOR checksum incrementally.
    pub fn writer_at(&self, offset: u64) -> BXorBlockWriter<'a, A> {
        BXorBlockWriter {
            inner: unsafe { self.data_slice() }.writer_at(offset),
            full_data: unsafe { self.full_data_slice() },
            checksum: unsafe { self.checksum_slice() },
        }
    }

    unsafe fn data_slice(&self) -> BStackSlice<'a, A> {
        self.slice.subslice(self.start, self.end)
    }

    unsafe fn full_data_slice(&self) -> BStackSlice<'a, A> {
        self.slice.subslice(0, self.full_len)
    }

    unsafe fn checksum_slice(&self) -> BStackSlice<'a, A> {
        self.slice
            .subslice(self.full_len, self.full_len + CHECKSUM_LENGTH)
    }

    /// Incrementally update checksum: XOR out `old`, XOR in `new`.
    fn update_checksum_delta(&self, block_offset: u64, old: &[u8], new: &[u8]) -> io::Result<()> {
        let n = old.len().min(new.len());
        let mut cs = [0u8; 4];
        unsafe { self.checksum_slice() }.read_into(&mut cs)?;
        for i in 0..n {
            cs[(block_offset as usize + i) % 4] ^= old[i] ^ new[i];
        }
        unsafe { self.checksum_slice() }.write(cs)
    }

    /// Incrementally update checksum: XOR out `old` bytes (new bytes are zero).
    fn xor_out_bytes(&self, block_offset: u64, old: &[u8]) -> io::Result<()> {
        let mut cs = [0u8; 4];
        unsafe { self.checksum_slice() }.read_into(&mut cs)?;
        for (i, &b) in old.iter().enumerate() {
            cs[(block_offset as usize + i) % 4] ^= b;
        }
        unsafe { self.checksum_slice() }.write(cs)
    }
}

/// A cursor-based reader over the bytes covered by a [`BXorBlockView`].
///
/// Implements [`io::Read`] and [`io::Seek`]. Constructed via
/// [`BXorBlock::reader`], [`BXorBlock::reader_at`], [`BXorBlockView::reader`],
/// or [`BXorBlockView::reader_at`].
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BXorBlockReader<'a, A: BStackAllocator> {
    inner: BStackSliceReader<'a, A>,
}

impl<'a, A: BStackAllocator> fmt::Debug for BXorBlockReader<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BXorBlockReader")
            .field("start", &self.inner.slice().start())
            .field("end", &self.inner.slice().end())
            .field("len", &self.inner.slice().len())
            .field("cursor", &self.inner.position())
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> BXorBlockReader<'a, A> {
    /// Return the current cursor position within the view's coordinate space.
    pub fn position(&self) -> u64 {
        self.inner.position()
    }
}

impl<'a, A: BStackAllocator> PartialEq<BXorBlockWriter<'a, A>> for BXorBlockReader<'a, A> {
    fn eq(&self, other: &BXorBlockWriter<'a, A>) -> bool {
        self.inner.slice() == other.inner.slice() && self.inner.position() == other.inner.position()
    }
}

impl<'a, A: BStackAllocator> PartialOrd<BXorBlockWriter<'a, A>> for BXorBlockReader<'a, A> {
    fn partial_cmp(&self, other: &BXorBlockWriter<'a, A>) -> Option<Ordering> {
        let self_pos = self.inner.slice().start() + self.inner.position();
        let other_pos = other.inner.slice().start() + other.inner.position();
        Some(
            self_pos
                .cmp(&other_pos)
                .then(self.inner.slice().len().cmp(&other.inner.slice().len())),
        )
    }
}

impl<'a, A: BStackAllocator> io::Read for BXorBlockReader<'a, A> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<'a, A: BStackAllocator> io::Seek for BXorBlockReader<'a, A> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// A cursor-based writer over the bytes covered by a [`BXorBlockView`].
///
/// Implements [`io::Write`] and [`io::Seek`]. Every write updates the XOR
/// checksum **incrementally** — only the bytes being overwritten are re-read,
/// not the full block. Constructed via [`BXorBlock::writer`],
/// [`BXorBlock::writer_at`], [`BXorBlockView::writer`], or [`BXorBlockView::writer_at`].
#[derive(Clone)]
pub struct BXorBlockWriter<'a, A: BStackAllocator> {
    inner: BStackSliceWriter<'a, A>,
    /// Full block data region — needed to compute view-relative block offsets.
    full_data: BStackSlice<'a, A>,
    checksum: BStackSlice<'a, A>,
}

impl<'a, A: BStackAllocator> fmt::Debug for BXorBlockWriter<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BXorBlockWriter")
            .field("start", &self.inner.slice().start())
            .field("end", &self.inner.slice().end())
            .field("len", &self.inner.slice().len())
            .field("cursor", &self.inner.position())
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> BXorBlockWriter<'a, A> {
    /// Return the current cursor position within the view's coordinate space.
    pub fn position(&self) -> u64 {
        self.inner.position()
    }
}

impl<'a, A: BStackAllocator> PartialEq for BXorBlockWriter<'a, A> {
    fn eq(&self, other: &Self) -> bool {
        self.inner.slice() == other.inner.slice() && self.inner.position() == other.inner.position()
    }
}

impl<'a, A: BStackAllocator> Eq for BXorBlockWriter<'a, A> {}

impl<'a, A: BStackAllocator> Hash for BXorBlockWriter<'a, A> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.slice().hash(state);
        self.inner.position().hash(state);
    }
}

impl<'a, A: BStackAllocator> PartialOrd for BXorBlockWriter<'a, A> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a, A: BStackAllocator> Ord for BXorBlockWriter<'a, A> {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_pos = self.inner.slice().start() + self.inner.position();
        let other_pos = other.inner.slice().start() + other.inner.position();
        self_pos
            .cmp(&other_pos)
            .then(self.inner.slice().len().cmp(&other.inner.slice().len()))
    }
}

impl<'a, A: BStackAllocator> PartialEq<BXorBlockReader<'a, A>> for BXorBlockWriter<'a, A> {
    fn eq(&self, other: &BXorBlockReader<'a, A>) -> bool {
        other == self
    }
}

impl<'a, A: BStackAllocator> PartialOrd<BXorBlockReader<'a, A>> for BXorBlockWriter<'a, A> {
    fn partial_cmp(&self, other: &BXorBlockReader<'a, A>) -> Option<Ordering> {
        other.partial_cmp(self).map(|o| o.reverse())
    }
}

impl<'a, A: BStackAllocator> io::Write for BXorBlockWriter<'a, A> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Block-relative offset of the current write position.
        let block_offset =
            self.inner.slice().start() - self.full_data.start() + self.inner.position();
        let remaining = self
            .inner
            .slice()
            .len()
            .saturating_sub(self.inner.position()) as usize;
        let n = buf.len().min(remaining);
        if n == 0 {
            return Ok(0);
        }

        // Read old bytes before overwriting so we can XOR them out.
        let mut old = vec![0u8; n];
        self.full_data.read_range_into(block_offset, &mut old)?;

        let written = self.inner.write(&buf[..n])?;

        if written > 0 {
            let mut cs = [0u8; 4];
            self.checksum.read_into(&mut cs)?;
            for i in 0..written {
                cs[(block_offset as usize + i) % 4] ^= old[i] ^ buf[i];
            }
            self.checksum.write(cs)?;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, A: BStackAllocator> io::Seek for BXorBlockWriter<'a, A> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Implements [`BStackAllocator`] for [`BXorBlockAllocator`], exposing it as
/// a composable allocator layer.
///
/// `Allocated<'_>` is `BXorBlock<'_, BXorBlockAllocator<A>>`. Inner allocated
/// handles are reconstructed via `BStackRawAllocator::from_raw` for
/// `realloc` and `dealloc`, so no back-conversion from offset alone is needed.
impl<A> BStackAllocator for BXorBlockAllocator<A>
where
    A: BStackAllocator<Error = io::Error> + BStackRawAllocator,
    for<'a> A::Allocated<'a>: BlockStart + Copy,
{
    type Error = io::Error;
    type Allocated<'a>
        = BXorBlock<'a, BXorBlockAllocator<A>>
    where
        A: 'a;

    fn stack(&self) -> &BStack {
        self.inner.stack()
    }

    fn into_stack(self) -> BStack {
        self.inner.into_stack()
    }

    fn alloc(&self, len: u64) -> io::Result<BXorBlock<'_, BXorBlockAllocator<A>>> {
        let inner = self.inner.alloc(len + CHECKSUM_LENGTH)?;
        let offset = inner.block_start();
        let slice = unsafe { BStackSlice::from_raw_parts(self, offset, len + CHECKSUM_LENGTH) };
        Ok(BXorBlock { slice, len })
    }

    fn realloc<'a>(
        &'a self,
        block: BXorBlock<'a, BXorBlockAllocator<A>>,
        new_len: u64,
    ) -> io::Result<BXorBlock<'a, BXorBlockAllocator<A>>> {
        let offset = block.slice.start();
        let inner_old_slice = unsafe {
            BStackSlice::from_raw_parts(&self.inner, offset, block.len + CHECKSUM_LENGTH)
        };
        let inner_old: A::Allocated<'_> = unsafe { A::from_raw(inner_old_slice) };
        let inner_new = self.inner.realloc(inner_old, new_len + CHECKSUM_LENGTH)?;
        let new_offset = inner_new.block_start();
        let slice =
            unsafe { BStackSlice::from_raw_parts(self, new_offset, new_len + CHECKSUM_LENGTH) };
        Ok(BXorBlock {
            slice,
            len: new_len,
        })
    }

    fn dealloc(&self, block: BXorBlock<'_, BXorBlockAllocator<A>>) -> io::Result<()> {
        let offset = block.slice.start();
        let inner_slice = unsafe {
            BStackSlice::from_raw_parts(&self.inner, offset, block.len + CHECKSUM_LENGTH)
        };
        let inner: A::Allocated<'_> = unsafe { A::from_raw(inner_slice) };
        self.inner.dealloc(inner)
    }
}

/// Satisfies the `Allocated<'a>: TryInto<BStackSlice<'a, Self>>` bound
/// required by [`BStackAllocator`]. The conversion is infallible: the raw
/// backing slice is returned as-is.
impl<'a, A> TryInto<BStackSlice<'a, BXorBlockAllocator<A>>> for BXorBlock<'a, BXorBlockAllocator<A>>
where
    A: BStackAllocator<Error = io::Error> + BStackRawAllocator,
    for<'b> A::Allocated<'b>: BlockStart + Copy,
{
    type Error = std::convert::Infallible;

    fn try_into(self) -> Result<BStackSlice<'a, BXorBlockAllocator<A>>, Self::Error> {
        Ok(self.slice)
    }
}

impl<'a, A: BStackAllocator> BlockStart for BXorBlock<'a, A> {
    fn block_start(&self) -> u64 {
        self.slice.start()
    }
}

unsafe impl<A> BStackRawAllocator for BXorBlockAllocator<A>
where
    A: BStackAllocator<Error = io::Error> + BStackRawAllocator,
    for<'a> A::Allocated<'a>: BlockStart + Copy,
{
    unsafe fn from_raw<'a>(
        slice: BStackSlice<'a, BXorBlockAllocator<A>>,
    ) -> BXorBlock<'a, BXorBlockAllocator<A>> {
        let len = slice.len() - CHECKSUM_LENGTH;
        BXorBlock { slice, len }
    }
}

/// Implements [`BStackGuardedSlice`] for [`BXorBlock`].
///
/// * `as_slice()` returns the data region only (excludes the 4-byte checksum
///   trailer), so callers read and write only usable payload bytes.
/// * `write()` reads the bytes about to be overwritten, writes the new data,
///   then updates the checksum via `cs[i % 4] ^= old[i] ^ new[i]` — only the
///   written range is touched.
/// * `zero()` reads the current data, zeroes the region, then XORs each old
///   byte out of the checksum. Both operations are incremental and avoid
///   reading the full block.
impl<'a, A: BStackAllocator + 'a> BStackGuardedSlice<'a, A> for BXorBlock<'a, A> {
    fn len(&self) -> u64 {
        self.len
    }

    unsafe fn raw_block(&self) -> BStackSlice<'a, A> {
        self.slice
    }

    fn as_slice(&self) -> io::Result<BStackSlice<'a, A>> {
        Ok(unsafe { self.data_slice() })
    }

    fn write(&self, data: impl AsRef<[u8]>) -> io::Result<()> {
        let data = data.as_ref();
        let n = (data.len() as u64).min(self.len) as usize;
        let mut old = vec![0u8; n];
        unsafe { self.data_slice() }.read_range_into(0, &mut old)?;
        unsafe { self.data_slice() }.write(data)?;
        let mut cs = [0u8; 4];
        unsafe { self.checksum_slice() }.read_into(&mut cs)?;
        for i in 0..n {
            cs[i % 4] ^= old[i] ^ data[i];
        }
        unsafe { self.checksum_slice() }.write(cs)
    }

    fn zero(&self) -> io::Result<()> {
        let old = unsafe { self.data_slice() }.read()?;
        unsafe { self.data_slice() }.zero()?;
        let mut cs = [0u8; 4];
        unsafe { self.checksum_slice() }.read_into(&mut cs)?;
        for (i, &b) in old.iter().enumerate() {
            cs[i % 4] ^= b;
        }
        unsafe { self.checksum_slice() }.write(cs)
    }
}

impl<'a, A: BStackAllocator + 'a> BStackGuardedSliceSubview<'a, A> for BXorBlockView<'a, A> {
    fn subview(&self, start: u64, end: u64) -> impl BStackGuardedSliceSubview<'a, A> + '_ {
        BXorBlockView {
            slice: self.slice,
            full_len: self.full_len,
            start: self.start + start,
            end: self.start + end,
        }
    }
}

/// Implements [`BStackGuardedSlice`] for [`BXorBlockView`].
///
/// * `as_slice()` returns the bytes covered by this view.
/// * `write()` reads the old bytes in the view range, writes the new data,
///   then updates the XOR checksum incrementally over the changed range.
/// * `zero()` reads the current view bytes, zeroes the range, then XORs the
///   old bytes out of the checksum. Both operations are incremental.
impl<'a, A: BStackAllocator + 'a> BStackGuardedSlice<'a, A> for BXorBlockView<'a, A> {
    fn len(&self) -> u64 {
        self.end - self.start
    }

    unsafe fn raw_block(&self) -> BStackSlice<'a, A> {
        unsafe { self.data_slice() }
    }

    fn as_slice(&self) -> io::Result<BStackSlice<'a, A>> {
        Ok(unsafe { self.data_slice() })
    }

    fn write(&self, data: impl AsRef<[u8]>) -> io::Result<()> {
        let data = data.as_ref();
        let n = data.len() as u64;
        let old = self.slice.subslice(self.start, self.start + n).read()?;
        unsafe { self.data_slice() }.write(data)?;
        self.update_checksum_delta(self.start, &old, data)
    }

    fn zero(&self) -> io::Result<()> {
        let data_slice = unsafe { self.data_slice() };
        let old = data_slice.read()?;
        data_slice.zero()?;
        self.xor_out_bytes(self.start, &old)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bstack::{BStack, BStackGuardedSlice, LinearBStackAllocator};
    use tempfile::NamedTempFile;

    fn make_allocator() -> (BXorBlockAllocator<LinearBStackAllocator>, NamedTempFile) {
        let file = NamedTempFile::new().unwrap();
        let stack = BStack::open(file.path()).unwrap();
        let allocator = BXorBlockAllocator::new(LinearBStackAllocator::new(stack));
        (allocator, file)
    }

    #[test]
    fn test_alloc_len() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(30).unwrap();
        assert_eq!(block.len(), 30);
        let raw_len = unsafe { block.into_slice().len() };
        assert_eq!(raw_len, 34);
    }

    #[test]
    fn test_write_and_verify() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(5).unwrap();
        let view = block.view();
        view.write(b"hello").unwrap();
        assert!(view.verify().unwrap());
        assert_eq!(view.read().unwrap(), b"hello");
    }

    #[test]
    fn test_verify_fails_after_raw_write() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(5).unwrap();
        let view = block.view();
        view.write(b"hello").unwrap();
        unsafe {
            block.into_slice().write(b"world").unwrap();
        }
        assert!(!view.verify().unwrap());
    }

    #[test]
    fn test_verify_full_xor_consistency() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.view().write(b"abcdefgh").unwrap();
        // Manually recompute XOR and compare to stored.
        let data = block.view().read().unwrap();
        let expected = xor_checksum(&data);
        assert_eq!(block.checksum().unwrap(), expected);
    }

    #[test]
    fn test_realloc() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(4).unwrap();
        block.view().write(b"abcd").unwrap();
        let block2 = alloc.realloc(block, 8).unwrap();
        assert_eq!(block2.len(), 8);
        let raw_len = unsafe { block2.into_slice().len() };
        assert_eq!(raw_len, 12);
    }

    #[test]
    fn test_zero_clears_and_valid() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(6).unwrap();
        let view = block.view();
        view.write(b"foobar").unwrap();
        view.zero().unwrap();
        assert_eq!(view.read().unwrap(), vec![0u8; 6]);
        assert!(view.verify().unwrap());
    }

    #[test]
    fn test_zero_range() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.view().write(b"abcdefgh").unwrap();
        block.view().zero_range(2, 4).unwrap();
        assert!(block.verify().unwrap());
        let data = block.view().read().unwrap();
        assert_eq!(data, b"ab\x00\x00\x00\x00gh");
    }

    #[test]
    fn test_to_from_bytes() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.view().write(&b"rustacean"[..8]).unwrap();
        let bytes: [u8; 16] = block.into();
        let block2 = BXorBlock::from_bytes(alloc.inner(), bytes);
        assert_eq!(block2.len(), 8);
        assert!(block2.verify().unwrap());
        assert_eq!(block2.view().read().unwrap(), &b"rustacean"[..8]);
    }

    #[test]
    fn test_reader() {
        use std::io::Read;
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(4).unwrap();
        block.view().write(b"abcd").unwrap();
        let mut buf = [0u8; 4];
        block.reader().read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"abcd");
    }

    #[test]
    fn test_writer_maintains_checksum() {
        use std::io::Write;
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(4).unwrap();
        block.writer().write_all(b"WXYZ").unwrap();
        assert!(block.verify().unwrap());
        assert_eq!(block.view().read().unwrap(), b"WXYZ");
    }

    #[test]
    fn test_writer_seek_and_overwrite() {
        use std::io::{Seek, SeekFrom, Write};
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(4).unwrap();
        let mut w = block.writer();
        w.write_all(b"abcd").unwrap();
        w.seek(SeekFrom::Start(2)).unwrap();
        w.write_all(b"XY").unwrap();
        assert!(block.verify().unwrap());
        assert_eq!(block.view().read().unwrap(), b"abXY");
    }

    #[test]
    fn test_writer_incremental_matches_full() {
        // Verify incremental XOR matches a full recompute after partial overwrite.
        use std::io::{Seek, SeekFrom, Write};
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.view().write(b"12345678").unwrap();
        let mut w = block.writer_at(3);
        w.write_all(b"XY").unwrap();
        drop(w);
        // Stored checksum must equal fresh full XOR.
        let data = block.view().read().unwrap();
        assert_eq!(block.checksum().unwrap(), xor_checksum(&data));
        assert!(block.verify().unwrap());

        // Seek back and overwrite again.
        let mut w2 = block.writer();
        w2.seek(SeekFrom::Start(0)).unwrap();
        w2.write_all(b"abcdefgh").unwrap();
        drop(w2);
        let data2 = block.view().read().unwrap();
        assert_eq!(block.checksum().unwrap(), xor_checksum(&data2));
        assert!(block.verify().unwrap());
    }

    #[test]
    fn test_reader_writer_cmp() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(4).unwrap();
        let r = block.reader();
        let w = block.writer();
        assert_eq!(r, w);
        assert_eq!(w, r);
    }

    #[test]
    fn test_subview_read() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.view().write(b"hello!!!").unwrap();
        let sub = block.view().subview(0, 5);
        assert_eq!(sub.len(), 5);
        assert_eq!(sub.read().unwrap(), b"hello");
    }

    #[test]
    fn test_subview_write_updates_full_checksum() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.view().write(b"hello!!!").unwrap();
        let sub = block.view().subview(0, 5);
        sub.write(b"world").unwrap();
        assert!(block.verify().unwrap());
        assert_eq!(block.view().read().unwrap(), b"world!!!");
    }

    #[test]
    fn test_subview_writer_updates_full_checksum() {
        use std::io::Write;
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.view().write(b"hello!!!").unwrap();
        block
            .view()
            .subview(0, 5)
            .writer()
            .write_all(b"world")
            .unwrap();
        assert!(block.verify().unwrap());
        assert_eq!(block.view().read().unwrap(), b"world!!!");
    }

    #[test]
    fn test_subview_nested() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.view().write(b"abcdefgh").unwrap();
        // subview [2, 6) then subview [1, 3) of that → block bytes [3, 5)
        let sub = block.view().subview(2, 6).subview(1, 3);
        assert_eq!(sub.len(), 2);
        assert_eq!(sub.read().unwrap(), b"de");
        sub.write(b"XY").unwrap();
        assert!(block.verify().unwrap());
        assert_eq!(block.view().read().unwrap(), b"abcXYfgh");
    }
}
