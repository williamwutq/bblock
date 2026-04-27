use bstack::{BStackAllocator, BStackSlice, BStackSliceReader, BStackSliceWriter};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;

/// Number of bytes appended to every allocation for the CRC32 checksum.
///
/// CRC32 produces a 32-bit (4-byte) value stored in little-endian order
/// immediately after the usable data in each block.
pub const CHECKSUM_LENGTH: u64 = 4;

/// Wraps any [`BStackAllocator`] and produces [`BBlock`]s whose allocations
/// include a trailing 4-byte CRC32 checksum.
///
/// `BBlockAllocator` does not import or depend on any concrete allocator
/// implementation; it is generic over any `A: BStackAllocator`.
pub struct BBlockAllocator<A: BStackAllocator> {
    inner: A,
}

impl<A: BStackAllocator> BBlockAllocator<A> {
    /// Create a new `BBlockAllocator` wrapping `inner`.
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

    /// Allocate `len` usable bytes plus a 4-byte checksum trailer.
    ///
    /// The returned [`BBlock`] has `len()` equal to `len`. The backing
    /// allocation is `len + 4` bytes.
    pub fn alloc(&self, len: u64) -> io::Result<BBlock<'_, A>> {
        let slice = self.inner.alloc(len + CHECKSUM_LENGTH)?;
        Ok(BBlock { slice, len })
    }

    /// Resize an existing block to `new_len` usable bytes.
    ///
    /// The backing allocation becomes `new_len + 4` bytes.
    pub fn realloc<'a>(&'a self, block: BBlock<'a, A>, new_len: u64) -> io::Result<BBlock<'a, A>> {
        let slice = self.inner.realloc(block.slice, new_len + CHECKSUM_LENGTH)?;
        Ok(BBlock {
            slice,
            len: new_len,
        })
    }

    /// Deallocate a block, releasing its backing storage.
    pub fn dealloc(&self, block: BBlock<'_, A>) -> io::Result<()> {
        self.inner.dealloc(block.slice)
    }
}

/// A checksummed block of bytes allocated from a [`BBlockAllocator`].
///
/// The backing allocation is `len + 4` bytes: the first `len` bytes are usable
/// data and the last 4 bytes store the CRC32 checksum in little-endian order.
///
/// Use [`BBlock::view`] to obtain a [`BBlockView`] for safe reads and writes
/// that maintain checksum integrity. Use [`BBlock::into_slice`] only when raw
/// access is required, accepting that checksum invariants are no longer upheld.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BBlock<'a, A: BStackAllocator> {
    slice: BStackSlice<'a, A>,
    len: u64,
}

impl<'a, A: BStackAllocator> BBlock<'a, A> {
    /// Number of usable (non-checksum) bytes in this block.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Returns `true` if this block has zero usable bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Serialize this block reference as a 16-byte array.
    ///
    /// The format is `[offset: u64 LE | usable_len: u64 LE]`. Reconstruct
    /// with [`BBlock::from_bytes`].
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.slice.start().to_le_bytes());
        out[8..].copy_from_slice(&self.len.to_le_bytes());
        out
    }

    /// Reconstruct a block reference from a 16-byte array produced by [`BBlock::to_bytes`].
    pub fn from_bytes(allocator: &'a A, bytes: [u8; 16]) -> Self {
        let offset = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let len = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        BBlock {
            slice: BStackSlice::new(allocator, offset, len + CHECKSUM_LENGTH),
            len,
        }
    }

    /// Read the stored CRC32 checksum from the backing store.
    pub fn checksum(&self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        unsafe { self.checksum_slice() }.read_into(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Return `true` if the stored checksum matches a freshly computed CRC32
    /// of the current data bytes.
    pub fn verify(&self) -> io::Result<bool> {
        let data = unsafe { self.data_slice() }.read()?;
        let stored = self.checksum()?;
        Ok(crc32fast::hash(&data) == stored)
    }

    /// Return a [`BBlockView`] covering the full usable data region.
    ///
    /// The view shares the same backing region as this block; both remain
    /// independently usable because [`BStackSlice`] is `Copy`.
    pub fn view(&self) -> BBlockView<'a, A> {
        BBlockView {
            slice: self.slice,
            full_len: self.len,
            start: 0,
            end: self.len,
        }
    }

    /// Return a cursor-based reader positioned at the start of the usable data.
    pub fn reader(&self) -> BBlockReader<'a, A> {
        BBlockReader {
            inner: unsafe { self.data_slice() }.reader(),
        }
    }

    /// Return a cursor-based reader positioned at `offset` within the usable data.
    pub fn reader_at(&self, offset: u64) -> BBlockReader<'a, A> {
        BBlockReader {
            inner: unsafe { self.data_slice() }.reader_at(offset),
        }
    }

    /// Return a cursor-based writer positioned at the start of the usable data.
    ///
    /// Every write through the returned [`BBlockWriter`] automatically
    /// recomputes and persists the CRC32 checksum over the full data region.
    pub fn writer(&self) -> BBlockWriter<'a, A> {
        let full_data = unsafe { self.data_slice() };
        BBlockWriter {
            inner: full_data.writer(),
            full_data,
            checksum: unsafe { self.checksum_slice() },
        }
    }

    /// Return a cursor-based writer positioned at `offset` within the usable data.
    ///
    /// Every write through the returned [`BBlockWriter`] automatically
    /// recomputes and persists the CRC32 checksum over the full data region.
    pub fn writer_at(&self, offset: u64) -> BBlockWriter<'a, A> {
        let full_data = unsafe { self.data_slice() };
        BBlockWriter {
            inner: full_data.writer_at(offset),
            full_data,
            checksum: unsafe { self.checksum_slice() },
        }
    }

    /// Consume the block and return the raw underlying [`BStackSlice`].
    ///
    /// # Safety
    ///
    /// Any mutation of the returned slice bypasses checksum tracking. After
    /// calling this function the caller is responsible for maintaining or
    /// ignoring checksum integrity.
    pub unsafe fn into_slice(self) -> BStackSlice<'a, A> {
        self.slice
    }

    /// # Safety
    ///
    /// The returned slice covers only the usable data region. Any write to it
    /// bypasses checksum tracking; callers must maintain checksum integrity
    /// manually or accept that the checksum will be stale.
    unsafe fn data_slice(&self) -> BStackSlice<'a, A> {
        self.slice.subslice(0, self.len)
    }

    /// # Safety
    ///
    /// The returned slice covers the raw checksum bytes. Writing to it allows
    /// forging an arbitrary checksum; callers must ensure the written value
    /// correctly reflects the data region.
    unsafe fn checksum_slice(&self) -> BStackSlice<'a, A> {
        self.slice.subslice(self.len, self.len + CHECKSUM_LENGTH)
    }
}

impl<'a, A: BStackAllocator> From<BBlock<'a, A>> for [u8; 16] {
    fn from(block: BBlock<'a, A>) -> [u8; 16] {
        block.to_bytes()
    }
}

/// A safe view into a sub-range of a [`BBlock`]'s usable data.
///
/// Every mutation automatically recomputes the CRC32 checksum over the
/// **full block data** (not just the view's sub-range), so integrity is always
/// maintained from the block's perspective.
///
/// A full-block view is obtained via [`BBlock::view`] or [`BBlockView::new`].
/// Sub-range views are obtained via [`BBlockView::subview`].
///
/// Read/write coordinates are relative to the view's own start (position 0 =
/// first byte covered by this view), matching the behaviour of
/// [`BStackSlice`]'s own sub-slice API.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BBlockView<'a, A: BStackAllocator> {
    /// The full block allocation: `[data: full_len bytes][checksum: 4 bytes]`.
    slice: BStackSlice<'a, A>,
    /// Length of the full usable data region (used for checksum recomputation).
    full_len: u64,
    /// Inclusive start of this view within the data region.
    start: u64,
    /// Exclusive end of this view within the data region.
    end: u64,
}

impl<'a, A: BStackAllocator> BBlockView<'a, A> {
    /// Create a full-block view from an existing [`BBlock`].
    pub fn new(block: &BBlock<'a, A>) -> Self {
        Self {
            slice: block.slice,
            full_len: block.len,
            start: 0,
            end: block.len,
        }
    }

    /// Number of bytes covered by this view.
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    /// Returns `true` if this view covers zero bytes.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Return a view covering `[start, end)` within this view's coordinate space.
    ///
    /// Coordinates are relative: `subview(0, 3)` on a view that itself starts at
    /// byte 5 of the block produces a view covering bytes 5–7 of the block.
    ///
    /// Writes through the returned view update the **full block checksum**.
    pub fn subview(&self, start: u64, end: u64) -> Self {
        BBlockView {
            slice: self.slice,
            full_len: self.full_len,
            start: self.start + start,
            end: self.start + end,
        }
    }

    /// Read all bytes in this view into a new `Vec`.
    pub fn read(&self) -> io::Result<Vec<u8>> {
        unsafe { self.data_slice() }.read()
    }

    /// Read all bytes in this view into `buf`.
    pub fn read_into(&self, buf: &mut [u8]) -> io::Result<()> {
        unsafe { self.data_slice() }.read_into(buf)
    }

    /// Read bytes starting at `start` within this view into `buf`.
    pub fn read_range_into(&self, start: u64, buf: &mut [u8]) -> io::Result<()> {
        unsafe { self.data_slice() }.read_range_into(start, buf)
    }

    /// Read the stored CRC32 checksum of the containing block.
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
        Ok(crc32fast::hash(&data) == stored)
    }

    /// Overwrite the beginning of this view with `data` and recompute the
    /// block checksum.
    pub fn write(&self, data: &[u8]) -> io::Result<()> {
        unsafe { self.data_slice() }.write(data)?;
        self.update_checksum()
    }

    /// Overwrite bytes starting at `start` within this view with `data` and
    /// recompute the block checksum.
    pub fn write_range(&self, start: u64, data: &[u8]) -> io::Result<()> {
        unsafe { self.data_slice() }.write_range(start, data)?;
        self.update_checksum()
    }

    /// Zero all bytes in this view and recompute the block checksum.
    pub fn zero(&self) -> io::Result<()> {
        unsafe { self.data_slice() }.zero()?;
        self.update_checksum()
    }

    /// Zero `n` bytes starting at `start` within this view and recompute the
    /// block checksum.
    pub fn zero_range(&self, start: u64, n: u64) -> io::Result<()> {
        unsafe { self.data_slice() }.zero_range(start, n)?;
        self.update_checksum()
    }

    /// Return a cursor-based reader positioned at the start of this view.
    pub fn reader(&self) -> BBlockReader<'a, A> {
        BBlockReader {
            inner: unsafe { self.data_slice() }.reader(),
        }
    }

    /// Return a cursor-based reader positioned at `offset` within this view.
    pub fn reader_at(&self, offset: u64) -> BBlockReader<'a, A> {
        BBlockReader {
            inner: unsafe { self.data_slice() }.reader_at(offset),
        }
    }

    /// Return a cursor-based writer positioned at the start of this view.
    ///
    /// Every write automatically recomputes the full block checksum.
    pub fn writer(&self) -> BBlockWriter<'a, A> {
        BBlockWriter {
            inner: unsafe { self.data_slice() }.writer(),
            full_data: unsafe { self.full_data_slice() },
            checksum: unsafe { self.checksum_slice() },
        }
    }

    /// Return a cursor-based writer positioned at `offset` within this view.
    ///
    /// Every write automatically recomputes the full block checksum.
    pub fn writer_at(&self, offset: u64) -> BBlockWriter<'a, A> {
        BBlockWriter {
            inner: unsafe { self.data_slice() }.writer_at(offset),
            full_data: unsafe { self.full_data_slice() },
            checksum: unsafe { self.checksum_slice() },
        }
    }

    /// # Safety
    ///
    /// Returns only the bytes covered by this view. Any write bypasses checksum
    /// tracking; callers must call `update_checksum` or accept stale checksums.
    unsafe fn data_slice(&self) -> BStackSlice<'a, A> {
        self.slice.subslice(self.start, self.end)
    }

    /// # Safety
    ///
    /// Returns the full block data region. Intended for checksum recomputation.
    unsafe fn full_data_slice(&self) -> BStackSlice<'a, A> {
        self.slice.subslice(0, self.full_len)
    }

    /// # Safety
    ///
    /// Returns the raw checksum bytes. Writing an incorrect value forges the
    /// checksum; callers must ensure it reflects the full data region.
    unsafe fn checksum_slice(&self) -> BStackSlice<'a, A> {
        self.slice
            .subslice(self.full_len, self.full_len + CHECKSUM_LENGTH)
    }

    fn update_checksum(&self) -> io::Result<()> {
        let data = unsafe { self.full_data_slice() }.read()?;
        let crc = crc32fast::hash(&data);
        unsafe { self.checksum_slice() }.write(&crc.to_le_bytes())
    }
}

/// A cursor-based reader over the bytes covered by a [`BBlockView`].
///
/// Implements [`io::Read`] and [`io::Seek`] within the coordinate space of the
/// view (position 0 = first byte of the view). Constructed via
/// [`BBlock::reader`], [`BBlock::reader_at`], [`BBlockView::reader`], or
/// [`BBlockView::reader_at`].
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BBlockReader<'a, A: BStackAllocator> {
    inner: BStackSliceReader<'a, A>,
}

impl<'a, A: BStackAllocator> fmt::Debug for BBlockReader<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BBlockReader")
            .field("start", &self.inner.slice().start())
            .field("end", &self.inner.slice().end())
            .field("len", &self.inner.slice().len())
            .field("cursor", &self.inner.position())
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> BBlockReader<'a, A> {
    /// Return the current cursor position within the view's coordinate space.
    pub fn position(&self) -> u64 {
        self.inner.position()
    }
}

/// Two readers compare equal when their active slice and cursor position match.
impl<'a, A: BStackAllocator> PartialEq<BBlockWriter<'a, A>> for BBlockReader<'a, A> {
    fn eq(&self, other: &BBlockWriter<'a, A>) -> bool {
        self.inner.slice() == other.inner.slice() && self.inner.position() == other.inner.position()
    }
}

/// Ordered by absolute payload position, then by active length.
impl<'a, A: BStackAllocator> PartialOrd<BBlockWriter<'a, A>> for BBlockReader<'a, A> {
    fn partial_cmp(&self, other: &BBlockWriter<'a, A>) -> Option<Ordering> {
        let self_pos = self.inner.slice().start() + self.inner.position();
        let other_pos = other.inner.slice().start() + other.inner.position();
        Some(
            self_pos
                .cmp(&other_pos)
                .then(self.inner.slice().len().cmp(&other.inner.slice().len())),
        )
    }
}

impl<'a, A: BStackAllocator> io::Read for BBlockReader<'a, A> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<'a, A: BStackAllocator> io::Seek for BBlockReader<'a, A> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// A cursor-based writer over the bytes covered by a [`BBlockView`].
///
/// Implements [`io::Write`] and [`io::Seek`] within the coordinate space of the
/// view. Every write automatically recomputes the CRC32 checksum over the
/// **full block data** (not just the active view range), keeping the block's
/// integrity invariant intact. Constructed via [`BBlock::writer`],
/// [`BBlock::writer_at`], [`BBlockView::writer`], or [`BBlockView::writer_at`].
#[derive(Clone)]
pub struct BBlockWriter<'a, A: BStackAllocator> {
    /// Cursor writer scoped to the view's active range.
    inner: BStackSliceWriter<'a, A>,
    /// Full block data region — read to recompute the checksum after each write.
    full_data: BStackSlice<'a, A>,
    /// Checksum slot — written after each mutation.
    checksum: BStackSlice<'a, A>,
}

impl<'a, A: BStackAllocator> fmt::Debug for BBlockWriter<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BBlockWriter")
            .field("start", &self.inner.slice().start())
            .field("end", &self.inner.slice().end())
            .field("len", &self.inner.slice().len())
            .field("cursor", &self.inner.position())
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> BBlockWriter<'a, A> {
    /// Return the current cursor position within the view's coordinate space.
    pub fn position(&self) -> u64 {
        self.inner.position()
    }

    fn update_checksum(&self) -> io::Result<()> {
        let data = self.full_data.read()?;
        let crc = crc32fast::hash(&data);
        self.checksum.write(&crc.to_le_bytes())
    }
}

/// Two writers compare equal when their active slice and cursor position match.
impl<'a, A: BStackAllocator> PartialEq for BBlockWriter<'a, A> {
    fn eq(&self, other: &Self) -> bool {
        self.inner.slice() == other.inner.slice() && self.inner.position() == other.inner.position()
    }
}

impl<'a, A: BStackAllocator> Eq for BBlockWriter<'a, A> {}

impl<'a, A: BStackAllocator> Hash for BBlockWriter<'a, A> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.slice().hash(state);
        self.inner.position().hash(state);
    }
}

/// Ordered by absolute payload position, then by active length.
impl<'a, A: BStackAllocator> PartialOrd for BBlockWriter<'a, A> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a, A: BStackAllocator> Ord for BBlockWriter<'a, A> {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_pos = self.inner.slice().start() + self.inner.position();
        let other_pos = other.inner.slice().start() + other.inner.position();
        self_pos
            .cmp(&other_pos)
            .then(self.inner.slice().len().cmp(&other.inner.slice().len()))
    }
}

impl<'a, A: BStackAllocator> PartialEq<BBlockReader<'a, A>> for BBlockWriter<'a, A> {
    fn eq(&self, other: &BBlockReader<'a, A>) -> bool {
        other == self
    }
}

impl<'a, A: BStackAllocator> PartialOrd<BBlockReader<'a, A>> for BBlockWriter<'a, A> {
    fn partial_cmp(&self, other: &BBlockReader<'a, A>) -> Option<Ordering> {
        other.partial_cmp(self).map(|o| o.reverse())
    }
}

impl<'a, A: BStackAllocator> io::Write for BBlockWriter<'a, A> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        if n > 0 {
            self.update_checksum()?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, A: BStackAllocator> io::Seek for BBlockWriter<'a, A> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bstack::{BStack, LinearBStackAllocator};
    use tempfile::NamedTempFile;

    fn make_allocator() -> (BBlockAllocator<LinearBStackAllocator>, NamedTempFile) {
        let file = NamedTempFile::new().unwrap();
        let stack = BStack::open(file.path()).unwrap();
        let allocator = BBlockAllocator::new(LinearBStackAllocator::new(stack));
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
    fn test_to_from_bytes() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.view().write(&b"rustacean"[..8]).unwrap();
        let bytes: [u8; 16] = block.into();
        let block2 = BBlock::from_bytes(alloc.inner(), bytes);
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
