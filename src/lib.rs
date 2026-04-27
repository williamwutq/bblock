use bstack::{BStackAllocator, BStackSlice};
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
#[derive(Copy, Clone, Debug)]
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

    /// Read the stored CRC32 checksum from the backing store.
    pub fn checksum(&self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.checksum_slice().read_into(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Return `true` if the stored checksum matches a freshly computed CRC32
    /// of the current data bytes.
    pub fn verify(&self) -> io::Result<bool> {
        let data = self.data_slice().read()?;
        let stored = self.checksum()?;
        Ok(crc32fast::hash(&data) == stored)
    }

    /// Return a [`BBlockView`] for safe reads and checksum-aware writes.
    ///
    /// The view shares the same backing region as this block; both remain
    /// independently usable because [`BStackSlice`] is `Copy`.
    pub fn view(&self) -> BBlockView<'a, A> {
        BBlockView {
            slice: self.slice,
            len: self.len,
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

    fn data_slice(&self) -> BStackSlice<'a, A> {
        self.slice.subslice(0, self.len)
    }

    fn checksum_slice(&self) -> BStackSlice<'a, A> {
        self.slice.subslice(self.len, self.len + CHECKSUM_LENGTH)
    }
}

/// A safe view into a [`BBlock`] with read and checksum-aware write operations.
///
/// All write methods automatically recompute and persist the CRC32 checksum
/// after each mutation, ensuring the stored checksum always reflects the
/// current data. This is the primary interface for mutating block contents.
#[derive(Copy, Clone, Debug)]
pub struct BBlockView<'a, A: BStackAllocator> {
    slice: BStackSlice<'a, A>,
    len: u64,
}

impl<'a, A: BStackAllocator> BBlockView<'a, A> {
    /// Create a view from an existing [`BBlock`].
    pub fn new(block: &BBlock<'a, A>) -> Self {
        Self {
            slice: block.slice,
            len: block.len,
        }
    }

    /// Number of usable (non-checksum) bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Returns `true` if this view covers zero usable bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Read all usable bytes into a new `Vec`.
    pub fn read(&self) -> io::Result<Vec<u8>> {
        self.data_slice().read()
    }

    /// Read all usable bytes into `buf`.
    pub fn read_into(&self, buf: &mut [u8]) -> io::Result<()> {
        self.data_slice().read_into(buf)
    }

    /// Read bytes starting at `start` into `buf`.
    pub fn read_range_into(&self, start: u64, buf: &mut [u8]) -> io::Result<()> {
        self.data_slice().read_range_into(start, buf)
    }

    /// Read the stored CRC32 checksum.
    pub fn checksum(&self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.checksum_slice().read_into(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Return `true` if the stored checksum matches the current data.
    pub fn verify(&self) -> io::Result<bool> {
        let data = self.read()?;
        let stored = self.checksum()?;
        Ok(crc32fast::hash(&data) == stored)
    }

    /// Overwrite the beginning of the block with `data` and recompute the checksum.
    pub fn write(&self, data: &[u8]) -> io::Result<()> {
        self.data_slice().write(data)?;
        self.update_checksum()
    }

    /// Overwrite bytes starting at `start` with `data` and recompute the checksum.
    pub fn write_range(&self, start: u64, data: &[u8]) -> io::Result<()> {
        self.data_slice().write_range(start, data)?;
        self.update_checksum()
    }

    /// Zero all usable bytes and recompute the checksum.
    pub fn zero(&self) -> io::Result<()> {
        self.data_slice().zero()?;
        self.update_checksum()
    }

    /// Zero `n` usable bytes starting at `start` and recompute the checksum.
    pub fn zero_range(&self, start: u64, n: u64) -> io::Result<()> {
        self.data_slice().zero_range(start, n)?;
        self.update_checksum()
    }

    fn data_slice(&self) -> BStackSlice<'a, A> {
        self.slice.subslice(0, self.len)
    }

    fn checksum_slice(&self) -> BStackSlice<'a, A> {
        self.slice.subslice(self.len, self.len + CHECKSUM_LENGTH)
    }

    fn update_checksum(&self) -> io::Result<()> {
        let data = self.read()?;
        let checksum = crc32fast::hash(&data);
        self.checksum_slice().write(&checksum.to_le_bytes())
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
}
