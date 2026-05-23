//! AES-256-GCM authenticated-encryption blocks.
//!
//! # Overview
//!
//! This module wraps any [`BStackAllocator`] and stores every allocation as
//! an authenticated ciphertext.  Reads decrypt transparently; writes encrypt
//! with a caller-supplied nonce generator.  The AEAD authentication tag
//! provides strong integrity guarantees — no separate checksum layer is needed.
//!
//! The main types:
//!
//! | Type                   | Role                                                         |
//! |------------------------|--------------------------------------------------------------|
//! | [`BAESBlockAllocator`] | Wraps a `BStackAllocator`; produces [`BAESBlock`]s           |
//! | [`BAESBlock`]          | Encrypted block handle; source of readers and writers        |
//! | [`BAESBlockReader`]    | Cursor-based `io::Read + io::Seek` over decrypted plaintext  |
//! | [`BAESBlockWriter`]    | Buffered `io::Write + io::Seek`; encrypts on `flush()`/drop  |
//!
//! # On-disk format
//!
//! ```text
//! [algo: 4 bytes = b"A2GM"][nonce: 12 bytes][ciphertext: n bytes][tag: 16 bytes]
//! ```
//!
//! Total overhead: [`AES_OVERHEAD`] = 32 bytes per block.
//!
//! # Security
//!
//! AES-256-GCM is an AEAD cipher with hardware acceleration on platforms with
//! AES-NI.  The authentication tag covers both the ciphertext and the nonce,
//! so any tampering with any byte of the stored block is detected on the next
//! read or [`BAESBlock::verify`].
//!
//! **Nonce uniqueness is critical**: never reuse the same (key, nonce) pair for
//! different plaintexts.  The [`BAESBlockAllocator`] calls the provided
//! `nonce_gen` function for every fresh encryption (each `write` / `alloc` /
//! size-changing `realloc`); it is the caller's responsibility to supply a
//! generator that returns unique nonces (e.g. a CSPRNG).
//!
//! # Detection, not recovery
//!
//! A failed [`BAESBlock::verify`] or a decryption error means the data must
//! not be trusted.  This module provides no repair or rollback mechanism.

use crate::{BStackRawAllocator, BlockStart};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use bstack::{BStack, BStackAllocator, BStackGuardedSlice, BStackSlice};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::marker::PhantomData;

/// Four-byte magic identifying the AES-256-GCM algorithm.
const AES_MAGIC: &[u8; 4] = b"A2GM";

/// Number of extra bytes stored per block:
/// 4 (magic) + 12 (nonce) + 16 (tag).
pub const AES_OVERHEAD: u64 = 32;

// ── Allocator ────────────────────────────────────────────────────────────────

/// Wraps any [`BStackAllocator`] and transparently encrypts every allocation
/// with AES-256-GCM.
///
/// Each allocation stores [`AES_OVERHEAD`] (32) extra bytes on disk, so
/// `alloc(n)` allocates `n + 32` bytes in the underlying stack.
///
/// The `nonce_gen` function is called for every fresh encryption.  It must
/// return a unique 12-byte nonce; use a CSPRNG in production code.
pub struct BAESBlockAllocator<A: BStackAllocator> {
    inner: A,
    key: [u8; 32],
    nonce_gen: fn() -> [u8; 12],
}

impl<A: BStackAllocator> BAESBlockAllocator<A> {
    /// Create a new allocator wrapping `inner`.
    ///
    /// `key` is the 256-bit AES-256-GCM key used for all blocks.
    /// `nonce_gen` is called on every write to produce a fresh 12-byte nonce.
    pub fn new(inner: A, key: [u8; 32], nonce_gen: fn() -> [u8; 12]) -> Self {
        Self {
            inner,
            key,
            nonce_gen,
        }
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

// ── Block handle ─────────────────────────────────────────────────────────────

/// A handle to an AES-256-GCM encrypted block.
///
/// **Backing layout:** `[b"A2GM": 4][nonce: 12][ciphertext: len][tag: 16]`
///
/// `BAESBlock` is `Copy`: every copy refers to the same physical region.
///
/// ## Reading and writing
///
/// Use the inherent [`read`](BAESBlock::read) method to decrypt and return
/// the full plaintext.  For streaming I/O use [`reader`](BAESBlock::reader)
/// and [`writer`](BAESBlock::writer).
///
/// [`BStackGuardedSlice::write`] and [`BStackGuardedSlice::zero`] are also
/// available (requires `use bstack::BStackGuardedSlice`).  `as_slice()` is
/// intentionally unsupported — exposing raw ciphertext as a plaintext slice
/// has no safe semantics.
///
/// ## Integrity
///
/// [`verify`](BAESBlock::verify) attempts a full decryption; it returns
/// `Ok(false)` (not `Err`) if the authentication tag fails, so callers can
/// distinguish corruption from I/O errors.
pub struct BAESBlock<'a, A: BStackAllocator> {
    slice: BStackSlice<'a, A>,
    len: u64,
    key: [u8; 32],
    nonce_gen: fn() -> [u8; 12],
}

impl<'a, A: BStackAllocator> Copy for BAESBlock<'a, A> {}

impl<'a, A: BStackAllocator> Clone for BAESBlock<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, A: BStackAllocator> fmt::Debug for BAESBlock<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BAESBlock")
            .field("start", &self.slice.start())
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> PartialEq for BAESBlock<'a, A> {
    fn eq(&self, other: &Self) -> bool {
        self.slice == other.slice && self.len == other.len
    }
}

impl<'a, A: BStackAllocator> Eq for BAESBlock<'a, A> {}

impl<'a, A: BStackAllocator> Hash for BAESBlock<'a, A> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.slice.hash(state);
        self.len.hash(state);
    }
}

impl<'a, A: BStackAllocator> PartialOrd for BAESBlock<'a, A> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a, A: BStackAllocator> Ord for BAESBlock<'a, A> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.slice.cmp(&other.slice).then(self.len.cmp(&other.len))
    }
}

impl<'a, A: BStackAllocator> From<BAESBlock<'a, A>> for [u8; 16] {
    fn from(block: BAESBlock<'a, A>) -> [u8; 16] {
        block.to_bytes()
    }
}

impl<'a, A: BStackAllocator> BAESBlock<'a, A> {
    /// Serialize this block reference as a 16-byte array `[offset: u64 LE | len: u64 LE]`.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.slice.start().to_le_bytes());
        out[8..].copy_from_slice(&self.len.to_le_bytes());
        out
    }

    /// Return `true` if the block decrypts successfully (magic matches and tag
    /// is valid).  Returns `Ok(false)` for corruption, `Err` for I/O errors.
    pub fn verify(&self) -> io::Result<bool> {
        match self.decrypt_read() {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Decrypt and return the full plaintext.
    pub fn read(&self) -> io::Result<Vec<u8>> {
        self.decrypt_read()
    }

    /// Return a cursor-based reader over the decrypted plaintext.
    ///
    /// The full block is decrypted once on construction; subsequent reads and
    /// seeks operate on the in-memory buffer.
    pub fn reader(&self) -> io::Result<BAESBlockReader<'a, A>> {
        Ok(BAESBlockReader {
            buf: self.decrypt_read()?,
            pos: 0,
            _marker: PhantomData,
        })
    }

    /// Return a buffered writer over the plaintext.
    ///
    /// The current plaintext is decrypted into an in-memory buffer on
    /// construction.  Writes and seeks modify the buffer only.  The buffer is
    /// re-encrypted and written to disk when [`flush`](io::Write::flush) is
    /// called or when the writer is dropped.
    pub fn writer(&self) -> io::Result<BAESBlockWriter<'a, A>> {
        Ok(BAESBlockWriter {
            block: *self,
            buf: self.decrypt_read()?,
            pos: 0,
            dirty: false,
        })
    }

    /// Consume the block and return the raw underlying [`BStackSlice`].
    ///
    /// # Safety
    ///
    /// Any mutation through the returned slice bypasses encryption and will
    /// corrupt or forge the stored ciphertext.
    pub unsafe fn into_slice(self) -> BStackSlice<'a, A> {
        self.slice
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn encrypt_write(&self, plaintext: &[u8]) -> io::Result<()> {
        let nonce_bytes = (self.nonce_gen)();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|_| io::Error::other("AES-GCM encryption failed"))?;
        self.slice.subslice(0, 4).write(*AES_MAGIC)?;
        self.slice.subslice(4, 16).write(nonce_bytes)?;
        self.slice.subslice(16, self.len + AES_OVERHEAD).write(&ct)
    }

    fn decrypt_read(&self) -> io::Result<Vec<u8>> {
        let mut magic = [0u8; 4];
        self.slice.subslice(0, 4).read_into(&mut magic)?;
        if &magic != AES_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "wrong algo magic: expected A2GM",
            ));
        }
        let mut nonce_bytes = [0u8; 12];
        self.slice.subslice(4, 16).read_into(&mut nonce_bytes)?;
        let ct = self.slice.subslice(16, self.len + AES_OVERHEAD).read()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ct.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AES-GCM decryption failed"))
    }
}

#[allow(private_bounds)]
impl<'a, A> BAESBlock<'a, BAESBlockAllocator<A>>
where
    A: BStackAllocator<Error = io::Error> + BStackRawAllocator,
    for<'b> A::Allocated<'b>: BlockStart + Copy,
{
    /// Reconstruct a block from a 16-byte array produced by
    /// [`BAESBlock::to_bytes`].
    pub fn from_bytes(allocator: &'a BAESBlockAllocator<A>, bytes: [u8; 16]) -> Self {
        let offset = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let len = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        BAESBlock {
            slice: unsafe { BStackSlice::from_raw_parts(allocator, offset, len + AES_OVERHEAD) },
            len,
            key: allocator.key,
            nonce_gen: allocator.nonce_gen,
        }
    }
}

// ── Reader ───────────────────────────────────────────────────────────────────

/// A cursor-based reader over the decrypted plaintext of a [`BAESBlock`].
///
/// The full plaintext is decrypted once at construction time and held in an
/// in-memory buffer.  `Read` and `Seek` operations work on that buffer; no
/// further I/O is performed.
///
/// Constructed via [`BAESBlock::reader`].
pub struct BAESBlockReader<'a, A: BStackAllocator> {
    buf: Vec<u8>,
    pos: usize,
    _marker: PhantomData<BAESBlock<'a, A>>,
}

impl<'a, A: BStackAllocator> fmt::Debug for BAESBlockReader<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BAESBlockReader")
            .field("len", &self.buf.len())
            .field("pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> io::Read for BAESBlockReader<'a, A> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.buf.len().saturating_sub(self.pos);
        let n = buf.len().min(remaining);
        buf[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<'a, A: BStackAllocator> io::Seek for BAESBlockReader<'a, A> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            io::SeekFrom::Start(n) => n as i64,
            io::SeekFrom::End(n) => self.buf.len() as i64 + n,
            io::SeekFrom::Current(n) => self.pos as i64 + n,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to negative position",
            ));
        }
        self.pos = new_pos as usize;
        Ok(self.pos as u64)
    }
}

// ── Writer ───────────────────────────────────────────────────────────────────

/// A buffered writer over the plaintext of a [`BAESBlock`].
///
/// On construction the current plaintext is decrypted into an in-memory
/// buffer.  `Write` and `Seek` operate on that buffer.  When
/// [`flush`](io::Write::flush) is called (or the writer is dropped), the
/// buffer is re-encrypted with a fresh nonce and written back to disk.
///
/// Drop silently discards flush errors; call [`flush`](io::Write::flush)
/// explicitly if you need to observe errors.
///
/// Constructed via [`BAESBlock::writer`].
pub struct BAESBlockWriter<'a, A: BStackAllocator> {
    block: BAESBlock<'a, A>,
    buf: Vec<u8>,
    pos: usize,
    dirty: bool,
}

impl<'a, A: BStackAllocator> fmt::Debug for BAESBlockWriter<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BAESBlockWriter")
            .field("len", &self.buf.len())
            .field("pos", &self.pos)
            .field("dirty", &self.dirty)
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> io::Write for BAESBlockWriter<'a, A> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = self.buf.len().saturating_sub(self.pos);
        let n = buf.len().min(remaining);
        if n == 0 {
            return Ok(0);
        }
        self.buf[self.pos..self.pos + n].copy_from_slice(&buf[..n]);
        self.pos += n;
        self.dirty = true;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.dirty {
            self.block.encrypt_write(&self.buf)?;
            self.dirty = false;
        }
        Ok(())
    }
}

impl<'a, A: BStackAllocator> io::Seek for BAESBlockWriter<'a, A> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            io::SeekFrom::Start(n) => n as i64,
            io::SeekFrom::End(n) => self.buf.len() as i64 + n,
            io::SeekFrom::Current(n) => self.pos as i64 + n,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to negative position",
            ));
        }
        self.pos = new_pos as usize;
        Ok(self.pos as u64)
    }
}

impl<'a, A: BStackAllocator> Drop for BAESBlockWriter<'a, A> {
    fn drop(&mut self) {
        let _ = io::Write::flush(self);
    }
}

// ── BStackAllocator impl ─────────────────────────────────────────────────────

impl<A> BStackAllocator for BAESBlockAllocator<A>
where
    A: BStackAllocator<Error = io::Error> + BStackRawAllocator,
    for<'a> A::Allocated<'a>: BlockStart + Copy,
{
    type Error = io::Error;
    type Allocated<'a>
        = BAESBlock<'a, BAESBlockAllocator<A>>
    where
        A: 'a;

    fn stack(&self) -> &BStack {
        self.inner.stack()
    }

    fn into_stack(self) -> BStack {
        self.inner.into_stack()
    }

    fn alloc(&self, len: u64) -> io::Result<BAESBlock<'_, BAESBlockAllocator<A>>> {
        let inner = self.inner.alloc(len + AES_OVERHEAD)?;
        let offset = inner.block_start();
        let slice = unsafe { BStackSlice::from_raw_parts(self, offset, len + AES_OVERHEAD) };
        let block = BAESBlock {
            slice,
            len,
            key: self.key,
            nonce_gen: self.nonce_gen,
        };
        block.encrypt_write(&vec![0u8; len as usize])?;
        Ok(block)
    }

    fn realloc<'a>(
        &'a self,
        block: BAESBlock<'a, BAESBlockAllocator<A>>,
        new_len: u64,
    ) -> io::Result<BAESBlock<'a, BAESBlockAllocator<A>>> {
        let offset = block.slice.start();
        let inner_old_slice =
            unsafe { BStackSlice::from_raw_parts(&self.inner, offset, block.len + AES_OVERHEAD) };
        let inner_old: A::Allocated<'_> = unsafe { A::from_raw(inner_old_slice) };

        if new_len == block.len {
            let inner_new = self.inner.realloc(inner_old, new_len + AES_OVERHEAD)?;
            let new_offset = inner_new.block_start();
            let slice =
                unsafe { BStackSlice::from_raw_parts(self, new_offset, new_len + AES_OVERHEAD) };
            return Ok(BAESBlock {
                slice,
                len: new_len,
                key: block.key,
                nonce_gen: block.nonce_gen,
            });
        }

        let mut plaintext = block.decrypt_read()?;
        let inner_new = self.inner.realloc(inner_old, new_len + AES_OVERHEAD)?;
        let new_offset = inner_new.block_start();
        let new_slice =
            unsafe { BStackSlice::from_raw_parts(self, new_offset, new_len + AES_OVERHEAD) };
        let new_block = BAESBlock {
            slice: new_slice,
            len: new_len,
            key: block.key,
            nonce_gen: block.nonce_gen,
        };
        plaintext.resize(new_len as usize, 0);
        new_block.encrypt_write(&plaintext)?;
        Ok(new_block)
    }

    fn dealloc(&self, block: BAESBlock<'_, BAESBlockAllocator<A>>) -> io::Result<()> {
        let offset = block.slice.start();
        let inner_slice =
            unsafe { BStackSlice::from_raw_parts(&self.inner, offset, block.len + AES_OVERHEAD) };
        let inner: A::Allocated<'_> = unsafe { A::from_raw(inner_slice) };
        self.inner.dealloc(inner)
    }
}

impl<'a, A> TryInto<BStackSlice<'a, BAESBlockAllocator<A>>> for BAESBlock<'a, BAESBlockAllocator<A>>
where
    A: BStackAllocator<Error = io::Error> + BStackRawAllocator,
    for<'b> A::Allocated<'b>: BlockStart + Copy,
{
    type Error = std::convert::Infallible;

    fn try_into(self) -> Result<BStackSlice<'a, BAESBlockAllocator<A>>, Self::Error> {
        Ok(self.slice)
    }
}

impl<'a, A: BStackAllocator> BlockStart for BAESBlock<'a, A> {
    fn block_start(&self) -> u64 {
        self.slice.start()
    }
}

// ── BStackGuardedSlice impl ───────────────────────────────────────────────────

/// * `len()` returns the plaintext length.
/// * `write()` encrypts `data` with a fresh nonce and writes the full block.
/// * `zero()` encrypts a zero-filled buffer and writes the full block.
/// * `as_slice()` is intentionally unsupported (exposing ciphertext has no
///   useful plaintext semantics); the default implementation from bstack
///   signals this.
impl<'a, A: BStackAllocator + 'a> BStackGuardedSlice<'a, A> for BAESBlock<'a, A> {
    fn len(&self) -> u64 {
        self.len
    }

    unsafe fn raw_block(&self) -> BStackSlice<'a, A> {
        self.slice
    }

    fn write(&self, data: impl AsRef<[u8]>) -> io::Result<()> {
        self.encrypt_write(data.as_ref())
    }

    fn zero(&self) -> io::Result<()> {
        self.encrypt_write(&vec![0u8; self.len as usize])
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bstack::{BStack, BStackAllocator, BStackGuardedSlice, LinearBStackAllocator};
    use std::io::{Read, Seek, SeekFrom, Write};
    use tempfile::NamedTempFile;

    fn counter_nonce() -> fn() -> [u8; 12] {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(1);
        fn make_nonce() -> [u8; 12] {
            let n = CTR.fetch_add(1, Ordering::Relaxed);
            let mut out = [0u8; 12];
            out[..8].copy_from_slice(&n.to_le_bytes());
            out
        }
        make_nonce
    }

    fn make_allocator() -> (BAESBlockAllocator<LinearBStackAllocator>, NamedTempFile) {
        let file = NamedTempFile::new().unwrap();
        let stack = BStack::open(file.path()).unwrap();
        let key = [0x42u8; 32];
        let alloc =
            BAESBlockAllocator::new(LinearBStackAllocator::new(stack), key, counter_nonce());
        (alloc, file)
    }

    #[test]
    fn test_alloc_len() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(30).unwrap();
        assert_eq!(block.len(), 30);
        let raw_len = unsafe { block.into_slice().len() };
        assert_eq!(raw_len, 30 + AES_OVERHEAD);
    }

    #[test]
    fn test_write_and_read() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(5).unwrap();
        block.write(b"hello").unwrap();
        assert_eq!(block.read().unwrap(), b"hello");
    }

    #[test]
    fn test_verify_passes() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(5).unwrap();
        block.write(b"hello").unwrap();
        assert!(block.verify().unwrap());
    }

    #[test]
    fn test_verify_fails_after_raw_write() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(5).unwrap();
        block.write(b"hello").unwrap();
        let raw = unsafe { block.into_slice() };
        let ct_byte = raw.subslice(16, 17);
        let mut b = [0u8; 1];
        ct_byte.read_into(&mut b).unwrap();
        b[0] ^= 0xff;
        ct_byte.write(b).unwrap();
        assert!(!block.verify().unwrap());
    }

    #[test]
    fn test_wrong_algo_magic() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(4).unwrap();
        block.write(b"data").unwrap();
        unsafe { block.into_slice() }
            .subslice(0, 4)
            .write(*b"XXXX")
            .unwrap();
        assert!(!block.verify().unwrap());
    }

    #[test]
    fn test_zero_encrypts_zeros() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(6).unwrap();
        block.write(b"foobar").unwrap();
        block.zero().unwrap();
        assert_eq!(block.read().unwrap(), vec![0u8; 6]);
        assert!(block.verify().unwrap());
    }

    #[test]
    fn test_to_from_bytes() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.write(&b"rustacean"[..8]).unwrap();
        let bytes: [u8; 16] = block.into();
        let block2 = BAESBlock::from_bytes(&alloc, bytes);
        assert_eq!(block2.len(), 8);
        assert!(block2.verify().unwrap());
        assert_eq!(block2.read().unwrap(), &b"rustacean"[..8]);
    }

    #[test]
    fn test_reader() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(4).unwrap();
        block.write(b"abcd").unwrap();
        let mut reader = block.reader().unwrap();
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"abcd");
    }

    #[test]
    fn test_reader_seek() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.write(b"abcdefgh").unwrap();
        let mut reader = block.reader().unwrap();
        reader.seek(SeekFrom::Start(4)).unwrap();
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"efgh");
    }

    #[test]
    fn test_writer_flush() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(4).unwrap();
        {
            let mut w = block.writer().unwrap();
            w.write_all(b"WXYZ").unwrap();
            w.flush().unwrap();
        }
        assert!(block.verify().unwrap());
        assert_eq!(block.read().unwrap(), b"WXYZ");
    }

    #[test]
    fn test_writer_seek_and_overwrite() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(4).unwrap();
        {
            let mut w = block.writer().unwrap();
            w.write_all(b"abcd").unwrap();
            w.seek(SeekFrom::Start(2)).unwrap();
            w.write_all(b"XY").unwrap();
            w.flush().unwrap();
        }
        assert!(block.verify().unwrap());
        assert_eq!(block.read().unwrap(), b"abXY");
    }

    #[test]
    fn test_writer_drop_flushes() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(4).unwrap();
        {
            let mut w = block.writer().unwrap();
            w.write_all(b"drop").unwrap();
        }
        assert_eq!(block.read().unwrap(), b"drop");
    }

    #[test]
    fn test_realloc_same_size() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(4).unwrap();
        block.write(b"abcd").unwrap();
        let block2 = alloc.realloc(block, 4).unwrap();
        assert_eq!(block2.len(), 4);
        assert!(block2.verify().unwrap());
        assert_eq!(block2.read().unwrap(), b"abcd");
    }

    #[test]
    fn test_realloc_larger() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(4).unwrap();
        block.write(b"abcd").unwrap();
        let block2 = alloc.realloc(block, 8).unwrap();
        assert_eq!(block2.len(), 8);
        assert!(block2.verify().unwrap());
        let data = block2.read().unwrap();
        assert_eq!(&data[..4], b"abcd");
        assert_eq!(&data[4..], &[0u8; 4]);
    }

    #[test]
    fn test_realloc_smaller() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.write(b"abcdefgh").unwrap();
        let block2 = alloc.realloc(block, 4).unwrap();
        assert_eq!(block2.len(), 4);
        assert!(block2.verify().unwrap());
        assert_eq!(block2.read().unwrap(), b"abcd");
    }
}
