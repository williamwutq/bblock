//! ChaCha20-Poly1305 authenticated-encryption blocks.
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
//! | Type                      | Role                                                         |
//! |---------------------------|--------------------------------------------------------------|
//! | [`BChaChaBlockAllocator`] | Wraps a `BStackAllocator`; produces [`BChaChaBlock`]s        |
//! | [`BChaChaBlock`]          | Encrypted block handle; source of readers and writers        |
//! | [`BChaChaBlockReader`]    | Cursor-based `io::Read + io::Seek` over decrypted plaintext  |
//! | [`BChaChaBlockWriter`]    | Buffered `io::Write + io::Seek`; encrypts on `flush()`/drop  |
//!
//! # On-disk format
//!
//! ```text
//! [algo: 4 bytes = b"CC20"][nonce: 12 bytes][ciphertext: n bytes][tag: 16 bytes]
//! ```
//!
//! Total overhead: [`CHACHA_OVERHEAD`] = 32 bytes per block.
//!
//! # Security
//!
//! ChaCha20-Poly1305 is an AEAD cipher.  The authentication tag covers both
//! the ciphertext and the nonce, so any tampering with any byte of the stored
//! block is detected on the next read or [`BChaChaBlock::verify`].
//!
//! **Nonce uniqueness is critical**: never reuse the same (key, nonce) pair for
//! different plaintexts.  The [`BChaChaBlockAllocator`] calls the provided
//! `nonce_gen` function for every fresh encryption (each `write` / `alloc` /
//! size-changing `realloc`); it is the caller's responsibility to supply a
//! generator that returns unique nonces (e.g. a CSPRNG).
//!
//! # Detection, not recovery
//!
//! A failed [`BChaChaBlock::verify`] or a decryption error means the data must
//! not be trusted.  This module provides no repair or rollback mechanism.

use crate::{BStackRawAllocator, BlockStart};
use bstack::{BStack, BStackAllocator, BStackGuardedSlice, BStackGuardedSliceSubview, BStackSlice};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::marker::PhantomData;

/// Four-byte magic identifying the ChaCha20-Poly1305 algorithm.
const CHACHA_MAGIC: &[u8; 4] = b"CC20";

/// Number of extra bytes stored per block:
/// 4 (magic) + 12 (nonce) + 16 (tag).
pub const CHACHA_OVERHEAD: u64 = 32;

// ── Allocator ────────────────────────────────────────────────────────────────

/// Wraps any [`BStackAllocator`] and transparently encrypts every allocation
/// with ChaCha20-Poly1305.
///
/// Each allocation stores [`CHACHA_OVERHEAD`] (32) extra bytes on disk, so
/// `alloc(n)` allocates `n + 32` bytes in the underlying stack.
///
/// The `nonce_gen` function is called for every fresh encryption.  It must
/// return a unique 12-byte nonce; use a CSPRNG in production code.
pub struct BChaChaBlockAllocator<A: BStackAllocator> {
    inner: A,
    key: [u8; 32],
    nonce_gen: fn() -> [u8; 12],
}

impl<A: BStackAllocator> BChaChaBlockAllocator<A> {
    /// Create a new allocator wrapping `inner`.
    ///
    /// `key` is the 256-bit ChaCha20-Poly1305 key used for all blocks.
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

/// A handle to a ChaCha20-Poly1305 encrypted block.
///
/// **Backing layout:** `[b"CC20": 4][nonce: 12][ciphertext: len][tag: 16]`
///
/// `BChaChaBlock` is `Copy`: every copy refers to the same physical region.
///
/// ## Reading and writing
///
/// Use the inherent [`read`](BChaChaBlock::read) method to decrypt and return
/// the full plaintext.  For streaming I/O use [`reader`](BChaChaBlock::reader)
/// and [`writer`](BChaChaBlock::writer).
///
/// [`BStackGuardedSlice::write`] and [`BStackGuardedSlice::zero`] are also
/// available (requires `use bstack::BStackGuardedSlice`).  `as_slice()` is
/// intentionally unsupported — exposing raw ciphertext as a plaintext slice
/// has no safe semantics.
///
/// ## Integrity
///
/// [`verify`](BChaChaBlock::verify) attempts a full decryption; it returns
/// `Ok(false)` (not `Err`) if the authentication tag fails, so callers can
/// distinguish corruption from I/O errors.
pub struct BChaChaBlock<'a, A: BStackAllocator> {
    slice: BStackSlice<'a, A>,
    len: u64,
    key: [u8; 32],
    nonce_gen: fn() -> [u8; 12],
}

impl<'a, A: BStackAllocator> Copy for BChaChaBlock<'a, A> {}

impl<'a, A: BStackAllocator> Clone for BChaChaBlock<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, A: BStackAllocator> fmt::Debug for BChaChaBlock<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BChaChaBlock")
            .field("start", &self.slice.start())
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> PartialEq for BChaChaBlock<'a, A> {
    fn eq(&self, other: &Self) -> bool {
        self.slice == other.slice && self.len == other.len
    }
}

impl<'a, A: BStackAllocator> Eq for BChaChaBlock<'a, A> {}

impl<'a, A: BStackAllocator> Hash for BChaChaBlock<'a, A> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.slice.hash(state);
        self.len.hash(state);
    }
}

impl<'a, A: BStackAllocator> PartialOrd for BChaChaBlock<'a, A> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a, A: BStackAllocator> Ord for BChaChaBlock<'a, A> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.slice.cmp(&other.slice).then(self.len.cmp(&other.len))
    }
}

impl<'a, A: BStackAllocator> From<BChaChaBlock<'a, A>> for [u8; 16] {
    fn from(block: BChaChaBlock<'a, A>) -> [u8; 16] {
        block.to_bytes()
    }
}

impl<'a, A: BStackAllocator> BChaChaBlock<'a, A> {
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
    pub fn reader(&self) -> io::Result<BChaChaBlockReader<'a, A>> {
        Ok(BChaChaBlockReader {
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
    pub fn writer(&self) -> io::Result<BChaChaBlockWriter<'a, A>> {
        Ok(BChaChaBlockWriter {
            block: *self,
            buf: self.decrypt_read()?,
            pos: 0,
            dirty: false,
        })
    }

    /// Return a [`BChaChaBlockView`] covering the full plaintext region.
    ///
    /// The view can be narrowed with [`BChaChaBlockView::subview`].
    pub fn view(&self) -> BChaChaBlockView<'a, A> {
        BChaChaBlockView {
            block: *self,
            start: 0,
            end: self.len,
        }
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
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|_| io::Error::other("ChaCha20 encryption failed"))?;
        self.slice.subslice(0, 4).write(*CHACHA_MAGIC)?;
        self.slice.subslice(4, 16).write(nonce_bytes)?;
        self.slice
            .subslice(16, self.len + CHACHA_OVERHEAD)
            .write(&ct)
    }

    fn decrypt_read(&self) -> io::Result<Vec<u8>> {
        let mut magic = [0u8; 4];
        self.slice.subslice(0, 4).read_into(&mut magic)?;
        if &magic != CHACHA_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "wrong algo magic: expected CC20",
            ));
        }
        let mut nonce_bytes = [0u8; 12];
        self.slice.subslice(4, 16).read_into(&mut nonce_bytes)?;
        let ct = self.slice.subslice(16, self.len + CHACHA_OVERHEAD).read()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ct.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ChaCha20 decryption failed"))
    }
}

// Reconstruct a block reference from a 16-byte serialized handle.
// Requires the allocator type to be BChaChaBlockAllocator so we can recover
// the key and nonce_gen.
#[allow(private_bounds)]
impl<'a, A> BChaChaBlock<'a, BChaChaBlockAllocator<A>>
where
    A: BStackAllocator<Error = io::Error> + BStackRawAllocator,
    for<'b> A::Allocated<'b>: BlockStart + Copy,
{
    /// Reconstruct a block from a 16-byte array produced by
    /// [`BChaChaBlock::to_bytes`].
    pub fn from_bytes(allocator: &'a BChaChaBlockAllocator<A>, bytes: [u8; 16]) -> Self {
        let offset = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let len = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        BChaChaBlock {
            slice: unsafe { BStackSlice::from_raw_parts(allocator, offset, len + CHACHA_OVERHEAD) },
            len,
            key: allocator.key,
            nonce_gen: allocator.nonce_gen,
        }
    }
}

// ── View ─────────────────────────────────────────────────────────────────────

/// A read/write sub-range view over a [`BChaChaBlock`].
///
/// A full-range view is obtained via [`BChaChaBlock::view`];
/// a sub-range via [`BChaChaBlockView::subview`]. All coordinates are
/// **relative** to the current view's start.
///
/// ## Write semantics
///
/// Because ChaCha20-Poly1305 is a full-block AEAD cipher, every write —
/// even a single byte — decrypts the full plaintext, patches the covered
/// range, and re-encrypts with a fresh nonce. The authentication tag always
/// covers the entire block.
///
/// ## `BStackGuardedSlice` and `BStackGuardedSliceSubview`
///
/// `BChaChaBlockView` implements [`bstack::BStackGuardedSlice`]: `write()`
/// and `zero()` operate on the view's sub-range while re-encrypting the full
/// block. `as_slice()` is intentionally unsupported. It also implements
/// [`bstack::BStackGuardedSliceSubview`] for use in generic guarded-I/O
/// contexts.
pub struct BChaChaBlockView<'a, A: BStackAllocator> {
    block: BChaChaBlock<'a, A>,
    start: u64,
    end: u64,
}

impl<'a, A: BStackAllocator> Copy for BChaChaBlockView<'a, A> {}

impl<'a, A: BStackAllocator> Clone for BChaChaBlockView<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, A: BStackAllocator> fmt::Debug for BChaChaBlockView<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BChaChaBlockView")
            .field("start", &self.start)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> PartialEq for BChaChaBlockView<'a, A> {
    fn eq(&self, other: &Self) -> bool {
        self.block == other.block && self.start == other.start && self.end == other.end
    }
}

impl<'a, A: BStackAllocator> Eq for BChaChaBlockView<'a, A> {}

impl<'a, A: BStackAllocator> Hash for BChaChaBlockView<'a, A> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.block.hash(state);
        self.start.hash(state);
        self.end.hash(state);
    }
}

impl<'a, A: BStackAllocator> PartialOrd for BChaChaBlockView<'a, A> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a, A: BStackAllocator> Ord for BChaChaBlockView<'a, A> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.block
            .cmp(&other.block)
            .then(self.start.cmp(&other.start))
            .then(self.end.cmp(&other.end))
    }
}

impl<'a, A: BStackAllocator> BChaChaBlockView<'a, A> {
    /// Return a view covering `[start, end)` within this view's coordinate space.
    ///
    /// Coordinates are relative: `subview(0, 3)` on a view starting at byte 5
    /// produces a view covering bytes 5–7 of the block's plaintext.
    pub fn subview(&self, start: u64, end: u64) -> Self {
        BChaChaBlockView {
            block: self.block,
            start: self.start + start,
            end: self.start + end,
        }
    }

    /// Return `true` if the block decrypts and authenticates successfully.
    pub fn verify(&self) -> io::Result<bool> {
        self.block.verify()
    }

    /// Decrypt and return the bytes covered by this view.
    pub fn read(&self) -> io::Result<Vec<u8>> {
        let plaintext = self.block.decrypt_read()?;
        Ok(plaintext[self.start as usize..self.end as usize].to_vec())
    }

    fn patch_and_encrypt(&self, data: &[u8]) -> io::Result<()> {
        let mut plaintext = self.block.decrypt_read()?;
        plaintext[self.start as usize..self.end as usize].copy_from_slice(data);
        self.block.encrypt_write(&plaintext)
    }

    fn zero_and_encrypt(&self) -> io::Result<()> {
        let mut plaintext = self.block.decrypt_read()?;
        plaintext[self.start as usize..self.end as usize].fill(0);
        self.block.encrypt_write(&plaintext)
    }
}

impl<'a, A: BStackAllocator + 'a> BStackGuardedSliceSubview<'a, A> for BChaChaBlockView<'a, A> {
    fn subview(&self, start: u64, end: u64) -> impl BStackGuardedSliceSubview<'a, A> + '_ {
        BChaChaBlockView {
            block: self.block,
            start: self.start + start,
            end: self.start + end,
        }
    }
}

impl<'a, A: BStackAllocator + 'a> BStackGuardedSlice<'a, A> for BChaChaBlockView<'a, A> {
    fn len(&self) -> u64 {
        self.end - self.start
    }

    unsafe fn raw_block(&self) -> BStackSlice<'a, A> {
        self.block.slice
    }

    // as_slice() left at default — ciphertext has no safe plaintext mapping

    fn write(&self, data: impl AsRef<[u8]>) -> io::Result<()> {
        self.patch_and_encrypt(data.as_ref())
    }

    fn zero(&self) -> io::Result<()> {
        self.zero_and_encrypt()
    }
}

// ── Reader ───────────────────────────────────────────────────────────────────

/// A cursor-based reader over the decrypted plaintext of a [`BChaChaBlock`].
///
/// The full plaintext is decrypted once at construction time and held in an
/// in-memory buffer.  `Read` and `Seek` operations work on that buffer; no
/// further I/O is performed.
///
/// Constructed via [`BChaChaBlock::reader`].
pub struct BChaChaBlockReader<'a, A: BStackAllocator> {
    buf: Vec<u8>,
    pos: usize,
    _marker: PhantomData<BChaChaBlock<'a, A>>,
}

impl<'a, A: BStackAllocator> fmt::Debug for BChaChaBlockReader<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BChaChaBlockReader")
            .field("len", &self.buf.len())
            .field("pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> io::Read for BChaChaBlockReader<'a, A> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.buf.len().saturating_sub(self.pos);
        let n = buf.len().min(remaining);
        buf[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<'a, A: BStackAllocator> io::Seek for BChaChaBlockReader<'a, A> {
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

/// A buffered writer over the plaintext of a [`BChaChaBlock`].
///
/// On construction the current plaintext is decrypted into an in-memory
/// buffer.  `Write` and `Seek` operate on that buffer.  When
/// [`flush`](io::Write::flush) is called (or the writer is dropped), the
/// buffer is re-encrypted with a fresh nonce and written back to disk.
///
/// Drop silently discards flush errors; call [`flush`](io::Write::flush)
/// explicitly if you need to observe errors.
///
/// Constructed via [`BChaChaBlock::writer`].
pub struct BChaChaBlockWriter<'a, A: BStackAllocator> {
    block: BChaChaBlock<'a, A>,
    buf: Vec<u8>,
    pos: usize,
    dirty: bool,
}

impl<'a, A: BStackAllocator> fmt::Debug for BChaChaBlockWriter<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BChaChaBlockWriter")
            .field("len", &self.buf.len())
            .field("pos", &self.pos)
            .field("dirty", &self.dirty)
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> io::Write for BChaChaBlockWriter<'a, A> {
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

impl<'a, A: BStackAllocator> io::Seek for BChaChaBlockWriter<'a, A> {
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

impl<'a, A: BStackAllocator> Drop for BChaChaBlockWriter<'a, A> {
    fn drop(&mut self) {
        let _ = io::Write::flush(self);
    }
}

// ── BStackAllocator impl ─────────────────────────────────────────────────────

impl<A> BStackAllocator for BChaChaBlockAllocator<A>
where
    A: BStackAllocator<Error = io::Error> + BStackRawAllocator,
    for<'a> A::Allocated<'a>: BlockStart + Copy,
{
    type Error = io::Error;
    type Allocated<'a>
        = BChaChaBlock<'a, BChaChaBlockAllocator<A>>
    where
        A: 'a;

    fn stack(&self) -> &BStack {
        self.inner.stack()
    }

    fn into_stack(self) -> BStack {
        self.inner.into_stack()
    }

    fn alloc(&self, len: u64) -> io::Result<BChaChaBlock<'_, BChaChaBlockAllocator<A>>> {
        let inner = self.inner.alloc(len + CHACHA_OVERHEAD)?;
        let offset = inner.block_start();
        let slice = unsafe { BStackSlice::from_raw_parts(self, offset, len + CHACHA_OVERHEAD) };
        let block = BChaChaBlock {
            slice,
            len,
            key: self.key,
            nonce_gen: self.nonce_gen,
        };
        // Initialise to encrypted zeros so any read before the first write is valid.
        block.encrypt_write(&vec![0u8; len as usize])?;
        Ok(block)
    }

    fn realloc<'a>(
        &'a self,
        block: BChaChaBlock<'a, BChaChaBlockAllocator<A>>,
        new_len: u64,
    ) -> io::Result<BChaChaBlock<'a, BChaChaBlockAllocator<A>>> {
        let offset = block.slice.start();
        let inner_old_slice = unsafe {
            BStackSlice::from_raw_parts(&self.inner, offset, block.len + CHACHA_OVERHEAD)
        };
        let inner_old: A::Allocated<'_> = unsafe { A::from_raw(inner_old_slice) };

        if new_len == block.len {
            // Same size: move raw bytes unchanged — no crypto work needed.
            let inner_new = self.inner.realloc(inner_old, new_len + CHACHA_OVERHEAD)?;
            let new_offset = inner_new.block_start();
            let slice =
                unsafe { BStackSlice::from_raw_parts(self, new_offset, new_len + CHACHA_OVERHEAD) };
            return Ok(BChaChaBlock {
                slice,
                len: new_len,
                key: block.key,
                nonce_gen: block.nonce_gen,
            });
        }

        // Size change: decrypt → resize → inner realloc → re-encrypt with fresh nonce.
        let mut plaintext = block.decrypt_read()?;
        let inner_new = self.inner.realloc(inner_old, new_len + CHACHA_OVERHEAD)?;
        let new_offset = inner_new.block_start();
        let new_slice =
            unsafe { BStackSlice::from_raw_parts(self, new_offset, new_len + CHACHA_OVERHEAD) };
        let new_block = BChaChaBlock {
            slice: new_slice,
            len: new_len,
            key: block.key,
            nonce_gen: block.nonce_gen,
        };
        plaintext.resize(new_len as usize, 0);
        new_block.encrypt_write(&plaintext)?;
        Ok(new_block)
    }

    fn dealloc(&self, block: BChaChaBlock<'_, BChaChaBlockAllocator<A>>) -> io::Result<()> {
        let offset = block.slice.start();
        let inner_slice = unsafe {
            BStackSlice::from_raw_parts(&self.inner, offset, block.len + CHACHA_OVERHEAD)
        };
        let inner: A::Allocated<'_> = unsafe { A::from_raw(inner_slice) };
        self.inner.dealloc(inner)
    }
}

impl<'a, A> TryInto<BStackSlice<'a, BChaChaBlockAllocator<A>>>
    for BChaChaBlock<'a, BChaChaBlockAllocator<A>>
where
    A: BStackAllocator<Error = io::Error> + BStackRawAllocator,
    for<'b> A::Allocated<'b>: BlockStart + Copy,
{
    type Error = std::convert::Infallible;

    fn try_into(self) -> Result<BStackSlice<'a, BChaChaBlockAllocator<A>>, Self::Error> {
        Ok(self.slice)
    }
}

impl<'a, A: BStackAllocator> BlockStart for BChaChaBlock<'a, A> {
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
impl<'a, A: BStackAllocator + 'a> BStackGuardedSlice<'a, A> for BChaChaBlock<'a, A> {
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
        // A trivially unique nonce for tests (not safe for production).
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

    fn make_allocator() -> (BChaChaBlockAllocator<LinearBStackAllocator>, NamedTempFile) {
        let file = NamedTempFile::new().unwrap();
        let stack = BStack::open(file.path()).unwrap();
        let key = [0x42u8; 32];
        let alloc =
            BChaChaBlockAllocator::new(LinearBStackAllocator::new(stack), key, counter_nonce());
        (alloc, file)
    }

    #[test]
    fn test_alloc_len() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(30).unwrap();
        assert_eq!(block.len(), 30);
        let raw_len = unsafe { block.into_slice().len() };
        assert_eq!(raw_len, 30 + CHACHA_OVERHEAD);
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
        // Corrupt the ciphertext bytes.
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
        // Overwrite the magic bytes.
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
        let block2 = BChaChaBlock::from_bytes(&alloc, bytes);
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
            // No explicit flush — rely on Drop.
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

    #[test]
    fn test_view_read_full() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.write(b"abcdefgh").unwrap();
        let view = block.view();
        assert_eq!(view.len(), 8);
        assert_eq!(view.read().unwrap(), b"abcdefgh");
    }

    #[test]
    fn test_view_read_subrange() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.write(b"abcdefgh").unwrap();
        let sub = block.view().subview(2, 6);
        assert_eq!(sub.len(), 4);
        assert_eq!(sub.read().unwrap(), b"cdef");
    }

    #[test]
    fn test_view_write_subrange() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.write(b"abcdefgh").unwrap();
        block.view().subview(2, 5).write(b"XYZ").unwrap();
        assert!(block.verify().unwrap());
        assert_eq!(block.read().unwrap(), b"abXYZfgh");
    }

    #[test]
    fn test_view_zero_subrange() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.write(b"abcdefgh").unwrap();
        block.view().subview(3, 6).zero().unwrap();
        assert!(block.verify().unwrap());
        assert_eq!(block.read().unwrap(), b"abc\x00\x00\x00gh");
    }

    #[test]
    fn test_view_subview_nested() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(8).unwrap();
        block.write(b"abcdefgh").unwrap();
        // subview [2, 6) then [1, 3) of that → block bytes [3, 5)
        let sub = block.view().subview(2, 6).subview(1, 3);
        assert_eq!(sub.len(), 2);
        assert_eq!(sub.read().unwrap(), b"de");
        sub.write(b"XY").unwrap();
        assert!(block.verify().unwrap());
        assert_eq!(block.read().unwrap(), b"abcXYfgh");
    }

    #[test]
    fn test_view_verify() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(4).unwrap();
        block.write(b"test").unwrap();
        assert!(block.view().verify().unwrap());
        let raw = unsafe { block.into_slice() };
        let mut b = [0u8; 1];
        raw.subslice(16, 17).read_into(&mut b).unwrap();
        b[0] ^= 0xff;
        raw.subslice(16, 17).write(b).unwrap();
        assert!(!block.view().verify().unwrap());
    }
}
