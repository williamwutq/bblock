//! LZMA2-compressed persistent blocks.
//!
//! # Overview
//!
//! This module wraps any [`BStackAllocator`] and stores every allocation as a
//! self-describing LZMA2-compressed payload (with a raw-storage fallback for
//! incompressible data). Reads decompress transparently; writes compress with
//! the allocator's configured preset.
//!
//! Unlike the [`crate::crypt`] wrappers — whose ciphertext is always the same
//! length as the plaintext — compressed payloads have a data-dependent size.
//! `alloc(n)` reserves `n + LZMA2_OVERHEAD` bytes on disk: `n` is both the
//! apparent capacity (`len()`) and the on-disk payload budget. On write, the
//! plaintext is compressed and the result is stored if it fits within `n`
//! bytes; otherwise the plaintext itself is stored raw if it fits within `n`
//! bytes; otherwise the write fails. [`BStackGuardedSlice::write`] truncates
//! its input to `n` bytes first, so it always fits via the raw fallback.
//!
//! The main types:
//!
//! | Type                     | Role                                                    |
//! |--------------------------|---------------------------------------------------------|
//! | [`BLZMA2BlockAllocator`] | Wraps a `BStackAllocator`; produces [`BLZMA2Block`]s    |
//! | [`BLZMA2Block`]          | Compressed block handle; source of readers and writers  |
//! | [`BLZMA2BlockReader`]    | Cursor `io::Read + io::Seek` over decompressed plaintext|
//! | [`BLZMA2BlockWriter`]    | Buffered `io::Write + io::Seek`; recompresses on flush  |
//!
//! # On-disk format
//!
//! ```text
//! [magic: 4 bytes = b"LZM2"]
//! [flag: 1 byte]               // 0 = raw, 1 = LZMA2-compressed
//! [plaintext_len: 4 bytes LE]  // decompressed payload length
//! [payload_len: 4 bytes LE]    // bytes occupied by the payload region
//! [payload: payload_len bytes] // compressed stream (flag=1) or raw plaintext (flag=0)
//! [unused: padding up to n bytes]
//! ```
//!
//! Total overhead: [`LZMA2_OVERHEAD`] = 13 bytes per block.
//!
//! # BStackGuardedSlice hooks
//!
//! The implementation uses the hook protocol of [`bstack::BStackGuardedSlice`]:
//! `post_read` decompresses raw disk bytes into plaintext, and `pre_write`
//! compresses plaintext into the framed on-disk representation. The default
//! `read()` and `write()` from the trait therefore work correctly without
//! being overridden.  `zero()` is overridden to store an empty-plaintext frame.
//!
//! # Detection, not recovery
//!
//! A failed [`BLZMA2Block::verify`] or a decompression error means the data
//! must not be trusted. This module provides no repair or rollback mechanism.

use crate::{BStackRawAllocator, BlockStart};
use bstack::{BStack, BStackAllocator, BStackGuardedSlice, BStackSlice};
use lzma_rust2::{Lzma2Options, Lzma2Reader, Lzma2Writer};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{self, Read as _, Write as _};
use std::marker::PhantomData;

/// Four-byte magic identifying the LZMA2 algorithm.
const LZMA2_MAGIC: &[u8; 4] = b"LZM2";

/// Storage flag: payload is the raw plaintext.
const FLAG_RAW: u8 = 0;
/// Storage flag: payload is an LZMA2-compressed stream.
const FLAG_COMPRESSED: u8 = 1;

/// Number of extra bytes stored per block:
/// 4 (magic) + 1 (flag) + 4 (plaintext_len) + 4 (payload_len).
pub const LZMA2_OVERHEAD: u64 = 13;

// ── Allocator ────────────────────────────────────────────────────────────────

/// Wraps any [`BStackAllocator`] and transparently compresses every allocation
/// with LZMA2.
///
/// `preset` selects the LZMA2 compression level (0–9; 6 is the LZMA default).
/// `alloc(n)` reserves `n + LZMA2_OVERHEAD` bytes on disk: `n` is both the
/// apparent capacity and the on-disk payload budget shared by the compressed
/// stream and the raw fallback.
pub struct BLZMA2BlockAllocator<A: BStackAllocator> {
    inner: A,
    preset: u32,
}

impl<A: BStackAllocator> BLZMA2BlockAllocator<A> {
    /// Create a new allocator wrapping `inner`.
    ///
    /// `preset` is the LZMA2 compression preset (0–9). Higher values compress
    /// harder; values above 9 are clamped to 9 by `lzma-rust2`.
    pub fn new(inner: A, preset: u32) -> Self {
        Self { inner, preset }
    }

    /// Return a shared reference to the inner allocator.
    pub fn inner(&self) -> &A {
        &self.inner
    }

    /// Consume the wrapper and return the inner allocator.
    pub fn into_inner(self) -> A {
        self.inner
    }

    /// The LZMA2 preset used for all blocks produced by this allocator.
    pub fn preset(&self) -> u32 {
        self.preset
    }
}

// ── Block handle ─────────────────────────────────────────────────────────────

/// A handle to an LZMA2-compressed block.
///
/// **Backing layout:** `[b"LZM2": 4][flag: 1][plaintext_len: 4 LE][payload_len: 4 LE][payload]`
///
/// `BLZMA2Block` is `Copy`: every copy refers to the same physical region.
///
/// ## Capacity model
///
/// `n` is the on-disk payload capacity declared at `alloc(n)` time, shared by
/// the compressed stream and the raw fallback: a write is stored compressed
/// if the compressed stream fits in `n` bytes, otherwise stored raw if the
/// plaintext itself fits in `n` bytes, otherwise the write fails.
/// Writes through [`BStackGuardedSlice::write`] are silently truncated to `n`
/// bytes before compression, so they always fit via the raw fallback. For
/// writes that must not be silently truncated, use [`BLZMA2BlockWriter`]
/// which fails explicitly when the buffer cannot fit after compression.
///
/// ## Reading and writing
///
/// Use [`read`](BLZMA2Block::read) to decompress and return the full plaintext.
/// For streaming I/O use [`reader`](BLZMA2Block::reader) and
/// [`writer`](BLZMA2Block::writer).
///
/// [`BStackGuardedSlice::write`] and [`BStackGuardedSlice::zero`] are also
/// available (requires `use bstack::BStackGuardedSlice`). `as_slice()` is
/// intentionally unsupported — exposing compressed bytes as a plaintext slice
/// has no safe semantics.
///
/// ## Integrity
///
/// [`verify`](BLZMA2Block::verify) attempts a full decompression; it returns
/// `Ok(false)` (not `Err`) if the magic byte or compressed stream is corrupt,
/// so callers can distinguish corruption from I/O errors.
pub struct BLZMA2Block<'a, A: BStackAllocator> {
    slice: BStackSlice<'a, A>,
    /// `n` — the on-disk payload capacity passed to `alloc(n)`.
    n: u64,
    preset: u32,
}

impl<'a, A: BStackAllocator> Copy for BLZMA2Block<'a, A> {}

impl<'a, A: BStackAllocator> Clone for BLZMA2Block<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, A: BStackAllocator> fmt::Debug for BLZMA2Block<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BLZMA2Block")
            .field("start", &self.slice.start())
            .field("n", &self.n)
            .field("preset", &self.preset)
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> PartialEq for BLZMA2Block<'a, A> {
    fn eq(&self, other: &Self) -> bool {
        self.slice == other.slice && self.n == other.n
    }
}

impl<'a, A: BStackAllocator> Eq for BLZMA2Block<'a, A> {}

impl<'a, A: BStackAllocator> Hash for BLZMA2Block<'a, A> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.slice.hash(state);
        self.n.hash(state);
    }
}

impl<'a, A: BStackAllocator> PartialOrd for BLZMA2Block<'a, A> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a, A: BStackAllocator> Ord for BLZMA2Block<'a, A> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.slice.cmp(&other.slice).then(self.n.cmp(&other.n))
    }
}

impl<'a, A: BStackAllocator> From<BLZMA2Block<'a, A>> for [u8; 16] {
    fn from(block: BLZMA2Block<'a, A>) -> [u8; 16] {
        block.to_bytes()
    }
}

impl<'a, A: BStackAllocator> BLZMA2Block<'a, A> {
    /// Serialize this block reference as a 16-byte array `[offset: u64 LE | n: u64 LE]`.
    ///
    /// `n` is the on-disk payload capacity declared at allocation time;
    /// [`BLZMA2Block::from_bytes`] reconstructs the disk reservation from it
    /// as `n + LZMA2_OVERHEAD`.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.slice.start().to_le_bytes());
        out[8..].copy_from_slice(&self.n.to_le_bytes());
        out
    }

    /// The on-disk payload capacity `n` declared at `alloc(n)` time.
    pub fn capacity(&self) -> u64 {
        self.n
    }

    /// Return `true` if the block decompresses successfully (magic matches,
    /// header is well-formed, and any compressed payload decodes cleanly).
    ///
    /// Returns `Ok(false)` for corruption, `Err` for I/O errors.
    pub fn verify(&self) -> io::Result<bool> {
        match self.decompress_read() {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Decompress and return the full plaintext.
    pub fn read(&self) -> io::Result<Vec<u8>> {
        self.decompress_read()
    }

    /// Return a cursor-based reader over the decompressed plaintext.
    ///
    /// The full block is decompressed once on construction; subsequent reads
    /// and seeks operate on the in-memory buffer.
    pub fn reader(&self) -> io::Result<BLZMA2BlockReader<'a, A>> {
        Ok(BLZMA2BlockReader {
            buf: self.decompress_read()?,
            pos: 0,
            _marker: PhantomData,
        })
    }

    /// Return a buffered writer over the plaintext.
    ///
    /// The current plaintext is decompressed into an in-memory buffer on
    /// construction. Writes and seeks modify the buffer only. The buffer is
    /// recompressed (or written raw if compression does not help) and stored
    /// when [`flush`](io::Write::flush) is called or when the writer is dropped.
    /// Unlike [`BStackGuardedSlice::write`], the writer does **not** truncate
    /// the buffer and returns [`io::ErrorKind::InvalidInput`] if it cannot fit.
    pub fn writer(&self) -> io::Result<BLZMA2BlockWriter<'a, A>> {
        Ok(BLZMA2BlockWriter {
            block: *self,
            buf: self.decompress_read()?,
            pos: 0,
            dirty: false,
        })
    }

    /// Consume the block and return the raw underlying [`BStackSlice`].
    ///
    /// # Safety
    ///
    /// Any mutation through the returned slice bypasses the compression
    /// framing and will corrupt the stored payload.
    pub unsafe fn into_slice(self) -> BStackSlice<'a, A> {
        self.slice
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Compress `plaintext`, frame it with the on-disk header, and return the
    /// framed bytes (without padding). Falls back to raw storage when the
    /// compressed output would exceed `n` bytes. Returns `InvalidInput` if
    /// neither path fits.
    fn compress_frame(&self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let disk_payload = self.n;
        let compressed = lzma2_compress(plaintext, self.preset)?;

        let (flag, payload): (u8, &[u8]) = if (compressed.len() as u64) <= disk_payload {
            (FLAG_COMPRESSED, compressed.as_slice())
        } else if (plaintext.len() as u64) <= disk_payload {
            (FLAG_RAW, plaintext)
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "LZMA2 block: plaintext ({} B) compressed to {} B, \
                     neither fits in {} B payload capacity",
                    plaintext.len(),
                    compressed.len(),
                    disk_payload
                ),
            ));
        };

        let plaintext_len: u32 = plaintext
            .len()
            .try_into()
            .map_err(|_| io::Error::other("LZMA2 block: plaintext exceeds u32::MAX"))?;
        let payload_len: u32 = payload
            .len()
            .try_into()
            .map_err(|_| io::Error::other("LZMA2 block: payload exceeds u32::MAX"))?;

        let mut out = Vec::with_capacity(LZMA2_OVERHEAD as usize + payload.len());
        out.extend_from_slice(LZMA2_MAGIC);
        out.push(flag);
        out.extend_from_slice(&plaintext_len.to_le_bytes());
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Frame `plaintext` and write it to the underlying slice.
    fn compress_write(&self, plaintext: &[u8]) -> io::Result<()> {
        let framed = self.compress_frame(plaintext)?;
        self.slice.subslice(0, framed.len() as u64).write(&framed)
    }

    /// Parse the on-disk header and decompress from an in-memory `raw` buffer
    /// (as returned by reading the full underlying slice).
    fn decompress_raw(&self, raw: &[u8]) -> io::Result<Vec<u8>> {
        if raw.len() < LZMA2_OVERHEAD as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZMA2 block: slice too short to contain header",
            ));
        }
        if &raw[..4] != LZMA2_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZMA2 block: wrong magic, expected LZM2",
            ));
        }
        let flag = raw[4];
        let plaintext_len = u32::from_le_bytes(raw[5..9].try_into().unwrap()) as u64;
        let payload_len = u32::from_le_bytes(raw[9..13].try_into().unwrap()) as u64;

        let end = (LZMA2_OVERHEAD + payload_len) as usize;
        if end > raw.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZMA2 block: payload_len exceeds slice",
            ));
        }
        let payload = &raw[LZMA2_OVERHEAD as usize..end];

        match flag {
            FLAG_RAW => {
                if payload.len() as u64 != plaintext_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "LZMA2 block: raw payload length disagrees with plaintext_len",
                    ));
                }
                Ok(payload.to_vec())
            }
            FLAG_COMPRESSED => {
                let expected = plaintext_len
                    .try_into()
                    .map_err(|_| io::Error::other("LZMA2 block: plaintext_len exceeds usize"))?;
                let out = lzma2_decompress(payload, self.preset, expected)?;
                if out.len() as u64 != plaintext_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "LZMA2 block: decompressed length disagrees with plaintext_len",
                    ));
                }
                Ok(out)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LZMA2 block: unknown storage flag",
            )),
        }
    }

    /// Read the full underlying slice from disk and decompress.
    fn decompress_read(&self) -> io::Result<Vec<u8>> {
        let raw = self.slice.read()?;
        self.decompress_raw(&raw)
    }

    /// Write the header for an empty plaintext (raw, length 0).
    fn init_empty(&self) -> io::Result<()> {
        let mut header = [0u8; LZMA2_OVERHEAD as usize];
        header[..4].copy_from_slice(LZMA2_MAGIC);
        header[4] = FLAG_RAW;
        // plaintext_len = 0, payload_len = 0 — both already zeroed.
        self.slice.subslice(0, LZMA2_OVERHEAD).write(header)
    }
}

// Reconstruct a block reference from a 16-byte serialized handle.
// Requires the allocator type to be BLZMA2BlockAllocator so we can recover
// the preset.
#[allow(private_bounds)]
impl<'a, A> BLZMA2Block<'a, BLZMA2BlockAllocator<A>>
where
    A: BStackAllocator<Error = io::Error> + BStackRawAllocator,
    for<'b> A::Allocated<'b>: BlockStart + Copy,
{
    /// Reconstruct a block from a 16-byte array produced by
    /// [`BLZMA2Block::to_bytes`].
    pub fn from_bytes(allocator: &'a BLZMA2BlockAllocator<A>, bytes: [u8; 16]) -> Self {
        let offset = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let n = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        let disk_len = n + LZMA2_OVERHEAD;
        BLZMA2Block {
            slice: unsafe { BStackSlice::from_raw_parts(allocator, offset, disk_len) },
            n,
            preset: allocator.preset,
        }
    }
}

// ── Reader ───────────────────────────────────────────────────────────────────

/// A cursor-based reader over the decompressed plaintext of a [`BLZMA2Block`].
///
/// The full plaintext is decompressed once at construction and held in an
/// in-memory buffer. `Read` and `Seek` operations work on that buffer; no
/// further I/O is performed.
///
/// Constructed via [`BLZMA2Block::reader`].
pub struct BLZMA2BlockReader<'a, A: BStackAllocator> {
    buf: Vec<u8>,
    pos: usize,
    _marker: PhantomData<BLZMA2Block<'a, A>>,
}

impl<'a, A: BStackAllocator> fmt::Debug for BLZMA2BlockReader<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BLZMA2BlockReader")
            .field("len", &self.buf.len())
            .field("pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> io::Read for BLZMA2BlockReader<'a, A> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.buf.len().saturating_sub(self.pos);
        let n = buf.len().min(remaining);
        buf[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<'a, A: BStackAllocator> io::Seek for BLZMA2BlockReader<'a, A> {
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

/// A buffered writer over the plaintext of a [`BLZMA2Block`].
///
/// On construction the current plaintext is decompressed into an in-memory
/// buffer. `Write` and `Seek` operate on that buffer; the buffer grows as
/// needed. When [`flush`](io::Write::flush) is called (or the writer is
/// dropped), the buffer is recompressed and written back to disk, falling
/// back to raw storage if compression does not help.
///
/// Unlike [`BStackGuardedSlice::write`], the writer does **not** silently
/// truncate the buffer: flush returns [`io::ErrorKind::InvalidInput`] if the
/// buffer cannot fit (neither compressed nor raw) within the block's
/// reservation.
///
/// Drop silently discards flush errors; call [`flush`](io::Write::flush)
/// explicitly if you need to observe errors.
///
/// Constructed via [`BLZMA2Block::writer`].
pub struct BLZMA2BlockWriter<'a, A: BStackAllocator> {
    block: BLZMA2Block<'a, A>,
    buf: Vec<u8>,
    pos: usize,
    dirty: bool,
}

impl<'a, A: BStackAllocator> fmt::Debug for BLZMA2BlockWriter<'a, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BLZMA2BlockWriter")
            .field("len", &self.buf.len())
            .field("pos", &self.pos)
            .field("dirty", &self.dirty)
            .finish_non_exhaustive()
    }
}

impl<'a, A: BStackAllocator> io::Write for BLZMA2BlockWriter<'a, A> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let end = self.pos + data.len();
        if end > self.buf.len() {
            self.buf.resize(end, 0);
        }
        self.buf[self.pos..end].copy_from_slice(data);
        self.pos = end;
        self.dirty = true;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.dirty {
            self.block.compress_write(&self.buf)?;
            self.dirty = false;
        }
        Ok(())
    }
}

impl<'a, A: BStackAllocator> io::Seek for BLZMA2BlockWriter<'a, A> {
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

impl<'a, A: BStackAllocator> Drop for BLZMA2BlockWriter<'a, A> {
    fn drop(&mut self) {
        let _ = io::Write::flush(self);
    }
}

// ── BStackAllocator impl ─────────────────────────────────────────────────────

impl<A> BStackAllocator for BLZMA2BlockAllocator<A>
where
    A: BStackAllocator<Error = io::Error> + BStackRawAllocator,
    for<'a> A::Allocated<'a>: BlockStart + Copy,
{
    type Error = io::Error;
    type Allocated<'a>
        = BLZMA2Block<'a, BLZMA2BlockAllocator<A>>
    where
        A: 'a;

    fn stack(&self) -> &BStack {
        self.inner.stack()
    }

    fn into_stack(self) -> BStack {
        self.inner.into_stack()
    }

    fn alloc(&self, n: u64) -> io::Result<BLZMA2Block<'_, BLZMA2BlockAllocator<A>>> {
        let disk_len = n + LZMA2_OVERHEAD;
        let inner = self.inner.alloc(disk_len)?;
        let offset = inner.block_start();
        let slice = unsafe { BStackSlice::from_raw_parts(self, offset, disk_len) };
        let block = BLZMA2Block {
            slice,
            n,
            preset: self.preset,
        };
        block.init_empty()?;
        Ok(block)
    }

    fn realloc<'a>(
        &'a self,
        block: BLZMA2Block<'a, BLZMA2BlockAllocator<A>>,
        new_n: u64,
    ) -> io::Result<BLZMA2Block<'a, BLZMA2BlockAllocator<A>>> {
        let offset = block.slice.start();
        let old_disk_len = block.n + LZMA2_OVERHEAD;
        let new_disk_len = new_n + LZMA2_OVERHEAD;

        let inner_old_slice =
            unsafe { BStackSlice::from_raw_parts(&self.inner, offset, old_disk_len) };
        let inner_old: A::Allocated<'_> = unsafe { A::from_raw(inner_old_slice) };

        if new_n == block.n {
            let inner_new = self.inner.realloc(inner_old, new_disk_len)?;
            let new_offset = inner_new.block_start();
            let slice = unsafe { BStackSlice::from_raw_parts(self, new_offset, new_disk_len) };
            return Ok(BLZMA2Block {
                slice,
                n: new_n,
                preset: block.preset,
            });
        }

        // Size change: decompress → inner realloc → re-frame at new size.
        let plaintext = block.decompress_read()?;
        let inner_new = self.inner.realloc(inner_old, new_disk_len)?;
        let new_offset = inner_new.block_start();
        let new_slice = unsafe { BStackSlice::from_raw_parts(self, new_offset, new_disk_len) };
        let new_block = BLZMA2Block {
            slice: new_slice,
            n: new_n,
            preset: block.preset,
        };
        // Truncate plaintext if it cannot fit the new capacity.
        let truncated = if plaintext.len() as u64 > new_n {
            &plaintext[..new_n as usize]
        } else {
            &plaintext[..]
        };
        new_block.compress_write(truncated)?;
        Ok(new_block)
    }

    fn dealloc(&self, block: BLZMA2Block<'_, BLZMA2BlockAllocator<A>>) -> io::Result<()> {
        let offset = block.slice.start();
        let disk_len = block.n + LZMA2_OVERHEAD;
        let inner_slice = unsafe { BStackSlice::from_raw_parts(&self.inner, offset, disk_len) };
        let inner: A::Allocated<'_> = unsafe { A::from_raw(inner_slice) };
        self.inner.dealloc(inner)
    }
}

impl<'a, A> TryInto<BStackSlice<'a, BLZMA2BlockAllocator<A>>>
    for BLZMA2Block<'a, BLZMA2BlockAllocator<A>>
where
    A: BStackAllocator<Error = io::Error> + BStackRawAllocator,
    for<'b> A::Allocated<'b>: BlockStart + Copy,
{
    type Error = std::convert::Infallible;

    fn try_into(self) -> Result<BStackSlice<'a, BLZMA2BlockAllocator<A>>, Self::Error> {
        Ok(self.slice)
    }
}

impl<'a, A: BStackAllocator> BlockStart for BLZMA2Block<'a, A> {
    fn block_start(&self) -> u64 {
        self.slice.start()
    }
}

// ── BStackGuardedSlice impl ───────────────────────────────────────────────────

/// * `len()` returns `n`, the on-disk payload capacity declared at `alloc(n)`
///   — the apparent data capacity for this block. The default `write()`
///   truncates its input to `n` bytes before calling `pre_write`; since the
///   raw fallback fits any plaintext of `n` bytes or fewer, the truncated
///   write always succeeds.
/// * `post_read` decompresses raw on-disk bytes into plaintext via the
///   [`decompress_raw`](BLZMA2Block::decompress_raw) helper.
/// * `pre_write` compresses plaintext and frames it for disk via
///   [`compress_frame`](BLZMA2Block::compress_frame); because the default
///   `write()` pre-truncates data to `len()` = `n` bytes, the frame always fits.
/// * `zero()` is overridden to store an empty-plaintext frame rather than
///   compressing a buffer of zeros.
/// * `as_slice()` is intentionally unsupported (exposing compressed bytes has
///   no safe plaintext semantics); the default implementation from bstack
///   signals this.
impl<'a, A: BStackAllocator + 'a> BStackGuardedSlice<'a, A> for BLZMA2Block<'a, A> {
    fn len(&self) -> u64 {
        self.n
    }

    unsafe fn raw_block(&self) -> BStackSlice<'a, A> {
        self.slice
    }

    fn post_read<'d>(&self, data: &'d [u8]) -> io::Result<Cow<'d, [u8]>> {
        Ok(Cow::Owned(self.decompress_raw(data)?))
    }

    fn pre_write<'d>(&self, data: &'d [u8]) -> io::Result<Cow<'d, [u8]>> {
        Ok(Cow::Owned(self.compress_frame(data)?))
    }

    fn zero(&self) -> io::Result<()> {
        self.init_empty()
    }
}

// ── LZMA2 helpers ─────────────────────────────────────────────────────────────

fn lzma2_compress(plaintext: &[u8], preset: u32) -> io::Result<Vec<u8>> {
    let options = Lzma2Options::with_preset(preset);
    let mut writer = Lzma2Writer::new(Vec::new(), options);
    writer.write_all(plaintext)?;
    writer.finish()
}

fn lzma2_decompress(compressed: &[u8], preset: u32, expected_len: usize) -> io::Result<Vec<u8>> {
    let dict_size = Lzma2Options::with_preset(preset).lzma_options.dict_size;
    let mut reader = Lzma2Reader::new(compressed, dict_size, None);
    let mut out = Vec::with_capacity(expected_len);
    reader
        .read_to_end(&mut out)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(out)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bstack::{BStack, BStackAllocator, BStackGuardedSlice, LinearBStackAllocator};
    use std::io::{Read, Seek, SeekFrom, Write};
    use tempfile::NamedTempFile;

    fn make_allocator() -> (BLZMA2BlockAllocator<LinearBStackAllocator>, NamedTempFile) {
        make_allocator_with(6)
    }

    fn make_allocator_with(
        preset: u32,
    ) -> (BLZMA2BlockAllocator<LinearBStackAllocator>, NamedTempFile) {
        let file = NamedTempFile::new().unwrap();
        let stack = BStack::open(file.path()).unwrap();
        let alloc = BLZMA2BlockAllocator::new(LinearBStackAllocator::new(stack), preset);
        (alloc, file)
    }

    #[test]
    fn test_alloc_reserves_n_plus_overhead() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        // n=64 → disk = 64 + 13 = 77
        let raw_len = unsafe { block.into_slice().len() };
        assert_eq!(raw_len, 64 + LZMA2_OVERHEAD);
        assert_eq!(block.capacity(), 64);
    }

    #[test]
    fn test_empty_block_reads_empty_plaintext() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        assert!(block.verify().unwrap());
        assert_eq!(block.read().unwrap(), Vec::<u8>::new());
    }

    // BStackGuardedSlice::read() should return the same plaintext as the inherent read().
    #[test]
    fn test_guarded_read_matches_inherent_read() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        block.write(b"hello guarded").unwrap();
        let guarded: Vec<u8> = <BLZMA2Block<_> as BStackGuardedSlice<_>>::read(&block).unwrap();
        assert_eq!(guarded, b"hello guarded");
    }

    // BStackGuardedSlice::write() truncates to n=64 bytes first.
    #[test]
    fn test_write_and_read_compressible_data_via_trait() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        let data = vec![b'x'; 64]; // n = 64
        block.write(&data).unwrap();
        assert!(block.verify().unwrap());
        assert_eq!(block.read().unwrap(), data);
    }

    // The writer does NOT truncate; compressible data larger than n can be stored
    // as long as it compresses to fit within n.
    #[test]
    fn test_writer_stores_compressible_data_larger_than_n() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap(); // n = 64
        let data = vec![b'x'; 1024]; // 1024 b'x' compresses to ~20 bytes — fits easily
        {
            let mut w = block.writer().unwrap();
            w.write_all(&data).unwrap();
            w.flush().unwrap();
        }
        assert!(block.verify().unwrap());
        assert_eq!(block.read().unwrap(), data);
    }

    // Incompressible data exactly at capacity falls back to raw storage, since
    // LZMA2's framing overhead makes the compressed form larger than n.
    #[test]
    fn test_writer_raw_fallback_for_incompressible_data_at_capacity() {
        let (alloc, _f) = make_allocator(); // n = 64
        let block = alloc.alloc(64).unwrap();
        let data: Vec<u8> = (0..64u8)
            .map(|i| i.wrapping_mul(37).wrapping_add(13))
            .collect();
        {
            let mut w = block.writer().unwrap();
            w.write_all(&data).unwrap();
            w.flush().unwrap();
        }
        assert!(block.verify().unwrap());
        assert_eq!(block.read().unwrap(), data);
    }

    // BStackGuardedSlice::write() truncates to n bytes; data beyond that is dropped.
    #[test]
    fn test_guarded_write_silently_truncates_to_n() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(16).unwrap(); // n=16
        // write 200 bytes — only first n=16 survive.
        let data: Vec<u8> = (0..200u8).collect();
        block.write(&data).unwrap(); // must not error
        let back = block.read().unwrap();
        assert_eq!(back.len(), 16);
        assert_eq!(back, &data[..16]);
    }

    // The writer (unlike the trait write()) fails when data cannot fit after compression.
    #[test]
    fn test_writer_fails_when_too_large_for_both_paths() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(16).unwrap();
        // 200 random bytes; neither compresses to ≤16 nor fits raw ≤16.
        let data: Vec<u8> = (0..200u8)
            .map(|i| i.wrapping_mul(91).wrapping_add(7))
            .collect();
        let mut w = block.writer().unwrap();
        w.write_all(&data).unwrap(); // buffered — no error yet
        let err = w.flush().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_zero_resets_to_empty() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        block.write(b"some data").unwrap();
        block.zero().unwrap();
        assert!(block.verify().unwrap());
        assert_eq!(block.read().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_verify_fails_on_corrupt_magic() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        block.write(b"hello").unwrap();
        unsafe { block.into_slice() }
            .subslice(0, 4)
            .write(*b"XXXX")
            .unwrap();
        assert!(!block.verify().unwrap());
    }

    #[test]
    fn test_verify_fails_on_corrupt_payload() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        let data = vec![b'a'; 200]; // compresses, payload non-empty
        block.write(&data).unwrap();
        // Corrupt a payload byte after the header.
        let raw = unsafe { block.into_slice() };
        let byte = raw.subslice(LZMA2_OVERHEAD, LZMA2_OVERHEAD + 1);
        let mut b = [0u8; 1];
        byte.read_into(&mut b).unwrap();
        b[0] ^= 0xff;
        byte.write(b).unwrap();
        assert!(!block.verify().unwrap());
    }

    #[test]
    fn test_to_from_bytes_roundtrip() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        block.write(b"persistent payload").unwrap();
        let bytes: [u8; 16] = block.into();
        let block2 = BLZMA2Block::from_bytes(&alloc, bytes);
        assert_eq!(block2.capacity(), 64);
        assert!(block2.verify().unwrap());
        assert_eq!(block2.read().unwrap(), b"persistent payload");
    }

    #[test]
    fn test_reader() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        block.write(b"abcdefgh").unwrap();
        let mut reader = block.reader().unwrap();
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"abcdefgh");
    }

    #[test]
    fn test_reader_seek() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
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
        let block = alloc.alloc(64).unwrap();
        {
            let mut w = block.writer().unwrap();
            w.write_all(b"hello world via writer").unwrap();
            w.flush().unwrap();
        }
        assert!(block.verify().unwrap());
        assert_eq!(block.read().unwrap(), b"hello world via writer");
    }

    #[test]
    fn test_writer_drop_flushes() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        block.zero().unwrap();
        {
            let mut w = block.writer().unwrap();
            w.write_all(b"drop-flushed").unwrap();
        }
        assert_eq!(block.read().unwrap(), b"drop-flushed");
    }

    #[test]
    fn test_writer_seek_and_overwrite() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        {
            let mut w = block.writer().unwrap();
            w.write_all(b"abcdefgh").unwrap();
            w.seek(SeekFrom::Start(2)).unwrap();
            w.write_all(b"XY").unwrap();
            w.flush().unwrap();
        }
        assert_eq!(block.read().unwrap(), b"abXYefgh");
    }

    #[test]
    fn test_realloc_same_size_preserves_data() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        block.write(b"unchanged").unwrap();
        let block2 = alloc.realloc(block, 64).unwrap();
        assert_eq!(block2.capacity(), 64);
        assert_eq!(block2.read().unwrap(), b"unchanged");
    }

    #[test]
    fn test_realloc_larger_preserves_data() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        block.write(b"grow me").unwrap();
        let block2 = alloc.realloc(block, 128).unwrap();
        assert_eq!(block2.capacity(), 128);
        assert_eq!(block2.read().unwrap(), b"grow me");
    }

    #[test]
    fn test_realloc_smaller_preserves_fitting_data() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(128).unwrap();
        block.write(b"shrink me").unwrap();
        let block2 = alloc.realloc(block, 32).unwrap();
        assert_eq!(block2.capacity(), 32);
        assert_eq!(block2.read().unwrap(), b"shrink me");
    }

    #[test]
    fn test_dealloc() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(64).unwrap();
        block.write(b"data").unwrap();
        alloc.dealloc(block).unwrap();
    }

    #[test]
    fn test_len_returns_n() {
        let (alloc, _f) = make_allocator();
        let block = alloc.alloc(50).unwrap();
        // len() = n = 50, the disk payload capacity, regardless of overhead.
        assert_eq!(<BLZMA2Block<_> as BStackGuardedSlice<_>>::len(&block), 50);
    }
}
