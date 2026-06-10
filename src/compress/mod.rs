//! Transparent compression block types.
//!
//! This module provides compression wrappers for persistent blocks:
//! - [`lzma2`] — LZMA2 (high ratio, dictionary-based; built on the `lzma-rust2` crate)
//!
//! Unlike checksum or crypt wrappers, the on-disk size of a compressed payload
//! is data-dependent. To keep the allocation model fixed-size (so block handles
//! remain `Copy` and offsets are stable), each allocator reserves `n + overhead`
//! bytes on disk for `alloc(n)`. The block header records whether the stored
//! payload is compressed or stored raw, so incompressible data falls back to
//! raw storage within the same `n`-byte reservation.
//!
//! All block types are re-exported at this level for convenience:
//!
//! ```rust,no_run
//! use bblock::compress::BLZMA2BlockAllocator;
//! ```

pub mod lzma2;

pub use lzma2::{
    BLZMA2Block, BLZMA2BlockAllocator, BLZMA2BlockReader, BLZMA2BlockWriter, LZMA2_OVERHEAD,
};
