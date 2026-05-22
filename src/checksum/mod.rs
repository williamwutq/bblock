//! Checksum algorithms for block integrity verification.
//!
//! This module provides multiple checksum implementations:
//! - [`crc`] — CRC32 checksums (industry standard, robust)
//! - [`xor`] — XOR checksums (fast, simple, incremental updates)
//!
//! All types are re-exported at this level for convenience:
//!
//! ```rust,no_run
//! use bblock::checksum::{BCrcBlockAllocator, BXorBlockAllocator};
//! ```

pub mod crc;
pub mod xor;

pub use crc::{
    BCrcBlock, BCrcBlockAllocator, BCrcBlockReader, BCrcBlockView, BCrcBlockWriter, CHECKSUM_LENGTH,
};
pub use xor::{BXorBlock, BXorBlockAllocator, BXorBlockReader, BXorBlockView, BXorBlockWriter};
