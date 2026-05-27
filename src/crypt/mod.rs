//! Authenticated-encryption block types.
//!
//! This module provides transparent encryption for persistent blocks:
//! - [`chacha`] — ChaCha20-Poly1305 (fast on platforms without AES-NI)
//! - [`aes`] — AES-256-GCM (hardware-accelerated on modern CPUs)
//!
//! Both algorithms are AEAD ciphers: the authentication tag embedded in each
//! block provides integrity guarantees equivalent to a strong checksum, so no
//! separate checksum layer is needed.
//!
//! All block types are re-exported at this level for convenience:
//!
//! ```rust,no_run
//! use bblock::crypt::{BChaChaBlockAllocator, BAESBlockAllocator};
//! ```
//!
//! ## On-disk overhead
//!
//! Both formats add [`CRYPT_OVERHEAD`] (32 bytes) per block:
//! `[algo: 4][nonce: 12][ciphertext: n][tag: 16]`.

pub mod aes;
pub mod chacha;

pub use aes::{
    AES_OVERHEAD, BAESBlock, BAESBlockAllocator, BAESBlockReader, BAESBlockView, BAESBlockWriter,
};
pub use chacha::{
    BChaChaBlock, BChaChaBlockAllocator, BChaChaBlockReader, BChaChaBlockView, BChaChaBlockWriter,
    CHACHA_OVERHEAD,
};

/// Overhead in bytes added to every encrypted block (4 magic + 12 nonce + 16 tag).
pub const CRYPT_OVERHEAD: u64 = 32;
