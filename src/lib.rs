//! Checksummed persistent blocks built on top of [`bstack`](https://docs.rs/bstack).
//!
//! # Overview
//!
//! `bblock` wraps any [`BStackAllocator`] and appends a 4-byte checksum to
//! every allocation. Two checksum strategies are available:
//!
//! | Module        | Checksum | Update strategy              | Use when                            |
//! |---------------|----------|------------------------------|-------------------------------------|
//! | [`crc`]       | CRC32    | Full-block recompute         | Detection strength matters most     |
//! | [`xor`]       | XOR      | Incremental (changed bytes only) | Write throughput matters most   |
//!
//! Both modules expose the same API shape. CRC types ([`BBlockAllocator`],
//! [`BBlock`], [`BBlockView`], [`BBlockReader`], [`BBlockWriter`]) are
//! re-exported at the crate root for backward compatibility.
//!
//! # Detection, not recovery
//!
//! `bblock` only **detects** corruption — it does not repair or revert. A
//! `verify()` returning `false` means the data must not be trusted, but the
//! crate provides no mechanism to restore a previous good value.
//!
//! # Quick start
//!
//! ## CRC32 (default, stronger integrity)
//!
//! ```rust,no_run
//! use bstack::{BStack, LinearBStackAllocator};
//! use bblock::BBlockAllocator;
//!
//! let stack = BStack::open("data.bstk").unwrap();
//! let alloc = BBlockAllocator::new(LinearBStackAllocator::new(stack));
//!
//! let block = alloc.alloc(16).unwrap();
//! block.view().write(b"hello, bblock!!!").unwrap();
//! assert!(block.verify().unwrap());
//! ```
//!
//! ## XOR (faster writes)
//!
//! ```rust,no_run
//! use bstack::{BStack, LinearBStackAllocator};
//! use bblock::xor::BXorBlockAllocator;
//!
//! let stack = BStack::open("data.bstk").unwrap();
//! let alloc = BXorBlockAllocator::new(LinearBStackAllocator::new(stack));
//!
//! let block = alloc.alloc(16).unwrap();
//! block.view().write(b"hello, bblock!!!").unwrap();
//! assert!(block.verify().unwrap());
//! ```

pub mod crc;
pub mod xor;

// Backward-compatible re-exports of the CRC32 types at the crate root.
pub use crc::{BBlock, BBlockAllocator, BBlockReader, BBlockView, BBlockWriter, CHECKSUM_LENGTH};
pub use xor::{BXorBlock, BXorBlockAllocator, BXorBlockReader, BXorBlockView, BXorBlockWriter};
