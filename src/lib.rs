//! Checksummed persistent blocks built on top of [`bstack`](https://docs.rs/bstack).
//!
//! # Overview
//!
//! `bblock` wraps any [`BStackAllocator`] and appends a 4-byte checksum to
//! every allocation. Two checksum strategies are available:
//!
//! | Module              | Checksum | Update strategy              | Use when                            |
//! |---------------------|----------|------------------------------|-------------------------------------|
//! | [`checksum::crc`]   | CRC32    | Full-block recompute         | Detection strength matters most     |
//! | [`checksum::xor`]   | XOR      | Incremental (changed bytes only) | Write throughput matters most   |
//!
//! Both modules expose the same API shape. All types are re-exported at
//! [`checksum`] (e.g. [`checksum::BCrcBlock`]) and at the
//! crate root for backward compatibility.
//!
//! # Composability
//!
//! Both allocator wrappers implement [`bstack::BStackAllocator`] themselves,
//! so they can be used in any generic context that accepts `T: BStackAllocator`.
//! This is what allows [`BCrcBlock`] and [`BXorBlock`] to implement
//! [`bstack::BStackGuardedSlice`] without requiring the stricter
//! `BStackSliceAllocator` bound.
//!
//! The wrappers can be composed freely:
//!
//! ```rust,no_run
//! use bstack::{BStack, LinearBStackAllocator};
//! use bblock::checksum::{BCrcBlockAllocator, BXorBlockAllocator};
//!
//! let stack = BStack::open("data.bstk").unwrap();
//! // XOR checksum over CRC32-checksummed blocks
//! let alloc = BXorBlockAllocator::new(BCrcBlockAllocator::new(LinearBStackAllocator::new(stack)));
//! ```
//!
//! # bstack `guarded` feature
//!
//! When bstack is built with the `guarded` feature (enabled by default in this
//! crate), all four concrete types implement [`bstack::BStackGuardedSlice`]:
//! [`BCrcBlock`], [`BCrcBlockView`], [`BXorBlock`], and [`BXorBlockView`]. The view
//! types additionally implement [`bstack::BStackGuardedSliceSubview`].
//!
//! * `as_slice()` returns the data region only (the checksum trailer is hidden;
//!   for views, only the view's sub-range is exposed).
//! * `write()` and `zero()` automatically keep the checksum consistent.
//!   `BCrcBlock`/`BCrcBlockView` recompute the full CRC32; `BXorBlock`/`BXorBlockView`
//!   update incrementally.
//! * `len()`, `is_empty()` (block types) and `len()`, `is_empty()`, `read()`,
//!   `write()`, `zero()` (view types) are provided by the trait — callers must
//!   `use bstack::BStackGuardedSlice`.
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
//! use bstack::{BStack, BStackAllocator, BStackGuardedSlice, LinearBStackAllocator};
//! use bblock::BCrcBlockAllocator;
//!
//! let stack = BStack::open("data.bstk").unwrap();
//! let alloc = BCrcBlockAllocator::new(LinearBStackAllocator::new(stack));
//!
//! let block = alloc.alloc(16).unwrap();
//! block.view().write(b"hello, bblock!!!").unwrap();
//! assert!(block.verify().unwrap());
//! ```
//!
//! ## XOR (faster writes)
//!
//! ```rust,no_run
//! use bstack::{BStack, BStackAllocator, BStackGuardedSlice, LinearBStackAllocator};
//! use bblock::checksum::BXorBlockAllocator;
//!
//! let stack = BStack::open("data.bstk").unwrap();
//! let alloc = BXorBlockAllocator::new(LinearBStackAllocator::new(stack));
//!
//! let block = alloc.alloc(16).unwrap();
//! block.view().write(b"hello, bblock!!!").unwrap();
//! assert!(block.verify().unwrap());
//! ```

pub mod checksum;
pub mod compress;
pub mod crypt;

// Backwards compatibility: re-export submodules at their old paths.
pub use checksum::crc;
pub use checksum::xor;

use bstack::{BStackAllocator, BStackSlice, BStackSliceAllocator};

/// Retrieves the start offset of an inner allocation without consuming it.
///
/// Implemented for [`bstack::BStackSlice`] (base case) and for the block
/// types produced by each wrapper allocator (recursive case).
pub(crate) trait BlockStart {
    fn block_start(&self) -> u64;
}

impl<'a, A: BStackAllocator> BlockStart for BStackSlice<'a, A> {
    fn block_start(&self) -> u64 {
        self.start()
    }
}

/// Reconstructs an inner allocation handle from a raw `BStackSlice`.
///
/// # Safety
///
/// `slice` must be an allocation previously returned by `Self::alloc` or
/// `Self::realloc` — passing an arbitrary slice is undefined behavior.
pub(crate) unsafe trait BStackRawAllocator: BStackAllocator {
    unsafe fn from_raw<'a>(slice: BStackSlice<'a, Self>) -> Self::Allocated<'a>;
}

// Every BStackSliceAllocator is trivially a BStackRawAllocator because
// its allocated type IS the slice.
unsafe impl<A: BStackSliceAllocator> BStackRawAllocator for A {
    unsafe fn from_raw<'a>(slice: BStackSlice<'a, A>) -> BStackSlice<'a, A> {
        slice
    }
}

pub use checksum::{
    BCrcBlock, BCrcBlockAllocator, BCrcBlockReader, BCrcBlockView, BCrcBlockWriter, BXorBlock,
    BXorBlockAllocator, BXorBlockReader, BXorBlockView, BXorBlockWriter, CHECKSUM_LENGTH,
};

#[deprecated(since = "0.3.0", note = "Renamed to BCrcBlockAllocator")]
pub type BBlockAllocator<A> = BCrcBlockAllocator<A>;
#[deprecated(since = "0.3.0", note = "Renamed to BCrcBlock")]
pub type BBlock<'a, A> = BCrcBlock<'a, A>;
#[deprecated(since = "0.3.0", note = "Renamed to BCrcBlockView")]
pub type BBlockView<'a, A> = BCrcBlockView<'a, A>;
#[deprecated(since = "0.3.0", note = "Renamed to BCrcBlockReader")]
pub type BBlockReader<'a, A> = BCrcBlockReader<'a, A>;
#[deprecated(since = "0.3.0", note = "Renamed to BCrcBlockWriter")]
pub type BBlockWriter<'a, A> = BCrcBlockWriter<'a, A>;
