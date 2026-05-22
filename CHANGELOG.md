# Changelog

All notable changes to `bblock` will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **`checksum` module** — `crc` and `xor` are now sub-modules of a unified
  `bblock::checksum` module. All types are re-exported at `bblock::checksum`
  so the preferred import style is now:
  ```rust
  use bblock::checksum::{BCrcBlockAllocator, BXorBlockAllocator};
  // or individual types:
  use bblock::checksum::BCrcBlock;
  ```
  The sub-modules remain accessible as `bblock::checksum::crc` and
  `bblock::checksum::xor` for explicit qualification when needed.

### Changed

- **`BCrcBlock*` rename** *(semver-breaking)* — all CRC32 types have been renamed
  to make the checksum algorithm explicit and align with `BXorBlock*` naming:
  - `BBlock` → `BCrcBlock`
  - `BBlockAllocator` → `BCrcBlockAllocator`
  - `BBlockView` → `BCrcBlockView`
  - `BBlockReader` → `BCrcBlockReader`
  - `BBlockWriter` → `BCrcBlockWriter`

  The old names are still available as `#[deprecated]` type aliases and will be
  removed in a future release. To migrate, find-and-replace the names above and
  update imports accordingly (`use bblock::checksum::BCrcBlockAllocator`).
- **`bblock::crc` and `bblock::xor` re-exported for backwards compatibility** —
  existing imports such as `use bblock::crc::BCrcBlock` or
  `use bblock::xor::BXorBlockAllocator` continue to compile unchanged.
  These re-exports will be removed in a future release; prefer
  `bblock::checksum::crc` / `bblock::checksum::xor` or the flat
  `bblock::checksum::*` re-exports.

---

## [0.2.1] - 2026-06-19

### Added

- **Allocator composability** — `BCrcBlockAllocator` and `BXorBlockAllocator` can
  now be stacked inside each other. The inner allocator constraint is relaxed
  from `BStackSliceAllocator` to `BStackAllocator` with two crate-internal
  helper traits (`BStackRawAllocator`, `BlockStart`).
- **`BStackGuardedSlice` impls for view types** — `BCrcBlockView` and
  `BXorBlockView` now implement `bstack::BStackGuardedSlice`:
  - `as_slice()` returns the bytes covered by this view (not the full block).
  - `write()` and `zero()` maintain the block checksum: full CRC32 recompute
    for `BCrcBlockView`, incremental XOR delta for `BXorBlockView`.
  - `read()`, `len()`, and `is_empty()` are provided by the trait's defaults
    and no longer need to be inherent (see **Changed** below).
- **`BStackGuardedSliceSubview` impls** — `BCrcBlockView` and `BXorBlockView` now
  implement `bstack::BStackGuardedSliceSubview`, enabling them to be used in
  generic contexts constrained on `T: BStackGuardedSliceSubview`. The inherent
  `subview()` method is retained and preferred for direct calls; the trait impl
  is additive.

### Changed

- **`len()` and `is_empty()` removed from inherent impls of `BCrcBlock` and
  `BXorBlock`** *(semver-breaking — callers must bring `bstack::BStackGuardedSlice`
  into scope to call these methods)*. The implementations are identical; the
  trait is the single source now.
- **`len()`, `is_empty()`, `read()`, `write()`, and `zero()` removed from
  inherent impls of `BCrcBlockView` and `BXorBlockView`** *(semver-breaking —
  same requirement: `use bstack::BStackGuardedSlice`)*. These are now provided
  by the `BStackGuardedSlice` impl described above.

---

## [0.2.0] - 2026-05-15

### Added

- **XOR checksum module** (`xor`) — XOR-based checksummed blocks with
  incremental checksum updates for improved write performance.
  - `BXorBlockAllocator<A>` — wraps any `A: BStackAllocator`; appends a
    4-byte XOR checksum to every allocation.
  - `BXorBlock<'a, A>` — `Copy + Clone` handle with layout
    `[data: len bytes][xor: 4 bytes LE]`. Provides `verify`, `checksum`,
    `view`, `reader`, `reader_at`, `writer`, `writer_at`, `to_bytes`,
    `from_bytes`, and the unsafe escape hatch `into_slice`.
  - `BXorBlockView<'a, A>` — read/write window with `subview` support; all
    writes update the checksum **incrementally** (only the changed bytes are
    re-read, not the full block).
  - `BXorBlockReader<'a, A>` — cursor-based `io::Read + io::Seek`.
  - `BXorBlockWriter<'a, A>` — cursor-based `io::Write + io::Seek`; updates
    the XOR checksum incrementally after every write.
  - `xor::CHECKSUM_LENGTH: u64 = 4`.
  - XOR types re-exported at the crate root alongside the CRC32 types.
- **`BStackAllocator` impls** — both `BCrcBlockAllocator<A>` and
  `BXorBlockAllocator<A>` now implement `bstack::BStackAllocator` with
  `Allocated<'_>` set to the corresponding block type. This makes the
  allocator wrappers usable in any generic context that accepts
  `T: BStackAllocator`, and is what enables the `BStackGuardedSlice` impls
  (see below). Note: the wrappers cannot be stacked inside each other because
  each requires its inner `A` to satisfy `BStackSliceAllocator`.
- **`TryInto<BStackSlice>` impls** — `BCrcBlock` and `BXorBlock` implement
  `TryInto<BStackSlice<'_, Self::Allocator>>` to satisfy the
  `BStackAllocator::Allocated` bound. Both conversions are infallible.
- **`BStackGuardedSlice` impls** (requires bstack `guarded` feature) —
  `BCrcBlock` and `BXorBlock` implement `bstack::BStackGuardedSlice`:
  - `as_slice()` returns the data region only; the checksum trailer is hidden.
  - `write()` writes data and recomputes the checksum. `BCrcBlock` does a full
    CRC32 recompute; `BXorBlock` applies an incremental XOR delta.
  - `zero()` zeroes the data region and updates the checksum accordingly.

### Changed

- **Dependency: bstack `0.1` → `0.2`** *(semver-breaking — forces downstream
  crates using bstack directly to also upgrade to `0.2`)*. bblock's own API
  surface has no breaking changes in this release; all modifications below are
  backward-compatible relaxations or additions.
- **Allocator bounds relaxed** — `BCrcBlock`, `BCrcBlockView`, `BCrcBlockReader`,
  `BCrcBlockWriter`, and their XOR counterparts now accept any
  `A: BStackAllocator` rather than the stricter `A: BStackSliceAllocator`.
  All existing code continues to compile unchanged.
- `Copy` and `Clone` for `BCrcBlock`, `BCrcBlockView`, `BXorBlock`, and
  `BXorBlockView` are now implemented manually (without `#[derive]`) so that
  the impls do not impose spurious `A: Copy + Clone` bounds on the inner
  allocator type. All existing code continues to compile unchanged.

### Dependencies

- [`bstack`](https://crates.io/crates/bstack) updated to `0.2` with
  `features = ["alloc", "set", "guarded"]`
- [`crc32fast`](https://crates.io/crates/crc32fast) `1.5` (unchanged)

---

## [0.1.0] - 2026-04-27

Initial release.

### Added

- `BCrcBlockAllocator<A>` — generic wrapper over any `A: BStackAllocator` that
  appends a 4-byte CRC32 checksum to every allocation. Exposes `alloc`,
  `realloc`, and `dealloc` mirroring the inner allocator's interface, plus
  `inner` and `into_inner` accessors.
- `BCrcBlock<'a, A>` — `Copy + Clone` handle to a checksummed allocation with
  layout `[data: len bytes][crc32: 4 bytes LE]`. Provides `verify`,
  `checksum`, `view`, `reader`, `reader_at`, `writer`, `writer_at`,
  `to_bytes`, `from_bytes`, and the unsafe escape hatch `into_slice`.
- `BCrcBlockView<'a, A>` — `Copy + Clone` read/write window over a sub-range of a
  block's usable data. All writes recompute the CRC32 over the full block.
  Supports `subview(start, end)` for relative sub-range access; sub-views share
  the same checksum slot and the same `verify()` scope as the parent block.
  Provides `read`, `read_into`, `read_range_into`, `write`, `write_range`,
  `zero`, `zero_range`, `checksum`, `verify`, `reader`, `reader_at`, `writer`,
  and `writer_at`.
- `BCrcBlockReader<'a, A>` — cursor-based `io::Read + io::Seek` scoped to a
  view's data range. Implements `PartialEq`, `Eq`, `Hash`, `PartialOrd`, `Ord`
  within itself and cross-type with `BCrcBlockWriter`.
- `BCrcBlockWriter<'a, A>` — cursor-based `io::Write + io::Seek` that
  automatically recomputes the full-block CRC32 after every write, including
  writes through a sub-range view. Implements `PartialEq`, `Eq`, `Hash`,
  `PartialOrd`, `Ord` within itself and cross-type with `BCrcBlockReader`.
- `CHECKSUM_LENGTH: u64 = 4` — public constant for the CRC32 trailer size.

### Dependencies

- [`bstack`](https://crates.io/crates/bstack) `>=0.1.6` with
  `features = ["alloc", "set"]`
- [`crc32fast`](https://crates.io/crates/crc32fast) `1.5`
