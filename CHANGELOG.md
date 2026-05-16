# Changelog

All notable changes to `bblock` will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
- **`BStackAllocator` impls** — both `BBlockAllocator<A>` and
  `BXorBlockAllocator<A>` now implement `bstack::BStackAllocator` with
  `Allocated<'_>` set to the corresponding block type. This makes the
  allocator wrappers usable in any generic context that accepts
  `T: BStackAllocator`, and is what enables the `BStackGuardedSlice` impls
  (see below). Note: the wrappers cannot be stacked inside each other because
  each requires its inner `A` to satisfy `BStackSliceAllocator`.
- **`TryInto<BStackSlice>` impls** — `BBlock` and `BXorBlock` implement
  `TryInto<BStackSlice<'_, Self::Allocator>>` to satisfy the
  `BStackAllocator::Allocated` bound. Both conversions are infallible.
- **`BStackGuardedSlice` impls** (requires bstack `guarded` feature) —
  `BBlock` and `BXorBlock` implement `bstack::BStackGuardedSlice`:
  - `as_slice()` returns the data region only; the checksum trailer is hidden.
  - `write()` writes data and recomputes the checksum. `BBlock` does a full
    CRC32 recompute; `BXorBlock` applies an incremental XOR delta.
  - `zero()` zeroes the data region and updates the checksum accordingly.

### Changed

- **Dependency: bstack `0.1` → `0.2`** *(semver-breaking — forces downstream
  crates using bstack directly to also upgrade to `0.2`)*. bblock's own API
  surface has no breaking changes in this release; all modifications below are
  backward-compatible relaxations or additions.
- **Allocator bounds relaxed** — `BBlock`, `BBlockView`, `BBlockReader`,
  `BBlockWriter`, and their XOR counterparts now accept any
  `A: BStackAllocator` rather than the stricter `A: BStackSliceAllocator`.
  All existing code continues to compile unchanged.
- `Copy` and `Clone` for `BBlock`, `BBlockView`, `BXorBlock`, and
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

- `BBlockAllocator<A>` — generic wrapper over any `A: BStackAllocator` that
  appends a 4-byte CRC32 checksum to every allocation. Exposes `alloc`,
  `realloc`, and `dealloc` mirroring the inner allocator's interface, plus
  `inner` and `into_inner` accessors.
- `BBlock<'a, A>` — `Copy + Clone` handle to a checksummed allocation with
  layout `[data: len bytes][crc32: 4 bytes LE]`. Provides `verify`,
  `checksum`, `view`, `reader`, `reader_at`, `writer`, `writer_at`,
  `to_bytes`, `from_bytes`, and the unsafe escape hatch `into_slice`.
- `BBlockView<'a, A>` — `Copy + Clone` read/write window over a sub-range of a
  block's usable data. All writes recompute the CRC32 over the full block.
  Supports `subview(start, end)` for relative sub-range access; sub-views share
  the same checksum slot and the same `verify()` scope as the parent block.
  Provides `read`, `read_into`, `read_range_into`, `write`, `write_range`,
  `zero`, `zero_range`, `checksum`, `verify`, `reader`, `reader_at`, `writer`,
  and `writer_at`.
- `BBlockReader<'a, A>` — cursor-based `io::Read + io::Seek` scoped to a
  view's data range. Implements `PartialEq`, `Eq`, `Hash`, `PartialOrd`, `Ord`
  within itself and cross-type with `BBlockWriter`.
- `BBlockWriter<'a, A>` — cursor-based `io::Write + io::Seek` that
  automatically recomputes the full-block CRC32 after every write, including
  writes through a sub-range view. Implements `PartialEq`, `Eq`, `Hash`,
  `PartialOrd`, `Ord` within itself and cross-type with `BBlockReader`.
- `CHECKSUM_LENGTH: u64 = 4` — public constant for the CRC32 trailer size.

### Dependencies

- [`bstack`](https://crates.io/crates/bstack) `>=0.1.6` with
  `features = ["alloc", "set"]`
- [`crc32fast`](https://crates.io/crates/crc32fast) `1.5`
