# Changelog

All notable changes to `bblock` will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
