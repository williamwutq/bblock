# bblock

`bblock` wraps [`bstack`](https://crates.io/crates/bstack) allocators to provide
persistent, checksummed blocks. Every allocation carries a 4-byte CRC32 trailer;
`verify()` tells you at any time whether the stored bytes match the checksum.

[![Crates.io](https://img.shields.io/crates/v/bblock)](https://crates.io/crates/bblock)
[![Docs.rs](https://img.shields.io/docsrs/bblock)](https://docs.rs/bblock)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

## Features

- **Transparent checksumming** — allocate as usual; the 4-byte CRC32 trailer is
  managed automatically by the safe API.
- **Sub-range views** — `BBlockView::subview(start, end)` lets you operate on a
  named field of a record; writes still update the full-block checksum.
- **Cursor-based I/O** — `BBlockReader` and `BBlockWriter` implement
  `io::Read`/`io::Write`/`io::Seek` with the same checksum guarantees.
- **Allocator-agnostic** — `BBlockAllocator<A>` works with any
  `A: BStackAllocator`; no concrete allocator is imported by this crate.

---

## Quick start

Add to `Cargo.toml`:

```toml
[dependencies]
bblock = "0.1"
bstack = { version = ">=0.1.6", features = ["alloc", "set"] }
```

```rust,no_run
use bstack::{BStack, LinearBStackAllocator};
use bblock::BBlockAllocator;

// Open (or create) a bstack file and wrap the allocator.
let stack = BStack::open("data.bstk").unwrap();
let alloc = BBlockAllocator::new(LinearBStackAllocator::new(stack));

// Allocate a 16-byte block.  On disk it occupies 20 bytes (16 + 4 checksum).
let block = alloc.alloc(16).unwrap();
let view = block.view();

view.write(b"hello, bblock!!!").unwrap();
assert!(view.verify().unwrap()); // checksum is valid

// Sub-range views update the full-block checksum automatically.
view.subview(0, 5).write(b"world").unwrap();
assert!(block.verify().unwrap()); // still valid; full block was re-checksummed

// Cursor-based writer.
use std::io::Write;
let mut w = block.writer();
w.write_all(b"cursor  write!!!").unwrap();
assert!(block.verify().unwrap());
```

---

## API overview

| Type                  | Description                                                   |
|-----------------------|---------------------------------------------------------------|
| `BBlockAllocator<A>`  | Wraps `A: BStackAllocator`; `alloc`, `realloc`, `dealloc`     |
| `BBlock<'a, A>`       | Checksummed block handle; `Copy`; source of views and cursors |
| `BBlockView<'a, A>`   | Safe read/write window; supports `subview`                    |
| `BBlockReader<'a, A>` | `io::Read + io::Seek` over the view's data range              |
| `BBlockWriter<'a, A>` | `io::Write + io::Seek`; recomputes checksum after every write |
| `CHECKSUM_LENGTH`     | `4` — the CRC32 trailer size in bytes                         |

### `BBlock<'a, A>`

```rust
impl<'a, A: BStackAllocator> BBlock<'a, A> {
    // Dimensions
    pub fn len(&self) -> u64;
    pub fn is_empty(&self) -> bool;

    // Serialisation
    pub fn to_bytes(&self) -> [u8; 16];
    pub fn from_bytes(allocator: &'a A, bytes: [u8; 16]) -> Self;

    // Integrity
    pub fn checksum(&self) -> io::Result<u32>;
    pub fn verify(&self) -> io::Result<bool>;

    // Safe access
    pub fn view(&self) -> BBlockView<'a, A>;
    pub fn reader(&self) -> BBlockReader<'a, A>;
    pub fn reader_at(&self, offset: u64) -> BBlockReader<'a, A>;
    pub fn writer(&self) -> BBlockWriter<'a, A>;
    pub fn writer_at(&self, offset: u64) -> BBlockWriter<'a, A>;

    // Unsafe escape hatch — checksum is no longer tracked
    pub unsafe fn into_slice(self) -> BStackSlice<'a, A>;
}
```

### `BBlockView<'a, A>`

```rust
impl<'a, A: BStackAllocator> BBlockView<'a, A> {
    pub fn new(block: &BBlock<'a, A>) -> Self;

    // Dimensions (relative to this view's range)
    pub fn len(&self) -> u64;
    pub fn is_empty(&self) -> bool;

    // Sub-range — coordinates are relative to this view's start
    pub fn subview(&self, start: u64, end: u64) -> Self;

    // Read (from this view's range)
    pub fn read(&self) -> io::Result<Vec<u8>>;
    pub fn read_into(&self, buf: &mut [u8]) -> io::Result<()>;
    pub fn read_range_into(&self, start: u64, buf: &mut [u8]) -> io::Result<()>;

    // Write (to this view's range; always recomputes the full-block checksum)
    pub fn write(&self, data: &[u8]) -> io::Result<()>;
    pub fn write_range(&self, start: u64, data: &[u8]) -> io::Result<()>;
    pub fn zero(&self) -> io::Result<()>;
    pub fn zero_range(&self, start: u64, n: u64) -> io::Result<()>;

    // Integrity (always over the full block, not just this view's range)
    pub fn checksum(&self) -> io::Result<u32>;
    pub fn verify(&self) -> io::Result<bool>;

    // Cursors
    pub fn reader(&self) -> BBlockReader<'a, A>;
    pub fn reader_at(&self, offset: u64) -> BBlockReader<'a, A>;
    pub fn writer(&self) -> BBlockWriter<'a, A>;
    pub fn writer_at(&self, offset: u64) -> BBlockWriter<'a, A>;
}
```

---

## Limitations and caveats

**This crate detects corruption; it does not repair it.**  
`verify()` returning `false` means the data should not be trusted, but `bblock`
provides no mechanism to restore a previous good value.

**Checksumming is not part of the allocator's recovery strategy.**  
`bstack`'s crash recovery operates on committed-length metadata, independently
of `bblock`'s checksums. The recovery strategies of different allocators vary.
If you need checksum-based recovery baked into the allocator itself, use an
allocator that natively supports it.

**`unsafe` code, direct `bstack` writes, and buggy allocators are not covered.**  
The checksum is maintained only when you write through the safe API
(`BBlockView`, `BBlockWriter`). Writing through a raw `BStackSlice` from
`BBlock::into_slice`, using bstack directly on the same region, or relying on
a buggy allocator will all produce stale or incorrect checksums.

**If the checksum itself is corrupted, `verify()` cannot help you.**  
CRC32 catches the vast majority of real-world corruption scenarios, but it is
not a cryptographic guarantee. If both data and checksum are overwritten
consistently (e.g., a device returning all-zeros), `verify()` may return `true`
for corrupted data. For applications requiring strong consistency guarantees,
checksums are a useful building block but are not a substitute for write-ahead
logs, copy-on-write, two-phase commit, or other proper recovery strategies.

**Avoid double-wrapping small blocks.**  
Embedding a serialised `BBlock` reference (16 bytes) inside another `BBlock`
is valid, but the 4-byte checksum overhead is proportionally significant for
small payloads. Prefer coarser-grained checksumming for small structures.

---

## License

MIT — see [LICENSE](LICENSE).
