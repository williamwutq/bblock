# bblock

`bblock` wraps [`bstack`](https://crates.io/crates/bstack) allocators to provide
persistent, checksummed blocks. Two checksum strategies are available: **CRC32**
for stronger integrity guarantees and **XOR** for faster incremental updates.
Every allocation carries a 4-byte checksum trailer; `verify()` tells you at any
time whether the stored bytes match the checksum.

[![Crates.io](https://img.shields.io/crates/v/bblock)](https://crates.io/crates/bblock)
[![Docs.rs](https://img.shields.io/docsrs/bblock)](https://docs.rs/bblock)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

## Features

- **Transparent checksumming** — allocate as usual; the 4-byte checksum trailer is
  managed automatically by the safe API.
- **Two checksum strategies** — CRC32 (`crc` module / crate root) for stronger
  error detection; XOR (`xor` module) for faster incremental updates on writes.
- **Composability** — both allocator wrappers implement `BStackAllocator`
  themselves, so they can be stacked. `BXorBlockAllocator<BCrcBlockAllocator<A>>`
  gives XOR-checksummed allocations where each inner slot is also CRC32-protected.
- **`guarded` feature** — `BCrcBlock` and `BXorBlock` implement
  `bstack::BStackGuardedSlice`. `as_slice()` hides the checksum trailer;
  `write()` and `zero()` keep the checksum consistent automatically.
- **Sub-range views** — `BCrcBlockView::subview(start, end)` lets you operate on a
  named field of a record; writes still update the full-block checksum.
- **Cursor-based I/O** — `BCrcBlockReader` and `BCrcBlockWriter` implement
  `io::Read`/`io::Write`/`io::Seek` with the same checksum guarantees.
- **Allocator-agnostic** — `BCrcBlockAllocator<A>` works with any
  `A: BStackAllocator`; no concrete allocator is imported by this crate.

---

## Quick start

Add to `Cargo.toml`:

```toml
[dependencies]
bblock = "0.2"
bstack = { version = "0.2", features = ["alloc", "set", "guarded"] }
```

```rust,no_run
use bstack::{BStack, BStackGuardedSlice, LinearBStackAllocator};
use bblock::BCrcBlockAllocator;

// Open (or create) a bstack file and wrap the allocator.
let stack = BStack::open("data.bstk").unwrap();
let alloc = BCrcBlockAllocator::new(LinearBStackAllocator::new(stack));

// Allocate a 16-byte block.  On disk it occupies 20 bytes (16 + 4 checksum).
let block = alloc.alloc(16).unwrap();
let view = block.view();

view.write(b"hello, bblock!!!").unwrap();
assert!(view.verify().unwrap()); // checksum is valid

// Sub-range views update the checksum automatically.
view.subview(0, 5).write(b"world").unwrap();
assert!(block.verify().unwrap()); // still valid; full CRC32 was recomputed

// Cursor-based writer.
use std::io::Write;
let mut w = block.writer();
w.write_all(b"cursor  write!!!").unwrap();
assert!(block.verify().unwrap());
```

---

## XOR checksum (faster writes)

XOR types are available at the crate root and in the `xor` module.

```rust,no_run
use bstack::{BStack, BStackGuardedSlice, LinearBStackAllocator};
use bblock::BXorBlockAllocator;

// Open (or create) a bstack file and wrap the allocator.
let stack = BStack::open("data.bstk").unwrap();
let alloc = BXorBlockAllocator::new(LinearBStackAllocator::new(stack));

// Allocate a 16-byte block.  On disk it occupies 20 bytes (16 + 4 checksum).
let block = alloc.alloc(16).unwrap();
let view = block.view();

view.write(b"hello, bblock!!!").unwrap();
assert!(view.verify().unwrap()); // checksum is valid

// Subview writes update the checksum incrementally (reads only changed bytes).
view.subview(0, 5).write(b"world").unwrap();
assert!(block.verify().unwrap()); // still valid; checksum updated incrementally

// Cursor-based writer.
use std::io::Write;
let mut w = block.writer();
w.write_all(b"cursor  write!!!").unwrap();
assert!(block.verify().unwrap());
```

---

## Composability

Both allocator wrappers implement `BStackAllocator` themselves, so they can be
passed to any generic API that accepts `T: BStackAllocator`. This is what
allows `BCrcBlock` and `BXorBlock` to implement `BStackGuardedSlice` without
requiring the stricter `BStackSliceAllocator` bound. The wrappers can also be
stacked inside each other:

```rust,no_run
use bstack::{BStack, LinearBStackAllocator};
use bblock::{BCrcBlockAllocator, BXorBlockAllocator};

let stack = BStack::open("data.bstk").unwrap();
// XOR checksum over CRC32-checksummed blocks
let alloc = BXorBlockAllocator::new(BCrcBlockAllocator::new(LinearBStackAllocator::new(stack)));
```

---

## bstack `guarded` feature

When bstack is built with the `guarded` feature (enabled by default in this
crate's `Cargo.toml`), all four concrete types implement
`bstack::BStackGuardedSlice`: `BCrcBlock`, `BCrcBlockView`, `BXorBlock`, and
`BXorBlockView`. The view types additionally implement
`bstack::BStackGuardedSliceSubview`.

* `as_slice()` returns the data region only (the checksum trailer is hidden;
  for views, only the view's sub-range is exposed).
* `write()` and `zero()` keep the checksum consistent automatically.
  `BCrcBlock`/`BCrcBlockView` recompute the full CRC32; `BXorBlock`/`BXorBlockView`
  update incrementally.
* `len()`, `is_empty()` (block types) and `len()`, `is_empty()`, `read()`,
  `write()`, `zero()` (view types) are provided by the trait and require
  `use bstack::BStackGuardedSlice` to be in scope.

---

## API overview

| Type                  | Description                                                          |
|-----------------------|----------------------------------------------------------------------|
| `BCrcBlockAllocator<A>`  | Wraps `A: BStackAllocator`; `alloc`, `realloc`, `dealloc`            |
| `BCrcBlock<'a, A>`       | Checksummed block handle; `Copy`; source of views and cursors        |
| `BCrcBlockView<'a, A>`   | Safe read/write window; supports `subview`                           |
| `BCrcBlockReader<'a, A>` | `io::Read + io::Seek` over the view's data range                     |
| `BCrcBlockWriter<'a, A>` | `io::Write + io::Seek`; recomputes full CRC32 after every write      |
| `CHECKSUM_LENGTH`     | `4` — the CRC32 trailer size in bytes                                |

### XOR module types (also re-exported at crate root)

| Type                     | Description                                                          |
|--------------------------|----------------------------------------------------------------------|
| `BXorBlockAllocator<A>`  | Wraps `A: BStackAllocator`; `alloc`, `realloc`, `dealloc`            |
| `BXorBlock<'a, A>`       | Checksummed block handle; `Copy`; source of views and cursors        |
| `BXorBlockView<'a, A>`   | Safe read/write window; supports `subview`                           |
| `BXorBlockReader<'a, A>` | `io::Read + io::Seek` over the view's data range                     |
| `BXorBlockWriter<'a, A>` | `io::Write + io::Seek`; updates XOR checksum incrementally           |
| `xor::CHECKSUM_LENGTH`   | `4` — the XOR checksum trailer size in bytes                         |

Both CRC and XOR block types expose the same API shape. Substitute `BXorBlock` /
`BXorBlockView` / `BXorBlockReader` / `BXorBlockWriter` for the CRC32 variants.
The only behavioural difference is that XOR checksum updates are incremental.

### `BCrcBlock<'a, A>` / `BXorBlock<'a, A>`

```rust
impl<'a, A: BStackAllocator> BCrcBlock<'a, A> {       // same for BXorBlock
    // Serialisation
    pub fn to_bytes(&self) -> [u8; 16];
    pub fn from_bytes(allocator: &'a A, bytes: [u8; 16]) -> Self;

    // Integrity
    pub fn checksum(&self) -> io::Result<u32>;
    pub fn verify(&self) -> io::Result<bool>;

    // Safe access
    pub fn view(&self) -> BCrcBlockView<'a, A>;
    pub fn reader(&self) -> BCrcBlockReader<'a, A>;
    pub fn reader_at(&self, offset: u64) -> BCrcBlockReader<'a, A>;
    pub fn writer(&self) -> BCrcBlockWriter<'a, A>;
    pub fn writer_at(&self, offset: u64) -> BCrcBlockWriter<'a, A>;

    // Unsafe escape hatch — checksum is no longer tracked
    pub unsafe fn into_slice(self) -> BStackSlice<'a, A>;
}

// requires `use bstack::BStackGuardedSlice`
impl<'a, A: BStackAllocator> BStackGuardedSlice<'a, A> for BCrcBlock<'a, A> {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool;
    fn as_slice(&self) -> io::Result<BStackSlice<'a, A>>;
    fn read(&self) -> io::Result<Vec<u8>>;
    fn write(&self, data: impl AsRef<[u8]>) -> io::Result<()>;
    fn zero(&self) -> io::Result<()>;
}
```

### `BCrcBlockView<'a, A>` / `BXorBlockView<'a, A>`

```rust
impl<'a, A: BStackAllocator> BCrcBlockView<'a, A> {   // same for BXorBlockView
    pub fn new(block: &BCrcBlock<'a, A>) -> Self;

    // Sub-range — coordinates are relative to this view's start
    pub fn subview(&self, start: u64, end: u64) -> Self;

    // Read (from this view's range)
    pub fn read_into(&self, buf: &mut [u8]) -> io::Result<()>;
    pub fn read_range_into(&self, start: u64, buf: &mut [u8]) -> io::Result<()>;

    // Write (to this view's range; always recomputes the full-block checksum)
    pub fn write_range(&self, start: u64, data: &[u8]) -> io::Result<()>;
    pub fn zero_range(&self, start: u64, n: u64) -> io::Result<()>;

    // Integrity (always over the full block, not just this view's range)
    pub fn checksum(&self) -> io::Result<u32>;
    pub fn verify(&self) -> io::Result<bool>;

    // Cursors
    pub fn reader(&self) -> BCrcBlockReader<'a, A>;
    pub fn reader_at(&self, offset: u64) -> BCrcBlockReader<'a, A>;
    pub fn writer(&self) -> BCrcBlockWriter<'a, A>;
    pub fn writer_at(&self, offset: u64) -> BCrcBlockWriter<'a, A>;
}

// requires `use bstack::BStackGuardedSlice`
impl<'a, A: BStackAllocator> BStackGuardedSlice<'a, A> for BCrcBlockView<'a, A> {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool;
    fn as_slice(&self) -> io::Result<BStackSlice<'a, A>>;
    fn read(&self) -> io::Result<Vec<u8>>;
    fn write(&self, data: impl AsRef<[u8]>) -> io::Result<()>;
    fn zero(&self) -> io::Result<()>;
}

// requires `use bstack::BStackGuardedSliceSubview`
impl<'a, A: BStackAllocator> BStackGuardedSliceSubview<'a, A> for BCrcBlockView<'a, A> {
    fn subview(&self, start: u64, end: u64) -> impl BStackGuardedSliceSubview<'a, A>;
    fn subview_range(&self, range: Range<u64>) -> impl BStackGuardedSliceSubview<'a, A>;
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
(`BCrcBlockView`, `BCrcBlockWriter`). Writing through a raw `BStackSlice` from
`BCrcBlock::into_slice`, using bstack directly on the same region, or relying on
a buggy allocator will all produce stale or incorrect checksums.

**If the checksum itself is corrupted, `verify()` cannot help you.**  
CRC32 catches the vast majority of real-world corruption scenarios, but it is
not a cryptographic guarantee. If both data and checksum are overwritten
consistently (e.g., a device returning all-zeros), `verify()` may return `true`
for corrupted data. For applications requiring strong consistency guarantees,
checksums are a useful building block but are not a substitute for write-ahead
logs, copy-on-write, two-phase commit, or other proper recovery strategies.

**Avoid double-wrapping small blocks.**  
Embedding a serialised `BCrcBlock` reference (16 bytes) inside another `BCrcBlock`
is valid, but the 4-byte checksum overhead is proportionally significant for
small payloads. Prefer coarser-grained checksumming for small structures.

---

## License

MIT — see [LICENSE](LICENSE).
