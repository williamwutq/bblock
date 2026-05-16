# Planned Features

This document outlines upcoming features planned for the `bblock` crate. These enhancements aim to improve usability, performance, and integration while maintaining the core principles of durability, crash-safety, and checksum integrity.

---

## Compression Support

**Breaking change:** No

### Motivation

Many use cases for persistent checksummed blocks involve compressible data (logs, JSON, text, serialized structures). Compression provides:

- **Reduced disk space usage** — smaller storage footprint for the same logical data
- **Lower I/O bandwidth** — less data written to and read from disk
- **Better cache efficiency** — more logical blocks fit in memory
- **Cost savings** — particularly important for cloud storage

While users can compress data before passing it to `bblock`, doing so manually has drawbacks:
- Checksumming operates on compressed bytes, making corruption detection less meaningful
- Sub-range views and cursor I/O cannot operate on logical (uncompressed) data
- No ability to choose compression strategy per block or adaptively
- Extra complexity in application code

Built-in transparent compression would maintain `bblock`'s ergonomic API while providing these benefits automatically.

### Design

#### Module structure

Following the `crc`/`xor` pattern, add a new `compressed` module (or multiple algorithm-specific modules) with parallel types:

```rust
pub mod compressed {
    pub struct BCompressedBlockAllocator<A, C> { ... }
    pub struct BCompressedBlock<'a, A, C> { ... }
    pub struct BCompressedBlockView<'a, A, C> { ... }
    pub struct BCompressedBlockReader<'a, A, C> { ... }
    pub struct BCompressedBlockWriter<'a, A, C> { ... }
}
```

#### Compression algorithms

Provide multiple compression strategies as type parameters or feature flags:

- **LZ4** — fast compression/decompression, moderate ratio (default for speed-sensitive workloads)
- **Zstd** — excellent ratio, configurable levels (default for space-sensitive workloads)
- **Snappy** — very fast, moderate ratio (alternative to LZ4)
- **None** — pass-through for incompressible data or adaptive strategies

Dependencies: `lz4_flex`, `zstd`, `snap` as optional features.

#### Storage format

Compressed blocks require variable-size storage. Two approaches:

**Option A: Header with uncompressed size**
```
[compressed_data (variable)] [uncompressed_size: u32] [compressed_size: u32] [checksum: u32]
```

- Allocate with maximum size (uncompressed + overhead)
- Store actual compressed size in trailer
- Waste space but simpler implementation
- Compatible with current fixed-size allocation model

**Option B: Dynamic allocation (requires bstack enhancement)**
```
[compressed_data (variable)] [metadata: compressed_size, uncompressed_size] [checksum: u32]
```

- Only allocate needed space (compressed_size + metadata + checksum)
- Requires bstack to support resizable allocations or separate metadata region
- More efficient but breaks current API assumptions

**Recommendation:** Start with Option A for simplicity and non-breaking compatibility.

#### Interaction with checksumming

Compress **then** checksum:

```
original_data -> compress -> compressed_data -> compute_checksum(compressed_data)
```

Benefits:
- Checksum validates the compressed data actually stored on disk
- Detects corruption in compressed stream (which decompression will reject)
- Smaller checksum computation (operates on compressed data)

When reading:
```
validate_checksum(compressed_data) -> decompress -> original_data
```

#### API design

Mirror existing patterns with transparent compression/decompression:

```rust
let alloc = BCompressedBlockAllocator::new(inner_alloc, CompressionStrategy::Lz4);
let block = alloc.alloc(1024)?; // allocates 1024 + overhead for metadata + checksum

// Writes compress automatically
block.view().write(b"highly compressible data...")?;

// Reads decompress automatically
let mut buf = vec![0; 1024];
block.view().read(&mut buf)?;

// Verification checks checksum of compressed data
assert!(block.verify()?);

// Compression statistics
let stats = block.compression_stats()?;
println!("Compressed: {} -> {} bytes ({:.1}% ratio)", 
         stats.uncompressed_size, stats.compressed_size, 
         stats.compression_ratio * 100.0);
```

#### Adaptive compression

For advanced users, provide an adaptive strategy:

```rust
pub enum CompressionStrategy {
    Always(Algorithm),        // Always compress with algorithm
    Never,                    // Pass-through
    Adaptive {                // Compress only if ratio > threshold
        algorithm: Algorithm,
        threshold: f32,       // e.g., 0.9 = must compress to <90% of original
    },
}
```

If compression doesn't meet threshold, store uncompressed data with a flag in metadata.

#### Composability considerations

Current limitation: `BBlockAllocator` cannot wrap another `BBlockAllocator` because each requires the inner allocator to be a `BStackSliceAllocator`.

For compression + checksumming, consider:

1. **Built-in checksumming** — `BCompressedBlock` always includes checksum (recommended)
2. **Layering** — resolve the composability limitation to enable `BBlockAllocator<BCompressedBlockAllocator<A>>`
3. **Unified type** — `BCompressedBlockAllocator` with checksum strategy parameter (CRC32/XOR)

Recommendation: Option 1 for simplicity. Compressed blocks should always be checksummed.

#### Performance considerations

- **Write path:** Compression overhead (CPU) vs. reduced I/O (disk)
- **Read path:** Decompression overhead vs. reduced I/O
- **Memory:** Decompression requires temporary buffers
- **Trade-offs:** LZ4 typically faster than disk I/O; Zstd better for cold data

Consider async variants for large blocks to avoid blocking on compression/decompression.

#### Migration path

For non-breaking compatibility:

1. Add as new module, don't modify existing types
2. Use feature flags for compression algorithm dependencies
3. Provide conversion utilities to migrate uncompressed blocks to compressed format
4. Document performance characteristics and use case recommendations

---

