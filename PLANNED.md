# Planned Features

This document outlines upcoming features planned for the `bblock` crate. These enhancements aim to improve usability, performance, and integration while maintaining the core principles of durability, crash-safety, and checksum integrity.

---

## Checksum Algorithm Interface and Strategies

**Breaking change:** No

### Motivation

Currently, each checksum algorithm (CRC, XOR) is implemented independently with no shared abstraction. This creates limitations:

- **No generic code:** Cannot write functions that work with "any checksummed block"
- **Fixed algorithms:** Cannot choose checksum algorithm at runtime or based on configuration
- **No advanced strategies:** Cannot implement adaptive checksumming, combined checksums, or probabilistic verification
- **Inconsistent with future plans:** Compression and encryption support strategy enums (see [Compression Support](#compression-support)); checksums should have similar flexibility

Adding a `ChecksumAlgorithm` trait and `ChecksumStrategy` enum enables flexible, configurable checksumming while maintaining backwards compatibility with existing code.

### Design

#### Checksum algorithm trait

Define a trait that all checksum algorithms must implement:

```rust
/// Trait for checksum algorithms used in block verification.
pub trait ChecksumAlgorithm: Clone + Send + Sync + 'static {
    /// Size of the checksum in bytes
    const CHECKSUM_SIZE: usize;
    
    /// Human-readable name of the algorithm
    fn name(&self) -> &'static str;
    
    /// Compute checksum for the given data
    fn compute(&self, data: &[u8]) -> Vec<u8>;
    
    /// Verify that data matches the expected checksum
    fn verify(&self, data: &[u8], checksum: &[u8]) -> bool {
        self.compute(data) == checksum
    }
    
    /// Optional: Incremental checksum update for streaming data
    fn update(&mut self, _data: &[u8]) {
        // Default: no incremental support
        // Implementations can override for incremental computation
    }
}
```

Existing algorithms implement the trait:

```rust
// In src/checksum/crc.rs
#[derive(Clone)]
pub struct Crc32Algorithm;

impl ChecksumAlgorithm for Crc32Algorithm {
    const CHECKSUM_SIZE: usize = 4;
    
    fn name(&self) -> &'static str { "CRC32" }
    
    fn compute(&self, data: &[u8]) -> Vec<u8> {
        crc32fast::hash(data).to_le_bytes().to_vec()
    }
}

// In src/checksum/xor.rs
#[derive(Clone)]
pub struct XorAlgorithm;

impl ChecksumAlgorithm for XorAlgorithm {
    const CHECKSUM_SIZE: usize = 4;
    
    fn name(&self) -> &'static str { "XOR" }
    
    fn compute(&self, data: &[u8]) -> Vec<u8> {
        // XOR implementation
        ...
    }
}
```

#### Generic checksummed block types

Provide generic types parameterized by checksum algorithm:

```rust
/// Generic checksummed block allocator
pub struct BChecksumBlockAllocator<A, C: ChecksumAlgorithm> {
    inner: A,
    algorithm: C,
}

/// Generic checksummed block
pub struct BChecksumBlock<'a, A, C: ChecksumAlgorithm> {
    inner: BStackBlock<'a, A>,
    algorithm: C,
}

// Similar for BChecksumBlockView, BChecksumBlockReader, BChecksumBlockWriter
```

Existing concrete types become type aliases:

```rust
// In src/checksum/crc.rs
pub type BCrcBlockAllocator<A> = BChecksumBlockAllocator<A, Crc32Algorithm>;
pub type BCrcBlock<'a, A> = BChecksumBlock<'a, A, Crc32Algorithm>;
// ... etc

// In src/checksum/xor.rs
pub type BXorBlockAllocator<A> = BChecksumBlockAllocator<A, XorAlgorithm>;
pub type BXorBlock<'a, A> = BChecksumBlock<'a, A, XorAlgorithm>;
// ... etc
```

This maintains full backwards compatibility while enabling generic programming.

#### Checksum strategies

Inspired by the `CompressionStrategy` pattern, define flexible checksum strategies:

```rust
/// Strategy for applying checksums to blocks.
pub enum ChecksumStrategy {
    /// Always use specified algorithm
    Always(Algorithm),
    
    /// No checksum (pass-through, for testing or when integrity is guaranteed elsewhere)
    None,
    
    /// Choose algorithm adaptively based on data size
    Adaptive {
        fast: Algorithm,      // e.g., XOR for blocks < 4KB
        robust: Algorithm,    // e.g., CRC32 for blocks >= 4KB
        threshold: usize,     // Size threshold in bytes
    },
    
    /// Use multiple checksums for extra validation
    Combined {
        primary: Algorithm,   // Primary checksum (e.g., CRC32)
        secondary: Algorithm, // Secondary checksum (e.g., XOR)
        // Verification requires both to pass
    },
    
    /// Probabilistic verification (verify randomly for performance)
    Probabilistic {
        algorithm: Algorithm,
        probability: f32,     // e.g., 0.1 = verify 10% of reads
        seed: Option<u64>,    // Optional seed for deterministic behavior
    },
}

pub enum Algorithm {
    Crc32,
    Xor,
    // Future: Adler32, Fletcher16, etc.
}

impl ChecksumStrategy {
    /// Standard CRC32 checksum (recommended default)
    pub fn crc32() -> Self {
        Self::Always(Algorithm::Crc32)
    }
    
    /// Fast XOR checksum
    pub fn xor() -> Self {
        Self::Always(Algorithm::Xor)
    }
    
    /// No checksum (use with caution)
    pub fn none() -> Self {
        Self::None
    }
    
    /// Adaptive strategy: XOR for small blocks, CRC32 for large blocks
    pub fn adaptive_default() -> Self {
        Self::Adaptive {
            fast: Algorithm::Xor,
            robust: Algorithm::Crc32,
            threshold: 4096, // 4KB threshold
        }
    }
    
    /// Combined checksums for critical data
    pub fn combined_default() -> Self {
        Self::Combined {
            primary: Algorithm::Crc32,
            secondary: Algorithm::Xor,
        }
    }
}
```

#### Strategy-based allocator

Provide a high-level allocator that accepts strategies:

```rust
use bblock::checksum::{BStrategyBlockAllocator, ChecksumStrategy};

// Simple case: always use CRC32
let alloc = BStrategyBlockAllocator::new(
    inner_alloc,
    ChecksumStrategy::crc32()
);

// Adaptive: XOR for small blocks, CRC32 for large
let alloc = BStrategyBlockAllocator::new(
    inner_alloc,
    ChecksumStrategy::adaptive_default()
);

// Combined checksums for critical data
let alloc = BStrategyBlockAllocator::new(
    inner_alloc,
    ChecksumStrategy::Combined {
        primary: Algorithm::Crc32,
        secondary: Algorithm::Xor,
    }
);

// Probabilistic: verify 10% of reads for performance
let alloc = BStrategyBlockAllocator::new(
    inner_alloc,
    ChecksumStrategy::Probabilistic {
        algorithm: Algorithm::Crc32,
        probability: 0.1,
        seed: None,
    }
);
```

#### Storage considerations

Different strategies have different storage requirements:

- **Always/None/Adaptive:** Same as current (4 bytes for CRC32, 4 bytes for XOR)
- **Combined:** Sum of both checksums (8 bytes for CRC32+XOR)
- **Probabilistic:** Same as underlying algorithm (verification is selective, storage is not)

For `Combined`, store both checksums in the block trailer:

```
[data] [primary_checksum: 4 bytes] [secondary_checksum: 4 bytes]
```

#### API design

Support both concrete types (existing) and strategy-based types (new):

```rust
// Existing API: concrete types (backwards compatible)
use bblock::checksum::crc::BCrcBlockAllocator;
let alloc = BCrcBlockAllocator::new(inner_alloc);
let block = alloc.alloc(1024)?;

// New API: strategy-based
use bblock::checksum::{BStrategyBlockAllocator, ChecksumStrategy};
let alloc = BStrategyBlockAllocator::new(
    inner_alloc,
    ChecksumStrategy::adaptive_default()
);
let block = alloc.alloc(1024)?;

// Generic programming: accept any checksum algorithm
fn process_block<A, C: ChecksumAlgorithm>(
    block: BChecksumBlock<A, C>
) -> Result<()> {
    println!("Using {} checksum", block.algorithm().name());
    block.verify()?;
    // ... process block
    Ok(())
}
```

#### Performance considerations

- **Adaptive strategy:** XOR is ~10x faster than CRC32, so small blocks benefit significantly
- **Combined checksums:** Minimal overhead (~10-20ns extra) since XOR is very cheap
- **Probabilistic verification:** Can reduce verification overhead by 90%+ for read-heavy workloads
- **Zero-cost abstraction:** Strategy selection via generics has no runtime overhead

Benchmarks for typical workloads:

| Strategy | Small blocks (<4KB) | Large blocks (>4KB) |
|----------|---------------------|---------------------|
| Always(Crc32) | Baseline | Baseline |
| Always(Xor) | ~10x faster | ~10x faster |
| Adaptive | ~10x faster | Baseline |
| Combined | ~1% slower | ~0.1% slower |
| Probabilistic(10%) | ~9x faster verification | ~9x faster verification |

#### Migration and usage

Existing code continues to work unchanged:

```rust
// Old code: still works exactly as before
use bblock::{BCrcBlock, BCrcBlockAllocator};
let alloc = BCrcBlockAllocator::new(inner);
let block = alloc.alloc(1024)?;
```

New code can opt into strategies:

```rust
// New code: flexible strategies
use bblock::checksum::{BStrategyBlockAllocator, ChecksumStrategy};

// For most use cases: adaptive is a good default
let alloc = BStrategyBlockAllocator::new(
    inner,
    ChecksumStrategy::adaptive_default()
);

// For critical data: combined checksums
let alloc = BStrategyBlockAllocator::new(
    inner,
    ChecksumStrategy::combined_default()
);

// For performance-critical reads: probabilistic verification
let alloc = BStrategyBlockAllocator::new(
    inner,
    ChecksumStrategy::Probabilistic {
        algorithm: Algorithm::Crc32,
        probability: 0.05, // Verify 5% of reads
        seed: None,
    }
);
```

### Open Questions

- Should `Adaptive` strategy allow custom algorithm selection (e.g., via closure)?
- Should `Combined` checksums both be stored, or should secondary be computed on-demand for verification?
- Should `Probabilistic` verification be configurable per-operation (verify this specific read) or only at allocator construction?
- Are there other useful checksum algorithms to support initially (Adler32, Fletcher, etc.)?
- Should strategies be configurable at runtime (enum dispatch) or compile-time (generics), or both?

---

## Compression Support

**Breaking change:** No

### Motivation

There are many use cases for persistent checksummed blocks involve compressible data (logs, JSON, text, serialized structures).

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

#### Performance considerations

- **Write path:** Compression overhead (CPU) vs. reduced I/O (disk)
- **Read path:** Decompression overhead vs. reduced I/O
- **Memory:** Decompression requires temporary buffers
- **Trade-offs:** LZ4 typically faster than disk I/O; Zstd better for cold data

Consider async variants for large blocks to avoid blocking on compression/decompression.

## Open Questions

- What algorithms to support initially?
- How should compression interact with checksumming? Should the user explicitly compose checksummed and compressed allocators, or should compression include its own integrity checks?
- Should there be dynamic resizing of compressed blocks, or should we stick to fixed-size allocations with overhead for simplicity? If fixed, should there be pre-allocation of maximum compressed size and allow for unused space?
- Should compression stats be exposed in the API for monitoring and optimization purposes?

