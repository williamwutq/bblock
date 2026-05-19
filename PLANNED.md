# Planned Features

This document outlines upcoming features planned for the `bblock` crate. These enhancements aim to improve usability, performance, and integration while maintaining the core principles of durability, crash-safety, and checksum integrity.

---

## Rename BBlock to BCrcBlock

**Breaking change:** Yes

### Motivation

The current naming `BBlock` implies a generic block type, but it's actually specifically a CRC32-checksummed block. This creates ambiguity for users and makes the codebase less clear:

- Users might not realize that `BBlock` includes CRC32 checksumming
- It's unclear how `BBlock` relates to `BXorBlock` (both are checksummed blocks with different algorithms)
- Adding new checksum algorithms would create inconsistent naming
- Generic code cannot easily work with "any checksummed block"

Renaming to `BCrcBlock` makes the CRC32 checksum explicit and aligns with the naming pattern of `BXorBlock`.

### Design

#### Type renames

All CRC-related types will be renamed to include "Crc" in their name:

- `BBlock` → `BCrcBlock`
- `BBlockAllocator` → `BCrcBlockAllocator`
- `BBlockView` → `BCrcBlockView`
- `BBlockReader` → `BCrcBlockReader`
- `BBlockWriter` → `BCrcBlockWriter`

#### Import path changes

```rust
// Old
use bblock::{BBlock, BBlockAllocator};

// New
use bblock::{BCrcBlock, BCrcBlockAllocator};
// Or, after module refactoring:
use bblock::checksum::crc::{BCrcBlock, BCrcBlockAllocator};
```

#### Migration strategy

To ease the transition for existing users:

1. **Deprecated re-exports** — provide deprecated type aliases for one version:
   ```rust
   #[deprecated(since = "0.x.0", note = "Renamed to BCrcBlock")]
   pub type BBlock<A> = BCrcBlock<A>;
   
   #[deprecated(since = "0.x.0", note = "Renamed to BCrcBlockAllocator")]
   pub type BBlockAllocator<A> = BCrcBlockAllocator<A>;
   // ... etc
   ```

2. **Clear compiler warnings** — users will see deprecation warnings with suggested replacements

3. **Documentation** — update all examples, README, and documentation to use new names

4. **CHANGELOG entry** — clearly document the rename with migration instructions

#### Migration guide

For users upgrading:

```rust
// Step 1: Find and replace in your codebase
BBlock          → BCrcBlock
BBlockAllocator → BCrcBlockAllocator
BBlockView      → BCrcBlockView
BBlockReader    → BCrcBlockReader
BBlockWriter    → BCrcBlockWriter

// Step 2: Update imports
// Old
use bblock::{BBlock, BBlockAllocator};

// New
use bblock::{BCrcBlock, BCrcBlockAllocator};

// Step 3: Update type signatures
// Old
fn process(block: BBlock<LinearAllocator>) { ... }

// New
fn process(block: BCrcBlock<LinearAllocator>) { ... }
```

### Open Questions

- Should we keep the deprecated aliases for more than one release cycle?
- Should we provide a `cargo fix`-compatible automated migration tool?

---

## Unified Checksum Module Structure

**Breaking change:** No (with re-exports)

### Motivation

The current structure has separate `crc` and `xor` modules at the top level of the crate. This creates several issues:

- **Cluttered namespace:** As more checksum algorithms are added (Adler32, Fletcher, etc.), the top-level namespace becomes crowded
- **No clear grouping:** It's not immediately obvious that `crc` and `xor` are both checksum algorithm implementations
- **Inconsistent with future plans:** Compression and encryption will have their own modules; checksums should too
- **Difficult to discover:** Users might not realize multiple checksum algorithms are available

Refactoring into a unified `checksum` module with sub-modules for each algorithm improves organization, discoverability, and consistency.

### Design

#### New module hierarchy

```
src/
  lib.rs
  checksum/
    mod.rs          // Re-exports and shared types
    crc.rs          // CRC32 implementation (moved from src/crc.rs)
    xor.rs          // XOR implementation (moved from src/xor.rs)
```

#### Module organization

**`src/checksum/mod.rs`:**
```rust
//! Checksum algorithms for block integrity verification.
//!
//! This module provides multiple checksum implementations:
//! - [`crc`] — CRC32 checksums (industry standard, robust)
//! - [`xor`] — XOR checksums (fast, simple)

pub mod crc;
pub mod xor;

// Re-export commonly used types
pub use crc::{BCrcBlock, BCrcBlockAllocator, BCrcBlockView, BCrcBlockReader, BCrcBlockWriter};
pub use xor::{BXorBlock, BXorBlockAllocator, BXorBlockView, BXorBlockReader, BXorBlockWriter};
```

**`src/checksum/crc.rs`:**
```rust
//! CRC32 checksummed blocks.
//!
//! Provides blocks with CRC32 checksums for robust data integrity verification.

// (Current contents of src/crc.rs)
pub struct BCrcBlockAllocator<A> { ... }
pub struct BCrcBlock<'a, A> { ... }
// ... etc
```

**`src/checksum/xor.rs`:**
```rust
//! XOR checksummed blocks.
//!
//! Provides blocks with simple XOR checksums for fast integrity verification.

// (Current contents of src/xor.rs)
pub struct BXorBlockAllocator<A> { ... }
pub struct BXorBlock<'a, A> { ... }
// ... etc
```

#### Top-level re-exports

To maintain backwards compatibility, `src/lib.rs` re-exports all checksum types:

```rust
// Backwards compatibility: re-export checksum types at top level
pub use checksum::crc::{BCrcBlock, BCrcBlockAllocator, BCrcBlockView, BCrcBlockReader, BCrcBlockWriter};
pub use checksum::xor::{BXorBlock, BXorBlockAllocator, BXorBlockView, BXorBlockReader, BXorBlockWriter};

// New: also expose the checksum module
pub mod checksum;
```

This allows both import styles:

```rust
// Old style (still works)
use bblock::{BCrcBlock, BXorBlock};

// New style (preferred)
use bblock::checksum::crc::BCrcBlock;
use bblock::checksum::xor::BXorBlock;

// Or import the module
use bblock::checksum;
let alloc = checksum::crc::BCrcBlockAllocator::new(...);
```

#### File organization

The refactoring involves moving files:

1. `src/crc.rs` → `src/checksum/crc.rs` (with updates to module paths)
2. `src/xor.rs` → `src/checksum/xor.rs` (with updates to module paths)
3. Create `src/checksum/mod.rs` with re-exports and documentation

Internal imports within the moved files need updating:

```rust
// Old (in src/crc.rs)
use crate::SomeType;

// New (in src/checksum/crc.rs)
use crate::SomeType;  // No change needed for crate-level imports
```

#### Documentation updates

- Update module-level documentation to explain the checksum module hierarchy
- Add examples showing both import styles
- Update README and guides to use new import paths (with note about backwards compatibility)

### Open Questions

- Should we deprecate the top-level re-exports in a future version?
- Should we add a `checksum/prelude.rs` for convenient imports?

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

---

## Encrypted Blocks

**Breaking change:** No

### Motivation

Persistent data often requires encryption at rest for security and compliance.

While users can encrypt data before passing it to `bblock`, this has the same drawbacks as manual compression: checksums operate on ciphertext, sub-range views don't work on plaintext, and key management becomes application-specific boilerplate. Built-in transparent encryption maintains `bblock`'s ergonomic API while providing authenticated encryption automatically.

### Design

#### Module structure

Add an `encrypted` module following the existing pattern:

```rust
pub mod encrypted {
    pub struct BEncryptedBlockAllocator<A, C> { ... }
    pub struct BEncryptedBlock<'a, A, C> { ... }
    pub struct BEncryptedBlockView<'a, A, C> { ... }
    // Reader/Writer types
}
```

#### Encryption algorithms

Support authenticated encryption algorithms via type parameters or feature flags:

- **AES-256-GCM** — industry standard, hardware-accelerated on modern CPUs
- **ChaCha20-Poly1305** — faster on platforms without AES-NI, constant-time
- **XChaCha20-Poly1305** — extended nonce variant, better for random nonces

Dependencies: `aes-gcm`, `chacha20poly1305` as optional features via the `aead` crate.

Authenticated encryption is mandatory—no unauthenticated modes. The authentication tag replaces or supplements checksums (see below).

#### Storage format

Encrypted blocks need space for ciphertext, nonce/IV, and authentication tag:

```
[nonce] [ciphertext: len bytes] [auth_tag]
```

- Nonce generated randomly per write (96-bit for GCM, 192-bit for XChaCha20)
- Ciphertext is same size as plaintext (stream ciphers)
- Authentication tag validates both ciphertext and nonce (AEAD property)
- Total overhead: 28 bytes for AES-GCM/ChaCha20, 40 bytes for XChaCha20

Allocate `plaintext_len + nonce_len + tag_len` bytes from underlying allocator.

#### Key management

Support multiple key sources:

```rust
pub enum KeySource {
    Static([u8; 32]),           // Direct 256-bit key
    Derived { password: String, salt: [u8; 16] }, // PBKDF2/Argon2
    Callback(Box<dyn Fn() -> [u8; 32]>),  // External KMS/keyring
}

let alloc = BEncryptedBlockAllocator::new(inner_alloc, Algorithm::Aes256Gcm, key_source);
```

Key rotation considerations: blocks encrypted with old keys cannot be read with new keys. Provide utilities for re-encryption or support key IDs in block metadata (adds 4 bytes overhead).

#### Interaction with checksumming

Authenticated encryption **replaces** checksums for encrypted blocks. The authentication tag provides stronger integrity guarantees than CRC32/XOR:

```
plaintext -> encrypt_and_authenticate -> [nonce || ciphertext || tag]
```

AEAD algorithms guarantee that tampering with any byte (nonce, ciphertext, or tag) will be detected during decryption. Adding an additional checksum layer is redundant and wasteful.

However, for composability with compression:
```rust
// Compress then encrypt (recommended for space efficiency)
BEncryptedBlockAllocator::new(
    BCompressedBlockAllocator::new(linear_alloc),
    Algorithm::Aes256Gcm,
    key_source
)
```

The compression layer's checksum becomes redundant once encrypted, but removing it would require special-casing. Accept the minor overhead for simplicity.

#### API design

Mirror existing patterns with transparent encryption/decryption:

```rust
use bblock::encrypted::{BEncryptedBlockAllocator, Algorithm, KeySource};

let key_source = KeySource::Static([0u8; 32]); // Use proper key in production
let alloc = BEncryptedBlockAllocator::new(inner_alloc, Algorithm::Aes256Gcm, key_source);

let block = alloc.alloc(1024)?; // allocates 1024 + 28 bytes

// Writes encrypt automatically
block.view().write(b"sensitive data")?;

// Reads decrypt and authenticate automatically  
let mut buf = vec![0; 1024];
block.view().read(&mut buf)?; // Fails if tampered

// Verification checks authentication tag
assert!(block.verify()?);
```

#### Performance considerations

- **Write path:** Encryption overhead typically 1-5 GB/s (depends on algorithm, CPU)
- **Read path:** Decryption overhead similar to encryption
- **Memory:** Minimal additional buffering (AEAD is single-pass)
- **Hardware acceleration:** AES-GCM benefits from AES-NI instructions (~10x faster)

For large blocks, encryption overhead is usually less than disk I/O latency. Consider async variants for very large blocks.

#### Security considerations

- **Nonce uniqueness:** Critical for GCM security. Use random generation or counter-based with careful state management.
- **Key security:** Keys in memory are vulnerable to memory dumps.
- **Side channels:** Constant-time implementations are necessary. Rely on audited crates like `aes-gcm` and `chacha20poly1305`.
- **Authentication required:** Never expose unauthenticated ciphertext to application code.

## Open Questions

- What algorithms to support initially?
- Should we support separate metadata for key IDs to enable key rotation without re-encryption?
- How to handle nonce management for users who want deterministic encryption (e.g., for deduplication)? This is generally not recommended but may be a use case.
- Should we provide utilities for re-encrypting existing blocks when keys are rotated?
- What is the relationship between encryption and compression layers? Should the user be able to explicitly compose them, or should we provide a combination allocator that does both?

---

