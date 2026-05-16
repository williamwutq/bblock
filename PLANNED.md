# Planned Features

This document outlines upcoming features planned for the `bblock` crate. These enhancements aim to improve usability, performance, and integration while maintaining the core principles of durability, crash-safety, and checksum integrity.

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

