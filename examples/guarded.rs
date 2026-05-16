use bblock::{BBlockAllocator, BXorBlockAllocator};
use bstack::{BStack, BStackGuardedSlice, LinearBStackAllocator};
use std::io;

fn main() -> io::Result<()> {
    crc_guarded()?;
    println!();
    xor_guarded()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CRC32 block via BStackGuardedSlice
// ---------------------------------------------------------------------------

fn crc_guarded() -> io::Result<()> {
    println!("=== BBlock via BStackGuardedSlice (CRC32) ===");

    let stack = BStack::open("guarded_crc.bstack")?;
    let alloc = BBlockAllocator::new(LinearBStackAllocator::new(stack));
    let block = alloc.alloc(16)?;

    // write() — operates on the data region only; recomputes the full CRC32.
    block.write(b"hello, guarded!!")?;
    println!(
        "After write:    {:?}",
        String::from_utf8_lossy(block.view().read()?.as_slice())
    );
    println!("Checksum valid: {}", block.verify()?);

    // as_slice() — returns a BStackSlice for the data region (no checksum).
    let data_slice = block.as_slice()?;
    println!(
        "as_slice len:   {} bytes  (block.len() = {}, raw len = {})",
        data_slice.len(),
        block.len(),
        // The raw allocation is 4 bytes longer (the CRC32 trailer).
        unsafe { block.into_slice() }.len(),
    );

    // Reallocate since into_slice() consumed the block handle.
    let block = alloc.alloc(16)?;
    block.write(b"hello, guarded!!")?;

    // zero() — zeroes the data and recomputes the checksum.
    block.zero()?;
    println!("After zero:     {:?}", block.view().read()?);
    println!("Checksum valid: {}", block.verify()?);

    Ok(())
}

// ---------------------------------------------------------------------------
// XOR block via BStackGuardedSlice
// ---------------------------------------------------------------------------

fn xor_guarded() -> io::Result<()> {
    println!("=== BXorBlock via BStackGuardedSlice (XOR, incremental) ===");

    let stack = BStack::open("guarded_xor.bstack")?;
    let alloc = BXorBlockAllocator::new(LinearBStackAllocator::new(stack));
    let block = alloc.alloc(16)?;

    // write() — incremental: reads old bytes, writes new bytes, XORs the
    // delta into the 4-byte checksum (cs[i % 4] ^= old[i] ^ new[i]).
    block.write(b"hello, guarded!!")?;
    println!(
        "After write:    {:?}",
        String::from_utf8_lossy(block.view().read()?.as_slice())
    );
    println!("Checksum valid: {}", block.verify()?);

    // Overwrite a second time — the incremental update handles the diff.
    block.write(b"world, guarded!!")?;
    println!(
        "After overwrite:{:?}",
        String::from_utf8_lossy(block.view().read()?.as_slice())
    );
    println!("Checksum valid: {}", block.verify()?);

    // as_slice() — data region only, same as CRC32 variant.
    let data_slice = block.as_slice()?;
    println!(
        "as_slice len:   {} bytes  (block.len() = {})",
        data_slice.len(),
        block.len(),
    );

    // zero() — reads old bytes, zeroes the region, XORs old bytes out of
    // the checksum.
    block.zero()?;
    println!("After zero:     {:?}", block.view().read()?);
    println!("Checksum valid: {}", block.verify()?);

    Ok(())
}
