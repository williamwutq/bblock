use bblock::{BBlock, BBlockAllocator};
use bstack::{BStack, LinearBStackAllocator};
use std::io;

fn main() -> io::Result<()> {
    let stack = BStack::open("zero_copy_example.bstack")?;
    let alloc = BBlockAllocator::new(LinearBStackAllocator::new(stack));

    let block = alloc.alloc(8)?;

    let bytes = block.to_bytes();
    let raw_slice = unsafe { block.into_slice() };
    println!(
        "Raw slice start: {}, len: {}",
        raw_slice.start(),
        raw_slice.len()
    );

    raw_slice.write(b"raw data")?;

    let data = raw_slice.read()?;
    println!("Zero-copy read: {}", String::from_utf8_lossy(&data));

    let restored = BBlock::from_bytes(alloc.inner(), bytes);
    println!("Verification after raw write: {}", restored.verify()?);

    Ok(())
}
