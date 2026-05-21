use bblock::BCrcBlockAllocator;
use bstack::{BStack, BStackAllocator, BStackGuardedSlice, LinearBStackAllocator};
use std::io;

fn main() -> io::Result<()> {
    let stack = BStack::open("zero_copy_example.bstack")?;
    let alloc = BCrcBlockAllocator::new(LinearBStackAllocator::new(stack));

    let block = alloc.alloc(8)?;
    block.view().write(b"hello!!!")?;
    println!("Initial verify: {}", block.verify()?);

    let raw_slice = unsafe { block.into_slice() };
    println!(
        "Raw slice start: {}, len: {}",
        raw_slice.start(),
        raw_slice.len()
    );

    raw_slice.write(b"raw data")?;
    let data = raw_slice.read()?;
    println!("Zero-copy read: {}", String::from_utf8_lossy(&data));

    Ok(())
}
