use bblock::BBlockAllocator;
use bstack::{BStack, LinearBStackAllocator};
use std::io;

fn main() -> io::Result<()> {
    let stack = BStack::open("basic_example.bstack")?;
    let alloc = BBlockAllocator::new(LinearBStackAllocator::new(stack));

    let block = alloc.alloc(16)?;
    println!("Allocated block with {} usable bytes", block.len());

    let view = block.view();
    view.write(b"Hello, bblock!")?;
    println!(
        "Wrote data: {}",
        String::from_utf8_lossy(view.read()?.as_slice())
    );

    println!("Block verification: {}", block.verify()?);

    Ok(())
}
