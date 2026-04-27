use bblock::BBlockAllocator;
use bstack::{BStack, BStackAllocator, LinearBStackAllocator};
use std::io;

fn main() -> io::Result<()> {
    let stack = BStack::open("combined_example.bstack")?;
    let linear_alloc = LinearBStackAllocator::new(stack);
    let bblock_alloc = BBlockAllocator::new(linear_alloc);

    let header_block = bblock_alloc.alloc(64)?;
    let header_view = header_block.view();
    header_view.write(b"User Profile - Important data that needs integrity verified")?;
    println!("Header block verified: {}", header_view.verify()?);

    let profile_view = header_view.subview(0, 12);
    profile_view.write(b"User: john")?;
    println!("After profile update, verified: {}", header_view.verify()?);

    let liner_alloc = bblock_alloc.inner();
    let raw_slice = liner_alloc.alloc(128)?;
    raw_slice.write(b"Unimportant transient cache data - no checksum needed")?;
    println!("\nRaw BStackSlice (no checksum): ok");

    let profile_data = header_view.read()?;
    println!(
        "\nImportant data: {}",
        String::from_utf8_lossy(&profile_data)
    );

    let cache_data = raw_slice.read()?;
    println!("Cache data: {}", String::from_utf8_lossy(&cache_data));

    Ok(())
}
