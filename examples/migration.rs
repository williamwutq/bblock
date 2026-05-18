use bblock::BBlockAllocator;
use bstack::{BStack, BStackAllocator, BStackGuardedSlice, LinearBStackAllocator};
use std::io;

fn main() -> io::Result<()> {
    println!("=== BEFORE MIGRATION: Using raw BStackAllocator ===\n");
    before_migration()?;

    println!("\n=== AFTER MIGRATION: Using BBlockAllocator ===\n");
    after_migration()?;

    println!("\n=== MIGRATION GUIDE ===");
    println!("1. Wrap your BStackAllocator with BBlockAllocator::new()");
    println!("2. Change alloc() return type from BStackSlice to BBlock");
    println!("3. Use block.view() to get a BBlockView for read/write");
    println!("4. Call block.verify() to check data integrity");
    println!("5. For partial writes, use subview() - it auto-updates the checksum");

    Ok(())
}

fn before_migration() -> io::Result<()> {
    let stack = BStack::open("migration_example.bstack")?;
    let alloc = LinearBStackAllocator::new(stack);

    let block = alloc.alloc(32)?;
    block.write(b"User profile data without checksum")?;
    println!(
        "Raw BStackSlice written: {}",
        String::from_utf8_lossy(&block.read()?)
    );

    Ok(())
}

fn after_migration() -> io::Result<()> {
    let stack = BStack::open("migration_example.bstack")?;
    let alloc = BBlockAllocator::new(LinearBStackAllocator::new(stack));

    let block = alloc.alloc(32)?;
    block.view().write(b"User profile data with checksum")?;
    println!(
        "BBlock written: {}",
        String::from_utf8_lossy(&block.view().read()?)
    );
    println!("Verification: {}", block.verify()?);

    let view = block.view();
    let sub = view.subview(0, 12);
    sub.write(b"Updated!!!")?;
    println!(
        "After partial update: {}",
        String::from_utf8_lossy(&block.view().read()?)
    );
    println!("Subview auto-updated checksum: {}", block.verify()?);

    Ok(())
}
