use bblock::BBlockAllocator;
use bstack::{BStack, BStackAllocator, LinearBStackAllocator};
use std::io;

fn main() -> io::Result<()> {
    let stack = BStack::open("journal_example.bstack")?;
    let alloc = BBlockAllocator::new(LinearBStackAllocator::new(stack));

    let entries = vec![
        "INFO: Application started",
        "INFO: Connected to database",
        "WARN: High memory usage detected",
        "INFO: User login: alice",
        "ERROR: Failed to process request",
    ];

    let mut block_refs = Vec::new();
    for entry in entries {
        let entry_bytes = format!("{}\n", entry).into_bytes();
        let block = alloc.alloc(entry_bytes.len() as u64)?;
        block.view().write(&entry_bytes)?;
        block_refs.push(block);
        println!("Logged entry: {}", entry.trim());
    }

    println!("\nTotal log entries: {}", block_refs.len());

    for block in &block_refs {
        let data = block.view().read()?;
        print!("{}", String::from_utf8_lossy(&data));
    }

    let block = alloc.alloc(32)?;
    let view = block.view();
    view.write(b"First entry\nSecond entry\nThird entry\n")?;
    println!("\nVerification: {}", view.verify()?);

    let subview = view.subview(0, 12);
    println!(
        "Subview before: {}",
        String::from_utf8_lossy(&subview.read()?)
    );
    subview.write(b"Modified!!!")?;
    println!(
        "Subview after: {}",
        String::from_utf8_lossy(&subview.read()?)
    );
    println!("Full block still valid: {}", view.verify()?);

    Ok(())
}
