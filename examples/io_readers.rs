use bblock::BBlockAllocator;
use bstack::{BStack, LinearBStackAllocator};
use std::io::{Read, Seek, SeekFrom, Write};

fn main() -> std::io::Result<()> {
    let stack = BStack::open("io_example.bstack")?;
    let alloc = BBlockAllocator::new(LinearBStackAllocator::new(stack));

    let block = alloc.alloc(1024)?;

    {
        let mut writer = block.writer();
        writer.write_all(b"First chunk of data. ")?;
        writer.write_all(b"Second chunk after seek. ")?;
        writer.flush()?;
    }
    println!("After write, verification: {}", block.verify()?);

    {
        let mut reader = block.reader();
        let mut buf = [0u8; 20];
        reader.read_exact(&mut buf)?;
        println!("Read first 20 bytes: {}", String::from_utf8_lossy(&buf));
    }

    {
        let mut reader = block.reader();
        reader.seek(SeekFrom::Start(7))?;
        let mut buf = [0u8; 6];
        reader.read_exact(&mut buf)?;
        println!(
            "Seeked to pos 7, read 6 bytes: {}",
            String::from_utf8_lossy(&buf)
        );
    }

    {
        let mut reader = block.reader();
        reader.seek(SeekFrom::End(-7))?;
        let mut buf = [0u8; 7];
        reader.read_exact(&mut buf)?;
        println!(
            "Seeked from end -7, read: {}",
            String::from_utf8_lossy(&buf)
        );
    }

    let subview = block.view().subview(0, 100);
    {
        let mut writer = subview.writer();
        writer.write_all(b"Subview write at start")?;
    }
    println!("\nSubview write, verification: {}", block.verify()?);

    {
        let mut reader = subview.reader();
        let mut buf = [0u8; 10];
        reader.read_exact(&mut buf)?;
        println!(
            "Subview read first 10 bytes: {}",
            String::from_utf8_lossy(&buf)
        );
    }

    Ok(())
}
