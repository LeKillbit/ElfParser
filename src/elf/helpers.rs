/// Reads 2 bytes from the file and convert them into an u16
pub fn read_u16(io : &mut dyn std::io::Read) -> Option<u16> {
    let mut b = [0; 2];
    io.read_exact(&mut b).ok()?;
    Some(u16::from_le_bytes(b))
}

/// Reads 4 bytes from the file and convert them into an u32
pub fn read_u32(io : &mut dyn std::io::Read) -> Option<u32> {
    let mut b = [0; 4];
    io.read_exact(&mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

/// Reads 8 bytes from the file and convert them into an u64
pub fn read_u64(io : &mut dyn std::io::Read) -> Option<u64> {
    let mut b = [0; 8];
    io.read_exact(&mut b).ok()?;
    Some(u64::from_le_bytes(b))
}
