use std::mem;

macro_rules! read_uX {
    ($func_name:ident, $type:ty) => {
        pub fn $func_name(io : &mut dyn std::io::Read) 
            -> Option<$type>
        {
            let mut b = [0; mem::size_of::<$type>() as usize];
            io.read_exact(&mut b).ok()?;
            Some(<$type>::from_le_bytes(b))
        }
    }
}

read_uX!(read_u8, u8);
read_uX!(read_u16, u16);
read_uX!(read_u32, u32);
read_uX!(read_u64, u64);

/*
/// Reads 1 byte from the file and convert it into an u8
pub fn read_u8(io : &mut dyn std::io::Read) -> Option<u8> {
    let mut b = [0; 1];
    io.read_exact(&mut b).ok()?;
    Some(u8::from_le_bytes(b))
}

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
*/
