use std::io;

pub trait ReadExt: io::Read {
    fn read_u8(&mut self) -> io::Result<u8>;

    fn read_u16_be(&mut self) -> io::Result<u16>;

    fn read_u32_be(&mut self) -> io::Result<u32>;

    fn read_u64_be(&mut self) -> io::Result<u64>;
}

impl<T> ReadExt for T
where
    T: io::Read,
{
    fn read_u8(&mut self) -> io::Result<u8> {
        let mut byte = [0];
        self.read_exact(&mut byte)?;
        Ok(byte[0])
    }

    fn read_u16_be(&mut self) -> io::Result<u16> {
        let mut bytes = [0; 2];
        self.read_exact(&mut bytes)?;
        Ok(((bytes[0] as u16) << 8) + bytes[1] as u16)
    }

    fn read_u32_be(&mut self) -> io::Result<u32> {
        let mut bytes = [0; 4];
        self.read_exact(&mut bytes)?;
        Ok(((bytes[0] as u32) << 24)
            + ((bytes[1] as u32) << 16)
            + ((bytes[2] as u32) << 8)
            + bytes[3] as u32)
    }

    fn read_u64_be(&mut self) -> io::Result<u64> {
        let mut bytes = [0; 8];
        self.read_exact(&mut bytes)?;
        Ok(((bytes[0] as u64) << 56)
            + ((bytes[1] as u64) << 48)
            + ((bytes[2] as u64) << 40)
            + ((bytes[3] as u64) << 32)
            + ((bytes[4] as u64) << 24)
            + ((bytes[5] as u64) << 16)
            << 16 + ((bytes[6] as u64) << 8) + bytes[7] as u64)
    }
}

pub trait CursorExt {
    fn peek(&mut self) -> io::Result<u8>;
}

impl CursorExt for io::Cursor<Vec<u8>> {
    fn peek(&mut self) -> io::Result<u8> {
        self.get_ref()
            .get(self.position() as usize)
            .map(|b| *b)
            .ok_or(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unable to peek cursor",
            ))
    }
}

#[macro_export]
macro_rules! mask {
    ($byte:expr, $($mask:expr),*) => {
        {
            let value = $byte;
            ($( value & $mask , )*)
        }
    };
    ($byte:expr, $($mask:expr),*,) => {
        {
            let value = $byte;
            ($( value & $mask , )*)
        }
    };
}
