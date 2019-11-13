use crate::{Frame, Message};
use std::io::{self, Read};

// If I mutate the buffer of bytes inside recv_frame, recv_message needs to do block or yield,
// and therefore it will need to be inlined into the mio loop
//
// If I mutate the buffer in recv_message, recv_frame will need to return the number of bytes
// that it's read. It could do this by operating only on a Cursor

/// Attempt to read a message from the passed vector of bytes
/// If buf contains a complete websocket message, those bytes will be removed
/// If buf does not contain a complete message, the argument is not mutated
pub fn dequeue_message_from(buf: &mut Vec<u8>) -> std::io::Result<Message> {
    let mut cursor = io::Cursor::new(buf.as_slice());

    // Read one frame
    let Frame {
        mut is_fin,
        opcode,
        mut data,
    } = try_read_frame(&mut cursor)?;

    // While we haven't seen a fin frame, attempt to read more frames
    while !is_fin {
        let frame = try_read_frame(&mut cursor)?;
        data.extend_from_slice(&frame.data);
        is_fin = frame.is_fin;
        assert!(
            frame.opcode == 0,
            "Continuation frames must have opcode == 0"
        );
    }

    // If we get here, we've parsed a valid message. Remove those bytes from the buffer.
    let unused_bytes = buf[cursor.position() as usize..].to_vec();
    buf.clear();
    buf.extend_from_slice(&unused_bytes);

    Ok(match opcode {
        1 => Message::Text(String::from_utf8(data).unwrap()),
        2 => Message::Binary(data),
        8 => {
            if data.is_empty() {
                Message::Close(None)
            } else {
                let code = u16::from_be_bytes([data[0], data[1]]);
                Message::Close(Some((code, String::from_utf8(data[2..].to_vec()).unwrap())))
            }
        }
        9 => Message::Ping(data),
        10 => Message::Pong(data),
        _ => panic!("Unrecognized opcode"),
    })
}

// Just slam away on the cursor in here, someone else is going to clean up after us
fn try_read_frame(cursor: &mut std::io::Cursor<&[u8]>) -> std::io::Result<Frame> {
    let (fin, _rsv, opcode) = mask!(cursor.read_u8()?, 0b1000_0000, 0b0111_0000, 0b0000_1111);
    let is_fin = fin > 0;

    let (mask, payload_length) = mask!(cursor.read_u8()?, 0b1000_0000, 0b0111_1111);
    let has_mask = mask > 0;

    let payload_length = if payload_length == 126 {
        u64::from(cursor.read_u16_be()?)
    } else if payload_length == 127 {
        cursor.read_u64_be()?
    } else {
        payload_length as u64
    };

    let masking_key = if has_mask {
        let mut key = [0; 4];
        cursor.read_exact(&mut key)?;
        Some(key)
    } else {
        None
    };

    let mut data = vec![0; payload_length as usize];
    if payload_length > 0 {
        cursor.read_exact(&mut data)?;
    }

    if let Some(key) = masking_key {
        for (d, m) in data.iter_mut().zip(key.iter().cycle()) {
            *d ^= m;
        }
    }

    Ok(Frame {
        is_fin,
        opcode,
        data,
    })
}

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
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32_be(&mut self) -> io::Result<u32> {
        let mut bytes = [0; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64_be(&mut self) -> io::Result<u64> {
        let mut bytes = [0; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }
}

pub trait CursorExt {
    fn peek(&mut self) -> io::Result<u8>;
}

impl CursorExt for io::Cursor<Vec<u8>> {
    fn peek(&mut self) -> io::Result<u8> {
        self.get_ref()
            .get(self.position() as usize)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "unable to peek cursor"))
    }
}
