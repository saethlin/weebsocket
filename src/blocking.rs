use crate::{Error, Frame, Message, XorshiroRng};
use std::io::{self, Read, Write};

/// Wraps a TLS stream and manages the websocket connection
pub struct Client {
    rng: XorshiroRng,
    stream: rustls::StreamOwned<rustls::ClientSession, std::net::TcpStream>,
}

impl Client {
    /// Create a websocket client by connecting to a server at `uri`
    pub fn connect(uri: &str) -> Result<Self, Error> {
        use std::convert::TryFrom;
        let uri: http::Uri = http::Uri::try_from(uri)?;
        let host = uri
            .host()
            .ok_or_else(|| Error::Custom(format!("No host in URI {:?}", uri)))?;
        let port = uri.port_u16().unwrap_or(443);
        let path = uri
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str)
            .unwrap_or("/");

        let dns_name =
            webpki::DNSNameRef::try_from_ascii_str(host).map_err(|_| Error::InvalidHostname)?;
        let session = rustls::ClientSession::new(&crate::TLS_CONFIG, dns_name);
        let socket = std::net::TcpStream::connect((host, port))?;

        let mut stream = rustls::StreamOwned::new(session, socket);

        write!(
            stream,
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n",
            path, host,
        )
        .unwrap();
        stream.flush().unwrap();

        let mut buf = [0; 4096];
        let bytes = stream.read(&mut buf)?;

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        response.parse(&buf[..bytes])?;

        if response.version.is_none() {
            return Err(Error::Custom("Response doesn't have a version".to_string()));
        }

        if response.code != Some(101) {
            return Err(Error::Custom(format!(
                "Requested a protocol switch but got code: {:?}",
                response.code
            )));
        }

        // Find the Sec-Websocket-Accept header and validate
        assert_eq!(
            headers[..]
                .iter()
                .find(|h| h.name.to_lowercase() == "sec-websocket-accept")
                .map(|h| h.value),
            Some(&b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="[..])
        );

        Ok(Client {
            stream,
            rng: XorshiroRng::new(),
        })
    }

    /// Send a websocket message, blocking if needed
    pub fn send(&mut self, message: &Message) -> Result<(), crate::Error> {
        write_message(&mut self.stream, &mut self.rng, message)
    }

    /// Recieve a websocket message, blocking until one is available
    pub fn recv(&mut self) -> Result<Message, crate::Error> {
        let Frame {
            mut is_fin,
            opcode,
            mut data,
        } = self.recv_frame()?;

        while !is_fin {
            let frame = self.recv_frame()?;
            data.extend_from_slice(&frame.data);
            is_fin = frame.is_fin;
            if frame.opcode != 0 {
                return Err(Error::Custom(format!(
                    "Continuation frames must have opcode 0, got {}",
                    frame.opcode
                )));
            }
        }

        Ok(match opcode {
            1 => Message::Text(String::from_utf8(data).unwrap()),
            2 => Message::Binary(data),
            8 => {
                if let (Some(first), Some(second), Some(reason)) =
                    (data.get(0), data.get(1), data.get(2..))
                {
                    let code = u16::from_be_bytes([*first, *second]);
                    Message::Close(Some((code, String::from_utf8(reason.to_vec()).unwrap())))
                } else {
                    Message::Close(None)
                }
            }
            9 => Message::Ping(data),
            10 => Message::Pong(data),
            _ => return Err(Error::Custom(format!("Unrecognized opcode {}", opcode))),
        })
    }

    fn recv_frame(&mut self) -> std::io::Result<Frame> {
        let (fin, _rsv, opcode) = mask!(
            self.stream.read_u8()?,
            0b1000_0000,
            0b0111_0000,
            0b0000_1111
        );
        let is_fin = fin > 0;

        let (mask_byte, payload_length) = mask!(self.stream.read_u8()?, 0b1000_0000, 0b0111_1111);
        let has_mask = mask_byte > 0;

        let payload_length = if payload_length == 126 {
            self.stream.read_u16_be()? as u64
        } else if payload_length == 127 {
            self.stream.read_u64_be()?
        } else {
            payload_length as u64
        };

        let masking_key = if has_mask {
            let mut key = [0; 4];
            self.stream.read_exact(&mut key)?;
            Some(key)
        } else {
            None
        };

        let mut data = vec![0; payload_length as usize];
        if payload_length > 0 {
            self.stream.read_exact(&mut data)?;
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
}

// All messages are sent in one frame
fn write_message(
    stream: &mut impl std::io::Write,
    rng: &mut XorshiroRng,
    message: &Message,
) -> Result<(), crate::Error> {
    let (opcode, len) = match message {
        Message::Text(b) => (1, b.len()),
        Message::Binary(b) => (2, b.len()),
        Message::Close(None) => (8, 0),
        Message::Close(Some((_, b))) => (8, b.len() + 2),
        Message::Ping(b) => (9, b.len()),
        Message::Pong(b) => (10, b.len()),
    };

    if len > i64::max_value() as usize {
        return Err(Error::Custom(
            "Message length exceeds i64::max_value".to_string(),
        ));
    }

    // write fin, rsv, and opcode.
    // fin always 1, rsv always 0
    stream.write_all(&[0b1000_0000 | opcode])?;

    // First bit indicates if we're transmitting a mask.
    // We always transmit a mask.

    if len > u16::max_value() as usize {
        stream.write_all(&[0b1000_0000 | 127])?;
        stream.write_all(&(len as u64).to_be_bytes())?;
    } else if len > 125 {
        stream.write_all(&[0b1000_0000 | 126])?;
        stream.write_all(&(len as u16).to_be_bytes())?;
    } else {
        stream.write_all(&[0b1000_0000 | len as u8])?;
    }

    let mask = rng.next_u32().to_ne_bytes();
    stream.write_all(&mask)?;

    let mut data = match message {
        Message::Text(b) => b.as_bytes().to_vec(),
        Message::Binary(b) => b.to_vec(),
        Message::Close(None) => Vec::new(),
        Message::Close(Some((reason, b))) => reason
            .to_be_bytes()
            .iter()
            .copied()
            .chain(b.bytes())
            .collect(),
        Message::Ping(b) => b.to_vec(),
        Message::Pong(b) => b.to_vec(),
    };

    // Apply the mask
    for (d, m) in data.iter_mut().zip(mask.iter().cycle()) {
        *d ^= m;
    }

    stream.write_all(&data)?;

    Ok(())
}

trait ReadExt: io::Read {
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
