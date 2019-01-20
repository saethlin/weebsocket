use std::io::{Read, Write};

mod parse;
//pub mod async_client;

#[derive(Debug)]
pub enum Message {
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Text(String),
    Binary(Vec<u8>),
    Close(Option<(u16, String)>),
}

struct Frame {
    fin: bool,
    opcode: u8,
    data: Vec<u8>,
}

pub struct Client {
    rng: XoshiroRng,
    stream: Stream,
}

enum Stream {
    Tcp(std::net::TcpStream),
    #[cfg(feature = "tls")]
    Tls(rustls::StreamOwned<rustls::ClientSession, std::net::TcpStream>),
}

impl std::io::Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(bytes),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.read(bytes),
        }
    }
}

impl std::io::Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(bytes),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.write(bytes),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Tcp(s) => s.flush(),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.flush(),
        }
    }
}

impl Client {
    #[cfg(feature = "tls")]
    pub fn connect_secure(uri: &str) -> std::io::Result<Self> {
        let uri: http::Uri = http::HttpTryFrom::try_from(uri).unwrap();
        let host = uri.host().unwrap();
        let port = uri.port_part().map(|p| p.as_u16()).unwrap_or(443);

        let mut config = rustls::ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let config = std::sync::Arc::new(config);

        let dns_name = webpki::DNSNameRef::try_from_ascii_str(host).unwrap();
        let session = rustls::ClientSession::new(&config, dns_name);
        let socket = std::net::TcpStream::connect((host, port))?;

        let mut stream = rustls::StreamOwned::new(session, socket);

        Self::init_connection(&mut stream, &uri)?;

        Ok(Client {
            stream: Stream::Tls(stream),
            rng: XoshiroRng::new(),
        })
    }

    pub fn connect_insecure(uri: &str) -> std::io::Result<Self> {
        let uri: http::Uri = http::HttpTryFrom::try_from(uri).unwrap();
        let host = uri.host().unwrap();
        let port = uri.port_part().map(|p| p.as_u16()).unwrap_or(80);

        let mut stream = std::net::TcpStream::connect((host, port))?;

        Self::init_connection(&mut stream, &uri)?;

        Ok(Client {
            stream: Stream::Tcp(stream),
            rng: XoshiroRng::new(),
        })
    }

    fn init_connection<S>(stream: &mut S, uri: &http::Uri) -> std::io::Result<()>
    where
        S: std::io::Write + std::io::Read,
    {
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let host = uri.host().unwrap();
        write!(
            stream,
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n",
            path, host,
        )?;

        let mut buf = [0; 2048];
        let len = stream.read(&mut buf)?;

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        response.parse(&buf[..len]).unwrap();

        assert!(response.version.is_some());
        assert_eq!(response.code, Some(101));
        assert_eq!(response.reason, Some("Switching Protocols"));

        // Find the Sec-Websocket-Accept header and validate
        assert_eq!(
            headers[..]
                .iter()
                .find(|h| h.name.to_lowercase() == "sec-websocket-accept")
                .map(|h| h.value),
            Some(&b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="[..])
        );

        Ok(())
    }

    // All messages are sent in one frame
    pub fn send_message(&mut self, message: &Message) -> std::io::Result<()> {
        let (opcode, len) = match message {
            Message::Text(b) => (1, b.len()),
            Message::Binary(b) => (2, b.len()),
            Message::Close(None) => (8, 0),
            Message::Close(Some((_, b))) => (8, b.len() + 2),
            Message::Ping(b) => (9, b.len()),
            Message::Pong(b) => (10, b.len()),
        };

        // write fin, rsv, and opcode.
        // fin always 1, rsv always 0
        self.stream.write(&[128 + opcode])?;

        if len > u16::max_value() as usize {
            assert!(len <= i64::max_value() as usize);
            self.stream.write(&[128 + 127])?;
            self.stream.write(&(len as u64).to_be_bytes())?;
        } else if len > 125 {
            self.stream.write(&[128 + 126])?;
            self.stream.write(&(len as u16).to_be_bytes())?;
        } else {
            self.stream.write(&[128 + len as u8])?;
        }

        let mask = self.rng.next_u32().to_ne_bytes();
        self.stream.write(&mask)?;

        let mut data = match message {
            Message::Text(b) => b.as_bytes().to_vec(),
            Message::Binary(b) => b.to_vec(),
            Message::Close(None) => Vec::new(), // Number of bytes written
            Message::Close(Some((reason, b))) => {
                let mut v = Vec::with_capacity(2 + b.len());
                v.extend_from_slice(&reason.to_be_bytes());
                v.extend_from_slice(b.as_bytes());
                v
            }
            Message::Ping(b) => b.to_vec(),
            Message::Pong(b) => b.to_vec(),
        };

        // Apply the mask
        for i in 0..data.len() {
            data[i] ^= mask[i % 4];
        }

        self.stream.write(&data)?;

        Ok(())
    }

    pub fn recv_message(&mut self) -> std::io::Result<Message> {
        let Frame {
            mut fin,
            opcode,
            mut data,
        } = self.recv_frame()?;
        while !fin {
            let frame = self.recv_frame()?;
            data.extend_from_slice(&frame.data);
            fin = frame.fin;
            assert!(
                frame.opcode == 0,
                "Continuation frames must have opcode == 0"
            );
        }

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

    fn recv_frame(&mut self) -> std::io::Result<Frame> {
        use crate::mask;
        use crate::parse::ReadExt;

        let (fin, _rsv, opcode) = mask!(self.stream.read_u8()?, 0b10000000, 0b01110000, 0b00001111);
        let fin = fin > 0;

        let (mask, payload_length) = mask!(self.stream.read_u8()?, 0b10000000, 0b01111111);
        let mask = mask > 0;
        let mut payload_length = payload_length as u64;

        if payload_length == 126 {
            payload_length = self.stream.read_u16_be()? as u64;
        } else if payload_length == 127 {
            payload_length = self.stream.read_u64_be()?;
        }

        let masking_key = if mask {
            let mut key = [0; 4];
            self.stream.read(&mut key)?;
            Some(key)
        } else {
            None
        };

        let mut data = vec![0; payload_length as usize];
        if payload_length > 0 {
            self.stream.read_exact(&mut data)?;
        }

        if let Some(key) = masking_key {
            for i in 0..data.len() {
                data[i] ^= key[i % 4];
            }
        }

        Ok(Frame { fin, opcode, data })
    }
}

// The websocket RFC requires the contents of messages be randomly masked,
// but that's only done to scramble the bits to protect broken proxies from
// opening themselves up to cache-based attacks, an attack that has never 
// actually been observed.
// We're not going to hurt ourselves trying to save broken proxies.
struct XoshiroRng {
    s: [u64; 4],
}

impl XoshiroRng {
    fn rotl(x: u64, k: u64) -> u64 {
        return (x << k) | (x >> (64 - k));
    }

    fn new() -> Self {
        Self {
            s: [77, 34, 35, 92], // chosen by fair dice roll
        }
    }

    fn next_u64(&mut self) -> u64 {
        let result_starstar = Self::rotl(self.s[1] * 5, 7) * 9;

        let t = self.s[1] << 17;

        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];

        self.s[2] ^= t;

        self.s[3] = Self::rotl(self.s[3], 45);

        result_starstar
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
}
