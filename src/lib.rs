#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::restriction)]
#![allow(
    clippy::implicit_return,
    clippy::missing_docs_in_private_items,
    clippy::missing_inline_in_public_items
)]

//! A wee websocket library powered by rustls
//!
//! `weebsocket` is a basic websocket client library, which compiles reasonably fast, can produce
//! reasonably small binaries, and is dead simple to use.
//!
//! If you don't mind blocking, a `Client` can use blocking I/O on the current thread:
//! ```rust
//! use weebsocket::Message;
//!
//! let mut client = weebsocket::blocking::connect("wss://echo.websocket.org/").unwrap();
//! client.send(Message::Text("Hi")).unwrap();
//! assert_eq!(client.recv().unwrap(), Message::Text("Hi"));
//! ```

lazy_static::lazy_static! {
    pub(crate) static ref TLS_CONFIG: std::sync::Arc<rustls::ClientConfig> = {
        let mut config = rustls::ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        std::sync::Arc::new(config)
    };
}

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

/// A websocket client that uses blocking I/O on the current thread
pub mod blocking;
mod error;

pub use error::Error;

/// A websocket message, used by `Client::send` and `Client::recv`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// A Ping message (5.5.2)
    Ping(Vec<u8>),
    /// A Pong message (5.5.3)
    Pong(Vec<u8>),
    /// A message that contains UTF-8 encoded text (5.6)
    Text(String),
    /// A message that contains arbitrary bytes (5.6)
    Binary(Vec<u8>),
    /// A message that indicate closure of the connection,
    /// with an optional status code and reason (5.5.1)
    Close(Option<(u16, String)>),
}

pub(crate) struct Frame {
    pub is_fin: bool,
    pub opcode: u8,
    pub data: Vec<u8>,
}

/// Represents a websocket Stream and Sink
pub struct Client {
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    rng: XorshiroRng,
}

impl Client {
    /// Creates a futures that resolves to a websocket connection
    pub async fn connect(uri: &str) -> Result<Self, Error> {
        use std::convert::TryFrom;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

        let stream = tokio::net::TcpStream::connect((host, port)).await?;
        let connector = tokio_rustls::TlsConnector::from(TLS_CONFIG.clone());
        let mut tls = connector.connect(dns_name, stream).await?;

        let data = format!(
            "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
            path, host,
        );
        tls.write_all(data.as_bytes()).await?;

        let mut buf = [0; 4096];
        let bytes = tls.read(&mut buf).await?;

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
            stream: tls,
            rng: XorshiroRng::new(),
        })
    }

    /// Send a message on the websocket
    pub async fn send(&mut self, message: &Message) -> Result<(), Error> {
        use tokio::io::AsyncWriteExt;

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
        self.stream.write_all(&[0b1000_0000 | opcode]).await?;

        // First bit indicates if we're transmitting a mask.
        // We always transmit a mask.

        if len > u16::max_value() as usize {
            self.stream.write_all(&[0b1000_0000 | 127]).await?;
            self.stream.write_all(&(len as u64).to_be_bytes()).await?;
        } else if len > 125 {
            self.stream.write_all(&[0b1000_0000 | 126]).await?;
            self.stream.write_all(&(len as u16).to_be_bytes()).await?;
        } else {
            self.stream.write_all(&[0b1000_0000 | len as u8]).await?;
        }

        let mask = self.rng.next_u32().to_ne_bytes();
        self.stream.write_all(&mask).await?;

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

        self.stream.write_all(&data).await?;

        Ok(())
    }

    /// Recieve a websocket message, blocking until one is available
    pub async fn recv(&mut self) -> Result<Message, crate::Error> {
        use tokio::io::AsyncReadExt;

        let Frame {
            mut is_fin,
            opcode,
            mut data,
        } = self.recv_frame().await?;

        while !is_fin {
            let frame = self.recv_frame().await?;
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

    async fn recv_frame(&mut self) -> std::io::Result<Frame> {
        use tokio::io::AsyncReadExt;
        let (fin, _rsv, opcode) = mask!(
            self.stream.read_u8().await?,
            0b1000_0000,
            0b0111_0000,
            0b0000_1111
        );
        let is_fin = fin > 0;

        let (mask_byte, payload_length) = mask!(self.stream.read_u8().await?, 0b1000_0000, 0b0111_1111);
        let has_mask = mask_byte > 0;

        let payload_length = if payload_length == 126 {
            self.stream.read_u16().await? as u64
        } else if payload_length == 127 {
            self.stream.read_u64().await?
        } else {
            payload_length as u64
        };

        let masking_key = if has_mask {
            let mut key = [0; 4];
            self.stream.read_exact(&mut key).await?;
            Some(key)
        } else {
            None
        };

        let mut data = vec![0; payload_length as usize];
        if payload_length > 0 {
            self.stream.read_exact(&mut data).await?;
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

// The websocket RFC requires the contents of messages be randomly masked,
// but that's only done to scramble the bits to protect broken proxies from
// opening themselves up to cache-based attacks, an attack that has never
// actually been observed.
// We're not going to hurt ourselves trying to save broken proxies.
struct XorshiroRng {
    s: [u64; 4],
}

impl XorshiroRng {
    fn rotl(x: u64, k: u64) -> u64 {
        (x << k) | (x >> (64u64.wrapping_sub(k)))
    }

    fn new() -> Self {
        Self {
            s: [77, 34, 35, 92], // chosen by fair dice roll
        }
    }

    fn next_u64(&mut self) -> u64 {
        let result_starstar = Self::rotl(self.s[1].wrapping_mul(5), 7).wrapping_mul(9);

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
